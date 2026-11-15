//! Только pure clock/ledger fixtures: никаких socketpair, FD или owner queries ОС.
use super::*;
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
#[test]
fn r8_initiator_tuple_is_looked_up_without_endpoint_swap_and_unknown_never_mints() {
    use crate::profile_channel::{Binding, Frame, Message, Mode};
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/xray-profile-channel-v3/initiator-ingress-r8.json"
    ))
    .unwrap();
    let now = Instant::now();
    let binding = Binding {
        session: [1; 16],
        invocation: [2; 16],
        digest: [3; 32],
        generation: 4,
        epoch: 5,
    };
    for case in vectors["cases"].as_array().unwrap() {
        let hex = case["frame_hex"].as_str().unwrap();
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let frame = Frame::decode(&bytes, binding, Mode::Local, false).unwrap();
        let Message::OpenIngress { tuple, .. } = frame.message else {
            panic!("OPEN_INGRESS expected")
        };
        let owner_flow = tuple.owner_flow().unwrap();
        let mut actor = OwnerQueries::<u64>::new();
        let result = actor.resolve(
            1,
            owner_flow,
            OwnerReference::NONE,
            || now,
            || {
                // Fake kernel видит initiator socket; accepted Xray socket — другой.
                if owner_flow.family == 2
                    && owner_flow.local_port == 32001
                    && owner_flow.remote_port == 1080
                    && owner_flow.protocol == 6
                {
                    Ok(OwnerObservation {
                        value: 7,
                        expiry: now + Duration::from_millis(20),
                    })
                } else {
                    Err(Unavailable::Authority)
                }
            },
        );
        assert_eq!(result.is_ok(), case["name"] == "tcp");
        let mut unknown = OwnerQueries::<u64>::new();
        assert!(
            unknown
                .resolve(
                    2,
                    owner_flow,
                    OwnerReference::NONE,
                    || now,
                    || Err(Unavailable::Authority)
                )
                .is_err()
        );
    }
}

fn flow(port: u16) -> super::super::broker::Flow {
    let mut local = [0; 16];
    local[..4].copy_from_slice(&[192, 0, 2, 1]);
    let mut remote = [0; 16];
    remote[..4].copy_from_slice(&[198, 51, 100, 1]);
    super::super::broker::Flow {
        family: 2,
        protocol: 6,
        local_port: port,
        remote_port: 443,
        local,
        remote,
        cookie: None,
    }
}
#[test]
fn owner_credit_is_bounded_and_keeps_parent_reservation_until_last_proof_drop() {
    let budget = OwnerBudget::new().unwrap();
    let weak = Arc::downgrade(&budget);
    let mut credits = Vec::new();
    for _ in 0..224 {
        credits.push(budget.reserve().unwrap());
    }
    assert!(budget.reserve().is_err());
    drop(budget);
    assert!(weak.upgrade().is_some());
    credits.clear();
    assert!(weak.upgrade().is_none());
    assert!(std::mem::size_of::<OwnerReceiptEntry<OwnerRecord>>() <= 128);
    assert!(std::mem::size_of::<OwnerOperation>() <= 256);
    assert!(std::mem::size_of::<OwnerRecord>() + wire::MAX_PATH + 64 <= 2048);
}
#[test]
fn malformed_reference_and_id_wrap_deny_before_backend_lookup() {
    let now = Instant::now();
    let mut owner = OwnerQueries::<u64>::new();
    let calls = Cell::new(0);
    for (source, reference) in [
        (0, OwnerReference::NONE),
        (
            1,
            OwnerReference {
                kind: ReceiptKind::None,
                id: 1,
            },
        ),
    ] {
        assert!(
            owner
                .resolve(
                    source,
                    flow(1),
                    reference,
                    || now,
                    || {
                        calls.set(calls.get() + 1);
                        Err(Unavailable::Authority)
                    }
                )
                .is_err()
        );
    }
    assert_eq!(calls.get(), 0);
    owner.next_operation = u64::MAX;
    assert!(
        owner
            .resolve(
                1,
                flow(1),
                OwnerReference::NONE,
                || now,
                || {
                    calls.set(calls.get() + 1);
                    Ok(OwnerObservation {
                        value: 1,
                        expiry: now + Duration::from_millis(20),
                    })
                }
            )
            .is_err()
    );
    assert_eq!(calls.get(), 0);
}
#[test]
fn frozen_receipt_is_operation_bound_and_namespace_collision_falls_back_once() {
    let now = Instant::now();
    let calls = Cell::new(0);
    let mut owner = OwnerQueries::new();
    owner
        .sent_frozen(
            1,
            flow(1),
            OwnerObservation {
                value: 7,
                expiry: now + Duration::from_millis(20),
            },
            now,
        )
        .unwrap();
    let first = owner
        .resolve(
            1,
            flow(1),
            OwnerReference {
                kind: ReceiptKind::FrozenSent,
                id: 1,
            },
            || now,
            || {
                calls.set(calls.get() + 1);
                Err(Unavailable::Authority)
            },
        )
        .unwrap();
    assert_eq!(*first.value, 7);
    assert_eq!(calls.get(), 0);
    assert!(
        owner
            .resolve(
                2,
                flow(1),
                OwnerReference {
                    kind: ReceiptKind::FrozenSent,
                    id: 1
                },
                || now,
                || {
                    calls.set(calls.get() + 1);
                    Ok(OwnerObservation {
                        value: 8,
                        expiry: now + Duration::from_millis(20),
                    })
                }
            )
            .is_err()
    );
    assert_eq!(calls.get(), 0);
    let second = owner
        .resolve(
            2,
            flow(1),
            OwnerReference {
                kind: ReceiptKind::SidebandOperation,
                id: 1,
            },
            || now,
            || {
                calls.set(calls.get() + 1);
                Ok(OwnerObservation {
                    value: 9,
                    expiry: now + Duration::from_millis(20),
                })
            },
        )
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(second.reference.kind, ReceiptKind::SidebandOperation);
    assert_eq!(second.reference.id, 1);
    assert_eq!(*second.value, 9);
    assert!(
        owner
            .resolve(
                1,
                flow(1),
                second.reference,
                || now,
                || Err(Unavailable::Authority)
            )
            .is_err()
    );
}
#[test]
fn queue_delay_and_repeated_references_never_extend_original_expiry() {
    let began = Instant::now();
    let clock = Cell::new(began);
    let mut owner = OwnerQueries::new();
    let proof = owner
        .resolve(
            1,
            flow(1),
            OwnerReference::NONE,
            || clock.get(),
            || {
                clock.set(began + Duration::from_millis(19));
                Ok(OwnerObservation {
                    value: 7,
                    expiry: began + Duration::from_millis(20),
                })
            },
        )
        .unwrap();
    assert_eq!(proof.expiry, began + Duration::from_millis(20));
    clock.set(began + Duration::from_millis(20));
    assert!(
        owner
            .resolve(
                1,
                flow(1),
                proof.reference,
                || clock.get(),
                || Err(Unavailable::Timeout)
            )
            .is_err()
    );
    assert!(
        owner
            .resolve(
                1,
                flow(1),
                OwnerReference::NONE,
                || clock.get(),
                || Ok(OwnerObservation {
                    value: 8,
                    expiry: began + Duration::from_millis(20)
                })
            )
            .is_err()
    );
}
#[test]
fn cancel_one_and_ring_eviction_do_not_revoke_other_live_flows() {
    let now = Instant::now();
    let mut owner = OwnerQueries::new();
    let mut references = Vec::new();
    for id in 1..=65 {
        let proof = owner
            .resolve(
                id,
                flow(id as u16),
                OwnerReference::NONE,
                || now,
                || {
                    Ok(OwnerObservation {
                        value: id,
                        expiry: now + Duration::from_millis(20),
                    })
                },
            )
            .unwrap();
        references.push(proof.reference);
    }
    assert_eq!(owner.entries.len(), 64);
    assert!(
        owner
            .resolve(
                1,
                flow(1),
                references[0],
                || now,
                || Err(Unavailable::Authority)
            )
            .is_err()
    );
    owner.cancel_source(2);
    assert!(
        owner
            .resolve(
                2,
                flow(2),
                references[1],
                || now,
                || Err(Unavailable::Authority)
            )
            .is_err()
    );
    assert_eq!(
        *owner
            .resolve(
                65,
                flow(65),
                references[64],
                || now,
                || Err(Unavailable::Authority)
            )
            .unwrap()
            .value,
        65
    );
    owner.revoke();
    assert!(
        owner
            .resolve(
                65,
                flow(65),
                references[64],
                || now,
                || Ok(OwnerObservation {
                    value: 65,
                    expiry: now + Duration::from_millis(20)
                })
            )
            .is_err()
    );
}
