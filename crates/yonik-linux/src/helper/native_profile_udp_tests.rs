//! Только injected operations: никаких actual FD/socket/recv/owner lookup.
use super::{
    AssociationIssuer, InvocationHistory, KernelDatagram, ServiceError, Subject, UdpOperations,
    UdpStage, wire,
};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use wire::{
    LaunchRecord, Mode, Tuple,
    udp_v2::{Packet, Record},
};

struct Fake {
    now: Instant,
    system: bool,
    known: bool,
    foreign: bool,
    retired: Cell<bool>,
    closed: Cell<bool>,
    calls: Cell<usize>,
    peeks: Cell<usize>,
    revokes: Cell<usize>,
    flags: u16,
    payload: Vec<u8>,
}
fn principal() -> Subject {
    Subject {
        pid: 7,
        start: 9,
        executable: (11, 12),
        cookie: 101,
        epoch: 5,
        path: [13; 32],
    }
}
impl UdpOperations for Fake {
    type Control = ();
    type Relay = ();
    type Transfer = ();
    fn ready(&self) -> Result<(), ServiceError> {
        Ok(())
    }
    fn fence(&self) -> Result<(), ServiceError> {
        Ok(())
    }
    fn control(
        &mut self,
        _: (),
        _: Tuple,
        _: u16,
        source: u64,
    ) -> Result<((), u64, Option<Subject>), ServiceError> {
        self.calls.set(self.calls.get() + 1);
        Ok(((), 100 + source, self.system.then(principal)))
    }
    fn alive(&self, _: &()) -> Result<(), ServiceError> {
        Ok(())
    }
    fn relay(&mut self, _: &()) -> Result<((), u64, u16), ServiceError> {
        self.calls.set(self.calls.get() + 1);
        Ok(((), 102, 49152))
    }
    fn duplicate(&mut self, _: &()) -> Result<(), ServiceError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
    fn peek(
        &mut self,
        _: &(),
        out: &mut [u8; 65536],
    ) -> Result<Option<KernelDatagram>, ServiceError> {
        self.peeks.set(self.peeks.get() + 1);
        out[..self.payload.len()].copy_from_slice(&self.payload);
        Ok(Some(KernelDatagram {
            peer: "192.0.2.1:32002".parse().unwrap(),
            bytes: self.payload.len(),
            flags: self.flags,
        }))
    }
    fn consumed(&self, _: &(), _: Packet) -> Result<(), ServiceError> {
        Ok(())
    }
    fn owner(
        &mut self,
        _: u64,
        _: Tuple,
    ) -> Result<(Option<Subject>, Option<Instant>), ServiceError> {
        Ok((
            if self.system && self.known {
                Some(Subject {
                    pid: if self.foreign { 8 } else { 7 },
                    ..principal()
                })
            } else {
                None
            },
            self.known.then_some(self.now + Duration::from_millis(20)),
        ))
    }
    fn payload_retired(&self, _: u64, _: u64) -> Result<bool, ServiceError> {
        Ok(self.retired.get())
    }
    fn duplicate_closed(&self, _: &(), _: Record) -> Result<(), ServiceError> {
        if self.closed.get() {
            Ok(())
        } else {
            Err(ServiceError::Unavailable)
        }
    }
    fn revoke(&self) {
        self.revokes.set(self.revokes.get() + 1);
    }
}
fn launch(mode: Mode) -> LaunchRecord {
    LaunchRecord {
        mode,
        nonce: [6; 32],
        binding: wire::Binding {
            digest: [3; 32],
            session: [1; 16],
            invocation: [2; 16],
            generation: 4,
            epoch: 5,
        },
        owner_pid: 7,
        owner_start: 9,
        child_pid: if mode == Mode::System { 8 } else { 0 },
        child_start: if mode == Mode::System { 10 } else { 0 },
        manifest: [11; 32],
    }
}
fn issuer(mode: Mode, limit: u32) -> AssociationIssuer<Fake> {
    AssociationIssuer::new(
        Fake {
            now: Instant::now(),
            system: mode == Mode::System,
            known: true,
            foreign: false,
            retired: Cell::new(false),
            closed: Cell::new(false),
            calls: Cell::new(0),
            peeks: Cell::new(0),
            revokes: Cell::new(0),
            flags: 0,
            payload: vec![0, 0, 0, 1, 1, 2, 3, 4, 1, 187, 99],
        },
        launch(mode),
        limit,
        super::super::memory::ByteBudget::new(8 * 1024 * 1024),
    )
    .unwrap()
}
fn tcp() -> Tuple {
    Tuple {
        protocol: 6,
        family: 4,
        local_port: 32001,
        remote_port: 1080,
        local: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        remote: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    }
}
fn request(
    i: &mut AssociationIssuer<Fake>,
    r: Record,
    fd: Option<()>,
) -> Result<Option<super::UdpResponse<()>>, ServiceError> {
    let now = i.ops.now;
    i.handle(r, fd, now, now + Duration::from_secs(1))
}
fn association(i: &mut AssociationIssuer<Fake>, op: u64) -> (u64, u64) {
    let r = request(
        i,
        Record::Control {
            operation: op,
            proof: op,
            ingress: 0,
            tuple: tcp(),
        },
        Some(()),
    )
    .unwrap()
    .unwrap();
    let Record::ControlAck {
        control, cookie, ..
    } = r.record
    else {
        panic!("control")
    };
    let r = request(
        i,
        Record::Associate {
            operation: op + 1,
            control,
            cookie,
        },
        None,
    )
    .unwrap()
    .unwrap();
    assert!(r.fd.is_some());
    let Record::Associated { association, .. } = r.record else {
        panic!("association")
    };
    (control, association)
}
fn permit(i: &mut AssociationIssuer<Fake>, control: u64, association: u64, op: u64) -> Packet {
    let r = request(
        i,
        Record::Peek {
            association,
            operation: op,
            control,
        },
        None,
    )
    .unwrap()
    .unwrap();
    let Record::Permit { packet, .. } = r.record else {
        panic!("permit")
    };
    packet
}
#[test]
fn udp_v2_delays_grant_holds_buffer_and_requires_distinct_udp_owner() {
    for mode in [Mode::Local, Mode::System] {
        let mut i = issuer(mode, 256);
        let (c, a) = association(&mut i, 1);
        let p = permit(&mut i, c, a, 3);
        assert!(i.relays[&a].flows.is_empty());
        assert!(i.relays[&a].cycle.as_ref().unwrap().stage == UdpStage::Permitted);
        assert!(matches!(
            request(
                &mut i,
                Record::Peek {
                    association: a,
                    operation: 4,
                    control: c
                },
                None
            ),
            Err(ServiceError::Busy)
        ));
        assert_eq!(i.ops.peeks.get(), 1);
        request(
            &mut i,
            Record::Consumed {
                packet: p,
                sequence: 9,
            },
            None,
        )
        .unwrap();
        let original = i.relays[&a].cycle.as_ref().unwrap().original.unwrap();
        let now = i.ops.now;
        i.ops.known = false;
        assert_eq!(
            i.bind_source(9, 2, p.tuple, original.wire(), now).is_ok(),
            mode == Mode::Local
        );
        i.ops.known = true;
        i.bind_source(9, 2, p.tuple, original.wire(), now).unwrap();
        assert!(i.relays[&a].cycle.as_ref().unwrap().stage == UdpStage::Matched);
        i.check_grant(2, now).unwrap();
        i.granted(2, 17);
        assert!(matches!(
            request(
                &mut i,
                Record::Peek {
                    association: a,
                    operation: 4,
                    control: c
                },
                None
            ),
            Err(ServiceError::Busy)
        ));
        assert_eq!(i.ops.peeks.get(), 1);
        i.ops.retired.set(true);
        permit(&mut i, c, a, 4);
        assert_eq!(i.ops.peeks.get(), 2);
    }
}
#[test]
fn udp_v2_global_tombstones_exhaust_before_factory_and_never_evict() {
    let mut i = issuer(Mode::Local, 3);
    i.history.lock().unwrap().runtime(1).unwrap();
    request(
        &mut i,
        Record::Control {
            operation: 1,
            proof: 1,
            ingress: 0,
            tuple: tcp(),
        },
        Some(()),
    )
    .unwrap();
    let calls = i.ops.calls.get();
    assert!(matches!(
        request(
            &mut i,
            Record::Associate {
                operation: 2,
                control: 1,
                cookie: 101
            },
            None
        ),
        Err(ServiceError::Busy)
    ));
    assert_eq!(i.ops.calls.get(), calls);
    assert!(i.relays.is_empty());
    assert_eq!(i.history.lock().unwrap().len, 3);
    assert!(
        request(
            &mut i,
            Record::Associate {
                operation: 2,
                control: 1,
                cookie: 101
            },
            None
        )
        .is_err()
    );
    let budget = super::super::memory::ByteBudget::new(16384);
    let h = InvocationHistory::new(999, &budget).unwrap();
    assert_eq!(h.limit, 256);
}
#[test]
fn udp_v2_mismatch_frag_truncation_and_replay_revoke_without_forward() {
    for case in 0..4 {
        let mut i = issuer(Mode::Local, 256);
        let (c, a) = association(&mut i, 1);
        if case == 0 {
            i.ops.flags = 1;
        }
        if case == 1 {
            i.ops.payload[2] = 1;
        }
        if case < 2 {
            assert!(
                request(
                    &mut i,
                    Record::Peek {
                        association: a,
                        operation: 3,
                        control: c
                    },
                    None
                )
                .is_err()
            );
        } else {
            let mut p = permit(&mut i, c, a, 3);
            if case == 2 {
                p.fingerprint[0] ^= 1;
            } else {
                request(
                    &mut i,
                    Record::Consumed {
                        packet: p,
                        sequence: 9,
                    },
                    None,
                )
                .unwrap();
            }
            assert!(
                request(
                    &mut i,
                    Record::Consumed {
                        packet: p,
                        sequence: 9
                    },
                    None
                )
                .is_err()
            );
        }
        assert!(i.unknown);
        assert_eq!(i.ops.revokes.get(), 1);
        assert!(i.relays[&a].flows.is_empty());
    }
}
#[test]
fn udp_v2_two_associations_cancel_and_unknown_duplicate_custody() {
    let mut i = issuer(Mode::Local, 256);
    let (c, a) = association(&mut i, 1);
    let (d, b) = association(&mut i, 3);
    let p = permit(&mut i, c, a, 5);
    let q = permit(&mut i, d, b, 6);
    assert_ne!(p.association, q.association);
    request(
        &mut i,
        Record::Consumed {
            packet: p,
            sequence: 9,
        },
        None,
    )
    .unwrap();
    let original = i.relays[&a].cycle.as_ref().unwrap().original.unwrap();
    let now = i.ops.now;
    i.bind_source(9, 3, p.tuple, original.wire(), now).unwrap();
    i.cancel_flow(3);
    assert!(i.relays[&a].flows.is_empty());
    let close = i.retire(a, now).unwrap();
    let Record::Close { close, .. } = close.record else {
        panic!("close")
    };
    let record = Record::Closed {
        association: a,
        close,
        last_packet: p.packet,
        pending: 0,
        status: 1,
        joined: true,
        duplicates: 0,
        cookie: 102,
        retired: 9,
    };
    // Даже canonical Known ACK не закрывает duplicate без independent receipt.
    assert!(request(&mut i, record, None).is_err());
    assert!(i.unknown);
    assert_eq!(i.relays.len(), 2);
    assert!(i.relays[&b].cycle.as_ref().unwrap().stage == UdpStage::Permitted);
}
#[test]
fn udp_v2_known_closed_requires_receipt_and_zero_live_flows() {
    let mut i = issuer(Mode::Local, 256);
    let (_, a) = association(&mut i, 1);
    let now = i.ops.now;
    let r = i.retire(a, now).unwrap();
    let Record::Close { close, .. } = r.record else {
        panic!("close")
    };
    i.ops.closed.set(true);
    request(
        &mut i,
        Record::Closed {
            association: a,
            close,
            last_packet: 0,
            pending: 0,
            status: 1,
            joined: true,
            duplicates: 0,
            cookie: 102,
            retired: 0,
        },
        None,
    )
    .unwrap();
    assert!(i.relays.is_empty());
    assert!(i.controls.is_empty());
    assert_eq!(i.history.lock().unwrap().len, 3);
}

#[test]
fn udp_v2_delayed_readiness_error_is_sticky_and_retains_custody() {
    let mut i = issuer(Mode::Local, 256);
    let (c, a) = association(&mut i, 1);
    permit(&mut i, c, a, 3);
    // Inject readiness только меняет fake state; никакого OS receive.
    i.relays.get_mut(&a).unwrap().cycle.as_mut().unwrap().stage = UdpStage::Waiting;
    i.ops.flags = 2;
    let now = i.ops.now;
    assert!(i.progress(a, now).is_err());
    assert!(i.unknown);
    assert_eq!(i.ops.revokes.get(), 1);
    assert_eq!(i.relays.len(), 1);
}

#[test]
fn udp_v2_expired_udp_owner_and_missing_control_right_never_bind() {
    assert!(super::udp_v2_consumer_ready().is_err());
    let record = launch(Mode::System);
    let (bootstrap, ack, version) = super::profile_proof_setup(record).unwrap();
    assert_eq!(version, 1);
    assert_eq!(bootstrap, wire::proof_bootstrap(record).unwrap());
    assert_eq!(ack, wire::proof_bootstrap_ack(record).unwrap());
    let mut i = issuer(Mode::System, 256);
    let (c, a) = association(&mut i, 1);
    let p = permit(&mut i, c, a, 3);
    request(
        &mut i,
        Record::Consumed {
            packet: p,
            sequence: 9,
        },
        None,
    )
    .unwrap();
    let original = i.relays[&a].cycle.as_ref().unwrap().original.unwrap();
    i.ops.foreign = true;
    let now = i.ops.now;
    assert!(i.bind_source(9, 2, p.tuple, original.wire(), now).is_err());
    i.ops.foreign = false;
    let now = i.ops.now + Duration::from_millis(21);
    assert!(i.bind_source(9, 2, p.tuple, original.wire(), now).is_err());
    assert!(i.relays[&a].flows.is_empty());
    let mut i = issuer(Mode::Local, 256);
    assert!(
        request(
            &mut i,
            Record::Control {
                operation: 1,
                proof: 1,
                ingress: 0,
                tuple: tcp()
            },
            None
        )
        .is_err()
    );
    assert_eq!(i.ops.calls.get(), 0);
}

#[test]
fn udp_v2_known_ack_cannot_retire_live_flows_or_recover_unknown() {
    let mut i = issuer(Mode::Local, 256);
    let (_, a) = association(&mut i, 1);
    let now = i.ops.now;
    let credit = i.budget.reserve(128).unwrap();
    i.relays.get_mut(&a).unwrap().flows.insert(2, credit);
    let r = i.retire(a, now).unwrap();
    let Record::Close { close, .. } = r.record else {
        panic!("close")
    };
    i.ops.closed.set(true);
    let ack = Record::Closed {
        association: a,
        close,
        last_packet: 0,
        pending: 0,
        status: 1,
        joined: true,
        duplicates: 0,
        cookie: 102,
        retired: 9,
    };
    assert!(request(&mut i, ack, None).is_err());
    assert!(i.unknown);
    i.cancel_flow(2);
    assert!(request(&mut i, ack, None).is_err());
    assert_eq!(i.relays.len(), 1);
}
