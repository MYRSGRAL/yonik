use super::{
    Arc, AtomicBool, AtomicU64, BootstrapBinding, BootstrapScope, FakeOwner, FakePeer, Fixture,
    Instant, Mode, Ordering, ServiceError,
};
use crate::helper::registry::{DatagramScope as D, fake_datagram_image};
fn fixture5(mode: Mode, scopes: &[D]) -> Fixture {
    let (cap, launch, asset, reference, path, endpoint, budget, network_root) =
        super::super::super::dns_bundle::roots::tests::binding5_fixture(mode, 2);
    Fixture {
        peer: Arc::new(FakePeer {
            record: launch,
            image: [17; 32],
            config: launch.binding.digest,
            producer: Some(fake_datagram_image([17; 32], scopes)),
            valid: AtomicBool::new(true),
            clock: AtomicU64::new(0),
            start: Instant::now(),
            fds: crate::helper::memory::ByteBudget::new(64),
        }),
        owner: Arc::new(FakeOwner {
            mode,
            capsule: cap,
            reference,
            asset,
            peers: vec!["192.0.2.53:53".parse().unwrap()],
            valid: AtomicBool::new(true),
            fail_plan: AtomicBool::new(false),
        }),
        path,
        endpoint,
        budget,
        network_root,
        subject: 0,
    }
}
fn create5(f: &Fixture) -> Result<Option<Arc<BootstrapBinding>>, ServiceError> {
    BootstrapBinding::create_for(
        f.peer.clone(),
        f.owner.clone(),
        f.owner.capsule.clone(),
        f.peer.record,
        f.budget.clone(),
        super::super::Flavor::Datagram5,
    )
}
#[test]
fn tcp5_factory_independent_source_wire_release_and_carrier() {
    use crate::helper::registry::{Tcp5Scope as T, fake_tcp5_image};
    for mode in [Mode::Local,Mode::System] {
        let mut f = fixture5(mode,&[D::Source,D::Wire,D::Release]);
        let make = |f: &Fixture| BootstrapBinding::create_for(f.peer.clone(),f.owner.clone(),f.owner.capsule.clone(),f.peer.record,f.budget.clone(),super::super::Flavor::Tcp5);
        assert!(make(&f).unwrap().is_none(),"UDP5 review не mint TCP5");
        let legacy = crate::helper::registry::fake_bootstrap_image([17;32],&[BootstrapScope::Source,BootstrapScope::Wire,BootstrapScope::Release]);
        Arc::get_mut(&mut f.peer).unwrap().producer = Some(legacy);
        assert!(make(&f).unwrap().is_none(),"Source4 review не mint TCP5");
        Arc::get_mut(&mut f.peer).unwrap().producer = Some(fake_tcp5_image(fake_datagram_image([17;32],&[]),&[T::Source,T::Release]));
        let cap = crate::profile_channel::Capsule::decode(f.owner.capsule.bytes(),&f.peer.config).unwrap();
        let (scope,mask) = cap.subject_scope(0,6).unwrap();
        assert_eq!(mask,1);
        f.path = vec![(scope,0)];
        f.endpoint = cap.dial_scope(scope,0).unwrap().endpoint_index;
        let b = make(&f).unwrap().unwrap();
        let view = b.tcp5_views(f.peer.record).unwrap().unwrap();
        assert!(b.source().is_none() && b.transcript().is_none() && b.release().is_none());
        assert!(b.datagram_source(f.peer.record).unwrap().is_none());
        assert!(view.release(f.peer.record).is_ok());
        assert!(b.check(BootstrapScope::Wire,f.peer.record).is_err());
        assert!(view.source(f.peer.record).unwrap().parent(super::parent(&f,false,9)).is_ok());
        let mut wrong = super::parent(&f,false,10);
        wrong.original.protocol = 17;
        assert!(view.source(f.peer.record).unwrap().parent(wrong).is_err());
        let mut wrong = f.peer.record;
        wrong.binding.epoch += 1;
        assert!(view.release(wrong).is_err());
        f.owner.valid.store(false,Ordering::Release);
        assert!(view.release(f.peer.record).is_err());
        f.owner.valid.store(true,Ordering::Release);
        assert!(view.release(f.peer.record).is_err(),"source change sticky");
    }
}
#[test]
fn scope5_factory_local_system_independent_records_and_sticky_source() {
    for mode in [Mode::Local, Mode::System] {
        for scopes in [
            &[D::Source][..],
            &[D::Wire, D::Release][..],
            &[D::Source, D::Wire, D::Release][..],
        ] {
            let f = fixture5(mode, scopes);
            let b = create5(&f).unwrap().unwrap();
            assert_eq!(
                b.datagram_source(f.peer.record).unwrap().is_some(),
                scopes.contains(&D::Source)
            );
            assert_eq!(
                b.datagram_wire(f.peer.record).unwrap().is_some(),
                scopes.contains(&D::Wire)
            );
            assert_eq!(
                b.datagram_release(f.peer.record).unwrap().is_some(),
                scopes.contains(&D::Release)
            );
            assert!(b.source().is_none() && b.release().is_none());
            f.owner.valid.store(false, Ordering::Release);
            let scope = if scopes.contains(&D::Source) {
                BootstrapScope::Source
            } else {
                BootstrapScope::Wire
            };
            assert!(b.datagram_check(scope, f.peer.record).is_err());
            f.owner.valid.store(true, Ordering::Release);
            assert!(b.datagram_check(scope, f.peer.record).is_err());
        }
    }
}
#[test]
fn scope5_factory_wrong_image_launch_snapshot_and_expiry_fail_closed() {
    for fault in 0..7 {
        let mut f = fixture5(Mode::System, &[D::Source, D::Wire, D::Release]);
        match fault {
            0 => Arc::get_mut(&mut f.peer).unwrap().image[0] ^= 1,
            1 => Arc::get_mut(&mut f.peer).unwrap().config[0] ^= 1,
            2 => Arc::get_mut(&mut f.peer).unwrap().record.manifest[0] ^= 1,
            3 => Arc::get_mut(&mut f.owner).unwrap().reference.asset[0] ^= 1,
            4 => Arc::get_mut(&mut f.peer).unwrap().producer = None,
            5 => {
                Arc::get_mut(&mut f.peer).unwrap().producer =
                    Some(crate::helper::registry::fake_bootstrap_image(
                        [17; 32],
                        &[
                            BootstrapScope::Source,
                            BootstrapScope::Wire,
                            BootstrapScope::Release,
                        ],
                    ))
            }
            _ => Arc::get_mut(&mut f.owner).unwrap().mode = Mode::Local,
        }
        if matches!(fault, 4 | 5) {
            assert!(create5(&f).unwrap().is_none());
        } else {
            assert!(create5(&f).is_err());
        }
    }
    let f = fixture5(Mode::Local, &[D::Source, D::Wire, D::Release]);
    let b = create5(&f).unwrap().unwrap();
    let mut launch = f.peer.record;
    launch.nonce[0] ^= 1;
    assert!(b.datagram_source(launch).is_err());
    f.peer.clock.store(61_000_000_000, Ordering::Release);
    assert!(b.datagram_release(f.peer.record).is_err());
}
