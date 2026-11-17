//! Независимый sampled listener proof. Не FlowGrant/OS attribution и не pin
//! удалённого listener. Без защищённого service-policy issuer путь закрыт.

#[path = "resolver_policy.rs"]
mod resolver_policy;

use crate::attribution::broker::kernel::{Listener, ListenerSet};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    PolicyUnavailable,
    Untrusted,
    Incomplete,
    Ambiguous,
    Stale,
    Budget,
}
type Result<T> = std::result::Result<T, Error>;

/// Только общие resource credits, не service/Flow authority. Producer получает
/// существующие invocation ledgers; отдельного private pool здесь нет.
pub(crate) struct CaptureCredits {
    _fds: super::memory::ByteLease,
    _pending: super::memory::ByteLease,
    _bytes: super::memory::ByteLease,
}
impl CaptureCredits {
    #[allow(dead_code, reason = "Production path закрыт до approved installation")]
    fn reserve_policy_shared(
        fds: &super::memory::ByteBudget,
        pending: &super::memory::ByteBudget,
        bytes: &super::memory::ByteBudget,
    ) -> Result<Self> {
        let fds = fds.reserve(128).map_err(|_| Error::Budget)?;
        let pending = pending.reserve(1).map_err(|_| Error::Budget)?;
        let bytes = bytes.reserve(65536).map_err(|_| Error::Budget)?;
        Ok(Self {
            _fds: fds,
            _pending: pending,
            _bytes: bytes,
        })
    }
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Нет легитимного StubBind policy producer")
    )]
    pub(super) fn reserve_shared(
        fds: &super::memory::ByteBudget,
        pending: &super::memory::ByteBudget,
        bytes: &super::memory::ByteBudget,
    ) -> Result<Self> {
        let fds = fds.reserve(4).map_err(|_| Error::Budget)?;
        let pending = pending.reserve(1).map_err(|_| Error::Budget)?;
        let bytes = bytes.reserve(65536).map_err(|_| Error::Budget)?;
        Ok(Self {
            _fds: fds,
            _pending: pending,
            _bytes: bytes,
        })
    }
}

/// Existing anchors проверяют engines/yonik-worker, не resolver service code.
/// Root/UID/unit name/resolv.conf не заменяют отсутствующий policy contract.
pub(super) fn require_protected_policy(peer: SocketAddr, protocol: u8) -> Result<()> {
    if !peer.ip().is_loopback() || peer.port() == 0 || !matches!(protocol, 6 | 17) {
        return Err(Error::Untrusted);
    }
    Err(Error::PolicyUnavailable)
}

// До появления легитимного protected resolver-policy producer типы остаются
// private DATA/observation API. Factory ниже не принимает child metadata.
#[expect(
    dead_code,
    reason = "Reviewed resolver installation отсутствует; наблюдения не открывают issuer gate"
)]
mod observation {
    use super::*;
    use std::{fs::File, os::unix::fs::MetadataExt, sync::atomic::AtomicBool, time::Instant};

    const FRESH_NS: u64 = 20_000_000;
    const MAX_BYTES: usize = 65536;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum View {
        Local,
        System,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Unit {
        manager: String,
        invocation: [u8; 16],
        policy: [u8; 32],
        uid: u32,
        cgroup: u64,
        cgroup_identity: (u64, u64),
        namespace: (u64, u64),
        source_epoch: u64,
        view: View,
        delegated: bool,
        socket_activated: bool,
    }
    #[derive(Clone, Copy)]
    struct Context {
        view: View,
        namespace: (u64, u64),
        source_epoch: u64,
    }
    /// Оpaque independent evidence, не DTO из IPC. Production producer этого
    /// stamp должен закрепить reviewed service policy, manager owner и held FDs.
    pub(super) struct UnitEvidence {
        unit: Unit,
    }
    impl UnitEvidence {
        pub(super) fn from_policy(policy: super::resolver_policy::VerifiedPolicy) -> Self {
            let f = policy.into_facts();
            Self {
                unit: Unit {
                    manager: f.manager,
                    invocation: f.invocation,
                    policy: f.contract,
                    uid: f.uid,
                    cgroup: f.cgroup.1,
                    cgroup_identity: f.cgroup,
                    namespace: f.namespace,
                    source_epoch: f.epoch,
                    view: if f.system_view {
                        View::System
                    } else {
                        View::Local
                    },
                    delegated: false,
                    socket_activated: false,
                },
            }
        }
    }
    trait Source {
        type Handles;
        fn now(&self) -> u64;
        fn reserve(&mut self, fds: usize, pending: usize, bytes: usize) -> Result<Self::Handles>;
        fn unit(&mut self, held: &Self::Handles) -> Result<UnitEvidence>;
        fn listeners(
            &mut self,
            held: &Self::Handles,
            protocol: u8,
            port: u16,
        ) -> Result<ListenerSet>;
        fn revalidate_handles(&mut self, held: &Self::Handles) -> Result<()>;
    }
    /// Retained observation не является самостоятельной authority. Ошибка
    /// revalidate sticky; handles/credits остаются в объекте, не take/drop.
    struct RetainedStubBind<S: Source> {
        source: S,
        held: S::Handles,
        unit: Unit,
        listener: Listener,
        endpoint: SocketAddr,
        protocol: u8,
        observed_from: u64,
        expires: u64,
        poisoned: bool,
    }
    fn checked_unit(u: &Unit) -> Result<()> {
        if u.delegated
            || u.socket_activated
            || u.manager.len() > 255
            || !u.manager.starts_with(':')
            || u.invocation == [0; 16]
            || u.policy == [0; 32]
            || u.uid == 0
            || u.uid == u32::MAX
            || u.cgroup == 0
            || u.cgroup_identity.1 != u.cgroup
            || u.namespace == (0, 0)
            || u.source_epoch == 0
        {
            return Err(Error::Untrusted);
        }
        Ok(())
    }
    fn address(row: &Listener) -> IpAddr {
        if row.family == 2 {
            IpAddr::V4(std::net::Ipv4Addr::new(
                row.local[0],
                row.local[1],
                row.local[2],
                row.local[3],
            ))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(row.local))
        }
    }
    fn overlaps(row: &Listener, endpoint: SocketAddr) -> bool {
        let ip = address(row);
        if ip == endpoint.ip() {
            return true;
        }
        match (ip, endpoint.ip()) {
            (IpAddr::V4(ip), IpAddr::V4(_)) => ip.is_unspecified(),
            (IpAddr::V6(ip), IpAddr::V6(_)) => ip.is_unspecified(),
            (IpAddr::V6(ip), IpAddr::V4(target)) => {
                !row.v6only && (ip.is_unspecified() || ip.to_ipv4_mapped() == Some(target))
            }
            _ => false,
        }
    }
    fn select(
        set: &ListenerSet,
        unit: &Unit,
        endpoint: SocketAddr,
        protocol: u8,
    ) -> Result<Listener> {
        checked_unit(unit)?;
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 || !matches!(protocol, 6 | 17) {
            return Err(Error::Untrusted);
        }
        let mut selected = None;
        for row in set.iter() {
            if row.protocol != protocol || row.port != endpoint.port() {
                return Err(Error::Incomplete);
            }
            if !overlaps(row, endpoint) {
                continue;
            }
            // Wildcard/interface-bound/connected UDP и duplicate/reuseport не
            // выбираются по UID/cookie. Сначала полный set, затем unique exact.
            if address(row) != endpoint.ip()
                || row.interface != 0
                || row.remote_port != 0
                || row.remote.iter().any(|b| *b != 0)
                || row.uid != unit.uid
                || row.cgroup != unit.cgroup
                || row.inode == 0
                || if protocol == 6 {
                    row.state != 10
                } else {
                    row.state != 7
                }
            {
                return Err(Error::Ambiguous);
            }
            if selected.replace(*row).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        selected.ok_or(Error::Incomplete)
    }
    fn capture<S: Source>(
        mut source: S,
        endpoint: SocketAddr,
        protocol: u8,
        context: Context,
        expires: u64,
    ) -> Result<RetainedStubBind<S>> {
        let begun = source.now();
        if expires <= begun {
            return Err(Error::Stale);
        }
        // Held cgroup/netns + temporary diag socket/netns FD, one shared pending;
        // Source обязан debit existing invocation ledger до любых effects.
        let held = source.reserve(4, 1, MAX_BYTES)?;
        source.revalidate_handles(&held)?;
        let before = source.unit(&held)?.unit;
        checked_unit(&before)?;
        if before.view != context.view
            || before.namespace != context.namespace
            || before.source_epoch != context.source_epoch
        {
            return Err(Error::Untrusted);
        }
        let set = source.listeners(&held, protocol, endpoint.port())?;
        let listener = select(&set, &before, endpoint, protocol)?;
        source.revalidate_handles(&held)?;
        if source.unit(&held)?.unit != before
            || source.now() >= expires
            || source.now() < begun
            || source.now().saturating_sub(begun) > FRESH_NS
        {
            return Err(Error::Stale);
        }
        Ok(RetainedStubBind {
            source,
            held,
            unit: before,
            listener,
            endpoint,
            protocol,
            observed_from: begun,
            expires,
            poisoned: false,
        })
    }
    impl<S: Source> RetainedStubBind<S> {
        fn fresh(&self) -> Result<()> {
            let now = self.source.now();
            if self.poisoned
                || now >= self.expires
                || now < self.observed_from
                || now - self.observed_from > FRESH_NS
            {
                return Err(Error::Stale);
            }
            Ok(())
        }
        fn revalidate(&mut self) -> Result<()> {
            if self.poisoned {
                return Err(Error::Stale);
            }
            let result = self.revalidate_inner();
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
        fn revalidate_inner(&mut self) -> Result<()> {
            let begun = self.source.now();
            if begun >= self.expires {
                return Err(Error::Stale);
            }
            self.source.revalidate_handles(&self.held)?;
            if self.source.unit(&self.held)?.unit != self.unit {
                return Err(Error::Stale);
            }
            let set = self
                .source
                .listeners(&self.held, self.protocol, self.endpoint.port())?;
            if select(&set, &self.unit, self.endpoint, self.protocol)? != self.listener {
                return Err(Error::Stale);
            }
            self.source.revalidate_handles(&self.held)?;
            if self.source.unit(&self.held)?.unit != self.unit
                || self.source.now() >= self.expires
                || self.source.now() < begun
                || self.source.now().saturating_sub(begun) > FRESH_NS
            {
                return Err(Error::Stale);
            }
            self.observed_from = begun;
            self.fresh()
        }
    }

    /// Concrete compile-only kernel producer переиспользует retained nsfs FD,
    /// не proc scan/PID attribution. Production actor ниже удерживает manager/policy source;
    /// до approved installation observation не открывает public Allow gate.
    #[expect(
        clippy::too_many_arguments,
        reason = "Закрытый compile-only seam удержанных FD и одного credited запроса"
    )]
    fn kernel_sample(
        netns: &File,
        cgroup: &File,
        unit: &Unit,
        protocol: u8,
        port: u16,
        deadline: Instant,
        cancel: &AtomicBool,
        credit: &CaptureCredits,
    ) -> Result<ListenerSet> {
        if yonik_nsfs::namespace_type(netns).map_err(|_| Error::Untrusted)?
            != yonik_nsfs::NamespaceType::Net
        {
            return Err(Error::Untrusted);
        }
        let ns = netns.metadata().map_err(|_| Error::Untrusted)?;
        let group = cgroup.metadata().map_err(|_| Error::Untrusted)?;
        let fs = rustix::fs::fstatfs(cgroup).map_err(|_| Error::Untrusted)?;
        if usize::BITS != 64
            || !group.is_dir()
            || group.uid() != 0
            || group.mode() & 0o022 != 0
            || fs.f_type as u64 != 0x63677270
            || (group.dev(), group.ino()) != unit.cgroup_identity
            || (ns.dev(), ns.ino()) != unit.namespace
        {
            return Err(Error::Untrusted);
        }
        crate::attribution::broker::kernel::listener_census(
            protocol,
            port,
            (ns.dev(), ns.ino()),
            deadline,
            cancel,
            credit,
        )
        .map_err(|_| Error::Incomplete)
    }

    /// Один bounded production actor, holding source/credits даже после ошибки.
    struct ProtectedCapture {
        source: super::resolver_policy::production::Producer,
        unit: Unit,
        listener: Listener,
        endpoint: SocketAddr,
        protocol: u8,
        expires: Instant,
        poisoned: bool,
    }
    impl ProtectedCapture {
        async fn capture(
            budgets: (
                &super::super::memory::ByteBudget,
                &super::super::memory::ByteBudget,
                &super::super::memory::ByteBudget,
            ),
            endpoint: SocketAddr,
            protocol: u8,
            context: Context,
            expires: Instant,
            cancel: &AtomicBool,
        ) -> Result<Self> {
            let (fds, pending, bytes) = budgets;
            let deadline = expires.min(Instant::now() + std::time::Duration::from_nanos(FRESH_NS));
            let mut source = super::resolver_policy::production::Producer::open(
                fds, pending, bytes, deadline, cancel,
            )
            .await?;
            let before = UnitEvidence::from_policy(source.verified(cancel).await?).unit;
            if before.view != context.view
                || before.namespace != context.namespace
                || before.source_epoch != context.source_epoch
            {
                return Err(Error::Untrusted);
            }
            let (netns, cgroup, credit) = source.files();
            let set = kernel_sample(
                netns,
                cgroup,
                &before,
                protocol,
                endpoint.port(),
                deadline,
                cancel,
                credit,
            )?;
            let listener = select(&set, &before, endpoint, protocol)?;
            let after = UnitEvidence::from_policy(source.verified(cancel).await?).unit;
            if before != after || Instant::now() >= deadline {
                return Err(Error::Stale);
            }
            Ok(Self {
                source,
                unit: before,
                listener,
                endpoint,
                protocol,
                expires: deadline,
                poisoned: false,
            })
        }
        async fn revalidate(&mut self, cancel: &AtomicBool) -> Result<()> {
            if self.poisoned {
                return Err(Error::Stale);
            }
            let result = self.revalidate_inner(cancel).await;
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
        async fn revalidate_inner(&mut self, cancel: &AtomicBool) -> Result<()> {
            // Исходное 20ms окно и expiry никогда не продлеваются.
            if Instant::now() >= self.expires {
                return Err(Error::Stale);
            }
            if UnitEvidence::from_policy(self.source.verified(cancel).await?).unit != self.unit {
                return Err(Error::Stale);
            }
            let (netns, cgroup, credit) = self.source.files();
            let set = kernel_sample(
                netns,
                cgroup,
                &self.unit,
                self.protocol,
                self.endpoint.port(),
                self.expires,
                cancel,
                credit,
            )?;
            if select(&set, &self.unit, self.endpoint, self.protocol)? != self.listener {
                return Err(Error::Stale);
            }
            if UnitEvidence::from_policy(self.source.verified(cancel).await?).unit != self.unit
                || Instant::now() >= self.expires
            {
                return Err(Error::Stale);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{cell::Cell, rc::Rc};
        struct Held(Rc<Cell<usize>>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }
        struct Fake {
            clock: Rc<Cell<u64>>,
            unit: Unit,
            rows: Vec<Listener>,
            held: Rc<Cell<usize>>,
            effects: Rc<Cell<usize>>,
            budget_fail: bool,
            fail: bool,
            delay: u64,
            restart: bool,
            rewind: bool,
        }
        impl Source for Fake {
            type Handles = Held;
            fn now(&self) -> u64 {
                self.clock.get()
            }
            fn reserve(&mut self, f: usize, p: usize, b: usize) -> Result<Held> {
                assert_eq!((f, p, b), (4, 1, 65536));
                if self.budget_fail {
                    return Err(Error::Budget);
                }
                self.held.set(self.held.get() + 1);
                Ok(Held(Rc::clone(&self.held)))
            }
            fn unit(&mut self, _: &Held) -> Result<UnitEvidence> {
                Ok(UnitEvidence {
                    unit: self.unit.clone(),
                })
            }
            fn listeners(&mut self, _: &Held, _: u8, _: u16) -> Result<ListenerSet> {
                self.effects.set(self.effects.get() + 1);
                if self.fail {
                    return Err(Error::Incomplete);
                }
                self.clock.set(self.clock.get() + self.delay);
                if self.rewind {
                    self.clock.set(0);
                }
                if self.restart {
                    self.unit.invocation[0] ^= 1;
                }
                Ok(ListenerSet::fixture(&self.rows))
            }
            fn revalidate_handles(&mut self, _: &Held) -> Result<()> {
                if self.fail {
                    Err(Error::Incomplete)
                } else {
                    Ok(())
                }
            }
        }
        fn row(ip: &str, cookie: u64) -> Listener {
            let ip: IpAddr = ip.parse().unwrap();
            let mut local = [0; 16];
            let family = match ip {
                IpAddr::V4(ip) => {
                    local[..4].copy_from_slice(&ip.octets());
                    2
                }
                IpAddr::V6(ip) => {
                    local = ip.octets();
                    10
                }
            };
            Listener {
                family,
                protocol: 17,
                state: 7,
                local,
                remote: [0; 16],
                port: 53,
                remote_port: 0,
                interface: 0,
                uid: 991,
                inode: 100,
                cookie,
                cgroup: 42,
                v6only: false,
            }
        }
        fn fake() -> Fake {
            Fake {
                clock: Rc::new(Cell::new(100)),
                unit: Unit {
                    manager: ":1.4".into(),
                    invocation: [1; 16],
                    policy: [2; 32],
                    uid: 991,
                    cgroup: 42,
                    cgroup_identity: (3, 42),
                    namespace: (4, 5),
                    source_epoch: 7,
                    view: View::Local,
                    delegated: false,
                    socket_activated: false,
                },
                rows: vec![row("127.0.0.53", 11)],
                held: Rc::new(Cell::new(0)),
                effects: Rc::new(Cell::new(0)),
                budget_fail: false,
                fail: false,
                delay: 0,
                restart: false,
                rewind: false,
            }
        }
        fn context() -> Context {
            Context {
                view: View::Local,
                namespace: (4, 5),
                source_epoch: 7,
            }
        }
        fn endpoint() -> SocketAddr {
            "127.0.0.53:53".parse().unwrap()
        }
        #[test]
        fn stub_bind_pure_requires_independent_policy_before_effects() {
            assert_eq!(
                require_protected_policy(endpoint(), 17),
                Err(Error::PolicyUnavailable)
            );
            let mut f = fake();
            f.budget_fail = true;
            let effects = Rc::clone(&f.effects);
            assert!(matches!(
                capture(f, endpoint(), 17, context(), 100000000),
                Err(Error::Budget)
            ));
            assert_eq!(effects.get(), 0);
        }
        #[test]
        fn stub_bind_pure_unique_exact_and_all_ambiguity_shapes() {
            let f = fake();
            let unit = f.unit.clone();
            assert_eq!(
                select(&ListenerSet::fixture(&f.rows), &unit, endpoint(), 17)
                    .unwrap()
                    .cookie,
                11
            );
            for extra in [row("0.0.0.0", 12), row("::", 12), row("127.0.0.53", 12)] {
                assert_eq!(
                    select(
                        &ListenerSet::fixture(&[f.rows[0], extra]),
                        &unit,
                        endpoint(),
                        17
                    ),
                    Err(Error::Ambiguous)
                );
            }
            let mut v6 = row("::", 12);
            v6.v6only = true;
            assert!(
                select(
                    &ListenerSet::fixture(&[f.rows[0], v6]),
                    &unit,
                    endpoint(),
                    17
                )
                .is_ok()
            );
            for mutation in 0..5 {
                let mut r = f.rows[0];
                match mutation {
                    0 => r.uid += 1,
                    1 => r.cgroup += 1,
                    2 => r.interface = 1,
                    3 => r.remote_port = 123,
                    _ => r.state = 1,
                }
                assert!(select(&ListenerSet::fixture(&[r]), &unit, endpoint(), 17).is_err());
            }
            assert!(select(&ListenerSet::fixture(&[]), &unit, endpoint(), 17).is_err());
        }
        #[test]
        fn stub_bind_pure_restart_namespace_epoch_and_local_system_are_distinct() {
            for change in 0..6 {
                let mut f = fake();
                match change {
                    0 => f.unit.view = View::System,
                    1 => f.unit.namespace.1 += 1,
                    2 => f.unit.source_epoch += 1,
                    3 => f.unit.delegated = true,
                    4 => f.unit.socket_activated = true,
                    _ => f.restart = true,
                }
                assert!(capture(f, endpoint(), 17, context(), 100000000).is_err());
            }
            let mut f = fake();
            f.delay = 20_000_001;
            assert!(matches!(
                capture(f, endpoint(), 17, context(), 100000000),
                Err(Error::Stale)
            ));
        }
        #[test]
        fn stub_bind_pure_revalidation_is_sampled_sticky_and_retains_custody() {
            let f = fake();
            let held = Rc::clone(&f.held);
            let clock = Rc::clone(&f.clock);
            let mut r = capture(f, endpoint(), 17, context(), 90_000_000).unwrap();
            assert_eq!(held.get(), 1);
            clock.set(30_000_000);
            assert_eq!(r.fresh(), Err(Error::Stale));
            r.revalidate().unwrap();
            assert_eq!(r.observed_from, 30_000_000);
            assert_eq!(r.expires, 90_000_000);
            r.source.rows[0].cookie += 1;
            assert_eq!(r.revalidate(), Err(Error::Stale));
            assert_eq!(held.get(), 1);
            r.source.rows[0].cookie -= 1;
            let effects = r.source.effects.get();
            assert_eq!(r.revalidate(), Err(Error::Stale));
            assert_eq!(r.source.effects.get(), effects);
            drop(r);
            assert_eq!(held.get(), 0);
        }
        #[test]
        fn stub_bind_pure_failed_recapture_does_not_drop_neighbor_or_handles() {
            let a = fake();
            let held = Rc::clone(&a.held);
            let mut a = capture(a, endpoint(), 17, context(), 90_000_000).unwrap();
            let mut b = capture(fake(), endpoint(), 17, context(), 90_000_000).unwrap();
            a.source.fail = true;
            assert_eq!(a.revalidate(), Err(Error::Incomplete));
            assert_eq!(held.get(), 1);
            b.revalidate().unwrap();
            b.fresh().unwrap();
        }
        #[test]
        fn stub_bind_pure_clock_regression_cannot_create_fresh_observation() {
            let mut f = fake();
            f.rewind = true;
            assert!(matches!(
                capture(f, endpoint(), 17, context(), 90_000_000),
                Err(Error::Stale)
            ));
        }
        #[test]
        fn stub_bind_pure_shared_credits_are_reserved_before_effects_and_rollback() {
            use crate::helper::memory::ByteBudget;
            for (f, p, b) in [(3, 64, 8388608), (64, 0, 8388608), (64, 64, 65535)] {
                let (fds, pending, bytes) =
                    (ByteBudget::new(f), ByteBudget::new(p), ByteBudget::new(b));
                assert!(CaptureCredits::reserve_shared(&fds, &pending, &bytes).is_err());
                assert_eq!((fds.used(), pending.used(), bytes.used()), (0, 0, 0));
            }
            let (fds, pending, bytes) = (
                ByteBudget::new(64),
                ByteBudget::new(64),
                ByteBudget::new(8388608),
            );
            let credit = CaptureCredits::reserve_shared(&fds, &pending, &bytes).unwrap();
            assert_eq!((fds.used(), pending.used(), bytes.used()), (4, 1, 65536));
            drop(credit);
            assert_eq!((fds.used(), pending.used(), bytes.used()), (0, 0, 0));
        }
        #[test]
        fn stub_bind_pure_tcp_ipv6_and_unknown_policy_never_become_user_authority() {
            let mut f = fake();
            f.rows = vec![row("::1", 21)];
            f.rows[0].protocol = 6;
            f.rows[0].state = 10;
            f.rows[0].v6only = true;
            let mut r = capture(f, "[::1]:53".parse().unwrap(), 6, context(), 90_000_000).unwrap();
            r.revalidate().unwrap();
            assert_eq!(
                require_protected_policy("[::1]:53".parse().unwrap(), 6),
                Err(Error::PolicyUnavailable)
            );
            for change in 0..4 {
                let mut f = fake();
                match change {
                    0 => f.unit.uid = 0,
                    1 => f.unit.policy = [0; 32],
                    2 => f.unit.manager.clear(),
                    _ => f.unit.cgroup_identity.1 += 1,
                }
                assert!(capture(f, endpoint(), 17, context(), 90_000_000).is_err());
            }
        }
    }
}
