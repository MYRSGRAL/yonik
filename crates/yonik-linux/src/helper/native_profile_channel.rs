//! Full-profile issuer. Env/DTO/manifest DATA не создают runtime authority.
use super::ServiceError;
use super::native_bootstrap::RuntimeScopeStamp;
use crate::attribution::native_session::{KnownOwnerProof, OwnerEndpoint, OwnerReference};
use crate::profile_channel::{self as wire, LaunchRecord, Mode, Tuple};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
// Максимальный CODEC2 BundleAcquire2164 + Header128 + sentinel byte.
const RUNTIME_PACKET: usize = 128 + 33679 + 1;
// Постоянный RX metadata reserve сохраняется; payload очереди оплачивается по длине.
const RX_BYTES: usize = 256 * 1024;
#[path = "native_bootstrap_binding.rs"]
mod bootstrap_binding;
#[path = "native_dns_bundle.rs"]
mod dns_bundle;
#[path = "native_dns_rrset.rs"]
mod dns_rrset;
#[path = "native_dns_transport.rs"]
pub(crate) mod dns_transport;
use std::{
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
    sync::Arc,
};

/// DATA predicate; authority требует retained route и session fence caller-а.
pub(super) fn dns_route_socket_matches(
    endpoint: std::net::IpAddr,
    port: u16,
    protocol: crate::TransportProtocol,
    source: Option<std::net::IpAddr>,
    uid: u32,
    mark: u32,
    facts: &dns_transport::Facts,
) -> bool {
    facts.remote().ip() == endpoint
        && facts.remote().port() == port
        && facts.protocol()
            == match protocol {
                crate::TransportProtocol::Tcp => 6,
                crate::TransportProtocol::Udp => 17,
            }
        && source == Some(facts.local().ip())
        && facts.local().port() != 0
        && facts.mark() == mark
        && facts.uid() == uid
}
pub(crate) trait RouteAuthority: Send {
    fn check_bootstrap_permit(
        &mut self,
        _: &RuntimeScopeStamp,
        _: BootstrapDnsRoute,
    ) -> Result<(), ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn bootstrap_dns_socket(
        &mut self,
        _: &RuntimeScopeStamp,
        _: BootstrapDnsRoute,
        _: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn dns_socket(
        &mut self,
        scope: &RuntimeScopeStamp,
        ticket: Option<u64>,
        facts: &dns_transport::Facts,
    ) -> Result<(), ServiceError>;
    fn service(
        &mut self,
        scope: &RuntimeScopeStamp,
        manifest: [u8; 32],
        request: RouteRequest<'_>,
    ) -> Result<Option<u64>, ServiceError>;
    fn check(
        &mut self,
        scope: &RuntimeScopeStamp,
        request: RouteRequest<'_>,
        proof: &KnownOwnerProof,
        source: u64,
        flow: crate::attribution::broker::Flow,
    ) -> Result<Option<u64>, ServiceError>;
    fn release(&mut self, scope: &RuntimeScopeStamp, ticket: u64) -> Result<(), ServiceError>;
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteRequest<'a> {
    Static(wire::Destination<'a>),
    Chain,
    Direct(wire::Destination<'a>),
    Dns(wire::Destination<'a>),
}
/// Только issuer создаёт этот DATA binding после проверки live bootstrap permit.
pub(crate) struct BootstrapDnsRoute {
    manifest: [u8; 32],
    source: [u8; 32],
    resolver: u16,
    peer: Target,
}
impl BootstrapDnsRoute {
    pub(crate) fn peer(&self) -> wire::Destination<'_> {
        self.peer.wire()
    }
    pub(crate) fn validate(&self, cap: &wire::Capsule<'_>) -> Result<(), ServiceError> {
        let snapshot = cap.bootstrap_snapshot().map_err(unavailable)?;
        let row = cap.resolver_scope(self.resolver).map_err(unavailable)?;
        if cap.manifest != self.manifest
            || !snapshot.bootstrap()
            || snapshot.asset_reference().source != self.source
            || row.source != self.source
            || row.subject != u16::MAX
            || row.scope.is_some()
            || row.peer != self.peer.wire()
        {
            return Err(ServiceError::Unavailable);
        }
        let ip = match self.peer.family {
            4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(self.peer.wire().bytes).map_err(unavailable)?,
            )),
            6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(self.peer.wire().bytes).map_err(unavailable)?,
            )),
            _ => return Err(ServiceError::Unsupported),
        };
        if ip.is_loopback() {
            return Err(ServiceError::Unsupported);
        }
        reject_unproved_stub(self.peer.wire())
    }
}

struct ChannelBudget {
    _memory: super::memory::ByteLease,
    dynamic: super::memory::ByteBudget,
    routes: super::memory::ByteBudget,
}
impl ChannelBudget {
    fn new(
        capsule: &wire::OwnedCapsule,
        system: bool,
        digest: &[u8; 32],
    ) -> Result<Arc<Self>, ServiceError> {
        let decoded = wire::Capsule::decode(capsule.bytes(), digest).map_err(unavailable)?;
        let remaining = decoded.buffer_credit().map_err(unavailable)?;
        let bytes = 8usize * 1024 * 1024
            - usize::from(system) * (512 + 384) * 1024
            - RX_BYTES
            - 64 * 1024
            - capsule.bytes().len();
        Ok(Arc::new(Self {
            _memory: super::memory::config_budget()
                .reserve(bytes)
                .map_err(unavailable)?,
            dynamic: super::memory::ByteBudget::new(
                remaining
                    .checked_sub(128 * 1024)
                    .ok_or(ServiceError::Busy)?,
            ),
            // Ref/ticket cap существующего ProfileRoutes; unique exceptions
            // по-прежнему ограничивает durable PublicBlockPolicy cap128.
            routes: super::memory::ByteBudget::new(4096),
        }))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Target {
    protocol: u8,
    family: u8,
    port: u16,
    length: u16,
    bytes: [u8; 253],
}
impl Target {
    fn wire(&self) -> wire::Destination<'_> {
        wire::Destination {
            protocol: self.protocol,
            family: self.family,
            port: self.port,
            bytes: &self.bytes[..self.length as usize],
        }
    }
    fn host(host: &str, port: u16) -> Result<Self, ServiceError> {
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => Self::copy(wire::Destination {
                protocol: 6,
                family: 4,
                port,
                bytes: &ip.octets(),
            }),
            Ok(std::net::IpAddr::V6(ip)) => Self::copy(wire::Destination {
                protocol: 6,
                family: 6,
                port,
                bytes: &ip.octets(),
            }),
            Err(_) => Self::copy(wire::Destination {
                protocol: 6,
                family: 3,
                port,
                bytes: host.as_bytes(),
            }),
        }
    }
    fn copy(d: wire::Destination<'_>) -> Result<Self, ServiceError> {
        if d.bytes.len() > 253 {
            return Err(ServiceError::InvalidRequest);
        }
        let mut bytes = [0; 253];
        bytes[..d.bytes.len()].copy_from_slice(d.bytes);
        Ok(Self {
            protocol: d.protocol,
            family: d.family,
            port: d.port,
            length: d.bytes.len() as u16,
            bytes,
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Subject {
    pid: u32,
    start: u64,
    executable: (u64, u64),
    cookie: u64,
    epoch: u64,
    path: [u8; 32],
}
impl Subject {
    fn checked(
        proof: &KnownOwnerProof,
        scope: &RuntimeScopeStamp,
        source: u64,
        flow: crate::attribution::broker::Flow,
    ) -> Result<Self, ServiceError> {
        let (owner, path, _, _) = proof.checked(scope, source, flow).map_err(unavailable)?;
        if path.is_empty() || owner.cookie == 0 {
            return Err(ServiceError::Unavailable);
        }
        Ok(Self {
            pid: owner.pid,
            start: owner.start_time,
            executable: owner.executable,
            cookie: owner.cookie,
            epoch: owner.epoch,
            path: Sha256::digest(path.as_bytes()).into(),
        })
    }
}
trait Authority: Send {
    fn check_bootstrap_permit(&mut self, _: BootstrapDnsRoute) -> Result<(), ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn bootstrap_dns_socket(
        &mut self,
        _: BootstrapDnsRoute,
        _: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn dns_socket(&mut self, _: Option<u64>, _: &dns_transport::Facts) -> Result<(), ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn admission_deadline(&self) -> Option<Instant> {
        None
    }
    fn bind_ingress(
        &self,
        _: &Self::Ingress,
        _: u64,
        _: Option<Subject>,
        _: Option<Instant>,
    ) -> Result<(), ServiceError> {
        Ok(())
    }
    fn retired_ingress(&self, _: &Self::Ingress) {}
    fn service(
        &mut self,
        manifest: [u8; 32],
        request: RouteRequest<'_>,
    ) -> Result<Option<u64>, ServiceError>;
    type Proof: Send;
    type Ingress: Send;
    fn mode(&self) -> Mode;
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn fence(&self) -> Result<(), ServiceError>;
    fn revoke(&self);
    fn ingress(
        &mut self,
        request: u64,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        budget: &Arc<ChannelBudget>,
    ) -> Result<Self::Ingress, ServiceError>;
    fn check_ingress(&self, proof: &Self::Ingress) -> Result<(), ServiceError>;
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
        reference: OwnerReference,
    ) -> Result<Self::Proof, ServiceError>;
    fn subject(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<Subject>, ServiceError>;
    fn expiry(&self, proof: &Self::Proof) -> Option<Instant>;
    fn receipt(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<wire::Receipt, ServiceError>;
    fn route(
        &mut self,
        request: RouteRequest<'_>,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<u64>, ServiceError>;
    fn release(&mut self, ticket: u64) -> Result<(), ServiceError>;
    fn cancel_source(&mut self, source: u64) -> Result<(), ServiceError>;
}
struct SourceFlow<I> {
    numeric_only: bool,
    tuple: Tuple,
    original: Target,
    subject: Option<Subject>,
    socket: I,
    root: Option<(u16, Target)>,
    request: u64,
}
/// Общая bounded история v2. Runtime/proof IDs никогда не alias друг друга.
struct InvocationHistory {
    reserved: usize,
    entries: [Option<(u8, u64)>; 256],
    len: usize,
    limit: usize,
    last_operation: u64,
    next_source: u64,
    _credit: super::memory::ByteLease,
}
struct UdpControl<C> {
    value: C,
    tuple: Tuple,
    cookie: u64,
    principal: Option<Subject>,
    association: Option<u64>,
    ingress: u16,
    closing: bool,
    _fds: super::memory::ByteLease,
    _credit: super::memory::ByteLease,
}
struct UdpRelay<R> {
    value: R,
    control: u64,
    cookie: u64,
    port: u16,
    cycle: Option<UdpCycle>,
    buffer: Box<[u8; 65536]>,
    closing: Option<u64>,
    close_deadline: Option<Instant>,
    reserved_close: u64,
    last_packet: u64,
    flows: BTreeMap<u64, UdpFlowRef>,
    _fds: super::memory::ByteLease,
    _credit: super::memory::ByteLease,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpStage {
    Waiting,
    Permitted,
    Matched,
    Granted,
    Denied,
}
struct UdpCycle {
    packet: wire::udp_v2::Packet,
    original: Option<Target>,
    sequence: u64,
    source: u64,
    grant: u64,
    stage: UdpStage,
    deadline: Instant,
    binding: Option<Arc<UdpBinding>>,
    _pending: Option<super::memory::ByteLease>,
}
struct UdpFlowRef {
    _credit: super::memory::ByteLease,
    binding: Option<Arc<UdpBinding>>,
}
struct KernelDatagram {
    peer: SocketAddr,
    bytes: usize,
    flags: u16,
}
trait UdpOperations {
    fn control_closed(&self, control: &Self::Control) -> Result<bool, ServiceError> {
        self.alive(control).map(|_| false)
    }
    type Control;
    type Relay;
    type Transfer;
    fn ready(&self) -> Result<(), ServiceError>;
    fn fence(&self) -> Result<(), ServiceError>;
    fn control(
        &mut self,
        fd: Self::Transfer,
        tuple: Tuple,
        ingress: u16,
        source: u64,
    ) -> Result<(Self::Control, u64, Option<Subject>), ServiceError>;
    fn alive(&self, control: &Self::Control) -> Result<(), ServiceError>;
    fn relay(&mut self, control: &Self::Control) -> Result<(Self::Relay, u64, u16), ServiceError>;
    fn duplicate(&mut self, relay: &Self::Relay) -> Result<Self::Transfer, ServiceError>;
    fn peek(
        &mut self,
        relay: &Self::Relay,
        out: &mut [u8; 65536],
    ) -> Result<Option<KernelDatagram>, ServiceError>;
    fn consumed(
        &self,
        relay: &Self::Relay,
        packet: wire::udp_v2::Packet,
    ) -> Result<(), ServiceError>;
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
    ) -> Result<(Option<Subject>, Option<Instant>), ServiceError>;
    fn payload_retired(&self, association: u64, packet: u64) -> Result<bool, ServiceError>;
    fn duplicate_closed(
        &self,
        relay: &Self::Relay,
        record: wire::udp_v2::Record,
    ) -> Result<(), ServiceError>;
    fn revoke(&self);
}
struct UdpResponse<T> {
    record: wire::udp_v2::Record,
    fd: Option<T>,
}
struct AssociationIssuer<O: UdpOperations> {
    ops: O,
    launch: LaunchRecord,
    history: Arc<std::sync::Mutex<InvocationHistory>>,
    budget: super::memory::ByteBudget,
    controls: BTreeMap<u64, UdpControl<O::Control>>,
    relays: BTreeMap<u64, UdpRelay<O::Relay>>,
    next: u64,
    last_control_proof: u64,
    unknown: bool,
    slots: Arc<SidebandCredits>,
}
impl<O: UdpOperations> AssociationIssuer<O> {
    fn new(
        ops: O,
        launch: LaunchRecord,
        limit: u32,
        budget: super::memory::ByteBudget,
    ) -> Result<Self, ServiceError> {
        let history = Arc::new(std::sync::Mutex::new(InvocationHistory::new(
            limit, &budget,
        )?));
        Ok(Self {
            ops,
            launch,
            history,
            budget,
            controls: BTreeMap::new(),
            relays: BTreeMap::new(),
            next: 0,
            last_control_proof: 0,
            unknown: false,
            slots: SidebandCredits::new(),
        })
    }
    fn id(&mut self) -> Result<u64, ServiceError> {
        self.next = self
            .next
            .checked_add(1)
            .filter(|id| *id != u64::MAX)
            .ok_or(ServiceError::Unavailable)?;
        Ok(self.next)
    }
    fn check(&self) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        self.ops.fence()?;
        self.ops.ready()
    }
    fn handle(
        &mut self,
        record: wire::udp_v2::Record,
        fd: Option<O::Transfer>,
        now: Instant,
        until: Instant,
    ) -> Result<Option<UdpResponse<O::Transfer>>, ServiceError> {
        self.check()?;
        if now >= until {
            return Err(ServiceError::Unavailable);
        }
        let shape = record.encode(self.launch).map_err(unavailable)?;
        if !shape.from_go || shape.rights != usize::from(fd.is_some()) {
            return Err(ServiceError::InvalidRequest);
        }
        let result = self.handle_inner(record, fd, now, until.min(now + Duration::from_secs(1)));
        if result.is_err() && !matches!(result, Err(ServiceError::Busy)) {
            self.fail();
        }
        result
    }
    fn handle_inner(
        &mut self,
        record: wire::udp_v2::Record,
        fd: Option<O::Transfer>,
        now: Instant,
        until: Instant,
    ) -> Result<Option<UdpResponse<O::Transfer>>, ServiceError> {
        use wire::udp_v2::Record as R;
        let reply = match record {
            R::Control {
                operation,
                proof,
                ingress,
                tuple,
            } => {
                if proof <= self.last_control_proof {
                    return Err(ServiceError::InvalidRequest);
                }
                if self.controls.len() >= 8 {
                    return Err(ServiceError::Busy);
                }
                self.history
                    .lock()
                    .map_err(unavailable)?
                    .operation(operation)?;
                let credit = self.budget.reserve(2048).map_err(unavailable)?;
                let fds = self.slots.fds.reserve(2).map_err(unavailable)?;
                let source = self.history.lock().map_err(unavailable)?.source()?;
                let (value, cookie, principal) = self.ops.control(
                    fd.ok_or(ServiceError::InvalidRequest)?,
                    tuple,
                    ingress,
                    source,
                )?;
                if self.launch.mode.required() != principal.is_some()
                    || self.controls.values().any(|c| c.cookie == cookie)
                {
                    return Err(ServiceError::Unavailable);
                }
                self.last_control_proof = proof;
                self.controls.insert(
                    source,
                    UdpControl {
                        value,
                        tuple,
                        cookie,
                        principal,
                        association: None,
                        ingress,
                        closing: false,
                        _fds: fds,
                        _credit: credit,
                    },
                );
                R::ControlAck {
                    operation,
                    control: source,
                    cookie,
                    remaining: Self::remaining(until, now)?,
                }
            }
            R::Associate {
                operation,
                control,
                cookie,
            } => {
                if fd.is_some() || self.relays.len() >= 8 {
                    return Err(ServiceError::Busy);
                }
                self.history
                    .lock()
                    .map_err(unavailable)?
                    .operation(operation)?;
                let c = self
                    .controls
                    .get(&control)
                    .ok_or(ServiceError::InvalidRequest)?;
                if c.association.is_some() || c.cookie != cookie {
                    return Err(ServiceError::InvalidRequest);
                }
                self.ops.alive(&c.value)?;
                let credit = self.budget.reserve(133120).map_err(unavailable)?;
                let fds = self.slots.fds.reserve(4).map_err(unavailable)?;
                let association = self.id()?;
                let reserved_close = self.id()?;
                self.history
                    .lock()
                    .map_err(unavailable)?
                    .reserve(3, reserved_close)?;
                let c = self
                    .controls
                    .get(&control)
                    .ok_or(ServiceError::Unavailable)?;
                let buffer = Box::new([0; 65536]);
                let (value, cookie, port) = self.ops.relay(&c.value)?;
                let duplicate = self.ops.duplicate(&value)?;
                self.relays.insert(
                    association,
                    UdpRelay {
                        value,
                        control,
                        cookie,
                        port,
                        cycle: None,
                        buffer,
                        closing: None,
                        close_deadline: None,
                        reserved_close,
                        last_packet: 0,
                        flows: BTreeMap::new(),
                        _fds: fds,
                        _credit: credit,
                    },
                );
                self.controls
                    .get_mut(&control)
                    .ok_or(ServiceError::Unavailable)?
                    .association = Some(association);
                return Ok(Some(UdpResponse {
                    record: R::Associated {
                        operation,
                        control,
                        association,
                        cookie,
                        port,
                    },
                    fd: Some(duplicate),
                }));
            }
            R::Peek {
                association,
                operation,
                control,
            } => {
                if fd.is_some() {
                    return Err(ServiceError::InvalidRequest);
                }
                let relay = self
                    .relays
                    .get(&association)
                    .ok_or(ServiceError::InvalidRequest)?;
                if relay.control != control || relay.closing.is_some() {
                    return Err(ServiceError::InvalidRequest);
                }
                if let Some(cycle) = &relay.cycle {
                    if !matches!(cycle.stage, UdpStage::Granted | UdpStage::Denied)
                        || !self.ops.payload_retired(association, cycle.packet.packet)?
                    {
                        return Err(ServiceError::Busy);
                    }
                }
                self.history
                    .lock()
                    .map_err(unavailable)?
                    .operation(operation)?;
                self.ops.alive(
                    &self
                        .controls
                        .get(&control)
                        .ok_or(ServiceError::Unavailable)?
                        .value,
                )?;
                let packet = self.id()?;
                let permit = self.id()?;
                let relay = self
                    .relays
                    .get_mut(&association)
                    .ok_or(ServiceError::Unavailable)?;
                let pending = self.slots.pending.reserve(1).map_err(unavailable)?;
                relay.cycle = Some(UdpCycle {
                    packet: wire::udp_v2::Packet {
                        association,
                        packet,
                        permit,
                        cookie: relay.cookie,
                        tuple: Tuple {
                            protocol: 17,
                            family: 4,
                            local_port: 1,
                            remote_port: relay.port,
                            local: [0; 16],
                            remote: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        },
                        bytes: 0,
                        header: 0,
                        flags: 0,
                        fingerprint: [0; 32],
                    },
                    original: None,
                    sequence: 0,
                    source: 0,
                    grant: 0,
                    stage: UdpStage::Waiting,
                    deadline: until,
                    binding: None,
                    _pending: Some(pending),
                });
                return self.progress(association, now);
            }
            R::Consumed { packet, sequence } => {
                if fd.is_some() {
                    return Err(ServiceError::InvalidRequest);
                }
                let relay = self
                    .relays
                    .get_mut(&packet.association)
                    .ok_or(ServiceError::InvalidRequest)?;
                let cycle = relay.cycle.as_mut().ok_or(ServiceError::InvalidRequest)?;
                if relay.closing.is_some()
                    || cycle.stage != UdpStage::Permitted
                    || cycle.packet != packet
                    || now >= cycle.deadline
                {
                    return Err(ServiceError::Unavailable);
                }
                self.history
                    .lock()
                    .map_err(unavailable)?
                    .runtime(sequence)?;
                self.ops.consumed(&relay.value, packet)?;
                cycle.sequence = sequence;
                cycle.stage = UdpStage::Matched;
                R::Matched {
                    association: packet.association,
                    packet: packet.packet,
                    permit: packet.permit,
                    sequence,
                    status: 1,
                    remaining: Self::remaining(cycle.deadline, now)?,
                }
            }
            R::Closed {
                association,
                close,
                last_packet,
                pending,
                status,
                joined,
                duplicates,
                cookie,
                ..
            } => {
                if fd.is_some() {
                    return Err(ServiceError::InvalidRequest);
                }
                let relay = self
                    .relays
                    .get(&association)
                    .ok_or(ServiceError::InvalidRequest)?;
                if relay.closing != Some(close)
                    || relay.last_packet != last_packet
                    || relay.cookie != cookie
                    || status != 1
                    || !joined
                    || pending != 0
                    || duplicates != 0
                    || !relay.flows.is_empty()
                {
                    return Err(ServiceError::Unavailable);
                }
                self.ops.duplicate_closed(&relay.value, record)?;
                let relay = self
                    .relays
                    .remove(&association)
                    .ok_or(ServiceError::Unavailable)?;
                self.controls.remove(&relay.control);
                drop(relay);
                return Ok(None);
            }
            _ => return Err(ServiceError::InvalidRequest),
        };
        Ok(Some(UdpResponse {
            record: reply,
            fd: None,
        }))
    }
    fn remaining(until: Instant, now: Instant) -> Result<u64, ServiceError> {
        let ns = until
            .saturating_duration_since(now)
            .as_nanos()
            .min(1_000_000_000) as u64;
        if ns == 0 {
            Err(ServiceError::Unavailable)
        } else {
            Ok(ns)
        }
    }
    fn progress(
        &mut self,
        association: u64,
        now: Instant,
    ) -> Result<Option<UdpResponse<O::Transfer>>, ServiceError> {
        let result = self.progress_inner(association, now);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn fail(&mut self) {
        if !self.unknown {
            self.unknown = true;
            self.ops.revoke();
        }
    }
    fn tick(&mut self, now: Instant) -> Result<(), ServiceError> {
        let result = (|| {
            self.check()?;
            for relay in self.relays.values() {
                if relay.close_deadline.is_some_and(|until| now >= until)
                    || relay.closing.is_none()
                        && relay.cycle.as_ref().is_some_and(|c| now >= c.deadline)
                {
                    return Err(ServiceError::Unavailable);
                }
            }
            for control in self.controls.values() {
                if !control.closing {
                    self.ops.control_closed(&control.value)?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn progress_inner(
        &mut self,
        association: u64,
        now: Instant,
    ) -> Result<Option<UdpResponse<O::Transfer>>, ServiceError> {
        self.check()?;
        let relay = self
            .relays
            .get_mut(&association)
            .ok_or(ServiceError::InvalidRequest)?;
        let cycle = relay.cycle.as_mut().ok_or(ServiceError::InvalidRequest)?;
        if cycle.stage != UdpStage::Waiting {
            return Ok(None);
        }
        if now >= cycle.deadline {
            return Err(ServiceError::Unavailable);
        }
        let Some(datagram) = self.ops.peek(&relay.value, &mut relay.buffer)? else {
            return Ok(None);
        };
        if datagram.flags != 0 || datagram.bytes > wire::udp_v2::MAX_DATAGRAM {
            return Err(ServiceError::InvalidRequest);
        }
        let (original, header) = udp_original(&relay.buffer[..datagram.bytes])?;
        let SocketAddr::V4(peer) = datagram.peer else {
            return Err(ServiceError::Unsupported);
        };
        cycle.packet.tuple.local[..4].copy_from_slice(&peer.ip().octets());
        cycle.packet.tuple.local_port = peer.port();
        cycle.packet.bytes = datagram.bytes as u32;
        cycle.packet.header = header;
        cycle.packet.fingerprint =
            wire::udp_v2::fingerprint(self.launch, cycle.packet, &relay.buffer[..datagram.bytes])
                .map_err(unavailable)?;
        cycle.original = Some(original);
        cycle.stage = UdpStage::Permitted;
        relay.last_packet = cycle.packet.packet;
        Ok(Some(UdpResponse {
            record: wire::udp_v2::Record::Permit {
                packet: cycle.packet,
                remaining: Self::remaining(cycle.deadline, now)?,
            },
            fd: None,
        }))
    }
    fn bind_source(
        &mut self,
        sequence: u64,
        source: u64,
        tuple: Tuple,
        original: wire::Destination<'_>,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.check()?;
        let (_, relay) = self
            .relays
            .iter_mut()
            .find(|(_, r)| r.cycle.as_ref().is_some_and(|c| c.sequence == sequence))
            .ok_or(ServiceError::Unavailable)?;
        let cycle = relay.cycle.as_mut().ok_or(ServiceError::Unavailable)?;
        if cycle.stage != UdpStage::Matched
            || (cycle.source != 0 && cycle.source != source)
            || now >= cycle.deadline
            || cycle.packet.tuple != tuple
            || cycle.original != Some(Target::copy(original)?)
            || relay.flows.len() >= 256
        {
            return Err(ServiceError::Unavailable);
        }
        self.history
            .lock()
            .map_err(unavailable)?
            .runtime(sequence)?;
        // BTree refs отдельно от fixed pair metadata. Retry не резервирует
        // второй slot; credit предшествует owner lookup и allocation node.
        let flow_credit = if relay.flows.contains_key(&source) {
            None
        } else {
            Some(self.budget.reserve(128).map_err(unavailable)?)
        };
        let control = self
            .controls
            .get(&relay.control)
            .ok_or(ServiceError::Unavailable)?;
        self.ops.alive(&control.value)?;
        if tuple.local != control.tuple.local {
            return Err(ServiceError::Unavailable);
        }
        let (principal, expiry) = if let Some(binding) = &cycle.binding {
            if !binding.live.load(Ordering::Acquire)
                || binding.source.load(Ordering::Acquire) != source
            {
                return Err(ServiceError::Unavailable);
            }
            // Сравнение с actual Known UDP receipt уже выполнено bind_ingress.
            (None, None)
        } else {
            self.ops.owner(source, tuple)?
        };
        if cycle.binding.is_none()
            && self.launch.mode.required()
            && (principal
                .zip(control.principal)
                .is_none_or(|(udp, tcp)| !same_principal(udp, tcp))
                || expiry
                    .is_none_or(|until| until <= now || until > now + Duration::from_millis(20)))
        {
            return Err(ServiceError::Unavailable);
        }
        cycle.source = source;
        if let Some(credit) = flow_credit {
            relay.flows.insert(
                source,
                UdpFlowRef {
                    _credit: credit,
                    binding: cycle.binding.clone(),
                },
            );
        }
        Ok(())
    }
    fn check_grant(&mut self, source: u64, now: Instant) -> Result<(), ServiceError> {
        let Some(relay) = self.relays.values().find(|r| r.flows.contains_key(&source)) else {
            return Ok(());
        };
        self.check()?;
        if let Some(binding) = relay
            .flows
            .get(&source)
            .and_then(|flow| flow.binding.as_ref())
        {
            let control = self
                .controls
                .get(&relay.control)
                .ok_or(ServiceError::Unavailable)?;
            self.ops.alive(&control.value)?;
            return if binding.live.load(Ordering::Acquire)
                && binding.source.load(Ordering::Acquire) == source
            {
                Ok(())
            } else {
                Err(ServiceError::Unavailable)
            };
        }
        let cycle = relay.cycle.as_ref().ok_or(ServiceError::Unavailable)?;
        if cycle.source != source || cycle.stage != UdpStage::Matched || now >= cycle.deadline {
            return Err(ServiceError::Unavailable);
        }
        let control = self
            .controls
            .get(&relay.control)
            .ok_or(ServiceError::Unavailable)?;
        self.ops.alive(&control.value)?;
        if let Some(binding) = &cycle.binding {
            if !binding.live.load(Ordering::Acquire)
                || binding.source.load(Ordering::Acquire) != source
            {
                return Err(ServiceError::Unavailable);
            }
            return Ok(());
        }
        let (principal, expiry) = self.ops.owner(source, cycle.packet.tuple)?;
        if self.launch.mode.required()
            && (principal
                .zip(control.principal)
                .is_none_or(|(a, b)| !same_principal(a, b))
                || expiry
                    .is_none_or(|until| until <= now || until > now + Duration::from_millis(20)))
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
    fn granted(&mut self, source: u64, grant: u64) {
        for relay in self.relays.values_mut() {
            if let Some(c) = &mut relay.cycle {
                if c.source == source && c.stage == UdpStage::Matched {
                    c.stage = UdpStage::Granted;
                    c.grant = grant;
                }
            }
        }
    }
    fn denied(&mut self, request: u64, source: Option<u64>) {
        for relay in self.relays.values_mut() {
            if let Some(cycle) = &mut relay.cycle {
                if (request != 0 && cycle.sequence == request)
                    || source.is_some_and(|source| source == cycle.source)
                {
                    cycle.stage = UdpStage::Denied;
                    if let Some(binding) = &cycle.binding {
                        binding.live.store(false, Ordering::Release);
                    }
                }
            }
        }
    }
    fn retire(
        &mut self,
        association: u64,
        now: Instant,
    ) -> Result<UdpResponse<O::Transfer>, ServiceError> {
        self.check()?;
        let relay = self
            .relays
            .get_mut(&association)
            .ok_or(ServiceError::InvalidRequest)?;
        if relay.closing.is_some() {
            return Err(ServiceError::Unavailable);
        }
        let close = relay.reserved_close;
        relay.closing = Some(close);
        self.controls
            .get_mut(&relay.control)
            .ok_or(ServiceError::Unavailable)?
            .closing = true;
        relay.close_deadline = Some(now + Duration::from_secs(1));
        Ok(UdpResponse {
            record: wire::udp_v2::Record::Close {
                association,
                close,
                control: relay.control,
                reason: 1,
            },
            fd: None,
        })
    }
    fn cancel_flow(&mut self, source: u64) {
        for relay in self.relays.values_mut() {
            relay.flows.remove(&source);
        }
    }
    fn retire_control(
        &mut self,
        control: u64,
        cancel: &mut dyn FnMut(u64) -> Result<(), ServiceError>,
        now: Instant,
    ) -> Result<Option<UdpResponse<O::Transfer>>, ServiceError> {
        self.check()?;
        let c = self
            .controls
            .get_mut(&control)
            .ok_or(ServiceError::InvalidRequest)?;
        if c.closing {
            return Ok(None);
        }
        c.closing = true;
        let Some(association) = c.association else {
            self.controls.remove(&control);
            return Ok(None);
        };
        let relay = self
            .relays
            .get_mut(&association)
            .ok_or(ServiceError::Unavailable)?;
        let mut ids = [0; 256];
        let mut n = 0;
        for id in relay.flows.keys() {
            ids[n] = *id;
            n += 1;
        }
        if let Some(binding) = relay.cycle.as_ref().and_then(|c| c.binding.as_ref()) {
            let source = binding.source.load(Ordering::Acquire);
            if source != 0 && !relay.flows.contains_key(&source) {
                *ids.get_mut(n).ok_or(ServiceError::Busy)? = source;
                n += 1;
            }
        }
        for id in &ids[..n] {
            if let Err(error) = cancel(*id) {
                self.fail();
                return Err(error);
            }
            self.cancel_flow(*id);
        }
        if let Some(binding) = self
            .relays
            .get(&association)
            .and_then(|r| r.cycle.as_ref())
            .and_then(|c| c.binding.as_ref())
        {
            binding.live.store(false, Ordering::Release);
        }
        self.retire(association, now).map(Some)
    }
}
fn same_principal(a: Subject, b: Subject) -> bool {
    (a.pid, a.start, a.executable, a.epoch, a.path)
        == (b.pid, b.start, b.executable, b.epoch, b.path)
}
fn udp_original(bytes: &[u8]) -> Result<(Target, u16), ServiceError> {
    if bytes.len() < 4 || bytes[..3] != [0, 0, 0] {
        return Err(ServiceError::InvalidRequest);
    }
    let (family, start, length) = match bytes[3] {
        1 => (4, 4, 4),
        4 => (6, 4, 16),
        3 => {
            let n = *bytes.get(4).ok_or(ServiceError::InvalidRequest)? as usize;
            if n == 0 || n > 253 {
                return Err(ServiceError::InvalidRequest);
            }
            (3, 5, n)
        }
        _ => return Err(ServiceError::InvalidRequest),
    };
    let end = start + length;
    let address = bytes.get(start..end).ok_or(ServiceError::InvalidRequest)?;
    let port = bytes
        .get(end..end + 2)
        .ok_or(ServiceError::InvalidRequest)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    let original = wire::Destination {
        family,
        protocol: 17,
        port,
        bytes: address,
    };
    original.validate_original().map_err(unavailable)?;
    Ok((Target::copy(original)?, (end + 2) as u16))
}
struct KernelControl {
    socket: tokio::net::TcpStream,
    namespace: Option<OwnedFd>,
    number: Option<i32>,
    facts: SocketFacts,
    source: u64,
    tuple: Tuple,
}
struct KernelRelay {
    fd: tokio::net::UdpSocket,
    namespace: OwnedFd,
    cookie: u64,
    port: u16,
}
struct KernelUdpOperations {
    producer: Arc<VerifiedUdpProducer>,
    peer: Arc<Peer>,
    owner: Option<Arc<OwnerEndpoint>>,
    record: LaunchRecord,
    capsule: Arc<wire::OwnedCapsule>,
    handle: tokio::runtime::Handle,
}
/// Не source hash и не child ACK. Production constructor требует attestation
/// installed builder; такого producer в текущем deployment contract ещё нет.
#[derive(Clone)]
pub(crate) struct VerifiedUdpProducer {
    launch: LaunchRecord,
}
/// Только protected installed record + retained consuming exec custody.
/// Это не current-image measurement и не child receipt.
pub(super) struct VerifiedDnsProducer {
    capability: super::registry::DnsCapability,
    launch: LaunchRecord,
}
/// Независимый CODEC4 consuming transport/close contract, не USER Direct.
/// Production mint отсутствует до reviewed bootstrap image/source record.
pub(super) struct VerifiedBootstrapDnsProducer {
    launch: LaunchRecord,
    schema: [u8; 32],
    proof: BootstrapReleaseProof,
}
enum BootstrapReleaseProof {
    Installed(Arc<bootstrap_binding::BootstrapBinding>),
    #[cfg(test)]
    Injected,
}
/// Отдельный trusted capture endpoint; consuming-close token его не создаёт.
/// Production provider отсутствует до reviewed CODEC4 image/launch/source scope.
struct BootstrapDnsReceipt<'a> {
    lifetime_anchor: Instant,
    binding: dns_transport::Binding,
    proof: u64,
    revision: u64,
    exchange: u64,
    producer_sequence: u64,
    request: &'a [u8],
    response: &'a [u8],
}
trait BootstrapDnsTranscript: Send + Sync {
    fn observed(
        &self,
        launch: LaunchRecord,
        receipt: BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError>;
}
impl VerifiedBootstrapDnsProducer {
    fn bound(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        launch.encode().map_err(unavailable)?;
        if self.launch != launch
            || self.schema != <[u8; 32]>::from(Sha256::digest(wire::dns_v2::SCHEMA))
        {
            return Err(ServiceError::Unsupported);
        }
        match &self.proof {
            BootstrapReleaseProof::Installed(binding) => {
                binding.check(super::registry::BootstrapScope::Release, launch)?
            }
            #[cfg(test)]
            BootstrapReleaseProof::Injected => {}
        }
        Ok(())
    }
}
/// Отдельный audited producer contract: exact request/response actual bound peer.
/// Consuming-close contract не создаёт этот token.
pub(super) struct VerifiedDnsWireProducer {
    capability: super::registry::DnsCapability,
    launch: LaunchRecord,
}
/// Отдельный protected source contract logical handler/stream → exchange →
/// actual plaintext + consuming-close/join. Direct wire/release не его mint.
/// Production provider отсутствует до отдельного reviewed installed record.
pub(super) struct VerifiedDnsLogicalProducer {
    launch: LaunchRecord,
}
impl VerifiedDnsLogicalProducer {
    fn bound(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        if self.launch != launch {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
}
impl VerifiedDnsWireProducer {
    fn mint(
        proof: &super::registry::ImageContract,
        image: [u8; 32],
        config: [u8; 32],
        manifest: [u8; 32],
        launch: LaunchRecord,
    ) -> Result<Self, ServiceError> {
        let capability = proof.dns_wire_channel(image).map_err(unavailable)?;
        launch.encode().map_err(unavailable)?;
        if config != launch.binding.digest || manifest != launch.manifest {
            return Err(ServiceError::Unavailable);
        }
        Ok(Self { launch, capability })
    }
    fn bound(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        self.capability.check_wire().map_err(unavailable)?;
        if self.launch != launch {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
}
impl VerifiedDnsProducer {
    fn mint(
        proof: &super::registry::ImageContract,
        image: [u8; 32],
        config: [u8; 32],
        manifest: [u8; 32],
        launch: LaunchRecord,
    ) -> Result<Self, ServiceError> {
        let capability = proof.dns_release_channel(image).map_err(unavailable)?;
        launch.encode().map_err(unavailable)?;
        if config != launch.binding.digest || manifest != launch.manifest {
            return Err(ServiceError::Unavailable);
        }
        Ok(Self { launch, capability })
    }
    fn bound(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        self.capability.check_release().map_err(unavailable)?;
        if self.launch != launch {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
}
impl VerifiedUdpProducer {
    pub(super) fn mint(
        proof: &super::registry::ImageContract,
        image: [u8; 32],
        config: [u8; 32],
        manifest: [u8; 32],
        record: LaunchRecord,
    ) -> Result<Self, ServiceError> {
        proof.check(image).map_err(unavailable)?;
        record.encode().map_err(unavailable)?;
        if config != record.binding.digest || manifest != record.manifest {
            return Err(ServiceError::Unavailable);
        }
        Ok(Self { launch: record })
    }
    fn payload_retired(&self, record: LaunchRecord) -> Result<bool, ServiceError> {
        self.setup(record)?;
        Ok(true)
    }
    fn duplicate_closed(
        &self,
        record: LaunchRecord,
        receipt: wire::udp_v2::Record,
    ) -> Result<(), ServiceError> {
        self.setup(record)?;
        if !matches!(
            receipt,
            wire::udp_v2::Record::Closed {
                status: 1,
                pending: 0,
                joined: true,
                duplicates: 0,
                ..
            }
        ) {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn setup(
        &self,
        record: LaunchRecord,
    ) -> Result<([u8; 128], [u8; 40], u8), ServiceError> {
        if record != self.launch {
            return Err(ServiceError::Unavailable);
        }
        Ok((
            wire::udp_v2::bootstrap(record).map_err(unavailable)?,
            wire::udp_v2::bootstrap_ack(record).map_err(unavailable)?,
            2,
        ))
    }
}
/// Gate именно consuming producer/duplicate-close source proof, не env flag.
/// Runtime admission v2 этим milestone не разрешён.
#[cfg(test)]
fn udp_v2_consumer_ready() -> Result<(), ServiceError> {
    Err(ServiceError::Unsupported)
}
#[cfg(test)]
pub(crate) fn profile_proof_setup(
    record: LaunchRecord,
) -> Result<([u8; 128], [u8; 40], u8), ServiceError> {
    if udp_v2_consumer_ready().is_ok() {
        Ok((
            wire::udp_v2::bootstrap(record).map_err(unavailable)?,
            wire::udp_v2::bootstrap_ack(record).map_err(unavailable)?,
            2,
        ))
    } else {
        Ok((
            wire::proof_bootstrap(record).map_err(unavailable)?,
            wire::proof_bootstrap_ack(record).map_err(unavailable)?,
            1,
        ))
    }
}
impl KernelUdpOperations {
    fn observe(
        &self,
        source: u64,
        tuple: Tuple,
    ) -> Result<(Option<Subject>, Option<Instant>), ServiceError> {
        self.peer.validate()?;
        match (&self.owner, &self.peer.system_scope) {
            (Some(owner), Some(scope)) => {
                let flow = tuple.owner_flow().map_err(unavailable)?;
                let proof = owner
                    .lookup(
                        source,
                        flow,
                        OwnerReference::NONE,
                        Instant::now() + Duration::from_millis(20),
                    )
                    .map_err(unavailable)?;
                let subject = Subject::checked(&proof, scope, source, flow)?;
                Ok((Some(subject), Some(proof.original_expiry())))
            }
            (None, None) => Ok((None, None)),
            _ => Err(ServiceError::Unavailable),
        }
    }
    fn relay_valid(&self, relay: &KernelRelay) -> Result<(), ServiceError> {
        self.peer.validate()?;
        yonik_nsfs::socket_namespace::inspect_profile_udp(&relay.fd).map_err(unavailable)?;
        let facts = SocketFacts::capture(&relay.fd)?;
        if facts.cookie != relay.cookie
            || facts.local != SocketAddr::from(([127, 0, 0, 1], relay.port))
            || facts.remote.is_some()
        {
            return Err(ServiceError::Unavailable);
        }
        if let Some(scope) = &self.peer.system_scope {
            let current =
                yonik_nsfs::socket_namespace::socket_namespace(&relay.fd).map_err(unavailable)?;
            for fd in [&current, &relay.namespace] {
                let s = rustix::fs::fstat(fd).map_err(unavailable)?;
                if (s.st_dev, s.st_ino) != scope.lookup_binding().2.namespace() {
                    return Err(ServiceError::Unsupported);
                }
            }
        } else {
            let current = File::open("/proc/thread-self/ns/net").map_err(unavailable)?;
            let a = rustix::fs::fstat(&current).map_err(unavailable)?;
            let b = rustix::fs::fstat(&relay.namespace).map_err(unavailable)?;
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
                return Err(ServiceError::Unsupported);
            }
        }
        Ok(())
    }
}
impl UdpOperations for KernelUdpOperations {
    type Control = KernelControl;
    type Relay = KernelRelay;
    type Transfer = OwnedFd;
    fn ready(&self) -> Result<(), ServiceError> {
        self.producer.setup(self.record)?;
        self.peer.validate()
    }
    fn fence(&self) -> Result<(), ServiceError> {
        self.peer.validate()
    }
    fn control(
        &mut self,
        fd: OwnedFd,
        tuple: Tuple,
        ingress: u16,
        source: u64,
    ) -> Result<(KernelControl, u64, Option<Subject>), ServiceError> {
        self.ready()?;
        wire::Capsule::decode(self.capsule.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?
            .validate_udp_control(ingress, tuple)
            .map_err(unavailable)?;
        let facts = SocketFacts::capture(&fd)?;
        if !facts.matches(tuple, 2) {
            return Err(ServiceError::InvalidRequest);
        }
        let proof = if let Some(scope) = &self.peer.system_scope {
            let namespace =
                yonik_nsfs::socket_namespace::socket_namespace(&fd).map_err(unavailable)?;
            let s = rustix::fs::fstat(&namespace).map_err(unavailable)?;
            if (s.st_dev, s.st_ino) != scope.lookup_binding().2.namespace() {
                return Err(ServiceError::Unsupported);
            }
            SocketProof {
                peer: Arc::clone(&self.peer),
                fd,
                number: None,
                namespace: Some(namespace),
                facts,
                tuple,
                provenance: 2,
                udp: None,
                _fds: None,
            }
        } else {
            let independent = self.peer.socket(tuple, 2, 0, ingress)?;
            if independent.facts != facts {
                return Err(ServiceError::Unavailable);
            }
            drop(fd);
            independent
        };
        proof.validate()?;
        let (principal, _) = self.observe(source, tuple)?;
        let cookie = proof.facts.cookie;
        let SocketProof {
            fd,
            namespace,
            number,
            facts,
            ..
        } = proof;
        let flags = rustix::fs::fcntl_getfl(&fd).map_err(unavailable)?;
        rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(unavailable)?;
        let socket = {
            let _enter = self.handle.enter();
            tokio::net::TcpStream::from_std(std::net::TcpStream::from(fd)).map_err(unavailable)?
        };
        Ok((
            KernelControl {
                socket,
                namespace,
                number,
                facts,
                source,
                tuple,
            },
            cookie,
            principal,
        ))
    }
    fn alive(&self, control: &KernelControl) -> Result<(), ServiceError> {
        if self.control_closed(control)? {
            Err(ServiceError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn control_closed(&self, control: &KernelControl) -> Result<bool, ServiceError> {
        self.peer.validate()?;
        if SocketFacts::capture(&control.socket)? != control.facts
            || !control.facts.matches(control.tuple, 2)
        {
            return Err(ServiceError::Unavailable);
        }
        if let Some(scope) = &self.peer.system_scope {
            let namespace = yonik_nsfs::socket_namespace::socket_namespace(&control.socket)
                .map_err(unavailable)?;
            for fd in [Some(&namespace), control.namespace.as_ref()]
                .into_iter()
                .flatten()
            {
                let s = rustix::fs::fstat(fd).map_err(unavailable)?;
                if (s.st_dev, s.st_ino) != scope.lookup_binding().2.namespace() {
                    return Err(ServiceError::Unavailable);
                }
            }
        } else {
            let fd = rustix::process::pidfd_getfd(
                &self.peer.pidfd,
                control.number.ok_or(ServiceError::Unsupported)?,
                rustix::process::PidfdGetfdFlags::empty(),
            )
            .map_err(unavailable)?;
            if SocketFacts::capture(&fd)? != control.facts {
                return Err(ServiceError::Unavailable);
            }
        }
        let mut one = [0];
        match control.socket.try_io(tokio::io::Interest::READABLE, || {
            match rustix::net::recv(
                &control.socket,
                &mut one,
                rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
            ) {
                Err(rustix::io::Errno::AGAIN) => Err(std::io::ErrorKind::WouldBlock.into()),
                Ok((0, _)) => Ok(true),
                _ => Err(std::io::ErrorKind::InvalidData.into()),
            }
        }) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Ok(closed) => Ok(closed),
            Err(_) => Err(ServiceError::Unavailable),
        }
    }
    fn relay(&mut self, control: &KernelControl) -> Result<(KernelRelay, u64, u16), ServiceError> {
        self.ready()?;
        self.alive(control)?;
        let _fresh = self.observe(control.source, control.tuple)?;
        let (fd, namespace) = if self.record.mode == Mode::Local {
            crate::host::local_profile_channel::create_udp_relay().map_err(unavailable)?
        } else {
            let fd = rustix::net::socket_with(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::DGRAM,
                rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
                Some(rustix::net::ipproto::UDP),
            )
            .map_err(unavailable)?;
            rustix::net::bind(
                &fd,
                &std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
            )
            .map_err(unavailable)?;
            yonik_nsfs::socket_namespace::prepare_profile_udp(&fd).map_err(unavailable)?;
            let namespace =
                yonik_nsfs::socket_namespace::socket_namespace(&fd).map_err(unavailable)?;
            (fd, namespace)
        };
        let facts = SocketFacts::capture(&fd)?;
        let port = facts.local.port();
        let cookie = facts.cookie;
        let fd = {
            let _enter = self.handle.enter();
            tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(fd)).map_err(unavailable)?
        };
        let relay = KernelRelay {
            fd,
            namespace,
            cookie,
            port,
        };
        self.relay_valid(&relay)?;
        Ok((relay, cookie, port))
    }
    fn duplicate(&mut self, relay: &KernelRelay) -> Result<OwnedFd, ServiceError> {
        self.relay_valid(relay)?;
        rustix::io::fcntl_dupfd_cloexec(&relay.fd, 3).map_err(unavailable)
    }
    fn peek(
        &mut self,
        relay: &KernelRelay,
        out: &mut [u8; 65536],
    ) -> Result<Option<KernelDatagram>, ServiceError> {
        self.relay_valid(relay)?;
        let peek = match relay.fd.try_io(tokio::io::Interest::READABLE, || {
            yonik_nsfs::socket_namespace::peek_profile_udp(&relay.fd, out)?
                .ok_or_else(|| std::io::ErrorKind::WouldBlock.into())
        }) {
            Ok(p) => Some(p),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(e) => return Err(unavailable(e)),
        };
        peek.map(|p| {
            if p.overflow != 0 {
                Err(ServiceError::Unavailable)
            } else {
                Ok(KernelDatagram {
                    peer: SocketAddr::from((p.address, p.port)),
                    bytes: p.bytes,
                    flags: p.flags,
                })
            }
        })
        .transpose()
    }
    fn consumed(&self, relay: &KernelRelay, _: wire::udp_v2::Packet) -> Result<(), ServiceError> {
        self.ready()?;
        self.relay_valid(relay)
    }
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
    ) -> Result<(Option<Subject>, Option<Instant>), ServiceError> {
        self.observe(source, tuple)
    }
    fn payload_retired(&self, _: u64, _: u64) -> Result<bool, ServiceError> {
        self.ready()?;
        // Только authenticated next Peek от source-verified exclusive producer:
        // его contract запрещает Peek до downstream-credit transfer/destruction.
        self.peer.validate()?;
        self.producer.payload_retired(self.record)
    }
    fn duplicate_closed(
        &self,
        relay: &KernelRelay,
        record: wire::udp_v2::Record,
    ) -> Result<(), ServiceError> {
        self.ready()?;
        self.relay_valid(relay)?;
        self.peer.validate()?;
        // Такой record принимается лишь под готовым pinned producer contract,
        // а не как произвольное child assertion при старом installed image.
        self.producer.duplicate_closed(self.record, record)
    }
    fn revoke(&self) {
        if let Some(scope) = &self.peer.system_scope {
            scope.revoke();
        }
    }
}
impl InvocationHistory {
    fn new(limit: u32, budget: &super::memory::ByteBudget) -> Result<Self, ServiceError> {
        let credit = budget
            .reserve(std::mem::size_of::<Self>())
            .map_err(unavailable)?;
        Ok(Self {
            entries: [None; 256],
            reserved: 0,
            len: 0,
            limit: (limit as usize).min(256),
            last_operation: 0,
            next_source: 0,
            _credit: credit,
        })
    }
    fn runtime(&mut self, id: u64) -> Result<(), ServiceError> {
        self.reserve(1, id)
    }
    fn reserve(&mut self, kind: u8, id: u64) -> Result<(), ServiceError> {
        if id == 0 || id == u64::MAX {
            return Err(ServiceError::InvalidRequest);
        }
        if self.entries[..self.len].contains(&Some((kind, id))) {
            return Ok(());
        }
        if self.len + self.reserved >= self.limit {
            return Err(ServiceError::Busy);
        }
        self.entries[self.len] = Some((kind, id));
        self.len += 1;
        Ok(())
    }
    fn operation(&mut self, id: u64) -> Result<(), ServiceError> {
        if id <= self.last_operation {
            return Err(ServiceError::InvalidRequest);
        }
        self.reserve(2, id)?;
        self.last_operation = id;
        Ok(())
    }
    fn source(&mut self) -> Result<u64, ServiceError> {
        self.next_source = self
            .next_source
            .checked_add(1)
            .filter(|id| *id != u64::MAX)
            .ok_or(ServiceError::Unavailable)?;
        Ok(self.next_source)
    }
}
struct HistoryCredit {
    history: Arc<std::sync::Mutex<InvocationHistory>>,
    live: bool,
}
impl HistoryCredit {
    fn claim(history: Arc<std::sync::Mutex<InvocationHistory>>) -> Result<Self, ServiceError> {
        {
            let mut h = history.lock().map_err(unavailable)?;
            if h.len + h.reserved >= h.limit {
                return Err(ServiceError::Busy);
            }
            h.reserved += 1;
        }
        Ok(Self {
            history,
            live: true,
        })
    }
    fn commit(mut self, kind: u8, id: u64) -> Result<(), ServiceError> {
        let mut h = self.history.lock().map_err(unavailable)?;
        h.reserved -= 1;
        self.live = false;
        h.reserve(kind, id)
    }
}
impl Drop for HistoryCredit {
    fn drop(&mut self) {
        if self.live {
            // Poison сохраняет debit; дальнейшие history операции fail closed.
            if let Ok(mut h) = self.history.lock() {
                h.reserved -= 1;
            }
        }
    }
}
struct Grant {
    numeric: Option<dns_rrset::NumericBinding>,
    source: u64,
    subject: u16,
    scope: u16,
    branch: u8,
    chain: u16,
    stream: u16,
    class: u8,
    effective: Target,
    resolver: u16,
    query: Box<str>,
    expires: Instant,
    request: u64,
    tickets: Box<[u64]>,
    next: Option<(u16, u8, u16)>,
    _query_credit: super::memory::ByteLease,
    _routes: super::memory::ByteLease,
}
struct ServiceGrant {
    selector: [u16; 4],
    fingerprint: [u8; 32],
    request: u64,
    expires: Instant,
    tickets: Box<[u64]>,
    _credit: super::memory::ByteLease,
    _routes: super::memory::ByteLease,
}
/// Fixed scratch до allocation/effects. Chain remote не становится exception.
struct RoutePlan<'a> {
    items: [Option<RouteRequest<'a>>; 128],
    len: usize,
}
impl<'a> RoutePlan<'a> {
    fn new() -> Self {
        Self {
            items: [None; 128],
            len: 0,
        }
    }
    fn push(&mut self, route: RouteRequest<'a>) -> Result<(), ServiceError> {
        if self.items[..self.len].contains(&Some(route)) {
            return Ok(());
        }
        let slot = self.items.get_mut(self.len).ok_or(ServiceError::Busy)?;
        *slot = Some(route);
        self.len += 1;
        Ok(())
    }
    fn walk(
        &mut self,
        capsule: &'a wire::Capsule<'a>,
        scope: u16,
        mask: u8,
        target: wire::Destination<'a>,
        depth: u16,
        remaining: &mut u16,
    ) -> Result<(), ServiceError> {
        if depth > 256 {
            return Err(ServiceError::InvalidRequest);
        }
        for branch in 0..2 {
            if mask & (1 << branch) == 0 {
                continue;
            }
            *remaining = remaining.checked_sub(1).ok_or(ServiceError::Busy)?;
            let dial = capsule.dial_scope(scope, branch).map_err(unavailable)?;
            match dial.action {
                1 => self.push(RouteRequest::Static(
                    dial.endpoint.ok_or(ServiceError::InvalidRequest)?,
                ))?,
                2 => {
                    let (next, mask) = dial.next.ok_or(ServiceError::InvalidRequest)?;
                    self.walk(
                        capsule,
                        next,
                        mask,
                        dial.endpoint.ok_or(ServiceError::InvalidRequest)?,
                        depth + 1,
                        remaining,
                    )?;
                }
                3 if target.family != 3 => self.push(RouteRequest::Direct(wire::Destination {
                    protocol: dial.carrier,
                    ..target
                }))?,
                4 => {}
                _ => return Err(ServiceError::Unsupported),
            }
        }
        Ok(())
    }
    fn resolver(
        capsule: &'a wire::Capsule<'a>,
        resolver: &wire::ResolverScope<'a>,
    ) -> Result<Self, ServiceError> {
        let mut plan = Self::new();
        if resolver.peer.family == 3 {
            return Err(ServiceError::Unsupported);
        }
        if let Some((scope, mask)) = resolver.scope {
            plan.walk(capsule, scope, mask, resolver.peer, 0, &mut 4096)?;
        } else {
            plan.push(RouteRequest::Dns(resolver.peer))?;
        }
        if plan.len == 0 {
            return Err(ServiceError::Unsupported);
        }
        Ok(plan)
    }
}
struct Issuer<A: Authority> {
    bootstrap_transcript: Option<Arc<dyn BootstrapDnsTranscript>>,
    bootstrap_dns: Option<Arc<VerifiedBootstrapDnsProducer>>,
    bootstrap_source: Option<Arc<dyn dns_bundle::roots::Source>>,
    rrsets: dns_rrset::State,
    dns_wire: Option<VerifiedDnsWireProducer>,
    dns_logical: Option<VerifiedDnsLogicalProducer>,
    dns_release: Option<VerifiedDnsProducer>,
    transport: dns_transport::Transport,
    authority: A,
    capsule: Arc<wire::OwnedCapsule>,
    record: LaunchRecord,
    flows: BTreeMap<u64, Box<SourceFlow<A::Ingress>>>,
    grants: BTreeMap<u64, Box<Grant>>,
    services: BTreeMap<u64, Box<ServiceGrant>>,
    frontier: BTreeMap<(u64, u16, u8, u16), u16>,
    retired: VecDeque<(u64, Instant)>,
    next_flow: u64,
    next_grant: u64,
    unknown: bool,
    budget: Arc<ChannelBudget>,
    history: Option<Arc<std::sync::Mutex<InvocationHistory>>>,
    dns: dns_bundle::Bundles,
    negotiated: Option<wire::dns_v2::Negotiated>,
}
impl<A: Authority> Issuer<A> {
    fn new(
        authority: A,
        capsule: Arc<wire::OwnedCapsule>,
        record: LaunchRecord,
    ) -> Result<Self, ServiceError> {
        let decoded =
            wire::Capsule::decode(capsule.bytes(), &record.binding.digest).map_err(unavailable)?;
        if authority.mode() != record.mode
            || decoded.mode != record.mode
            || decoded.manifest != record.manifest
            || std::mem::size_of::<SourceFlow<A::Ingress>>() + 80 > 768
            || std::mem::size_of::<Grant>() + 80 > 576
        {
            return Err(ServiceError::Unsupported);
        }
        authority.fence()?;
        let budget = ChannelBudget::new(&capsule, record.mode.required(), &record.binding.digest)?;
        let dns = dns_bundle::Bundles::new(&budget.dynamic)?;
        Ok(Self {
            bootstrap_transcript: None,
            bootstrap_dns: None,
            authority,
            rrsets: dns_rrset::State::new(),
            dns_wire: None,
            bootstrap_source: None,
            dns_logical: None,
            dns_release: None,
            transport: dns_transport::Transport::new(&budget.dynamic)?,
            capsule,
            record,
            flows: BTreeMap::new(),
            grants: BTreeMap::new(),
            services: BTreeMap::new(),
            frontier: BTreeMap::new(),
            retired: VecDeque::new(),
            next_flow: 0,
            next_grant: 0,
            unknown: false,
            budget,
            history: None,
            dns,
            negotiated: None,
        })
    }
    fn capsule(&self) -> Result<wire::Capsule<'_>, ServiceError> {
        wire::Capsule::decode(self.capsule.bytes(), &self.record.binding.digest)
            .map_err(unavailable)
    }
    fn fence(&self) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        self.authority.fence()
    }
    fn id(counter: &mut u64) -> Result<u64, ServiceError> {
        *counter = counter
            .checked_add(1)
            .filter(|id| *id != u64::MAX)
            .ok_or(ServiceError::Unavailable)?;
        Ok(*counter)
    }
    fn open(
        &mut self,
        request: u64,
        message: &wire::Message<'_>,
    ) -> Result<(u64, A::Proof), ServiceError> {
        self.fence()?;
        let wire::Message::OpenIngress {
            tuple, original, ..
        } = message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        let owned = Arc::clone(&self.capsule);
        let capsule = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        if self.flows.len() >= capsule.limits()[6] as usize
            || self.retired.len() >= capsule.limits()[7] as usize
        {
            return Err(ServiceError::Busy);
        }
        let socket = self
            .authority
            .ingress(request, &capsule, message, &self.budget)?;
        let source = if let Some(history) = &self.history {
            let source = history.lock().map_err(unavailable)?.source()?;
            self.next_flow = source;
            source
        } else {
            Self::id(&mut self.next_flow)?
        };
        let proof = self.authority.owner(source, *tuple, OwnerReference::NONE)?;
        let subject = self.authority.subject(&proof, source, *tuple)?;
        if self.authority.mode().required() != subject.is_some() {
            return Err(ServiceError::Unavailable);
        }
        self.authority
            .bind_ingress(&socket, source, subject, self.authority.expiry(&proof))?;
        self.fence()?;
        self.flows.insert(
            source,
            Box::new(SourceFlow {
                numeric_only: false,
                tuple: *tuple,
                original: Target::copy(*original)?,
                subject,
                socket,
                root: None,
                request,
            }),
        );
        Ok((source, proof))
    }
    fn authorize(
        &mut self,
        request: u64,
        refresh: u64,
        a: &wire::Authorize<'_>,
    ) -> Result<(u64, A::Proof), ServiceError> {
        self.fence()?;
        if a.class != 1 && a.class != 3 {
            return Err(ServiceError::Unsupported);
        }
        let owned = Arc::clone(&self.capsule);
        let capsule = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        capsule
            .validate_request(&wire::Message::Authorize(*a))
            .map_err(unavailable)?;
        if refresh == 0
            && (self.grants.len() + self.services.len() + self.hosts_permission_count()
                >= capsule.limits()[0] as usize
                || self.retired.len() >= capsule.limits()[7] as usize)
        {
            return Err(ServiceError::Busy);
        }
        let source = self
            .flows
            .get(&a.source_flow)
            .ok_or(ServiceError::Unavailable)?;
        if source.numeric_only {
            return Err(ServiceError::Unsupported);
        }
        if source.original != Target::copy(a.original)? {
            return Err(ServiceError::InvalidRequest);
        }
        self.authority.check_ingress(&source.socket)?;
        let tuple = source.tuple;
        let source_subject = source.subject;
        let effective = Target::copy(a.effective)?;
        if refresh != 0 {
            let old = self.grants.get(&refresh).ok_or(ServiceError::Unavailable)?;
            if self.authority.now() >= old.expires
                || old.source != a.source_flow
                || old.subject != a.subject
                || old.scope != a.scope
                || old.branch != a.branch
                || old.chain != a.chain
                || old.stream != a.transport
                || old.class != a.class
                || old.effective != effective
                || old.resolver != a.resolver
                || old.query.as_ref() != a.query
            {
                return Err(ServiceError::InvalidRequest);
            }
        }
        let dial = if a.class == 1 {
            Some(capsule.dial_scope(a.scope, a.branch).map_err(unavailable)?)
        } else {
            None
        };
        if let Some(dial) = &dial {
            if let Some((root, target)) = source.root {
                if a.scope == root {
                    if target != effective {
                        return Err(ServiceError::InvalidRequest);
                    }
                } else if !self.frontier.iter().any(|((id, s, b, e), n)| {
                    *id == a.source_flow
                        && *s == a.scope
                        && *b == a.branch
                        && *n > 0
                        && capsule.endpoint(*e).is_ok_and(|d| d == a.effective)
                }) {
                    return Err(ServiceError::InvalidRequest);
                }
            } else if dial.input != source.original.protocol {
                return Err(ServiceError::InvalidRequest);
            }
        }
        let reference = OwnerReference {
            kind: a.receipt.kind,
            id: a.receipt.id,
        };
        let mut proof = self.authority.owner(a.source_flow, tuple, reference)?;
        if self.authority.subject(&proof, a.source_flow, tuple)? != source_subject {
            return Err(ServiceError::Unavailable);
        }
        let mut routes = RoutePlan::new();
        if let Some(dial) = &dial {
            routes.push(match dial.action {
                1 => RouteRequest::Static(dial.endpoint.ok_or(ServiceError::InvalidRequest)?),
                2 => RouteRequest::Chain,
                3 => RouteRequest::Direct(a.effective),
                _ => return Err(ServiceError::InvalidRequest),
            })?;
        } else {
            routes = RoutePlan::resolver(
                &capsule,
                &capsule.resolver_scope(a.resolver).map_err(unavailable)?,
            )?;
        }
        let grant = if refresh == 0 {
            Self::id(&mut self.next_grant)?
        } else {
            refresh
        };
        let query_credit = self
            .budget
            .dynamic
            .reserve(((a.query.len() + 15) & !15) + routes.len * 24)
            .map_err(unavailable)?;
        let route_credit = self
            .budget
            .routes
            .reserve(routes.len)
            .map_err(unavailable)?;
        let mut tickets = Vec::with_capacity(routes.len);
        for route in routes.items[..routes.len].iter().flatten() {
            match self.authority.route(*route, &proof, a.source_flow, tuple) {
                Ok(Some(ticket)) => tickets.push(ticket),
                Ok(None) => {}
                Err(error) => {
                    self.release_tickets(&tickets)?;
                    return Err(error);
                }
            }
        }
        let old_tickets = if refresh == 0 {
            None
        } else {
            self.grants
                .get_mut(&grant)
                .map(|g| std::mem::take(&mut g.tickets))
        };
        let result = (|| {
            if self
                .authority
                .expiry(&proof)
                .is_some_and(|until| until <= self.authority.now())
            {
                proof = self
                    .authority
                    .owner(a.source_flow, tuple, OwnerReference::NONE)?;
            }
            if self.authority.subject(&proof, a.source_flow, tuple)? != source_subject {
                return Err(ServiceError::Unavailable);
            }
            let now = self.authority.now();
            let expires = self
                .authority
                .expiry(&proof)
                .unwrap_or(now + Duration::from_secs(1))
                .min(now + Duration::from_secs(1));
            let next = dial
                .as_ref()
                .and_then(|d| d.next.map(|(s, m)| (s, m, d.endpoint_index)));
            self.fence()?;
            let entry = Grant {
                numeric: None,
                source: a.source_flow,
                subject: a.subject,
                scope: a.scope,
                branch: a.branch,
                chain: a.chain,
                stream: a.transport,
                class: a.class,
                effective,
                resolver: a.resolver,
                query: a.query.into(),
                expires,
                request,
                tickets: tickets.clone().into_boxed_slice(),
                next,
                _query_credit: query_credit,
                _routes: route_credit,
            };
            if refresh == 0 {
                if let Some((scope, mask, endpoint)) = next {
                    for branch in 0..2 {
                        if mask & (1 << branch) != 0 {
                            let count = self
                                .frontier
                                .entry((a.source_flow, scope, branch, endpoint))
                                .or_default();
                            *count = count.checked_add(1).ok_or(ServiceError::Busy)?;
                        }
                    }
                }
            }
            self.grants.insert(grant, Box::new(entry));
            if a.class == 1 {
                self.flows
                    .get_mut(&a.source_flow)
                    .ok_or(ServiceError::Unavailable)?
                    .root
                    .get_or_insert((a.scope, effective));
            }
            Ok((grant, proof))
        })();
        match result {
            Ok(value) => {
                if let Some(old) = old_tickets {
                    self.release_tickets(&old)?;
                }
                Ok(value)
            }
            Err(error) => {
                if let Some(old) = old_tickets {
                    if let Some(grant) = self.grants.get_mut(&grant) {
                        grant.tickets = old;
                    }
                }
                self.release_tickets(&tickets)?;
                Err(error)
            }
        }
    }
    fn release_tickets(&mut self, tickets: &[u64]) -> Result<(), ServiceError> {
        for ticket in tickets {
            if self.authority.release(*ticket).is_err() {
                self.unknown = true;
                self.authority.revoke();
                return Err(ServiceError::Unavailable);
            }
        }
        Ok(())
    }
    fn service(
        &mut self,
        request: u64,
        refresh: u64,
        message: &wire::Message<'_>,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let started = self.authority.now();
        let wire::Message::Probe {
            purpose,
            index,
            subject,
            resolver,
        } = *message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        let selector = [purpose, index, subject, resolver];
        let owned = Arc::clone(&self.capsule);
        let capsule = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        capsule.validate_request(message).map_err(unavailable)?;
        let target;
        let mut routes = RoutePlan::new();
        let mut hash = Sha256::new();
        hash.update(b"YNK-SERVICE-v1\0");
        hash.update(capsule.manifest);
        for value in selector {
            hash.update(value.to_be_bytes());
        }
        match purpose {
            1 => {
                let probe = capsule.probe_scope(index, subject).map_err(unavailable)?;
                target = Target::host(probe.host, probe.port)?;
                hash.update([probe.scheme, probe.branches]);
                hash.update(probe.scope.to_be_bytes());
                hash.update(probe.host.as_bytes());
                hash.update([0]);
                hash.update(probe.path.as_bytes());
                routes.walk(
                    &capsule,
                    probe.scope,
                    probe.branches,
                    target.wire(),
                    0,
                    &mut 4096,
                )?;
            }
            2 => {
                let endpoint = capsule
                    .bootstrap_query(index, subject, resolver)
                    .map_err(unavailable)?;
                let row = capsule.resolver_scope(resolver).map_err(unavailable)?;
                // Exact Go c75a8e9: только system snapshot bootstrap, без
                // заимствования internal/provider resolver по совпадению peer.
                if row.source == [0; 32] || row.subject != u16::MAX {
                    return Err(ServiceError::Unsupported);
                }
                hash.update(row.source);
                hash.update(endpoint.bytes);
                routes = RoutePlan::resolver(&capsule, &row)?;
            }
            _ => return Err(ServiceError::InvalidRequest),
        }
        if routes.len == 0 {
            return Err(ServiceError::Unsupported);
        }
        let fingerprint = hash.finalize().into();
        let id = if refresh == 0 {
            if self.grants.len() + self.services.len() + self.hosts_permission_count()
                >= capsule.limits()[0] as usize
                || self.retired.len() >= capsule.limits()[7] as usize
            {
                return Err(ServiceError::Busy);
            }
            Self::id(&mut self.next_grant)?
        } else {
            let old = self
                .services
                .get(&refresh)
                .ok_or(ServiceError::Unavailable)?;
            if old.selector != selector || old.fingerprint != fingerprint || started >= old.expires
            {
                return Err(ServiceError::InvalidRequest);
            }
            refresh
        };
        let credit = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<ServiceGrant>() + 80 + routes.len * 16)
            .map_err(unavailable)?;
        let route_credit = self
            .budget
            .routes
            .reserve(routes.len)
            .map_err(unavailable)?;
        let mut tickets = Vec::with_capacity(routes.len);
        for route in routes.items[..routes.len].iter().flatten() {
            match self.authority.service(capsule.manifest, *route) {
                Ok(Some(ticket)) => tickets.push(ticket),
                Ok(None) => {}
                Err(error) => {
                    self.release_tickets(&tickets)?;
                    return Err(error);
                }
            }
        }
        if let Err(error) = self.fence().and_then(|()| {
            if self.authority.now() >= started + Duration::from_secs(1) {
                Err(ServiceError::Unavailable)
            } else {
                Ok(())
            }
        }) {
            self.release_tickets(&tickets)?;
            return Err(error);
        }
        let old = self.services.insert(
            id,
            Box::new(ServiceGrant {
                selector,
                fingerprint,
                request,
                expires: started + Duration::from_secs(1),
                tickets: tickets.into_boxed_slice(),
                _credit: credit,
                _routes: route_credit,
            }),
        );
        if let Some(old) = old {
            self.release_tickets(&old.tickets)?;
        }
        Ok(id)
    }
    fn cancel_grant(&mut self, id: u64) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        if self.close_hosts_permission(id)? {
            return Ok(());
        }
        self.cancel_dns_root(id, self.services.contains_key(&id))?;
        if let Some(service) = self.services.remove(&id) {
            if let Err(error) = self.release_tickets(&service.tickets) {
                self.services.insert(id, service);
                return Err(error);
            }
            return Ok(());
        }
        let Some(grant) = self.grants.remove(&id) else {
            return Ok(());
        };
        if let Err(error) = self.release_tickets(&grant.tickets) {
            self.grants.insert(id, grant);
            return Err(error);
        }
        if let Some((scope, mask, endpoint)) = grant.next {
            for branch in 0..2 {
                if mask & (1 << branch) != 0 {
                    let key = (grant.source, scope, branch, endpoint);
                    if let Some(count) = self.frontier.get_mut(&key) {
                        *count -= 1;
                        if *count == 0 {
                            self.frontier.remove(&key);
                        }
                    }
                }
            }
        }
        // Уже обработанный request не может прийти повторно: sequence строгий,
        // grant IDs не переиспользуются. Tombstone нужен только queued request;
        // иначе cancel одного flow с >256 grants отозвал бы соседние flow.
        Ok(())
    }
    fn cancel_matching(&mut self, predicate: impl Fn(&Grant) -> bool) -> Result<(), ServiceError> {
        let mut ids = [0; 4096];
        let mut count = 0;
        for (id, grant) in &self.grants {
            if predicate(grant) {
                *ids.get_mut(count).ok_or(ServiceError::Busy)? = *id;
                count += 1;
            }
        }
        for id in &ids[..count] {
            self.cancel_grant(*id)?;
        }
        Ok(())
    }
    fn cancel_flow(&mut self, id: u64) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        if id > self.next_flow {
            return Err(ServiceError::InvalidRequest);
        }
        if !self.flows.contains_key(&id) {
            return Ok(());
        }
        self.cancel_matching(|grant| grant.source == id)?;
        self.authority.cancel_source(id)?;
        if let Some(flow) = self.flows.remove(&id) {
            self.authority.retired_ingress(&flow.socket);
        }
        Ok(())
    }
    fn cancel_request(&mut self, request: u64) -> Result<(), ServiceError> {
        self.rrsets.cancel_request(request);
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        self.close_hosts_request(request)?;
        match self.transport.cancel_request(request) {
            Ok(Some(id)) => self.rrsets.cancel_reservation(id),
            Ok(None) => {}
            Err(_) => {
                self.unknown = true;
                self.authority.revoke();
                return Err(ServiceError::Unavailable);
            }
        }
        self.cancel_numeric_dependents()?;
        self.cancel_dns_request(request)?;
        if let Some((id, _)) = self.services.iter().find(|(_, g)| g.request == request) {
            let id = *id;
            return self.cancel_grant(id);
        }
        if let Some((id, _)) = self.flows.iter().find(|(_, f)| f.request == request) {
            let id = *id;
            return self.cancel_flow(id);
        }
        if let Some((id, _)) = self.grants.iter().find(|(_, g)| g.request == request) {
            let id = *id;
            return self.cancel_grant(id);
        }
        if !self.retired.iter().any(|(id, _)| *id == request) {
            if self.retired.len() >= self.capsule()?.limits()[7] as usize {
                return Err(ServiceError::Busy);
            }
            self.retired
                .push_back((request, self.authority.now() + Duration::from_secs(2)));
        }
        Ok(())
    }
}
struct SocketHold {
    proof: SocketProof,
    _credit: super::memory::ByteLease,
}
struct SystemAuthority {
    scope: RuntimeScopeStamp,
    owner: Arc<OwnerEndpoint>,
    peer: Arc<Peer>,
    routes: Box<dyn RouteAuthority>,
}
impl Authority for SystemAuthority {
    fn check_bootstrap_permit(&mut self, route: BootstrapDnsRoute) -> Result<(), ServiceError> {
        self.fence()?;
        self.routes.check_bootstrap_permit(&self.scope, route)?;
        self.fence()
    }
    fn bootstrap_dns_socket(
        &mut self,
        route: BootstrapDnsRoute,
        facts: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        self.fence()?;
        self.routes
            .bootstrap_dns_socket(&self.scope, route, facts)?;
        self.fence()
    }
    fn dns_socket(
        &mut self,
        ticket: Option<u64>,
        facts: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        self.fence()?;
        self.routes.dns_socket(&self.scope, ticket, facts)?;
        self.fence()
    }
    fn admission_deadline(&self) -> Option<Instant> {
        Some(self.scope.admission_deadline())
    }
    fn bind_ingress(
        &self,
        ingress: &Self::Ingress,
        source: u64,
        subject: Option<Subject>,
        expiry: Option<Instant>,
    ) -> Result<(), ServiceError> {
        if let Some(proof) = ingress {
            proof.proof.bind_udp(source, subject, expiry)?;
        }
        Ok(())
    }
    fn retired_ingress(&self, ingress: &Self::Ingress) {
        if let Some(proof) = ingress {
            proof.proof.retire_udp();
        }
    }
    fn service(
        &mut self,
        manifest: [u8; 32],
        request: RouteRequest<'_>,
    ) -> Result<Option<u64>, ServiceError> {
        self.fence()?;
        let result = self.routes.service(&self.scope, manifest, request)?;
        self.fence()?;
        Ok(result)
    }
    type Proof = KnownOwnerProof;
    type Ingress = Option<Box<SocketHold>>;
    fn mode(&self) -> Mode {
        Mode::System
    }
    fn fence(&self) -> Result<(), ServiceError> {
        self.scope.validate().map_err(unavailable)?;
        self.peer.validate()
    }
    fn revoke(&self) {
        self.scope.revoke();
    }
    fn ingress(
        &mut self,
        request: u64,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        budget: &Arc<ChannelBudget>,
    ) -> Result<Self::Ingress, ServiceError> {
        let wire::Message::OpenIngress {
            tuple,
            provenance,
            ingress,
            ..
        } = message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        if *provenance == 1 {
            capsule.validate_request(message).map_err(unavailable)?;
            return Ok(None);
        }
        let credit = budget
            .dynamic
            .reserve(std::mem::size_of::<SocketHold>() + 32)
            .map_err(unavailable)?;
        let proof = self.peer.socket(*tuple, *provenance, request, *ingress)?;
        if *provenance == 3 {
            capsule
                .validate_associated_request(message, &proof)
                .map_err(unavailable)?;
        } else {
            capsule.validate_request(message).map_err(unavailable)?;
        }
        Ok(Some(Box::new(SocketHold {
            proof,
            _credit: credit,
        })))
    }
    fn check_ingress(&self, proof: &Self::Ingress) -> Result<(), ServiceError> {
        if let Some(proof) = proof {
            proof.proof.validate()?;
        }
        self.fence()
    }
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
        reference: OwnerReference,
    ) -> Result<Self::Proof, ServiceError> {
        self.owner
            .lookup(
                source,
                tuple.owner_flow().map_err(unavailable)?,
                reference,
                Instant::now() + Duration::from_millis(20),
            )
            .map_err(unavailable)
    }
    fn subject(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<Subject>, ServiceError> {
        let subject = Subject::checked(
            proof,
            &self.scope,
            source,
            tuple.owner_flow().map_err(unavailable)?,
        )?;
        if subject.pid == self.peer.pid {
            return Err(ServiceError::Unavailable);
        }
        Ok(Some(subject))
    }
    fn expiry(&self, proof: &Self::Proof) -> Option<Instant> {
        Some(proof.original_expiry())
    }
    fn receipt(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<wire::Receipt, ServiceError> {
        let (_, _, _, reference) = proof
            .checked(
                &self.scope,
                source,
                tuple.owner_flow().map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        Ok(wire::Receipt {
            kind: reference.kind,
            id: reference.id,
        })
    }
    fn route(
        &mut self,
        request: RouteRequest<'_>,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<u64>, ServiceError> {
        self.routes.check(
            &self.scope,
            request,
            proof,
            source,
            tuple.owner_flow().map_err(unavailable)?,
        )
    }
    fn release(&mut self, ticket: u64) -> Result<(), ServiceError> {
        self.routes.release(&self.scope, ticket)
    }
    fn cancel_source(&mut self, source: u64) -> Result<(), ServiceError> {
        self.owner.cancel_source(source).map_err(unavailable)
    }
}
struct LocalAuthority {
    deadline: Instant,
    peer: Arc<Peer>,
    revoked: Arc<AtomicBool>,
    prepared: Arc<crate::host::local_profile_channel::Prepared>,
}
impl Authority for LocalAuthority {
    fn check_bootstrap_permit(&mut self, route: BootstrapDnsRoute) -> Result<(), ServiceError> {
        self.fence()?;
        let cap = wire::Capsule::decode(self.prepared.capsule.bytes(), &self.peer.config_hash)
            .map_err(unavailable)?;
        route.validate(&cap)?;
        self.fence()
    }
    fn bootstrap_dns_socket(
        &mut self,
        route: BootstrapDnsRoute,
        facts: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        self.fence()?;
        let cap = wire::Capsule::decode(self.prepared.capsule.bytes(), &self.peer.config_hash)
            .map_err(unavailable)?;
        route.validate(&cap)?;
        if facts.remote()
            != SocketAddr::new(
                match route.peer.family {
                    4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(route.peer.wire().bytes).map_err(unavailable)?,
                    )),
                    6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(route.peer.wire().bytes).map_err(unavailable)?,
                    )),
                    _ => return Err(ServiceError::Unsupported),
                },
                route.peer.port,
            )
            || facts.protocol() != route.peer.protocol
        {
            return Err(ServiceError::Unavailable);
        }
        self.dns_socket(None, facts)
    }
    fn dns_socket(
        &mut self,
        ticket: Option<u64>,
        facts: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        self.fence()?;
        if ticket.is_some() || facts.mark() != 0 {
            return Err(ServiceError::Unsupported);
        }
        Ok(())
    }
    fn admission_deadline(&self) -> Option<Instant> {
        Some(self.deadline)
    }
    fn bind_ingress(
        &self,
        ingress: &Self::Ingress,
        source: u64,
        subject: Option<Subject>,
        expiry: Option<Instant>,
    ) -> Result<(), ServiceError> {
        if let Some(proof) = ingress {
            proof.proof.bind_udp(source, subject, expiry)?;
        }
        Ok(())
    }
    fn retired_ingress(&self, ingress: &Self::Ingress) {
        if let Some(proof) = ingress {
            proof.proof.retire_udp();
        }
    }
    fn service(
        &mut self,
        manifest: [u8; 32],
        request: RouteRequest<'_>,
    ) -> Result<Option<u64>, ServiceError> {
        self.fence()?;
        if self.prepared.capsule.bytes().get(..32) != Some(manifest.as_slice()) {
            return Err(ServiceError::Unavailable);
        }
        if let RouteRequest::Dns(peer) = request {
            // Local не получает kernel/route attribution System. Numeric peer
            // остаётся bound к retained resolver row; loopback требует bind proof.
            reject_unproved_stub(peer)?;
        }
        Ok(None)
    }
    type Proof = ();
    type Ingress = Option<Box<SocketHold>>;
    fn mode(&self) -> Mode {
        Mode::Local
    }
    fn fence(&self) -> Result<(), ServiceError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(ServiceError::Unavailable);
        }
        let (_keep, cancel) = crate::Cancellation::new();
        self.prepared.revalidate(&cancel).map_err(unavailable)?;
        self.peer.validate()
    }
    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
    fn ingress(
        &mut self,
        request: u64,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        budget: &Arc<ChannelBudget>,
    ) -> Result<Self::Ingress, ServiceError> {
        let wire::Message::OpenIngress {
            tuple,
            provenance,
            ingress,
            ..
        } = message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        if *provenance == 1 {
            return Err(ServiceError::Unsupported);
        }
        let credit = budget
            .dynamic
            .reserve(std::mem::size_of::<SocketHold>() + 32)
            .map_err(unavailable)?;
        let proof = self.peer.socket(*tuple, *provenance, request, *ingress)?;
        if *provenance == 3 {
            capsule
                .validate_associated_request(message, &proof)
                .map_err(unavailable)?;
        } else {
            capsule.validate_request(message).map_err(unavailable)?;
        }
        Ok(Some(Box::new(SocketHold {
            proof,
            _credit: credit,
        })))
    }
    fn check_ingress(&self, proof: &Self::Ingress) -> Result<(), ServiceError> {
        proof
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .proof
            .validate()?;
        self.fence()
    }
    fn owner(&mut self, _: u64, _: Tuple, reference: OwnerReference) -> Result<(), ServiceError> {
        if reference != OwnerReference::NONE {
            return Err(ServiceError::InvalidRequest);
        }
        self.fence()
    }
    fn subject(&self, _: &(), _: u64, _: Tuple) -> Result<Option<Subject>, ServiceError> {
        self.fence()?;
        Ok(None)
    }
    fn expiry(&self, _: &()) -> Option<Instant> {
        None
    }
    fn receipt(&self, _: &(), _: u64, _: Tuple) -> Result<wire::Receipt, ServiceError> {
        Ok(wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        })
    }
    fn route(
        &mut self,
        request: RouteRequest<'_>,
        _: &(),
        _: u64,
        _: Tuple,
    ) -> Result<Option<u64>, ServiceError> {
        self.fence()?;
        if let RouteRequest::Dns(peer) = request {
            reject_unproved_stub(peer)?;
        }
        Ok(None)
    }
    fn release(&mut self, _: u64) -> Result<(), ServiceError> {
        Err(ServiceError::InvalidRequest)
    }
    fn cancel_source(&mut self, _: u64) -> Result<(), ServiceError> {
        Ok(())
    }
}

pub(crate) struct ProfileRuntime {
    wake: Option<Arc<tokio::sync::Notify>>,
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<Box<dyn Send>>>,
    closure: ClosureFence,
}
struct ClosureFence {
    mode: Mode,
    worker: bool,
    rules: bool,
}
impl ClosureFence {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            worker: false,
            rules: false,
        }
    }
    fn local_reaped(&mut self) -> Result<(), ServiceError> {
        if self.mode != Mode::Local {
            return Err(ServiceError::Unavailable);
        }
        self.worker = true;
        self.rules = true;
        Ok(())
    }
    fn worker_closed(&mut self) -> Result<(), ServiceError> {
        if self.mode != Mode::System {
            return Err(ServiceError::Unavailable);
        }
        self.worker = true;
        Ok(())
    }
    fn rules_retired(&mut self) -> Result<(), ServiceError> {
        if self.mode != Mode::System || !self.worker {
            return Err(ServiceError::Unavailable);
        }
        self.rules = true;
        Ok(())
    }
    fn known(&self) -> bool {
        self.worker && self.rules
    }
}
impl ProfileRuntime {
    pub(crate) fn start_local(
        record: LaunchRecord,
        mut peer: Arc<Peer>,
        prepared: Arc<crate::host::local_profile_channel::Prepared>,
        channel: OwnedFd,
    ) -> Result<Self, ServiceError> {
        let deadline = Instant::now() + Duration::from_secs(1);
        if record.mode != Mode::Local {
            return Err(ServiceError::Unsupported);
        }
        // Проверка installed proof выполняется после actual child verification,
        // до HELLO/negotiation; невозможность v2 не превращается в v1 fallback.
        let producer = peer.verified_udp_producer(record, &prepared.capsule)?;
        Arc::get_mut(&mut peer)
            .ok_or(ServiceError::Unavailable)?
            .proofs = Some(Arc::new(std::sync::Mutex::new(ProofInbox::new()?)));
        let (proof, go_proof) = channel_pair()?;
        let handle = tokio::runtime::Handle::current();
        let wake = Arc::new(tokio::sync::Notify::new());
        let thread_wake = Arc::clone(&wake);
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_ready = Arc::clone(&ready);
        let authority = LocalAuthority {
            deadline,
            peer: Arc::clone(&peer),
            revoked: Arc::clone(&stop),
            prepared: Arc::clone(&prepared),
        };
        let issuer = Issuer::new(authority, Arc::clone(&prepared.capsule), record)?;
        let sideband = SystemChannel::new(
            rustix::io::fcntl_dupfd_cloexec(&channel, 3).map_err(unavailable)?,
            proof,
            Arc::clone(&peer),
            record,
            handle,
            thread_wake,
            2,
            producer.clone(),
            None,
            Arc::clone(&prepared.capsule),
            Arc::clone(&issuer.budget),
            bootstrap_binding::Sources::Local(Arc::clone(&prepared)),
        )?;
        let task = std::thread::Builder::new()
            .name("yonik-profile-local".into())
            .spawn(move || {
                let mut resources = (
                    issuer,
                    sideband,
                    prepared,
                    channel,
                    Some(go_proof),
                    producer,
                );
                let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::worker::role_handoff::send_proof_bootstrap(
                        &resources.3,
                        record,
                        &resources.5,
                        resources.4.as_ref().ok_or(ServiceError::Unavailable)?,
                        peer.pid,
                        peer.uid,
                        Instant::now() + Duration::from_secs(1),
                    )
                    .map_err(unavailable)?;
                    resources.4.take();
                    resources.1.hello(&thread_stop, deadline)?;
                    run_issuer(
                        &mut resources.0,
                        &resources.1,
                        peer.pid,
                        peer.uid,
                        &thread_stop,
                        &thread_ready,
                    )
                }));
                thread_stop.store(true, Ordering::Release);
                thread_ready.store(false, Ordering::Release);
                resources.1.shutdown();
                Box::new(resources) as Box<dyn Send>
            })
            .map_err(unavailable)?;
        Ok(Self {
            wake: Some(wake),
            stop,
            ready,
            task: Some(task),
            closure: ClosureFence::new(Mode::Local),
        })
    }
    pub(crate) fn start_system(
        scope: RuntimeScopeStamp,
        owner: OwnerEndpoint,
        payload: Arc<crate::worker::WorkerPayload>,
        uid: u32,
        routes: Box<dyn RouteAuthority>,
    ) -> Result<
        (
            Self,
            OwnedFd,
            std::sync::mpsc::SyncSender<crate::worker::role_handoff::VerifiedExecDelivery>,
        ),
        ServiceError,
    > {
        let profile = payload.full_profile().ok_or(ServiceError::Unsupported)?;
        let capsule = Arc::clone(profile.capsule());
        let record = scope.profile_launch_record(&capsule).map_err(unavailable)?;
        let (host, worker) = channel_pair()?;
        let (delivery_tx, delivery_rx) = std::sync::mpsc::sync_channel(1);
        let wake = Arc::new(tokio::sync::Notify::new());
        let thread_wake = Arc::clone(&wake);
        let handle = tokio::runtime::Handle::current();
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_ready = Arc::clone(&ready);
        let task = std::thread::Builder::new()
            .name("yonik-profile-system".into())
            .spawn(move || {
                let mut resources = SystemResources {
                    scope,
                    owner: Some(owner),
                    payload,
                    channel: host,
                    routes: Some(routes),
                    issuer: None,
                    proof_channel: None,
                    delivery: None,
                    peer: None,
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    resources.delivery = Some(
                        delivery_rx
                            .recv_timeout(
                                resources
                                    .scope
                                    .admission_deadline()
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_secs(1)),
                            )
                            .map_err(unavailable)?,
                    );
                    let (_keep, cancel) = crate::Cancellation::new();
                    resources
                        .payload
                        .full_profile()
                        .ok_or(ServiceError::Unsupported)?
                        .revalidate(&cancel)
                        .map_err(unavailable)?;
                    let peer = Peer::system(
                        record,
                        uid,
                        resources.scope.fork_lookup(),
                        resources
                            .delivery
                            .as_ref()
                            .ok_or(ServiceError::Unavailable)?,
                    )?;
                    resources.peer = Some(Arc::clone(&peer));
                    let producer = peer.verified_udp_producer(record, &capsule)?;
                    let (proof, go_proof) = channel_pair()?;
                    let proof_version = crate::worker::role_handoff::send_proof_bootstrap(
                        &resources.channel,
                        record,
                        &producer,
                        &go_proof,
                        record.child_pid,
                        uid,
                        resources
                            .scope
                            .admission_deadline()
                            .min(Instant::now() + Duration::from_secs(1)),
                    )
                    .map_err(unavailable)?;
                    drop(go_proof);
                    let owner = Arc::new(resources.owner.take().ok_or(ServiceError::Unavailable)?);
                    let authority = SystemAuthority {
                        scope: resources.scope.fork_lookup(),
                        owner: Arc::clone(&owner),
                        peer: Arc::clone(&peer),
                        routes: resources.routes.take().ok_or(ServiceError::Unavailable)?,
                    };
                    resources.issuer = Some(Issuer::new(authority, Arc::clone(&capsule), record)?);
                    let budget = Arc::clone(
                        &resources
                            .issuer
                            .as_ref()
                            .ok_or(ServiceError::Unavailable)?
                            .budget,
                    );
                    resources.proof_channel = Some(SystemChannel::new(
                        rustix::io::fcntl_dupfd_cloexec(&resources.channel, 3)
                            .map_err(unavailable)?,
                        proof,
                        Arc::clone(&peer),
                        record,
                        handle,
                        thread_wake,
                        proof_version,
                        producer,
                        Some(owner),
                        Arc::clone(&capsule),
                        budget,
                        bootstrap_binding::Sources::System(Arc::clone(
                            resources
                                .payload
                                .full_profile()
                                .ok_or(ServiceError::Unsupported)?,
                        )),
                    )?);
                    resources
                        .proof_channel
                        .as_ref()
                        .ok_or(ServiceError::Unavailable)?
                        .hello(&thread_stop, resources.scope.admission_deadline())?;
                    run_issuer(
                        resources.issuer.as_mut().ok_or(ServiceError::Unavailable)?,
                        resources
                            .proof_channel
                            .as_ref()
                            .ok_or(ServiceError::Unavailable)?,
                        record.child_pid,
                        uid,
                        &thread_stop,
                        &thread_ready,
                    )
                }));
                if result.is_err() {
                    resources.scope.revoke();
                }
                resources.scope.revoke();
                if let Some(channel) = &resources.proof_channel {
                    channel.shutdown();
                }
                let _shutdown =
                    rustix::net::shutdown(&resources.channel, rustix::net::Shutdown::Both);
                Box::new(resources) as Box<dyn Send>
            })
            .map_err(unavailable)?;
        Ok((
            Self {
                wake: Some(wake),
                stop,
                ready,
                task: Some(task),
                closure: ClosureFence::new(Mode::System),
            },
            worker,
            delivery_tx,
        ))
    }
    pub(crate) fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && self.task.as_ref().is_some_and(|t| !t.is_finished())
    }
    pub(crate) fn revoke(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(wake) = &self.wake {
            wake.notify_one();
        }
    }
    pub(crate) fn confirmed_closed(&mut self) -> Result<(), ServiceError> {
        self.closure.local_reaped()?;
        self.revoke();
        Ok(())
    }
    pub(crate) fn worker_closed(&mut self) -> Result<(), ServiceError> {
        self.closure.worker_closed()?;
        self.revoke();
        Ok(())
    }
    pub(crate) fn rules_retired(&mut self) -> Result<(), ServiceError> {
        self.closure.rules_retired()?;
        self.revoke();
        Ok(())
    }
}
impl Drop for ProfileRuntime {
    fn drop(&mut self) {
        self.revoke();
        if let Some(task) = self.task.take() {
            match task.join() {
                Ok(resources) if self.closure.known() => drop(resources),
                Ok(resources) => std::mem::forget(resources),
                Err(_) => {
                    self.closure.rules = false;
                }
            }
        }
    }
}
struct SystemResources {
    delivery: Option<crate::worker::role_handoff::VerifiedExecDelivery>,
    peer: Option<Arc<Peer>>,
    proof_channel: Option<SystemChannel>,
    scope: RuntimeScopeStamp,
    owner: Option<OwnerEndpoint>,
    payload: Arc<crate::worker::WorkerPayload>,
    channel: OwnedFd,
    routes: Option<Box<dyn RouteAuthority>>,
    issuer: Option<Issuer<SystemAuthority>>,
}
pub(crate) fn channel_pair() -> Result<(OwnedFd, OwnedFd), ServiceError> {
    use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
    let (a, b) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(unavailable)?;
    for fd in [&a, &b] {
        net::sockopt::set_socket_passcred(fd, true).map_err(unavailable)?;
    }
    Ok((a, b))
}
fn receive(
    socket: &impl AsFd,
    pid: u32,
    uid: u32,
    out: &mut [u8; RUNTIME_PACKET],
) -> Result<Option<usize>, ServiceError> {
    use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
    let mut control =
        [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut control);
    let msg = match net::recvmsg(
        socket,
        &mut [std::io::IoSliceMut::new(out)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(msg) => msg,
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(None),
        Err(_) => return Err(ServiceError::Unavailable),
    };
    let mut credentials = None;
    let mut bad = false;
    for part in ancillary.drain() {
        match part {
            RecvAncillaryMessage::ScmCredentials(c) if credentials.is_none() => {
                credentials = Some(c)
            }
            RecvAncillaryMessage::ScmRights(rights) => {
                bad = true;
                for fd in rights {
                    drop(fd);
                }
            }
            _ => bad = true,
        }
    }
    let c = credentials.ok_or(ServiceError::Unavailable)?;
    if bad
        || msg.bytes == 0
        || msg.bytes >= RUNTIME_PACKET
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || c.pid.as_raw_pid() as u32 != pid
        || c.uid.as_raw() != uid
    {
        return Err(ServiceError::Unavailable);
    }
    Ok(Some(msg.bytes))
}
trait Channel {
    fn bootstrap_dns_transcript(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<dyn BootstrapDnsTranscript>>, ServiceError> {
        Ok(None)
    }
    fn bootstrap_dns_producer(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<VerifiedBootstrapDnsProducer>>, ServiceError> {
        Ok(None)
    }
    fn bootstrap_source(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<dyn dns_bundle::roots::Source>>, ServiceError> {
        Ok(None)
    }
    fn dns_logical_producer(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<VerifiedDnsLogicalProducer>, ServiceError> {
        Ok(None)
    }
    fn dns_wire_producer(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<VerifiedDnsWireProducer>, ServiceError> {
        Ok(None)
    }
    fn dns_producer(&self, _: LaunchRecord) -> Result<Option<VerifiedDnsProducer>, ServiceError> {
        Ok(None)
    }
    fn dns_slots(&self) -> Result<Arc<SidebandCredits>, ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn take_dns(&self) -> Result<Option<dns_transport::Incoming>, ServiceError> {
        Ok(None)
    }
    fn take_dns_credit(&self, _: u64) -> Result<super::memory::ByteLease, ServiceError> {
        Err(ServiceError::Unsupported)
    }
    fn setup_read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        self.read(pid, uid, out)
    }
    fn setup_write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        self.write(bytes)
    }
    fn dns_committed(&self, _: wire::dns_v2::Negotiated) -> Result<(), ServiceError> {
        Ok(())
    }
    fn processed(&self, _: u64) -> Result<(), ServiceError> {
        Ok(())
    }
    fn maintain(
        &self,
        _: &mut dyn FnMut(u64) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        Ok(())
    }
    fn is_control_source(&self, _: u64) -> bool {
        false
    }
    fn history(&self) -> Option<Arc<std::sync::Mutex<InvocationHistory>>> {
        None
    }
    fn discard_ingress(&self, _request: u64) -> Result<(), ServiceError> {
        Ok(())
    }
    fn read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError>;
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError>;
    fn pause(&self) {
        std::thread::sleep(Duration::from_millis(1));
    }
    fn pause_until(&self, _until: Instant) {
        self.pause();
    }
    fn writable_until(&self, until: Instant) {
        self.pause_until(until);
    }
}
impl Channel for OwnedFd {
    fn read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        receive(self, pid, uid, out)
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        send(self, bytes)
    }
}
fn send(socket: &impl AsFd, bytes: &[u8]) -> Result<bool, ServiceError> {
    match rustix::net::send(
        socket,
        bytes,
        rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
    ) {
        Ok(sent) if sent == bytes.len() => Ok(true),
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(false),
        _ => Err(ServiceError::Unavailable),
    }
}
#[allow(clippy::too_many_arguments)] // Header routing и исходный deadline остаются явными.
fn send_message<A: Authority>(
    issuer: &Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    reply_to: u64,
    object: u64,
    message: &wire::Message<'_>,
    until: Instant,
) -> Result<(), ServiceError> {
    let mut bytes = [0; 65536];
    let kind = match message {
        wire::Message::Admit(_) => wire::Kind::Admit,
        wire::Message::IngressReply { .. } => wire::Kind::IngressReply,
        wire::Message::Grant { .. } => wire::Kind::Grant,
        wire::Message::CloseAck { .. } => wire::Kind::CloseAck,
        wire::Message::Deny { .. } => wire::Kind::Deny,
        _ => return Err(ServiceError::InvalidRequest),
    };
    loop {
        issuer.fence()?;
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        let remaining = until.saturating_duration_since(issuer.authority.now());
        let refreshed = if let wire::Message::Grant {
            status,
            class,
            required,
            grant,
            flow,
            revision,
            receipt,
            ..
        } = message
        {
            Some(wire::Message::Grant {
                status: *status,
                class: *class,
                required: *required,
                grant: *grant,
                flow: *flow,
                lease: remaining.as_millis().min(1000) as u32,
                revision: *revision,
                fresh: if *required {
                    remaining.as_nanos().min(20_000_000) as u64
                } else {
                    0
                },
                receipt: *receipt,
            })
        } else {
            None
        };
        let n = wire::Frame::encode(
            wire::Header {
                kind,
                sequence,
                reply_to,
                binding: issuer.record.binding,
                object_id: object,
            },
            refreshed.as_ref().unwrap_or(message),
            &mut bytes,
        )
        .map_err(unavailable)?;
        if socket.write(&bytes[..n])? {
            return Ok(());
        }
        socket.writable_until(until);
    }
}
struct SocketEvidence {
    fd: OwnedFd,
    namespace: OwnedFd,
    facts: SocketFacts,
    udp: Option<Arc<UdpBinding>>,
    _fds: super::memory::ByteLease,
}
struct SidebandCredits {
    pending: super::memory::ByteBudget,
    fds: super::memory::ByteBudget,
}
impl SidebandCredits {
    fn receive_runtime(
        &self,
        receive: impl FnOnce() -> Result<Option<usize>, ServiceError>,
    ) -> Result<(Option<usize>, super::memory::ByteLease), ServiceError> {
        // receive закрывает любые доставленные права до возврата/отказа.
        let (slot, _fds) = self.read_credit(16)?;
        Ok((receive()?, slot))
    }
    fn read_credit(
        &self,
        rights: usize,
    ) -> Result<(super::memory::ByteLease, super::memory::ByteLease), ServiceError> {
        let pending = self.pending.reserve(1).map_err(unavailable)?;
        let fds = self.fds.reserve(rights).map_err(unavailable)?;
        Ok((pending, fds))
    }
    fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: super::memory::ByteBudget::new(64),
            fds: super::memory::ByteBudget::new(64),
        })
    }
}
#[derive(Clone, Copy)]
struct UdpIngressRecord {
    sequence: u64,
    ingress: u16,
    packet: wire::udp_v2::Packet,
    original: Target,
    expires: Instant,
}
struct UdpBinding {
    record: UdpIngressRecord,
    principal: Option<Subject>,
    source: std::sync::atomic::AtomicU64,
    live: AtomicBool,
    _memory: super::memory::ByteLease,
}
struct WaitingUdp<T> {
    record: UdpIngressRecord,
    value: T,
    _slot: super::memory::ByteLease,
}
struct Waiting<T> {
    record: wire::SocketRecord,
    value: T,
    expires: Instant,
    _slot: super::memory::ByteLease,
}
struct WaitingFrame {
    packet: Queued,
    expires: Instant,
    _slot: super::memory::ByteLease,
    canceled: bool,
}
struct Rendezvous<T> {
    dns_physical: VecDeque<dns_transport::Incoming>,
    dns: Option<wire::dns_v2::Negotiated>,
    pending: BTreeMap<u64, Waiting<T>>,
    ready: BTreeMap<u64, Waiting<T>>,
    udp_pending: BTreeMap<u64, WaitingUdp<T>>,
    udp_ready: BTreeMap<u64, WaitingUdp<T>>,
    slots: Arc<SidebandCredits>,
    delivered: BTreeMap<u64, DeliveryCredit>,
    frames: VecDeque<WaitingFrame>,
    incoming: wire::Sequence,
    last_delivered: u64,
    last_proof: u64,
    _credit: super::memory::ByteLease,
}
impl<T> Rendezvous<T> {
    fn discard_udp_endpoint(&mut self, launch: LaunchRecord, port: u16) {
        for frame in &mut self.frames {
            if wire::Frame::decode(&frame.packet.bytes[..frame.packet.length],launch.binding,launch.mode,false).is_ok_and(|frame|matches!(frame.message,wire::Message::OpenIngress{provenance:3,tuple,..} if tuple.remote_port==port&&tuple.remote[..4]==[127,0,0,1])){frame.canceled=true;}
        }
    }
    fn discard_association(&mut self, association: u64) {
        let mut ids = [0; 64];
        let mut n = 0;
        for entry in self.udp_pending.values().chain(self.udp_ready.values()) {
            if entry.record.packet.association == association {
                ids[n] = entry.record.sequence;
                n += 1;
            }
        }
        for id in &ids[..n] {
            self.discard(*id);
        }
    }
    fn discard(&mut self, request: u64) {
        // Sequence/proof watermarks сохраняются: cleanup не разрешает replay.
        self.pending.remove(&request);
        self.ready.remove(&request);
        self.udp_pending.remove(&request);
        self.udp_ready.remove(&request);
        for frame in &mut self.frames {
            if frame.packet.sequence == request {
                frame.canceled = true;
            }
        }
    }
    fn new() -> Result<Self, ServiceError> {
        if std::mem::size_of::<Waiting<T>>() + 80 > 512 {
            return Err(ServiceError::Unsupported);
        }
        let credit = super::memory::config_budget()
            .reserve(RX_BYTES)
            .map_err(unavailable)?;
        let mut incoming = wire::Sequence::new();
        incoming.accept(1).map_err(unavailable)?;
        Ok(Self {
            dns: None,
            dns_physical: VecDeque::new(),
            pending: BTreeMap::new(),
            ready: BTreeMap::new(),
            udp_pending: BTreeMap::new(),
            udp_ready: BTreeMap::new(),
            slots: SidebandCredits::new(),
            delivered: BTreeMap::new(),
            frames: VecDeque::with_capacity(64),
            incoming,
            last_delivered: 1,
            last_proof: 0,
            _credit: credit,
        })
    }
    fn check(&self, now: Instant) -> Result<(), ServiceError> {
        if self
            .pending
            .values()
            .chain(self.ready.values())
            .any(|p| now >= p.expires)
            || self.frames.iter().any(|p| now >= p.expires)
            || self.delivered.values().any(|p| now >= p.expires)
            || self
                .udp_pending
                .values()
                .chain(self.udp_ready.values())
                .any(|p| now >= p.record.expires)
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
    fn proof_capacity(&self) -> Result<(), ServiceError> {
        if self.slots.pending.used() >= 64 {
            Err(ServiceError::Busy)
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    fn proof(
        &mut self,
        record: wire::SocketRecord,
        value: T,
        now: Instant,
    ) -> Result<(), ServiceError> {
        let slot = self.slots.pending.reserve(1).map_err(unavailable)?;
        self.proof_reserved(record, value, now, slot)
    }
    fn proof_reserved(
        &mut self,
        record: wire::SocketRecord,
        value: T,
        now: Instant,
        slot: super::memory::ByteLease,
    ) -> Result<(), ServiceError> {
        self.check(now)?;
        if record.request <= self.last_delivered
            || record.proof <= self.last_proof
            || record.proof == u64::MAX
            || record.request == u64::MAX
            || self.pending.contains_key(&record.request)
            || self.ready.contains_key(&record.request)
            || self.udp_pending.contains_key(&record.request)
            || self.udp_ready.contains_key(&record.request)
        {
            return Err(ServiceError::InvalidRequest);
        }
        self.last_proof = record.proof;
        self.pending.insert(
            record.request,
            Waiting {
                record,
                value,
                expires: now + Duration::from_secs(1),
                _slot: slot,
            },
        );
        Ok(())
    }
    #[cfg(test)]
    fn runtime(&mut self, packet: Queued, now: Instant) -> Result<(), ServiceError> {
        let slot = self.slots.pending.reserve(1).map_err(unavailable)?;
        self.runtime_reserved(packet, now, slot)
    }
    fn udp_proof(
        &mut self,
        record: UdpIngressRecord,
        value: T,
        slot: super::memory::ByteLease,
        now: Instant,
    ) -> Result<(), ServiceError> {
        self.check(now)?;
        if record.sequence <= self.last_delivered
            || record.sequence == u64::MAX
            || now >= record.expires
            || self
                .frames
                .iter()
                .any(|f| f.packet.sequence == record.sequence && f.canceled)
            || self.udp_pending.contains_key(&record.sequence)
            || self.udp_ready.contains_key(&record.sequence)
            || self.pending.contains_key(&record.sequence)
            || self.ready.contains_key(&record.sequence)
        {
            return Err(ServiceError::InvalidRequest);
        }
        self.udp_pending.insert(
            record.sequence,
            WaitingUdp {
                record,
                value,
                _slot: slot,
            },
        );
        Ok(())
    }
    fn runtime_reserved(
        &mut self,
        packet: Queued,
        now: Instant,
        slot: super::memory::ByteLease,
    ) -> Result<(), ServiceError> {
        self.check(now)?;
        if self.frames.len() >= 64 {
            return Err(ServiceError::Busy);
        }
        self.incoming.accept(packet.sequence).map_err(unavailable)?;
        self.frames.push_back(WaitingFrame {
            packet,
            expires: now + Duration::from_secs(1),
            _slot: slot,
            canceled: false,
        });
        Ok(())
    }
    fn next(&mut self, launch: LaunchRecord, now: Instant) -> Result<Option<Queued>, ServiceError> {
        self.check(now)?;
        let Some(front) = self.frames.front() else {
            return Ok(None);
        };
        if dns_bundle::is_dns(&front.packet.bytes[..front.packet.length]) {
            let frame = dns_bundle::decode(
                &front.packet.bytes[..front.packet.length],
                self.dns.as_ref().ok_or(ServiceError::Unavailable)?,
                wire::dns_v2::Direction::Producer,
            )?;
            self.last_delivered = frame.header.sequence;
            return self.deliver(None);
        }
        let frame = wire::Frame::decode(
            &front.packet.bytes[..front.packet.length],
            launch.binding,
            launch.mode,
            false,
        )
        .map_err(unavailable)?;
        let request = frame.header.sequence;
        if front.canceled {
            self.last_delivered = request;
            return self.deliver(None);
        }
        if let wire::Message::OpenIngress {
            ingress,
            provenance: 3,
            tuple,
            original,
        } = frame.message
        {
            if let Some(proof) = self.udp_pending.get(&request) {
                if proof.record.ingress != ingress
                    || proof.record.packet.tuple != tuple
                    || proof.record.original != Target::copy(original)?
                {
                    return Err(ServiceError::InvalidRequest);
                }
                let proof = self
                    .udp_pending
                    .remove(&request)
                    .ok_or(ServiceError::Unavailable)?;
                self.udp_ready.insert(request, proof);
            } else {
                let canceled=self.frames.iter().any(|p|wire::Frame::decode(&p.packet.bytes[..p.packet.length],launch.binding,launch.mode,false).is_ok_and(|f|matches!(f.message,wire::Message::Cancel{target:1,id,..} if id==request)));
                if !canceled {
                    return Ok(None);
                }
            }
        } else if self.udp_pending.contains_key(&request) {
            return Err(ServiceError::InvalidRequest);
        } else if let wire::Message::OpenIngress {
            ingress,
            provenance: 2,
            tuple,
            ..
        } = frame.message
        {
            if let Some(proof) = self.pending.get(&request) {
                if proof.record.ingress != ingress || proof.record.tuple != tuple {
                    return Err(ServiceError::InvalidRequest);
                }
                let proof = self
                    .pending
                    .remove(&request)
                    .ok_or(ServiceError::Unavailable)?;
                self.ready.insert(request, proof);
            } else {
                let canceled=self.frames.iter().any(|p|wire::Frame::decode(&p.packet.bytes[..p.packet.length],launch.binding,launch.mode,false).is_ok_and(|f|matches!(f.message,wire::Message::Cancel{target:1,id,..} if id==request)));
                if !canceled {
                    return Ok(None);
                }
            }
        } else if self.pending.contains_key(&request) {
            return Err(ServiceError::InvalidRequest);
        }
        self.last_delivered = request;
        let source = match frame.message {
            wire::Message::Authorize(ref a) if a.class == 1 => Some(a.source_flow),
            _ => None,
        };
        self.deliver(source)
    }
    fn deliver(&mut self, source: Option<u64>) -> Result<Option<Queued>, ServiceError> {
        let Some(frame) = self.frames.pop_front() else {
            return Ok(None);
        };
        self.delivered.insert(
            frame.packet.sequence,
            DeliveryCredit {
                source,
                expires: frame.expires,
                _slot: frame._slot,
            },
        );
        Ok(Some(frame.packet))
    }
    fn processed(&mut self, sequence: u64) {
        self.delivered.remove(&sequence);
    }
    fn take(&mut self, request: u64, tuple: Tuple, ingress: u16) -> Result<T, ServiceError> {
        self.check(Instant::now())?;
        if let Some(proof) = self.udp_ready.remove(&request) {
            if proof.record.packet.tuple != tuple || proof.record.ingress != ingress {
                return Err(ServiceError::InvalidRequest);
            }
            return Ok(proof.value);
        }
        let proof = self
            .ready
            .remove(&request)
            .ok_or(ServiceError::Unsupported)?;
        if proof.record.tuple != tuple || proof.record.ingress != ingress {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(proof.value)
    }
    fn deadline(&self, until: Instant) -> Instant {
        self.pending
            .values()
            .chain(self.ready.values())
            .map(|p| p.expires)
            .chain(self.frames.iter().map(|p| p.expires))
            .chain(self.delivered.values().map(|p| p.expires))
            .chain(
                self.udp_pending
                    .values()
                    .chain(self.udp_ready.values())
                    .map(|p| p.record.expires),
            )
            .fold(until, Instant::min)
    }
}
type ProofInbox = Rendezvous<SocketEvidence>;
struct DeliveryCredit {
    source: Option<u64>,
    expires: Instant,
    _slot: super::memory::ByteLease,
}
struct SystemChannel {
    bootstrap: Option<Arc<bootstrap_binding::BootstrapBinding>>,
    capsule: Arc<wire::OwnedCapsule>,
    budget: Arc<ChannelBudget>,
    runtime: tokio::net::UnixDatagram,
    proof: tokio::net::UnixDatagram,
    peer: Arc<Peer>,
    launch: LaunchRecord,
    handle: tokio::runtime::Handle,
    wake: Arc<tokio::sync::Notify>,
    failed: std::cell::Cell<bool>,
    udp: Option<std::cell::RefCell<AssociationIssuer<KernelUdpOperations>>>,
}
impl SystemChannel {
    fn send_udp(&self, response: UdpResponse<OwnedFd>) -> Result<(), ServiceError> {
        let encoded = response.record.encode(self.launch).map_err(unavailable)?;
        if encoded.from_go || encoded.rights != usize::from(response.fd.is_some()) {
            return Err(ServiceError::Unavailable);
        }
        let mut storage = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut storage);
        let fd = response.fd.as_ref().map(AsFd::as_fd);
        let rights = fd.as_slice();
        if !rights.is_empty() && !control.push(rustix::net::SendAncillaryMessage::ScmRights(rights))
        {
            return Err(ServiceError::Unavailable);
        }
        match rustix::net::sendmsg(
            &self.proof,
            &[std::io::IoSlice::new(&encoded.bytes[..encoded.length])],
            &mut control,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        ) {
            Ok(n) if n == encoded.length => Ok(()),
            _ => Err(ServiceError::Unavailable),
        }
    }
    fn progress_udp(&self) -> Result<(), ServiceError> {
        let Some(udp) = &self.udp else {
            return Ok(());
        };
        let mut udp = udp.borrow_mut();
        udp.tick(Instant::now())?;
        let mut pending = [0; 8];
        let mut count = 0;
        for (id, relay) in &udp.relays {
            if relay
                .cycle
                .as_ref()
                .is_some_and(|c| c.stage == UdpStage::Waiting)
            {
                pending[count] = *id;
                count += 1;
            }
        }
        for id in &pending[..count] {
            if let Some(response) = udp.progress(*id, Instant::now())? {
                self.send_udp(response)?;
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // Exact bound endpoint/resources одного owner loop.
    fn new(
        runtime: OwnedFd,
        proof: OwnedFd,
        peer: Arc<Peer>,
        launch: LaunchRecord,
        handle: tokio::runtime::Handle,
        wake: Arc<tokio::sync::Notify>,
        version: u8,
        producer: VerifiedUdpProducer,
        owner: Option<Arc<OwnerEndpoint>>,
        capsule: Arc<wire::OwnedCapsule>,
        budget: Arc<ChannelBudget>,
        sources: bootstrap_binding::Sources,
    ) -> Result<Self, ServiceError> {
        let bootstrap = bootstrap_binding::BootstrapBinding::prepare(
            Arc::clone(&peer),
            sources,
            Arc::clone(&capsule),
            launch,
            Arc::clone(&budget),
        )?;
        if version != producer.setup(launch)?.2 {
            return Err(ServiceError::Unsupported);
        }
        let udp = if version == 2 {
            let ops = KernelUdpOperations {
                producer: Arc::new(producer),
                peer: Arc::clone(&peer),
                owner,
                record: launch,
                capsule: Arc::clone(&capsule),
                handle: handle.clone(),
            };
            let mut issuer = AssociationIssuer::new(
                ops,
                launch,
                wire::Capsule::decode(capsule.bytes(), &launch.binding.digest)
                    .map_err(unavailable)?
                    .limits()[7],
                budget.dynamic.clone(),
            )?;
            issuer.slots = Arc::clone(
                &peer
                    .proofs
                    .as_ref()
                    .ok_or(ServiceError::Unsupported)?
                    .lock()
                    .map_err(unavailable)?
                    .slots,
            );
            Some(std::cell::RefCell::new(issuer))
        } else {
            None
        };
        for fd in [&runtime, &proof] {
            let flags = rustix::fs::fcntl_getfl(fd).map_err(unavailable)?;
            rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
                .map_err(unavailable)?;
        }
        let (runtime, proof) = {
            let _enter = handle.enter();
            (
                tokio::net::UnixDatagram::from_std(std::os::unix::net::UnixDatagram::from(runtime))
                    .map_err(unavailable)?,
                tokio::net::UnixDatagram::from_std(std::os::unix::net::UnixDatagram::from(proof))
                    .map_err(unavailable)?,
            )
        };
        Ok(Self {
            bootstrap,
            runtime,
            capsule,
            budget,
            proof,
            peer,
            launch,
            handle,
            wake,
            failed: std::cell::Cell::new(false),
            udp,
        })
    }
    fn shutdown(&self) {
        for fd in [&self.runtime, &self.proof] {
            let _result = rustix::net::shutdown(fd, rustix::net::Shutdown::Both);
        }
    }
    fn hello(&self, stop: &AtomicBool, until: Instant) -> Result<(), ServiceError> {
        let mut bytes = [0; RUNTIME_PACKET];
        loop {
            if stop.load(Ordering::Acquire) || Instant::now() >= until {
                return Err(ServiceError::Unavailable);
            }
            self.peer.validate()?;
            if let Some(length) = Self::ready(&self.runtime, tokio::io::Interest::READABLE, || {
                receive(&self.runtime, self.peer.pid, self.peer.uid, &mut bytes)
            })? {
                let frame = wire::Frame::decode(
                    &bytes[..length],
                    self.launch.binding,
                    self.launch.mode,
                    false,
                )
                .map_err(unavailable)?;
                if frame.header.sequence != 1
                    || !matches!(frame.message,wire::Message::Hello{nonce,mode} if nonce==self.launch.nonce&&mode==self.launch.mode)
                {
                    return Err(ServiceError::Unavailable);
                }
                return Ok(());
            }
            // До HELLO proof FD только удерживается. Его readable readiness не
            // будит setup loop: отдельные каналы не гарантируют receive order.
            self.handle.block_on(async{tokio::select!{biased;_=self.wake.notified()=>Ok(()),_=tokio::time::sleep_until(until.into())=>Ok(()),ready=self.runtime.readable()=>ready}}).map_err(unavailable)?;
        }
    }
    fn receive_proof(&self, inbox: &mut ProofInbox) -> Result<bool, ServiceError> {
        // Fixed credit включает один ingress scratch FD сверх 64 pending.
        // Это позволяет прочитать EOF/overflow без allocation нового slot.
        use rustix::net::{
            self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        };
        inbox.proof_capacity()?;
        let history_credit = self.history().map(HistoryCredit::claim).transpose()?;
        let dns_memory = self.budget.dynamic.reserve(2048).map_err(unavailable)?;
        let (slot, mut fds) = inbox.slots.read_credit(16)?;
        let mut bytes = [0; 257];
        let mut control = [std::mem::MaybeUninit::uninit();
            rustix::cmsg_space!(ScmRights(16), ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut control);
        let msg = match net::recvmsg(
            &self.proof,
            &mut [std::io::IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(msg) => msg,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(false),
            Err(_) => return Err(ServiceError::Unavailable),
        };
        let mut credentials = None;
        let mut socket = None;
        let mut bad = false;
        let mut rights_seen = false;
        for part in ancillary.drain() {
            match part {
                RecvAncillaryMessage::ScmCredentials(c) if credentials.is_none() => {
                    credentials = Some(c)
                }
                RecvAncillaryMessage::ScmRights(rights) => {
                    if rights_seen {
                        bad = true;
                    }
                    rights_seen = true;
                    for fd in rights {
                        if socket.is_none() && !bad {
                            socket = Some(fd);
                        } else {
                            bad = true;
                            drop(fd);
                        }
                    }
                }
                _ => bad = true,
            }
        }
        let c = credentials.ok_or(ServiceError::Unavailable)?;
        if bad
            || msg.bytes < 128
            || msg.bytes > 256
            || msg
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            || c.pid.as_raw_pid() as u32 != self.peer.pid
            || c.uid.as_raw() != self.peer.uid
        {
            return Err(ServiceError::Unavailable);
        }
        if &bytes[..8] == b"DNSPHY02" {
            if msg.bytes != 192 {
                return Err(ServiceError::Unavailable);
            }
            let packet = wire::dns_v2::PhysicalPacket::decode(
                &bytes[..192],
                inbox.dns.as_ref().ok_or(ServiceError::Unavailable)?,
                usize::from(socket.is_some()),
                1,
            )
            .map_err(unavailable)?;
            let mut raw = [0; 192];
            raw.copy_from_slice(packet.view().bytes());
            let evidence = dns_transport::Evidence::capture(
                socket.ok_or(ServiceError::Unavailable)?,
                Arc::clone(&self.peer),
            )?;
            fds.resize(2).map_err(unavailable)?;
            inbox
                .dns_physical
                .push_back(dns_transport::Incoming::captured(
                    raw,
                    evidence,
                    slot,
                    fds,
                    dns_memory,
                    history_credit,
                ));
            return Ok(true);
        }
        drop(history_credit);
        if &bytes[..8] != b"YNKSPF01" {
            let udp = self.udp.as_ref().ok_or(ServiceError::Unsupported)?;
            let record = wire::udp_v2::Record::decode(
                &bytes[..msg.bytes],
                self.launch,
                true,
                usize::from(socket.is_some()),
            )
            .map_err(unavailable)?;
            let mut udp = udp.borrow_mut();
            let udp = &mut *udp;
            let memory = udp.budget.reserve(1024).map_err(unavailable)?;
            let response = udp.handle(
                record,
                socket,
                Instant::now(),
                Instant::now() + Duration::from_secs(1),
            )?;
            if let wire::udp_v2::Record::Consumed { packet, sequence } = record {
                fds.resize(2).map_err(unavailable)?;
                let relay = udp
                    .relays
                    .get_mut(&packet.association)
                    .ok_or(ServiceError::Unavailable)?;
                let control = udp
                    .controls
                    .get(&relay.control)
                    .ok_or(ServiceError::Unavailable)?;
                let cycle = relay.cycle.as_mut().ok_or(ServiceError::Unavailable)?;
                let original = cycle.original.ok_or(ServiceError::Unavailable)?;
                let record = UdpIngressRecord {
                    sequence,
                    ingress: control.ingress,
                    packet,
                    original,
                    expires: cycle.deadline,
                };
                let binding = Arc::new(UdpBinding {
                    record,
                    principal: control.principal,
                    source: std::sync::atomic::AtomicU64::new(0),
                    live: AtomicBool::new(true),
                    _memory: memory,
                });
                udp.ops.relay_valid(&relay.value)?;
                let fd =
                    rustix::io::fcntl_dupfd_cloexec(&relay.value.fd, 3).map_err(unavailable)?;
                let namespace = rustix::io::fcntl_dupfd_cloexec(&relay.value.namespace, 3)
                    .map_err(unavailable)?;
                let facts = SocketFacts::capture(&fd)?;
                cycle.binding = Some(Arc::clone(&binding));
                cycle._pending.take();
                inbox.udp_proof(
                    record,
                    SocketEvidence {
                        fd,
                        namespace,
                        facts,
                        udp: Some(binding),
                        _fds: fds,
                    },
                    slot,
                    Instant::now(),
                )?;
            }
            if let Some(response) = response {
                self.send_udp(response)?;
            }
            return Ok(true);
        }
        if msg.bytes != 192 {
            return Err(ServiceError::Unavailable);
        }
        let fd = socket.ok_or(ServiceError::Unavailable)?;
        let record = wire::SocketRecord::decode(&bytes[..192], self.launch).map_err(unavailable)?;
        fds.resize(2).map_err(unavailable)?;
        let facts = SocketFacts::capture(&fd)?;
        if !facts.matches(record.tuple, 2) {
            return Err(ServiceError::InvalidRequest);
        }
        if self.peer.system_scope.is_none() {
            let _local_scratch = inbox.slots.fds.reserve(2).map_err(unavailable)?;
            let independent = self
                .peer
                .socket(record.tuple, 2, record.request, record.ingress)?;
            if independent.facts != facts {
                return Err(ServiceError::Unavailable);
            }
            // Local authority — независимый exact child FD/cookie, не System
            // namespace claim. Это namespace custody normal Host, не SIOCGSKNS.
            let namespace = File::open("/proc/thread-self/ns/net")
                .map_err(unavailable)?
                .into();
            inbox.proof_reserved(
                record,
                SocketEvidence {
                    fd,
                    namespace,
                    facts,
                    udp: None,
                    _fds: fds,
                },
                Instant::now(),
                slot,
            )?;
            return Ok(true);
        }
        let namespace = yonik_nsfs::socket_namespace::socket_namespace(&fd)
            .map_err(|_| ServiceError::Unsupported)?;
        let stat = rustix::fs::fstat(&namespace).map_err(unavailable)?;
        let scope = self
            .peer
            .system_scope
            .as_ref()
            .ok_or(ServiceError::Unsupported)?;
        scope.validate().map_err(unavailable)?;
        if (stat.st_dev, stat.st_ino) != scope.lookup_binding().2.namespace() {
            return Err(ServiceError::Unsupported);
        }
        inbox.proof_reserved(
            record,
            SocketEvidence {
                fd,
                namespace,
                facts,
                udp: None,
                _fds: fds,
            },
            Instant::now(),
            slot,
        )?;
        Ok(true)
    }
    fn wait(&self, until: Instant, writable: bool) {
        let until = self.udp.as_ref().map_or(until, |udp| {
            udp.borrow()
                .relays
                .values()
                .filter_map(|r| {
                    r.close_deadline
                        .or_else(|| r.cycle.as_ref().map(|c| c.deadline))
                })
                .fold(until, Instant::min)
        });
        let until = self
            .peer
            .proofs
            .as_ref()
            .and_then(|p| p.lock().ok().map(|p| p.deadline(until)))
            .unwrap_or(until);
        let result=self.handle.block_on(async {
            if writable {tokio::select!{biased; _=self.wake.notified()=>Ok(()),_=tokio::time::sleep_until(until.into())=>Ok(()),ready=self.runtime.writable()=>ready}}
            else {tokio::select!{biased;_=self.wake.notified()=>Ok(()),_=tokio::time::sleep_until(until.into())=>Ok(()),ready=self.runtime.readable()=>ready,ready=self.proof.readable()=>ready,ready=futures_util::future::poll_fn(|cx| {
                if let Some(udp)=&self.udp {
                    let udp=udp.borrow();
                    for control in udp.controls.values().filter(|control|!control.closing) {
                        if let std::task::Poll::Ready(result)=control.value.socket.poll_read_ready(cx){return std::task::Poll::Ready(result);}
                    }
                    for relay in udp.relays.values() {
                        if relay.cycle.as_ref().is_some_and(|c|c.stage==UdpStage::Waiting) {
                            if let std::task::Poll::Ready(result)=relay.value.fd.poll_recv_ready(cx){return std::task::Poll::Ready(result);}
                        }
                    }
                }
                std::task::Poll::Pending
            })=>ready}}
        });
        if result.is_err() {
            self.failed.set(true);
        }
    }
    fn ready<T>(
        socket: &tokio::net::UnixDatagram,
        interest: tokio::io::Interest,
        operation: impl FnOnce() -> Result<Option<T>, ServiceError>,
    ) -> Result<Option<T>, ServiceError> {
        match socket.try_io(interest, || match operation() {
            Ok(Some(value)) => Ok(Ok(value)),
            Ok(None) => Err(std::io::ErrorKind::WouldBlock.into()),
            Err(error) => Ok(Err(error)),
        }) {
            Ok(value) => value.map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }
}
impl Channel for SystemChannel {
    fn bootstrap_source(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<Arc<dyn dns_bundle::roots::Source>>, ServiceError> {
        let Some(binding) = &self.bootstrap else {
            return Ok(None);
        };
        let view = binding.source();
        if view.is_some() {
            binding.check(super::registry::BootstrapScope::Source, record)?;
        }
        Ok(view)
    }
    fn bootstrap_dns_transcript(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<Arc<dyn BootstrapDnsTranscript>>, ServiceError> {
        let Some(binding) = &self.bootstrap else {
            return Ok(None);
        };
        let view = binding.transcript();
        if view.is_some() {
            binding.check(super::registry::BootstrapScope::Wire, record)?;
        }
        Ok(view)
    }
    fn bootstrap_dns_producer(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<Arc<VerifiedBootstrapDnsProducer>>, ServiceError> {
        let Some(binding) = &self.bootstrap else {
            return Ok(None);
        };
        let view = binding.release();
        if view.is_some() {
            binding.check(super::registry::BootstrapScope::Release, record)?;
        }
        Ok(view)
    }
    fn dns_wire_producer(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<VerifiedDnsWireProducer>, ServiceError> {
        self.peer.validate()?;
        if self.peer.bound_launch != Some(record) {
            return Err(ServiceError::Unavailable);
        }
        let cap = wire::Capsule::decode(self.capsule.bytes(), &self.peer.config_hash)
            .map_err(unavailable)?;
        let proof = self
            .peer
            .producer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?;
        if proof.dns_wire_channel(self.peer.image_hash).is_err() {
            return Ok(None);
        }
        Ok(Some(VerifiedDnsWireProducer::mint(
            proof,
            self.peer.image_hash,
            self.peer.config_hash,
            cap.manifest,
            record,
        )?))
    }
    fn dns_producer(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<VerifiedDnsProducer>, ServiceError> {
        self.peer.validate()?;
        if self.peer.bound_launch != Some(record) {
            return Err(ServiceError::Unavailable);
        }
        let cap = wire::Capsule::decode(self.capsule.bytes(), &self.peer.config_hash)
            .map_err(unavailable)?;
        let proof = self
            .peer
            .producer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?;
        if proof.dns_release_channel(self.peer.image_hash).is_err() {
            return Ok(None);
        }
        Ok(Some(VerifiedDnsProducer::mint(
            proof,
            self.peer.image_hash,
            self.peer.config_hash,
            cap.manifest,
            record,
        )?))
    }
    fn dns_slots(&self) -> Result<Arc<SidebandCredits>, ServiceError> {
        Ok(Arc::clone(
            &self
                .peer
                .proofs
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .lock()
                .map_err(unavailable)?
                .slots,
        ))
    }
    fn take_dns(&self) -> Result<Option<dns_transport::Incoming>, ServiceError> {
        Ok(self
            .peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?
            .dns_physical
            .pop_front())
    }
    fn take_dns_credit(&self, sequence: u64) -> Result<super::memory::ByteLease, ServiceError> {
        Ok(self
            .peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?
            .delivered
            .remove(&sequence)
            .ok_or(ServiceError::Unavailable)?
            ._slot)
    }
    fn setup_read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        self.peer.validate()?;
        let slots = Arc::clone(
            &self
                .peer
                .proofs
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .lock()
                .map_err(unavailable)?
                .slots,
        );
        let (packet, _slot) = slots.receive_runtime(|| {
            Self::ready(&self.runtime, tokio::io::Interest::READABLE, || {
                receive(&self.runtime, pid, uid, out)
            })
        })?;
        Ok(packet)
    }
    fn setup_write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        self.peer.validate()?;
        Self::ready(&self.runtime, tokio::io::Interest::WRITABLE, || {
            send(&self.runtime, bytes).map(|sent| sent.then_some(()))
        })
        .map(|v| v.is_some())
    }
    fn dns_committed(&self, neg: wire::dns_v2::Negotiated) -> Result<(), ServiceError> {
        let mut inbox = self
            .peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?;
        if inbox.dns.is_some() {
            return Err(ServiceError::InvalidRequest);
        }
        inbox.dns = Some(neg);
        Ok(())
    }
    fn processed(&self, sequence: u64) -> Result<(), ServiceError> {
        self.peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?
            .processed(sequence);
        Ok(())
    }
    fn is_control_source(&self, id: u64) -> bool {
        self.udp
            .as_ref()
            .is_some_and(|udp| udp.borrow().controls.contains_key(&id))
    }
    fn maintain(
        &self,
        cancel: &mut dyn FnMut(u64) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        self.peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?
            .check(Instant::now())?;
        let Some(udp) = &self.udp else {
            return Ok(());
        };
        let mut udp = udp.borrow_mut();
        let mut ids = [0; 8];
        let mut n = 0;
        for (id, control) in &udp.controls {
            if !control.closing && udp.ops.control_closed(&control.value)? {
                ids[n] = *id;
                n += 1;
            }
        }
        for id in &ids[..n] {
            if let Some(association) = udp.controls.get(id).and_then(|c| c.association) {
                let mut inbox = self
                    .peer
                    .proofs
                    .as_ref()
                    .ok_or(ServiceError::Unavailable)?
                    .lock()
                    .map_err(unavailable)?;
                inbox.discard_association(association);
                if let Some(relay) = udp.relays.get(&association) {
                    inbox.discard_udp_endpoint(self.launch, relay.port);
                }
            }
            if let Some(response) = udp.retire_control(*id, cancel, Instant::now())? {
                self.send_udp(response)?;
            }
        }
        for relay in udp.relays.values_mut() {
            let mut ids = [0; 256];
            let mut n = 0;
            for (id, flow) in &relay.flows {
                if flow
                    .binding
                    .as_ref()
                    .is_some_and(|b| !b.live.load(Ordering::Acquire))
                {
                    ids[n] = *id;
                    n += 1;
                }
            }
            for id in &ids[..n] {
                cancel(*id)?;
                relay.flows.remove(id);
            }
        }
        Ok(())
    }
    fn history(&self) -> Option<Arc<std::sync::Mutex<InvocationHistory>>> {
        self.udp
            .as_ref()
            .map(|udp| Arc::clone(&udp.borrow().history))
    }
    fn discard_ingress(&self, request: u64) -> Result<(), ServiceError> {
        self.peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?
            .discard(request);
        Ok(())
    }
    fn read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        if self.failed.get() {
            return Err(ServiceError::Unavailable);
        }
        self.peer.validate()?;
        self.progress_udp()?;
        let mut inbox = self
            .peer
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .lock()
            .map_err(unavailable)?;
        for _ in 0..64 {
            inbox.check(Instant::now())?;
            let proof = Self::ready(&self.proof, tokio::io::Interest::READABLE, || {
                self.receive_proof(&mut inbox)
                    .map(|read| read.then_some(()))
            })?
            .is_some();
            if let Some(packet) = inbox.next(self.launch, Instant::now())? {
                out[..packet.length].copy_from_slice(&packet.bytes[..packet.length]);
                return Ok(Some(packet.length));
            }
            if inbox.frames.len() >= 64 {
                return Err(ServiceError::Busy);
            }
            let mut bytes = [0; RUNTIME_PACKET];
            let (frame, slot) = inbox.slots.receive_runtime(|| {
                Self::ready(&self.runtime, tokio::io::Interest::READABLE, || {
                    receive(&self.runtime, pid, uid, &mut bytes)
                })
            })?;
            if let Some(length) = frame {
                let sequence = if dns_bundle::is_dns(&bytes[..length]) {
                    dns_bundle::decode(
                        &bytes[..length],
                        inbox.dns.as_ref().ok_or(ServiceError::Unavailable)?,
                        wire::dns_v2::Direction::Producer,
                    )?
                    .header
                    .sequence
                } else {
                    wire::Frame::decode(
                        &bytes[..length],
                        self.launch.binding,
                        self.launch.mode,
                        false,
                    )
                    .map_err(unavailable)?
                    .header
                    .sequence
                };
                inbox.runtime_reserved(
                    Queued::new(&bytes[..length], sequence, &self.budget.dynamic)?,
                    Instant::now(),
                    slot,
                )?;
            }
            if let Some(packet) = inbox.next(self.launch, Instant::now())? {
                out[..packet.length].copy_from_slice(&packet.bytes[..packet.length]);
                return Ok(Some(packet.length));
            }
            if !proof && frame.is_none() {
                return Ok(None);
            }
        }
        Err(ServiceError::Busy)
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        if dns_bundle::is_dns(bytes) {
            let inbox = self
                .peer
                .proofs
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .lock()
                .map_err(unavailable)?;
            dns_bundle::decode(
                bytes,
                inbox.dns.as_ref().ok_or(ServiceError::Unavailable)?,
                wire::dns_v2::Direction::Issuer,
            )?;
            drop(inbox);
            return self.setup_write(bytes);
        }
        let frame = wire::Frame::decode(bytes, self.launch.binding, self.launch.mode, true)
            .map_err(unavailable)?;
        // Все authority checks предшествуют публикации ответа. Повтор после
        // WouldBlock сохраняет source ID и исходный deadline.
        if let (
            Some(udp),
            wire::Message::IngressReply {
                status: wire::Status::Allow,
                flow,
                ..
            },
        ) = (&self.udp, &frame.message)
        {
            let mut udp = udp.borrow_mut();
            let origin = udp.relays.values().find_map(|r| {
                r.cycle
                    .as_ref()
                    .filter(|c| c.sequence == frame.header.reply_to)
                    .and_then(|c| c.original.map(|o| (c.packet.tuple, o)))
            });
            if let Some((tuple, original)) = origin {
                udp.bind_source(
                    frame.header.reply_to,
                    *flow,
                    tuple,
                    original.wire(),
                    Instant::now(),
                )?;
            }
        }
        if let (Some(udp), wire::Message::CloseAck { target: 2, id, .. }) =
            (&self.udp, &frame.message)
        {
            // Child close report не доказывает уничтожение duplicate. Пока
            // independent consuming/closure endpoint закрыт, Known не публикуется.
            if udp
                .borrow()
                .controls
                .get(id)
                .is_some_and(|c| c.association.is_some())
            {
                return Err(ServiceError::Unavailable);
            }
        }
        if let (
            Some(udp),
            wire::Message::Grant {
                class: 1 | 3, flow, ..
            },
        ) = (&self.udp, &frame.message)
        {
            if *flow != 0 {
                udp.borrow_mut().check_grant(*flow, Instant::now())?;
            }
        }
        let sent = Self::ready(&self.runtime, tokio::io::Interest::WRITABLE, || {
            send(&self.runtime, bytes).map(|sent| sent.then_some(()))
        })
        .map(|sent| sent.is_some())?;
        if sent {
            let source = self
                .peer
                .proofs
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .lock()
                .map_err(unavailable)?
                .delivered
                .get(&frame.header.reply_to)
                .and_then(|delivery| delivery.source);
            if let Some(udp) = &self.udp {
                let mut udp = udp.borrow_mut();
                match frame.message {
                    wire::Message::Deny { .. } => udp.denied(frame.header.reply_to, source),
                    wire::Message::Grant {
                        class: 1,
                        flow,
                        grant,
                        ..
                    } => udp.granted(flow, grant),
                    wire::Message::CloseAck {
                        target: 2,
                        id,
                        status: wire::CloseStatus::KnownClosed,
                    } => {
                        if udp.controls.contains_key(&id) {
                            if let Some(association) =
                                udp.controls.get(&id).and_then(|c| c.association)
                            {
                                let response = udp.retire(association, Instant::now())?;
                                self.send_udp(response)?;
                            }
                        } else {
                            udp.denied(0, Some(id));
                            udp.cancel_flow(id);
                        }
                    }
                    wire::Message::CloseAck {
                        target: 1,
                        id,
                        status: wire::CloseStatus::KnownClosed,
                    } => udp.denied(id, None),
                    _ => {}
                }
            }
        }
        Ok(sent)
    }
    fn pause_until(&self, until: Instant) {
        self.wait(until, false);
    }
    fn writable_until(&self, until: Instant) {
        self.wait(until, true);
    }
}
struct Queued {
    bytes: Box<[u8]>,
    length: usize,
    sequence: u64,
    _payload: super::memory::ByteLease,
}
impl Queued {
    fn new(
        bytes: &[u8],
        sequence: u64,
        budget: &super::memory::ByteBudget,
    ) -> Result<Self, ServiceError> {
        if bytes.is_empty() || bytes.len() >= RUNTIME_PACKET {
            return Err(ServiceError::InvalidRequest);
        }
        let credit = budget.reserve(bytes.len() + 16).map_err(unavailable)?;
        Ok(Self {
            bytes: bytes.into(),
            length: bytes.len(),
            sequence,
            _payload: credit,
        })
    }
    #[cfg(test)]
    fn fixture(bytes: &[u8], sequence: u64) -> Self {
        Self::new(
            bytes,
            sequence,
            &super::memory::ByteBudget::new(8 * 1024 * 1024),
        )
        .unwrap()
    }
}
#[derive(Clone, Copy)]
struct CancelReply {
    dns: bool,
    request: u64,
    target: u8,
    id: u64,
    status: wire::CloseStatus,
}
#[allow(clippy::too_many_arguments)] // Единственный reader сохраняет ordering и pending holes.
fn drain_before_publication<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    pid: u32,
    uid: u32,
    incoming: &mut wire::Sequence,
    queued: &mut VecDeque<Queued>,
    acks: &mut VecDeque<CancelReply>,
) -> Result<(), ServiceError> {
    for _ in 0..64 {
        dns_transport::ingest(issuer, socket)?;
        socket.maintain(&mut |id| issuer.cancel_flow(id))?;
        if queued.len() + acks.len() >= 64 {
            return Err(ServiceError::Busy);
        }
        let mut bytes = [0; RUNTIME_PACKET];
        let next = socket.read(pid, uid, &mut bytes)?;
        dns_transport::ingest(issuer, socket)?;
        let Some(length) = next else {
            return Ok(());
        };
        if dns_bundle::is_dns(&bytes[..length]) {
            let f = dns_bundle::decode(
                &bytes[..length],
                issuer
                    .negotiated
                    .as_ref()
                    .ok_or(ServiceError::Unavailable)?,
                wire::dns_v2::Direction::Producer,
            )?;
            let sequence = f.header.sequence;
            incoming.accept(sequence).map_err(unavailable)?;
            if let Some(history) = &issuer.history {
                history.lock().map_err(unavailable)?.runtime(sequence)?;
            }
            if let wire::dns_v2::Record::Cancel(v) = f.record {
                let (target, id) = dns_bundle::cancel_fields(v);
                let result = dns_bundle::cancel(issuer, sequence, target, id);
                acks.push_back(CancelReply {
                    dns: true,
                    request: sequence,
                    target,
                    id,
                    status: if result.is_ok() {
                        wire::CloseStatus::KnownClosed
                    } else {
                        wire::CloseStatus::Unknown
                    },
                });
            } else {
                // Полученный до ACK record нельзя сделать позднее допустимым
                // лишь очередью: фиксируем denial до materialization/effects.
                if !issuer.transport.ready_at_arrival(f.record) {
                    issuer.cancel_request(sequence)?;
                }
                if !issuer.context_ready_at_arrival(f.record) {
                    issuer.cancel_request(sequence)?;
                }
                queued.push_back(Queued::new(
                    &bytes[..length],
                    sequence,
                    &issuer.budget.dynamic,
                )?);
            }
            continue;
        }
        let frame = wire::Frame::decode(
            &bytes[..length],
            issuer.record.binding,
            issuer.record.mode,
            false,
        )
        .map_err(unavailable)?;
        incoming
            .accept(frame.header.sequence)
            .map_err(unavailable)?;
        if let Some(history) = &issuer.history {
            history
                .lock()
                .map_err(unavailable)?
                .runtime(frame.header.sequence)?;
        }
        if let wire::Message::Cancel { target, id, .. } = frame.message {
            if target == 1 && id < frame.header.sequence {
                socket.discard_ingress(id)?;
            }
            let result = cancel_with_channel(issuer, socket, frame.header.sequence, target, id);
            acks.push_back(CancelReply {
                dns: false,
                request: frame.header.sequence,
                target,
                id,
                status: if result.is_ok() {
                    wire::CloseStatus::KnownClosed
                } else {
                    wire::CloseStatus::Unknown
                },
            });
            if issuer.unknown {
                return Err(ServiceError::Unavailable);
            }
        } else {
            queued.push_back(Queued::new(
                &bytes[..length],
                frame.header.sequence,
                &issuer.budget.dynamic,
            )?);
        }
    }
    Err(ServiceError::Busy)
}
fn cancel_with_channel<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    sequence: u64,
    target: u8,
    id: u64,
) -> Result<(), ServiceError> {
    if target == 2 && socket.is_control_source(id) {
        return Err(ServiceError::InvalidRequest);
    }
    cancel(issuer, sequence, target, id)
}
fn cancel<A: Authority>(
    issuer: &mut Issuer<A>,
    sequence: u64,
    target: u8,
    id: u64,
) -> Result<(), ServiceError> {
    match target {
        1 if id < sequence => issuer.cancel_request(id),
        2 => issuer.cancel_flow(id),
        3 if id <= issuer.next_grant => issuer.cancel_grant(id),
        4 => {
            issuer.authority.revoke();
            Err(ServiceError::Unavailable)
        }
        _ => Err(ServiceError::InvalidRequest),
    }
}
fn run_issuer<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    pid: u32,
    uid: u32,
    stop: &AtomicBool,
    ready: &AtomicBool,
) -> Result<(), ServiceError> {
    issuer.history = socket.history();
    let mut incoming = wire::Sequence::new();
    incoming.accept(1).map_err(unavailable)?;
    let mut outgoing = 1u64;
    let mut admission = issuer.capsule()?.admission_id;
    let manifest = issuer.record.manifest;
    let lease = Duration::from_millis(u64::from(issuer.capsule()?.lease_ms));
    let mut expires = issuer.authority.now() + lease.saturating_sub(Duration::from_secs(1));
    let mut awaiting = Some((
        outgoing,
        admission,
        issuer
            .authority
            .admission_deadline()
            .unwrap_or(issuer.authority.now() + Duration::from_secs(1)),
        expires,
    ));
    send_message(
        issuer,
        socket,
        stop,
        outgoing,
        1,
        0,
        &wire::Message::Admit(issuer.capsule.bytes()),
        awaiting.ok_or(ServiceError::Unavailable)?.2,
    )?;
    let mut bytes = [0; RUNTIME_PACKET];
    // MemoryPreflight уже включает caps[3]*2048 для этой очереди.
    // CODEC2 debit-ит только дополнительный storage, без двойного reservation.
    let existing = (issuer.capsule()?.limits()[3] as usize) * 2048;
    let _queue_credit = issuer
        .budget
        .dynamic
        .reserve((64 * std::mem::size_of::<Queued>()).saturating_sub(existing))
        .map_err(unavailable)?;
    let mut queued = VecDeque::<Queued>::with_capacity(64);
    let mut acks = VecDeque::<CancelReply>::with_capacity(64);
    loop {
        dns_transport::ingest(issuer, socket)?;
        socket.maintain(&mut |id| issuer.cancel_flow(id))?;
        issuer.fence()?;
        let now = issuer.authority.now();
        while issuer.retired.front().is_some_and(|(request, until)| {
            now >= *until
                && queued
                    .front()
                    .is_none_or(|pending| *request < pending.sequence)
        }) {
            issuer.retired.pop_front();
        }
        if stop.load(Ordering::Acquire) || now >= expires || awaiting.is_some_and(|a| now >= a.2) {
            return Err(ServiceError::Unavailable);
        }
        let mut expired_user = [0; 4096];
        let mut expired_count = 0;
        for (id, grant) in &issuer.grants {
            if now >= grant.expires && !issuer.transport.holds_root_cleanup(*id, false, now) {
                *expired_user
                    .get_mut(expired_count)
                    .ok_or(ServiceError::Busy)? = *id;
                expired_count += 1;
            }
        }
        for id in &expired_user[..expired_count] {
            issuer.cancel_grant(*id)?;
        }
        let mut expired = [0; 4096];
        let mut count = 0;
        for (id, grant) in &issuer.services {
            if now >= grant.expires && !issuer.transport.holds_root_cleanup(*id, true, now) {
                *expired.get_mut(count).ok_or(ServiceError::Busy)? = *id;
                count += 1;
            }
        }
        for id in &expired[..count] {
            issuer.cancel_grant(*id)?;
        }
        issuer.expire_dns()?;
        issuer.cancel_numeric_dependents()?;
        if awaiting.is_none() {
            dns_transport::progress(issuer, socket, stop, &mut outgoing, |issuer| {
                drain_before_publication(
                    issuer,
                    socket,
                    pid,
                    uid,
                    &mut incoming,
                    &mut queued,
                    &mut acks,
                )
            })?;
        }
        while let Some(ack) = acks.pop_front() {
            outgoing = outgoing
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
                .ok_or(ServiceError::Unavailable)?;
            send_cancel_reply(issuer, socket, stop, outgoing, ack, expires)?;
            socket.processed(ack.request)?;
        }
        let (n, sequenced) = if let Some(pending) = queued.pop_front() {
            bytes[..pending.length].copy_from_slice(&pending.bytes);
            (pending.length, true)
        } else {
            let Some(n) = socket.read(pid, uid, &mut bytes)? else {
                if awaiting.is_none()
                    && dns_transport::progress(issuer, socket, stop, &mut outgoing, |issuer| {
                        drain_before_publication(
                            issuer,
                            socket,
                            pid,
                            uid,
                            &mut incoming,
                            &mut queued,
                            &mut acks,
                        )
                    })?
                {
                    continue;
                }
                let until = issuer
                    .grants
                    .values()
                    .map(|g| g.expires)
                    .chain(issuer.services.values().map(|g| g.expires))
                    .filter(|until| *until > issuer.authority.now())
                    .chain(issuer.transport.cleanup_wakeup(issuer.authority.now()))
                    .chain(issuer.dns.wakeup(issuer.authority.now()))
                    .chain(awaiting.map(|a| a.2))
                    .fold(expires, Instant::min);
                socket.pause_until(until);
                continue;
            };
            (n, false)
        };
        if dns_bundle::is_dns(&bytes[..n]) {
            if awaiting.is_some() {
                return Err(ServiceError::Unavailable);
            }
            let neg = issuer.negotiated.ok_or(ServiceError::Unavailable)?;
            let request = dns_bundle::decode(&bytes[..n], &neg, wire::dns_v2::Direction::Producer)?
                .header
                .sequence;
            if !sequenced {
                incoming.accept(request).map_err(unavailable)?;
            }
            if let Some(history) = &issuer.history {
                history.lock().map_err(unavailable)?.runtime(request)?;
            }
            outgoing = outgoing
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .ok_or(ServiceError::Unavailable)?;
            dns_bundle::dispatch(
                issuer,
                socket,
                stop,
                outgoing,
                &bytes[..n],
                expires,
                |issuer| {
                    drain_before_publication(
                        issuer,
                        socket,
                        pid,
                        uid,
                        &mut incoming,
                        &mut queued,
                        &mut acks,
                    )
                },
            )?;
            socket.processed(request)?;
            while let Some(ack) = acks.pop_front() {
                outgoing = outgoing
                    .checked_add(1)
                    .filter(|v| *v != u64::MAX)
                    .ok_or(ServiceError::Unavailable)?;
                send_cancel_reply(issuer, socket, stop, outgoing, ack, expires)?;
                socket.processed(ack.request)?;
            }
            continue;
        }
        let frame = wire::Frame::decode(
            &bytes[..n],
            issuer.record.binding,
            issuer.record.mode,
            false,
        )
        .map_err(unavailable)?;
        if !sequenced {
            incoming
                .accept(frame.header.sequence)
                .map_err(unavailable)?;
        }
        if let wire::Message::AdmitAck {
            manifest: hash,
            admission: id,
            status,
        } = frame.message
        {
            let Some((sent, expected, setup_until, next_expiry)) = awaiting else {
                return Err(ServiceError::InvalidRequest);
            };
            if frame.header.reply_to != sent
                || hash != manifest
                || id != expected
                || status != wire::Status::Allow
            {
                return Err(ServiceError::Unavailable);
            }
            expires = next_expiry;
            awaiting = None;
            if issuer.negotiated.is_none() {
                issuer.dns_release = socket.dns_producer(issuer.record)?;
                issuer.dns_wire = socket.dns_wire_producer(issuer.record)?;
                issuer.bootstrap_source = socket.bootstrap_source(issuer.record)?;
                issuer.bootstrap_dns = socket.bootstrap_dns_producer(issuer.record)?;
                issuer.bootstrap_transcript = socket.bootstrap_dns_transcript(issuer.record)?;
                issuer.dns_logical = socket.dns_logical_producer(issuer.record)?;
                issuer.negotiated = Some(dns_bundle::negotiate(
                    issuer,
                    socket,
                    pid,
                    uid,
                    stop,
                    setup_until,
                )?);
            }
            ready.store(true, Ordering::Release);
            socket.processed(frame.header.sequence)?;
            continue;
        }
        if awaiting.is_some() {
            return Err(ServiceError::Unavailable);
        }
        outgoing = outgoing
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(ServiceError::Unavailable)?;
        let reply = frame.header.sequence;
        if let Some(history) = &issuer.history {
            history.lock().map_err(unavailable)?.runtime(reply)?;
        }
        if issuer.retired.iter().any(|(id, _)| *id == reply) {
            socket.discard_ingress(reply)?;
            send_message(
                issuer,
                socket,
                stop,
                outgoing,
                reply,
                0,
                &wire::Message::Deny {
                    status: wire::Status::Deny,
                    reason: 4,
                },
                expires.min(now + Duration::from_secs(1)),
            )?;
            socket.processed(reply)?;
            continue;
        }
        match &frame.message {
            wire::Message::Renew {
                admission: id,
                manifest: hash,
            } => {
                if *id != admission || *hash != manifest {
                    return Err(ServiceError::InvalidRequest);
                }
                admission = admission.checked_add(1).ok_or(ServiceError::Unavailable)?;
                let mut body = issuer.capsule.bytes().to_vec();
                body[32..64].copy_from_slice(&manifest);
                body[64..72].copy_from_slice(&admission.to_be_bytes());
                let until = Instant::now() + Duration::from_secs(1);
                let next_expiry = Instant::now() + lease.saturating_sub(Duration::from_secs(1));
                send_message(
                    issuer,
                    socket,
                    stop,
                    outgoing,
                    reply,
                    0,
                    &wire::Message::Admit(&body),
                    until,
                )?;
                awaiting = Some((outgoing, admission, until, next_expiry));
            }
            wire::Message::OpenIngress { .. } => {
                let result = issuer.open(reply, &frame.message);
                socket.discard_ingress(reply)?;
                match result {
                    Ok((flow, proof)) => {
                        drain_before_publication(
                            issuer,
                            socket,
                            pid,
                            uid,
                            &mut incoming,
                            &mut queued,
                            &mut acks,
                        )?;
                        if !issuer.flows.contains_key(&flow) {
                            send_message(
                                issuer,
                                socket,
                                stop,
                                outgoing,
                                reply,
                                0,
                                &wire::Message::Deny {
                                    status: wire::Status::Deny,
                                    reason: 4,
                                },
                                expires.min(now + Duration::from_secs(1)),
                            )?;
                        } else {
                            let source =
                                issuer.flows.get(&flow).ok_or(ServiceError::Unavailable)?;
                            issuer.authority.subject(&proof, flow, source.tuple)?;
                            let until = issuer
                                .authority
                                .expiry(&proof)
                                .unwrap_or(now + Duration::from_secs(1))
                                .min(expires);
                            send_message(
                                issuer,
                                socket,
                                stop,
                                outgoing,
                                reply,
                                0,
                                &wire::Message::IngressReply {
                                    status: wire::Status::Allow,
                                    required: issuer.record.mode.required(),
                                    flow,
                                    revision: issuer.capsule()?.policy_revision,
                                },
                                until,
                            )?;
                        }
                    }
                    Err(_) => send_message(
                        issuer,
                        socket,
                        stop,
                        outgoing,
                        reply,
                        0,
                        &wire::Message::Deny {
                            status: wire::Status::Unknown,
                            reason: 1,
                        },
                        expires.min(now + Duration::from_secs(1)),
                    )?,
                }
            }
            wire::Message::Authorize(a) => {
                match issuer.authorize(reply, frame.header.object_id, a) {
                    Ok((id, proof)) => {
                        drain_before_publication(
                            issuer,
                            socket,
                            pid,
                            uid,
                            &mut incoming,
                            &mut queued,
                            &mut acks,
                        )?;
                        if !issuer.grants.contains_key(&id) {
                            send_message(
                                issuer,
                                socket,
                                stop,
                                outgoing,
                                reply,
                                0,
                                &wire::Message::Deny {
                                    status: wire::Status::Deny,
                                    reason: 4,
                                },
                                expires.min(now + Duration::from_secs(1)),
                            )?;
                        } else {
                            let g = issuer.grants.get(&id).ok_or(ServiceError::Unavailable)?;
                            let flow = issuer
                                .flows
                                .get(&g.source)
                                .ok_or(ServiceError::Unavailable)?;
                            let receipt = issuer.authority.receipt(&proof, g.source, flow.tuple)?;
                            let fresh = issuer.authority.expiry(&proof).map_or(0, |until| {
                                until
                                    .saturating_duration_since(Instant::now())
                                    .as_nanos()
                                    .min(20_000_000) as u64
                            });
                            let until = g.expires.min(expires);
                            let duration = until.saturating_duration_since(Instant::now());
                            send_message(
                                issuer,
                                socket,
                                stop,
                                outgoing,
                                reply,
                                id,
                                &wire::Message::Grant {
                                    status: wire::Status::Allow,
                                    class: g.class,
                                    required: issuer.record.mode.required(),
                                    grant: id,
                                    flow: g.source,
                                    lease: duration.as_millis().min(1000) as u32,
                                    revision: issuer.capsule()?.policy_revision,
                                    fresh,
                                    receipt,
                                },
                                until,
                            )?;
                        }
                    }
                    Err(_) => send_message(
                        issuer,
                        socket,
                        stop,
                        outgoing,
                        reply,
                        0,
                        &wire::Message::Deny {
                            status: wire::Status::Unknown,
                            reason: 2,
                        },
                        expires.min(now + Duration::from_secs(1)),
                    )?,
                }
            }
            wire::Message::Cancel { target, id, .. } => {
                if *target == 1 && *id < reply {
                    socket.discard_ingress(*id)?;
                }
                let result = cancel_with_channel(issuer, socket, reply, *target, *id);
                let status = if result.is_ok() {
                    wire::CloseStatus::KnownClosed
                } else {
                    wire::CloseStatus::Unknown
                };
                send_message(
                    issuer,
                    socket,
                    stop,
                    outgoing,
                    reply,
                    0,
                    &wire::Message::CloseAck {
                        target: *target,
                        status,
                        id: *id,
                    },
                    expires.min(now + Duration::from_secs(1)),
                )?;
            }
            wire::Message::Probe { .. } => {
                let mut published = false;
                let grant = issuer.service(reply, frame.header.object_id, &frame.message);
                if let Ok(id) = grant {
                    drain_before_publication(
                        issuer,
                        socket,
                        pid,
                        uid,
                        &mut incoming,
                        &mut queued,
                        &mut acks,
                    )?;
                    if let Some(grant) = issuer.services.get(&id) {
                        let until = grant.expires.min(expires);
                        send_message(
                            issuer,
                            socket,
                            stop,
                            outgoing,
                            reply,
                            id,
                            &wire::Message::Grant {
                                status: wire::Status::Allow,
                                class: if grant.selector[0] == 1 { 2 } else { 3 },
                                required: false,
                                grant: id,
                                flow: 0,
                                lease: until
                                    .saturating_duration_since(Instant::now())
                                    .as_millis()
                                    .min(1000) as u32,
                                revision: issuer.capsule()?.policy_revision,
                                fresh: 0,
                                receipt: wire::Receipt {
                                    kind: wire::ReceiptKind::None,
                                    id: 0,
                                },
                            },
                            until,
                        )?;
                        published = true;
                    }
                }
                if !published {
                    send_message(
                        issuer,
                        socket,
                        stop,
                        outgoing,
                        reply,
                        0,
                        &wire::Message::Deny {
                            status: wire::Status::Deny,
                            reason: 3,
                        },
                        expires.min(now + Duration::from_secs(1)),
                    )?;
                }
            }
            _ => return Err(ServiceError::InvalidRequest),
        }
        socket.processed(reply)?;
        while let Some(ack) = acks.pop_front() {
            outgoing = outgoing.checked_add(1).ok_or(ServiceError::Unavailable)?;
            send_cancel_reply(issuer, socket, stop, outgoing, ack, expires)?;
            socket.processed(ack.request)?;
        }
    }
}
fn send_cancel_reply<A: Authority>(
    issuer: &Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    ack: CancelReply,
    expires: Instant,
) -> Result<(), ServiceError> {
    if ack.dns {
        return dns_bundle::send_canceled(
            issuer,
            socket,
            stop,
            sequence,
            ack.request,
            ack.id,
            ack.status,
            expires,
        );
    }
    send_message(
        issuer,
        socket,
        stop,
        sequence,
        ack.request,
        0,
        &wire::Message::CloseAck {
            target: ack.target,
            status: ack.status,
            id: ack.id,
        },
        expires.min(issuer.authority.now() + Duration::from_secs(1)),
    )
}
pub(super) fn reject_unproved_stub(peer: wire::Destination<'_>) -> Result<(), ServiceError> {
    let address = match peer.family {
        4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(peer.bytes).map_err(unavailable)?,
        )),
        6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(peer.bytes).map_err(unavailable)?,
        )),
        _ => return Err(ServiceError::Unsupported),
    };
    if address.is_loopback() {
        return super::resolver_stub::require_protected_policy(
            SocketAddr::new(address, peer.port),
            peer.protocol,
        )
        .map_err(|_| ServiceError::Unsupported);
    }
    if address.is_unspecified() || address.is_multicast() {
        return Err(ServiceError::Unsupported);
    }
    Ok(())
}

/// Planning проверяет только наличие typed codec, не installed authority.
pub(crate) fn consumer_planning_available() -> Result<(), ServiceError> {
    if super::registry::DnsSchema::current().map_err(unavailable)?
        != super::registry::DnsSchema::Codec4
    {
        return Err(ServiceError::Unsupported);
    }
    Ok(())
}
pub(crate) fn consumer_profile_plan(
    intent: &yonik_engine::native_profile::ProfileIntent,
    mode: Mode,
) -> Result<(), ServiceError> {
    ConsumerPlan::derive(intent, mode).map(|_| ())
}
pub(crate) fn consumer_request_plan(
    request: &super::profile_intent::FullProfileRequest,
    mode: Mode,
) -> Result<(), ServiceError> {
    consumer_profile_plan(request.intent(), mode)
}
/// Закрытая DATA selection: один raw VLESS TCP frontier, без provider DNS,
/// observatory, routing chains и transport extensions. Не grant.
struct ConsumerPlan;
impl ConsumerPlan {
    fn derive(
        intent: &yonik_engine::native_profile::ProfileIntent,
        _mode: Mode,
    ) -> Result<Self, ServiceError> {
        consumer_planning_available()?;
        if !intent.is_raw_tcp_consumer_subset() {
            return Err(ServiceError::Unsupported);
        }
        let graph = intent.validate().map_err(unavailable)?;
        let egress = graph.egress();
        if graph.subjects().len() != 1
            || graph.probe().is_some()
            || !graph.selector_sets().is_empty()
            || !graph.ingresses().is_empty()
            || !graph.resources().is_empty()
            || !egress.chains().is_empty()
            || !egress.direct_subjects().is_empty()
            || !egress.resolvers().is_empty()
            // P3 декларирует default system DNS app даже без provider DNS.
            // Exact no-routing/no-DNS predicate не требует USER-DNS query;
            // декларация не является authority и Direct USER4 не включается.
            || egress.system_resolvers().iter().any(|r| r.subject().is_some())
            || egress.physical().len() != 1
            || egress.physical()[0].protocol()
                != yonik_engine::native_profile::TransportProtocol::Tcp
        {
            return Err(ServiceError::Unsupported);
        }
        if let Ok(ip) = egress.physical()[0].host().parse::<std::net::IpAddr>() {
            if !dns_rrset::numeric_ip_allowed(ip) {
                return Err(ServiceError::Unsupported);
            }
        }
        Ok(Self)
    }
    fn image(&self, proof: &super::ImageContract, hash: [u8; 32]) -> Result<(), ServiceError> {
        for scope in [
            super::registry::BootstrapScope::Source,
            super::registry::BootstrapScope::Wire,
            super::registry::BootstrapScope::Release,
        ] {
            proof
                .bootstrap_channel(hash, scope)
                .map_err(unavailable)?
                .ok_or(ServiceError::Unsupported)?
                .check(hash, scope)
                .map_err(unavailable)?;
        }
        Ok(())
    }
}
/// Installed sealed image retained до конца prepare; launch проверяет actual
/// executable/config/capsule отдельно. Эта capability не FlowGrant.
pub(crate) struct ConsumerReady {
    _proof: super::ImageContract,
    _image: [u8; 32],
}
pub(crate) fn require_consumer(
    intent: &yonik_engine::native_profile::ProfileIntent,
    mode: Mode,
    image: &crate::host::BinarySnapshot,
) -> Result<ConsumerReady, ServiceError> {
    prepare_consumer(intent, mode, |plan| {
        if mode == Mode::Local
            && (rustix::process::geteuid().as_raw() == 0
                || rustix::process::geteuid() != rustix::process::getuid())
        {
            return Err(ServiceError::Unsupported);
        }
        if image.engine != yonik_engine::Engine::Xray {
            return Err(ServiceError::Unsupported);
        }
        let proof = image.producer().ok_or(ServiceError::Unsupported)?;
        plan.image(&proof, image.trusted_hash())?;
        Ok(ConsumerReady {
            _proof: proof,
            _image: image.trusted_hash(),
        })
    })
}

pub(crate) fn installed_consumer(
    intent: &yonik_engine::native_profile::ProfileIntent,
    mode: Mode,
) -> Result<(crate::host::BinarySnapshot, ConsumerReady), ServiceError> {
    prepare_consumer(intent, mode, |_| {
        let image = super::registry::TrustedRegistry::system()
            .map_err(unavailable)?
            .full_profile_snapshot()
            .map_err(unavailable)?;
        let ready = require_consumer(intent, mode, &image)?;
        Ok((image, ready))
    })
}

fn prepare_consumer<T>(
    intent: &yonik_engine::native_profile::ProfileIntent,
    mode: Mode,
    load: impl FnOnce(ConsumerPlan) -> Result<T, ServiceError>,
) -> Result<T, ServiceError> {
    let plan = ConsumerPlan::derive(intent, mode)?;
    load(plan)
}

pub(super) fn consumer_resolver_peers(peers: &[std::net::SocketAddr]) -> Result<(), ServiceError> {
    if peers.is_empty()
        || peers
            .iter()
            .any(|p| p.port() != 53 || !dns_rrset::numeric_ip_allowed(p.ip()))
    {
        return Err(ServiceError::Unsupported);
    }
    Ok(())
}
/// Captured DATA availability перед staging. Не выдаёт observation/route/grant.
pub(crate) fn validate_consumer_sources(
    intent: &yonik_engine::native_profile::ProfileIntent,
    sources: &super::profile_intent::FullProfileSources,
    cancel: &crate::Cancellation,
) -> Result<(), ServiceError> {
    use super::profile_intent::{LookupFamily, LookupStep};
    sources.revalidate(intent, cancel).map_err(unavailable)?;
    let graph = intent.validate().map_err(unavailable)?;
    for endpoint in graph
        .egress()
        .physical()
        .iter()
        .filter(|p| p.requires_bootstrap())
    {
        let snapshot = sources.snapshot().ok_or(ServiceError::Unsupported)?;
        // Epoch1 — только локальный DATA plan; его identity никуда не передаётся.
        // Реальный owning invocation заново создаёт binding перед observation.
        let plan = snapshot
            .retained_lookup_data(
                endpoint.host(),
                1,
                LookupFamily::Any,
                super::memory::config_budget(),
            )
            .map_err(unavailable)?;
        match plan.steps().first() {
            Some(LookupStep::Hosts(_)) => {}
            Some(LookupStep::Network(n)) => consumer_resolver_peers(n.peers())?,
            None => return Err(ServiceError::Unsupported),
        }
    }
    sources.revalidate(intent, cancel).map_err(unavailable)
}

#[cfg(test)]
pub(crate) fn fake_consumer_image(hash: [u8; 32]) -> super::ImageContract {
    use super::registry::{BootstrapScope, fake_bootstrap_image};
    fake_bootstrap_image(
        hash,
        &[
            BootstrapScope::Source,
            BootstrapScope::Wire,
            BootstrapScope::Release,
        ],
    )
}

#[cfg(test)]
mod subset_readiness_tests {
    use super::super::registry::{BootstrapScope, fake_bootstrap_image, fake_dns4_image};
    use super::*;
    use yonik_engine::native_profile::ProfileIntent;
    #[test]
    fn subset_captured_network_requires_nonloopback_peer_policy() {
        assert!(consumer_resolver_peers(&["192.0.2.53:53".parse().unwrap()]).is_ok());
        for peers in [
            vec![],
            vec!["127.0.0.53:53".parse().unwrap()],
            vec!["0.0.0.0:53".parse().unwrap()],
            vec!["192.0.2.53:54".parse().unwrap()],
            vec![
                "192.0.2.53:53".parse().unwrap(),
                "127.0.0.53:53".parse().unwrap(),
            ],
        ] {
            assert!(consumer_resolver_peers(&peers).is_err());
        }
    }

    fn intent(host: &str, change: impl FnOnce(&mut serde_json::Value)) -> ProfileIntent {
        let mut value = serde_json::json!({"version":1,"graph":{"outbounds":[{"tag":"b","protocol":"vless","settings":{"vnext":[{"address":host,"port":8443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]}}]}});
        change(&mut value);
        ProfileIntent::decode(&value.to_string()).unwrap()
    }
    #[test]
    fn subset_prepare_dispatch_local_hosts_network_and_system_numeric() {
        for (host, mode) in [
            ("physical.invalid", Mode::Local),
            ("192.0.2.80", Mode::Local),
            ("192.0.2.80", Mode::System),
            ("physical.invalid", Mode::System),
        ] {
            let intent = intent(host, |_| {});
            let scopes = [
                BootstrapScope::Source,
                BootstrapScope::Wire,
                BootstrapScope::Release,
            ];
            let image = fake_bootstrap_image([17; 32], &scopes);
            assert_eq!(
                prepare_consumer(&intent, mode, |plan| {
                    plan.image(&image, [17; 32])?;
                    Ok(7)
                })
                .unwrap(),
                7
            );
            for missing in scopes {
                let proof = fake_bootstrap_image(
                    [17; 32],
                    &scopes
                        .into_iter()
                        .filter(|s| *s != missing)
                        .collect::<Vec<_>>(),
                );
                assert!(
                    prepare_consumer(&intent, mode, |plan| plan.image(&proof, [17; 32])).is_err()
                );
            }
            let plan = ConsumerPlan::derive(&intent, mode).unwrap();
            assert!(plan.image(&image, [18; 32]).is_err());
            assert!(plan.image(&fake_dns4_image([17; 32]), [17; 32]).is_err());
        }
    }
    #[test]
    fn subset_prepare_unsupported_graph_never_loads_image_or_sources() {
        let variants = [
            intent(
                "physical.invalid",
                |v| v["graph"]["outbounds"][0]["streamSettings"] = serde_json::json!({"network":"tcp","security":"tls","tlsSettings":{"serverName":"fixture.invalid"}}),
            ),
            intent("physical.invalid", |v| {
                v["graph"]["outbounds"][0]["mux"] =
                    serde_json::json!({"enabled":true,"concurrency":8})
            }),
            intent("physical.invalid", |v| {
                v["graph"]["dns"] = serde_json::json!({"servers":["192.0.2.53"]})
            }),
            intent("physical.invalid", |v| {
                let mut next = v["graph"]["outbounds"][0].clone();
                next["tag"] = serde_json::json!("c");
                v["graph"]["outbounds"].as_array_mut().unwrap().push(next);
                v["graph"]["outbounds"][0]["proxySettings"] =
                    serde_json::json!({"tag":"c","transportLayer":true});
            }),
        ];
        let imported = yonik_import::import_profiles(
            include_bytes!("../../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
        )
        .unwrap();
        assert_eq!(imported.entries.len(), 7);
        let imported = imported.entries.into_iter().filter_map(|entry| {
            let yonik_import::ProfileEntry::Xray(profile) = entry else {
                panic!("native fixture");
            };
            // Уже Unsupported на typed IPC boundary также не достигает loader.
            ProfileIntent::from_profile(&profile).ok()
        });
        for intent in variants.into_iter().chain(imported) {
            let mut effects = 0;
            assert!(
                prepare_consumer(&intent, Mode::Local, |_| {
                    effects += 1;
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(effects, 0);
        }
    }
}

fn unavailable<T>(_: T) -> ServiceError {
    ServiceError::Unavailable
}
fn proc_text(path: String) -> Result<String, ServiceError> {
    let mut text = String::new();
    File::open(path)
        .map_err(unavailable)?
        .take(16385)
        .read_to_string(&mut text)
        .map_err(unavailable)?;
    if text.len() > 16384 {
        return Err(ServiceError::Unavailable);
    }
    Ok(text)
}
pub(crate) fn process_start(pid: u32) -> Result<u64, ServiceError> {
    proc_text(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .filter(|n| *n != 0)
        .ok_or(ServiceError::Unavailable)
}
fn process_parent(pid: u32) -> Result<u32, ServiceError> {
    proc_text(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(ServiceError::Unavailable)
}
pub(crate) struct Peer {
    bound_launch: Option<LaunchRecord>,
    config_hash: [u8; 32],
    producer: Option<super::registry::ImageContract>,
    image_hash: [u8; 32],
    system_scope: Option<RuntimeScopeStamp>,
    _config: Option<File>,
    proofs: Option<Arc<std::sync::Mutex<ProofInbox>>>,
    pid: u32,
    start: u64,
    uid: u32,
    pidfd: OwnedFd,
    image: File,
    identity: (u64, u64),
    _memory: super::memory::ByteLease,
}
impl Peer {
    fn verified_udp_producer(
        &self,
        record: LaunchRecord,
        capsule: &wire::OwnedCapsule,
    ) -> Result<VerifiedUdpProducer, ServiceError> {
        self.validate()?;
        if self.bound_launch != Some(record) {
            return Err(ServiceError::Unavailable);
        }
        let capsule =
            wire::Capsule::decode(capsule.bytes(), &self.config_hash).map_err(unavailable)?;
        if capsule.mode != record.mode {
            return Err(ServiceError::Unavailable);
        }
        VerifiedUdpProducer::mint(
            self.producer.as_ref().ok_or(ServiceError::Unsupported)?,
            self.image_hash,
            self.config_hash,
            capsule.manifest,
            record,
        )
    }
    pub(crate) fn local(
        record: LaunchRecord,
        child: &tokio::process::Child,
        binary: &crate::BinarySnapshot,
        config: &[u8],
    ) -> Result<Arc<Self>, ServiceError> {
        let uid = rustix::process::geteuid().as_raw();
        if config.is_empty() || config.len() > 65536 {
            return Err(ServiceError::Unsupported);
        }
        let pid = child.id().ok_or(ServiceError::Unavailable)?;
        if record.mode != Mode::Local
            || uid == 0
            || uid != rustix::process::getuid().as_raw()
            || record.owner_pid != std::process::id()
            || record.owner_start != process_start(record.owner_pid)?
            || process_parent(pid)? != record.owner_pid
        {
            return Err(ServiceError::Unsupported);
        }
        let mut peer = Self::capture(pid, process_start(pid)?, uid, binary.trusted_hash())?;
        Arc::get_mut(&mut peer)
            .ok_or(ServiceError::Unavailable)?
            .producer = binary.producer();
        let inner = Arc::get_mut(&mut peer).ok_or(ServiceError::Unavailable)?;
        inner.bound_launch = Some(record);
        let mut retained = File::from(
            rustix::fs::memfd_create(
                "yonik-local-config",
                rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
            )
            .map_err(unavailable)?,
        );
        retained.write_all(config).map_err(unavailable)?;
        rustix::fs::fcntl_add_seals(
            &retained,
            rustix::fs::SealFlags::SEAL
                | rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SHRINK,
        )
        .map_err(unavailable)?;
        inner.config_hash = Sha256::digest(config).into();
        inner._config = Some(retained);
        Ok(peer)
    }
    fn system(
        record: LaunchRecord,
        uid: u32,
        scope: RuntimeScopeStamp,
        delivery: &crate::worker::role_handoff::VerifiedExecDelivery,
    ) -> Result<Arc<Self>, ServiceError> {
        scope.validate().map_err(unavailable)?;
        let (pid, worker_uid, _) = scope.lookup_binding();
        if record.mode != Mode::System
            || uid == 0
            || uid != worker_uid
            || pid != record.child_pid
            || scope.context().5 != record.binding.digest
        {
            return Err(ServiceError::Unsupported);
        }
        let memory = super::memory::config_budget()
            .reserve(64 * 1024)
            .map_err(unavailable)?;
        let (image, config) = delivery.files(record).map_err(unavailable)?;
        let producer = super::registry::TrustedRegistry::system()
            .map_err(unavailable)?
            .producer_for_delivery(delivery, record)
            .map_err(unavailable)?;
        producer
            .check(delivery.image_digest())
            .map_err(unavailable)?;
        let m = image.metadata().map_err(unavailable)?;
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).ok_or(ServiceError::Unsupported)?,
            rustix::process::PidfdFlags::NONBLOCK,
        )
        .map_err(unavailable)?;
        let peer = Arc::new(Self {
            bound_launch: Some(record),
            config_hash: delivery.config_digest(),
            producer: Some(producer),
            image_hash: delivery.image_digest(),
            system_scope: Some(scope),
            _config: Some(config),
            proofs: Some(Arc::new(std::sync::Mutex::new(ProofInbox::new()?))),
            pid,
            start: record.child_start,
            uid,
            pidfd,
            image,
            identity: (m.dev(), m.ino()),
            _memory: memory,
        });
        peer.validate()?;
        Ok(peer)
    }
    fn capture(
        pid: u32,
        start: u64,
        uid: u32,
        expected: [u8; 32],
    ) -> Result<Arc<Self>, ServiceError> {
        let memory = super::memory::config_budget()
            .reserve(64 * 1024)
            .map_err(unavailable)?;
        let id = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or(ServiceError::Unavailable)?;
        let pidfd = rustix::process::pidfd_open(id, rustix::process::PidfdFlags::NONBLOCK)
            .map_err(unavailable)?;
        let image = File::open(format!("/proc/{pid}/exe")).map_err(unavailable)?;
        let before = image.metadata().map_err(unavailable)?;
        let seals = rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SEAL;
        if !before.is_file()
            || before.len() == 0
            || before.len() > crate::BinarySnapshot::MAX_SIZE
            || !rustix::fs::fcntl_get_seals(&image)
                .map_err(unavailable)?
                .contains(seals)
        {
            return Err(ServiceError::Unsupported);
        }
        use std::os::unix::fs::FileExt;
        let mut hash = Sha256::new();
        let mut bytes = [0; 16384];
        let mut offset = 0;
        while offset < before.len() {
            let n = image
                .read_at(
                    &mut bytes[..(before.len() - offset).min(16384) as usize],
                    offset,
                )
                .map_err(unavailable)?;
            if n == 0 {
                return Err(ServiceError::Unavailable);
            }
            hash.update(&bytes[..n]);
            offset += n as u64;
        }
        if <[u8; 32]>::from(hash.finalize()) != expected {
            return Err(ServiceError::Unsupported);
        }
        let peer = Arc::new(Self {
            bound_launch: None,
            config_hash: [0; 32],
            producer: None,
            image_hash: expected,
            system_scope: None,
            _config: None,
            proofs: None,
            pid,
            start,
            uid,
            pidfd,
            image,
            identity: (before.dev(), before.ino()),
            _memory: memory,
        });
        peer.validate()?;
        Ok(peer)
    }
    pub(crate) fn validate(&self) -> Result<(), ServiceError> {
        if let Some(scope) = &self.system_scope {
            scope.validate().map_err(unavailable)?;
        }
        let text = proc_text(format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd()))?;
        let pid = text.lines().find_map(|l| {
            l.strip_prefix("Pid:")
                .and_then(|s| s.trim().parse::<u32>().ok())
        });
        let current = if self.system_scope.is_some() {
            self.image.metadata().map_err(unavailable)?
        } else {
            std::fs::metadata(format!("/proc/{}/exe", self.pid)).map_err(unavailable)?
        };
        if pid != Some(self.pid)
            || process_start(self.pid)? != self.start
            || std::fs::metadata(format!("/proc/{}", self.pid))
                .map_err(unavailable)?
                .uid()
                != self.uid
            || (current.dev(), current.ino()) != self.identity
            || (
                self.image.metadata().map_err(unavailable)?.dev(),
                self.image.metadata().map_err(unavailable)?.ino(),
            ) != self.identity
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
    fn socket(
        self: &Arc<Self>,
        tuple: Tuple,
        provenance: u8,
        request: u64,
        ingress: u16,
    ) -> Result<SocketProof, ServiceError> {
        if (tuple.protocol == 17) != (provenance == 3) {
            return Err(ServiceError::Unsupported);
        }
        self.validate()?;
        if let Some(proofs) = self
            .proofs
            .as_ref()
            .filter(|_| self.system_scope.is_some() || provenance == 3)
        {
            let evidence = proofs
                .lock()
                .map_err(unavailable)?
                .take(request, tuple, ingress)?;
            let proof = SocketProof {
                peer: Arc::clone(self),
                fd: evidence.fd,
                number: None,
                namespace: Some(evidence.namespace),
                facts: evidence.facts,
                tuple,
                provenance,
                udp: evidence.udp,
                _fds: Some(evidence._fds),
            };
            proof.validate()?;
            return Ok(proof);
        }
        // Local не получает association authority из поиска child UDP FD.
        if provenance == 3 {
            return Err(ServiceError::Unsupported);
        }
        let _flow = tuple.owner_flow().map_err(unavailable)?;
        let mut found = None;
        let mut count = 0;
        for entry in std::fs::read_dir(format!("/proc/{}/fd", self.pid)).map_err(unavailable)? {
            count += 1;
            if count > 8192 {
                return Err(ServiceError::Unavailable);
            }
            let entry = entry.map_err(unavailable)?;
            let Some(number) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            let link = std::fs::read_link(entry.path()).map_err(unavailable)?;
            let Some(inode) = link
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            // Ни новых capabilities, ни fallback по UID. EPERM/unsupported => deny.
            let fd = rustix::process::pidfd_getfd(
                &self.pidfd,
                number,
                rustix::process::PidfdGetfdFlags::empty(),
            )
            .map_err(|_| ServiceError::Unsupported)?;
            let facts = match SocketFacts::capture(&fd) {
                Ok(facts) => facts,
                Err(ServiceError::Unsupported) => continue,
                Err(error) => return Err(error),
            };
            if facts.inode != inode || !facts.matches(tuple, provenance) {
                continue;
            }
            if found.is_some() {
                return Err(ServiceError::Unavailable);
            }
            found = Some(SocketProof {
                peer: Arc::clone(self),
                fd,
                number: Some(number),
                namespace: None,
                facts,
                tuple,
                provenance,
                udp: None,
                _fds: None,
            });
        }
        let proof = found.ok_or(ServiceError::Unsupported)?;
        proof.validate()?;
        Ok(proof)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SocketFacts {
    local: SocketAddr,
    remote: Option<SocketAddr>,
    protocol: u8,
    cookie: u64,
    inode: u64,
}
fn endpoint(family: u8, address: [u8; 16], port: u16) -> Result<SocketAddr, ServiceError> {
    match family {
        4 => Ok(SocketAddr::new(
            std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]).into(),
            port,
        )),
        6 => Ok(SocketAddr::new(
            std::net::Ipv6Addr::from(address).into(),
            port,
        )),
        _ => Err(ServiceError::Unavailable),
    }
}
impl SocketFacts {
    fn capture(fd: &impl AsFd) -> Result<Self, ServiceError> {
        use rustix::net::{self, sockopt};
        let protocol = match sockopt::socket_type(fd).map_err(unavailable)? {
            net::SocketType::STREAM => 6,
            net::SocketType::DGRAM => 17,
            _ => return Err(ServiceError::Unsupported),
        };
        if sockopt::socket_protocol(fd).map_err(unavailable)?
            != Some(if protocol == 6 {
                net::ipproto::TCP
            } else {
                net::ipproto::UDP
            })
        {
            return Err(ServiceError::Unsupported);
        }
        let local = SocketAddr::try_from(net::getsockname(fd).map_err(unavailable)?)
            .map_err(unavailable)?;
        let remote = match net::getpeername(fd) {
            Err(rustix::io::Errno::NOTCONN) if protocol == 17 => None,
            other => other.map_err(unavailable)?,
        }
        .map(SocketAddr::try_from)
        .transpose()
        .map_err(unavailable)?;
        let cookie = sockopt::socket_cookie(fd).map_err(unavailable)?;
        let inode = rustix::fs::fstat(fd).map_err(unavailable)?.st_ino;
        Ok(Self {
            local,
            remote,
            protocol,
            cookie,
            inode,
        })
    }
    fn matches(self, tuple: Tuple, provenance: u8) -> bool {
        let Ok(local) = endpoint(tuple.family, tuple.remote, tuple.remote_port) else {
            return false;
        };
        let Ok(remote) = endpoint(tuple.family, tuple.local, tuple.local_port) else {
            return false;
        };
        self.cookie != 0
            && self.inode != 0
            && self.protocol == tuple.protocol
            && self.local == local
            && match provenance {
                2 => self.protocol == 6 && self.remote == Some(remote),
                3 => self.protocol == 17 && self.remote.is_none_or(|peer| peer == remote),
                _ => false,
            }
    }
}
pub(crate) struct SocketProof {
    peer: Arc<Peer>,
    fd: OwnedFd,
    number: Option<i32>,
    namespace: Option<OwnedFd>,
    facts: SocketFacts,
    tuple: Tuple,
    provenance: u8,
    udp: Option<Arc<UdpBinding>>,
    _fds: Option<super::memory::ByteLease>,
}
impl SocketProof {
    fn bind_udp(
        &self,
        source: u64,
        subject: Option<Subject>,
        expiry: Option<Instant>,
    ) -> Result<(), ServiceError> {
        let Some(binding) = &self.udp else {
            return Ok(());
        };
        let now = Instant::now();
        if !binding.live.load(Ordering::Acquire)
            || now >= binding.record.expires
            || (self.peer.system_scope.is_some()
                && (subject
                    .zip(binding.principal)
                    .is_none_or(|(udp, tcp)| !same_principal(udp, tcp))
                    || expiry.is_none_or(|until| {
                        until <= now || until > now + Duration::from_millis(20)
                    })))
            || (self.peer.system_scope.is_none() && (subject.is_some() || expiry.is_some()))
        {
            return Err(ServiceError::Unavailable);
        }
        binding
            .source
            .compare_exchange(0, source, Ordering::AcqRel, Ordering::Acquire)
            .map_err(unavailable)?;
        Ok(())
    }
    fn retire_udp(&self) {
        if let Some(binding) = &self.udp {
            binding.live.store(false, Ordering::Release);
        }
    }
    pub(crate) fn validate_association(
        &self,
        tuple: Tuple,
        original: wire::Destination<'_>,
    ) -> Result<(), ServiceError> {
        let binding = self.udp.as_ref().ok_or(ServiceError::Unsupported)?;
        if self.provenance != 3
            || binding.record.original != Target::copy(original)?
            || tuple.protocol != 17
            || tuple.owner_flow().map_err(unavailable)?
                != self.tuple.owner_flow().map_err(unavailable)?
        {
            return Err(ServiceError::Unsupported);
        }
        self.validate()
    }
    fn validate(&self) -> Result<(), ServiceError> {
        self.peer.validate()?;
        if self.provenance == 3
            && self.udp.as_ref().is_none_or(|b| {
                !b.live.load(Ordering::Acquire) || b.record.packet.tuple != self.tuple
            })
        {
            return Err(ServiceError::Unavailable);
        }
        if let (Some(scope), Some(namespace)) = (&self.peer.system_scope, &self.namespace) {
            let _scratch = if self._fds.is_some() {
                Some(
                    self.peer
                        .proofs
                        .as_ref()
                        .ok_or(ServiceError::Unavailable)?
                        .lock()
                        .map_err(unavailable)?
                        .slots
                        .fds
                        .reserve(1)
                        .map_err(unavailable)?,
                )
            } else {
                None
            };
            let current = yonik_nsfs::socket_namespace::socket_namespace(&self.fd)
                .map_err(|_| ServiceError::Unsupported)?;
            let expected = scope.lookup_binding().2.namespace();
            for fd in [&current, namespace] {
                let s = rustix::fs::fstat(fd).map_err(unavailable)?;
                if (s.st_dev, s.st_ino) != expected {
                    return Err(ServiceError::Unsupported);
                }
            }
            if SocketFacts::capture(&self.fd)? != self.facts
                || !self.facts.matches(self.tuple, self.provenance)
            {
                return Err(ServiceError::Unavailable);
            }
            return self.peer.validate();
        }
        if self.provenance == 3 {
            let _local_scratch = self
                .peer
                .proofs
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .lock()
                .map_err(unavailable)?
                .slots
                .fds
                .reserve(1)
                .map_err(unavailable)?;
            let namespace = self.namespace.as_ref().ok_or(ServiceError::Unsupported)?;
            let current = File::open("/proc/thread-self/ns/net").map_err(unavailable)?;
            let a = current.metadata().map_err(unavailable)?;
            let b = rustix::fs::fstat(namespace).map_err(unavailable)?;
            if (a.dev(), a.ino()) != (b.st_dev, b.st_ino)
                || SocketFacts::capture(&self.fd)? != self.facts
                || !self.facts.matches(self.tuple, 3)
            {
                return Err(ServiceError::Unsupported);
            }
            return self.peer.validate();
        }
        let current = rustix::process::pidfd_getfd(
            &self.peer.pidfd,
            self.number.ok_or(ServiceError::Unsupported)?,
            rustix::process::PidfdGetfdFlags::empty(),
        )
        .map_err(|_| ServiceError::Unsupported)?;
        if SocketFacts::capture(&current)? != self.facts
            || SocketFacts::capture(&self.fd)? != self.facts
            || !self.facts.matches(self.tuple, self.provenance)
        {
            return Err(ServiceError::Unavailable);
        }
        self.peer.validate()
    }
}

#[cfg(test)]
#[path = "native_dns_transport_tests.rs"]
mod dns_transport_tests;
#[cfg(test)]
#[path = "native_profile_channel_tests.rs"]
mod issuer_tests;
#[cfg(test)]
#[path = "native_profile_udp_tests.rs"]
mod udp_tests;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_accepted_socket_and_owner_flow_have_distinct_verified_orientation() {
        let mut local = [0; 16];
        local[..4].copy_from_slice(&[192, 0, 2, 1]);
        let mut remote = [0; 16];
        remote[..4].copy_from_slice(&[127, 0, 0, 1]);
        let tcp = Tuple {
            protocol: 6,
            family: 4,
            local_port: 32001,
            remote_port: 1080,
            local,
            remote,
        };
        let facts = SocketFacts {
            local: "127.0.0.1:1080".parse().unwrap(),
            remote: Some("192.0.2.1:32001".parse().unwrap()),
            protocol: 6,
            cookie: 101,
            inode: 102,
        };
        assert!(facts.matches(tcp, 2));
        let owner = tcp.owner_flow().unwrap();
        assert_eq!(
            (owner.family, owner.local_port, owner.remote_port),
            (2, 32001, 1080)
        );
        let reversed = Tuple {
            local: tcp.remote,
            remote: tcp.local,
            local_port: 1080,
            remote_port: 32001,
            ..tcp
        };
        assert!(!facts.matches(reversed, 2));
        let udp = Tuple {
            protocol: 17,
            remote_port: 49152,
            ..tcp
        };
        let association = SocketFacts {
            local: "127.0.0.1:49152".parse().unwrap(),
            protocol: 17,
            ..facts
        };
        assert!(association.matches(udp, 3));
        assert!(!facts.matches(udp, 3));
        assert!(!association.matches(
            Tuple {
                remote_port: 49153,
                ..udp
            },
            3
        ));
        assert!(
            !SocketFacts {
                cookie: 0,
                ..association
            }
            .matches(udp, 3)
        );
        assert!(!association.matches(udp, 2));
        // Только факты в fixture: production proof дополнительно удерживает FD,
        // проверяет actual child PID/start/image и повторный pidfd_getfd+cookie.
    }
}
