//! Test-only stdio transport: actual run_issuer, fake Source/route/owner facts.
use super::super::super::super::{Channel, RUNTIME_PACKET, SidebandCredits};
use super::*;
use std::{
    cell::{Cell, RefCell},
    io::{BufRead, Read, Write},
};
#[path = "native_datagram_interop_tests.rs"]
mod datagram;
#[path = "native_france_interop_tests.rs"]
mod france;

fn emit(value: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{value}").unwrap();
    out.flush().unwrap();
}
fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(b.len() * 2);
    for byte in b {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}
fn input() -> Result<(bool, Vec<u8>), ServiceError> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(140_000)
        .read_line(&mut line)
        .map_err(unavailable)?;
    let value: serde_json::Value = serde_json::from_str(&line).map_err(unavailable)?;
    let physical = value.get("physical").is_some();
    let text = value[if physical { "physical" } else { "packet" }]
        .as_str()
        .ok_or(ServiceError::Unavailable)?;
    if text.len() > 2 * RUNTIME_PACKET
        || text.len() % 2 != 0
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ServiceError::InvalidRequest);
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(unavailable))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((physical, bytes))
}
struct Stdio {
    tcp5: Option<Arc<super::super::super::super::bootstrap_binding::Tcp5Views>>,
    diagnostic: Arc<super::super::super::super::bootstrap_binding::BootstrapBinding>,
    record: LaunchRecord,
    budget: Arc<super::super::super::super::ChannelBudget>,
    inbox: RefCell<std::collections::VecDeque<super::super::super::super::dns_transport::Incoming>>,
    transcript: Option<Arc<dyn super::super::super::super::BootstrapDnsTranscript>>,
    producer: Option<Arc<super::super::super::super::VerifiedBootstrapDnsProducer>>,
    closed: Arc<AtomicUsize>,
    permit: Arc<AtomicBool>,
    no_permit: bool,
    source: Option<Arc<dyn Source>>,
    datagram: Option<Arc<super::super::super::super::dns_datagram::Producer>>,
    datagram_wire: Option<Arc<super::super::super::super::dns_datagram::NetworkWire>>,
    datagram_release: Option<Arc<super::super::super::super::dns_datagram::NetworkRelease>>,
    dns_protocol: u8,
    physical_count: Cell<u16>,
    phases: [Cell<usize>; 128],
    descriptor: RefCell<Option<Vec<u8>>>,
    negotiated: RefCell<Option<wire::dns_v2::Negotiated>>,
    // recvmsg заменён framed stdin; после read drain обязан видеть пустую очередь.
    before_reply: Cell<bool>,
    slots: Arc<SidebandCredits>,
    credits: RefCell<BTreeMap<u64, super::super::super::super::super::memory::ByteLease>>,
}
struct TraceTranscript(
    Arc<dyn super::super::super::super::BootstrapDnsTranscript>,
    Arc<super::super::super::super::bootstrap_binding::BootstrapBinding>,
);
impl Stdio {
    fn note_phase(&self, kind: u16, reply: bool) {
        if kind < 64 {
            let cell = &self.phases[usize::from(kind) + usize::from(reply) * 64];
            cell.set(cell.get().max(self.budget.dynamic.used()));
        }
    }
    fn phase_report(&self) -> serde_json::Value {
        let rows = self
            .phases
            .iter()
            .enumerate()
            .filter(|(_, v)| v.get() != 0)
            .map(|(i, v)| serde_json::json!({"kind":i%64,"reply":i>=64,"held":v.get()}))
            .collect::<Vec<_>>();
        serde_json::json!({"phases":rows,"planner_peak":crate::helper::profile_intent::resolver_plan_audit_peak(),"parser_scratch":super::super::super::super::dns_rrset::SCRATCH,"parser_peak":super::super::super::super::dns_rrset::parser_audit_peak()})
    }
}
impl super::super::super::super::BootstrapDnsTranscript for TraceTranscript {
    fn observed(
        &self,
        launch: LaunchRecord,
        receipt: super::super::super::super::BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError> {
        eprintln!(
            "interop binding: {}",
            super::super::super::super::bootstrap_binding::tests::interop_status(
                &self.1,
                receipt.binding.query
            )
        );
        let result = self.0.observed(launch, receipt);
        eprintln!("interop transcript observed: {result:?}");
        result
    }
}
impl Channel for Stdio {
    fn bootstrap_tcp5(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<super::super::super::super::bootstrap_binding::Tcp5Views>>, ServiceError>
    {
        Ok(self.tcp5.clone())
    }
    fn bootstrap_datagram_wire(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<super::super::super::super::dns_datagram::NetworkWire>>, ServiceError>
    {
        Ok(self.datagram_wire.clone())
    }
    fn bootstrap_datagram_release(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<super::super::super::super::dns_datagram::NetworkRelease>>, ServiceError>
    {
        Ok(self.datagram_release.clone())
    }
    fn bootstrap_datagram_producer(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<super::super::super::super::dns_datagram::Producer>>, ServiceError> {
        Ok(self.datagram.clone())
    }
    fn bootstrap_dns_transcript(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<dyn super::super::super::super::BootstrapDnsTranscript>>, ServiceError>
    {
        Ok(self.transcript.clone().map(|v| {
            Arc::new(TraceTranscript(v, self.diagnostic.clone()))
                as Arc<dyn super::super::super::super::BootstrapDnsTranscript>
        }))
    }
    fn bootstrap_dns_producer(
        &self,
        _: LaunchRecord,
    ) -> Result<Option<Arc<super::super::super::super::VerifiedBootstrapDnsProducer>>, ServiceError>
    {
        Ok(self.producer.clone())
    }
    fn take_dns(
        &self,
    ) -> Result<Option<super::super::super::super::dns_transport::Incoming>, ServiceError> {
        Ok(self.inbox.borrow_mut().pop_front())
    }
    fn bootstrap_source(&self, _: LaunchRecord) -> Result<Option<Arc<dyn Source>>, ServiceError> {
        Ok(self.source.clone())
    }
    fn dns_slots(&self) -> Result<Arc<SidebandCredits>, ServiceError> {
        Ok(self.slots.clone())
    }
    fn take_dns_credit(
        &self,
        seq: u64,
    ) -> Result<super::super::super::super::super::memory::ByteLease, ServiceError> {
        self.credits
            .borrow_mut()
            .remove(&seq)
            .ok_or(ServiceError::Unavailable)
    }
    fn processed(&self, seq: u64) -> Result<(), ServiceError> {
        self.credits.borrow_mut().remove(&seq);
        Ok(())
    }
    fn setup_read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        let (physical, b) = input()?;
        if physical {
            return Err(ServiceError::InvalidRequest);
        }
        out[..b.len()].copy_from_slice(&b);
        *self.descriptor.borrow_mut() = Some(b.clone());
        Ok(Some(b.len()))
    }
    fn setup_write(&self, b: &[u8]) -> Result<bool, ServiceError> {
        // Только actual descriptor/ACK противоположных actors, без ACK fixture.
        let descriptor = self.descriptor.borrow();
        let d = descriptor.as_ref().ok_or(ServiceError::InvalidRequest)?;
        *self.negotiated.borrow_mut() = Some(
            if self.datagram.is_some() {
                wire::dns_v2::Negotiated::accept_datagram(d, b, self.record, [(0, 0); 2])
            } else {
                wire::dns_v2::Negotiated::accept(d, b, self.record, [(0, 0); 2])
            }
            .map_err(unavailable)?,
        );
        self.before_reply.set(false);
        emit(serde_json::json!({"packet":hex(b)}));
        Ok(true)
    }
    fn read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        if self.before_reply.get() {
            return Ok(None);
        }
        let credit = self.slots.pending.reserve(1).map_err(unavailable)?;
        let (physical, b) = input()?;
        if physical {
            let raw: [u8; 192] = b.try_into().map_err(|_| ServiceError::InvalidRequest)?;
            // Fake kernel facts принадлежат разным sockets, не полям child record.
            let index = self.physical_count.get();
            if index >= 2 {
                return Err(ServiceError::Busy);
            }
            self.physical_count.set(index + 1);
            let facts = super::super::super::super::dns_transport::fake_facts(
                std::net::SocketAddr::from(([192, 0, 2, 10], 32001 + index)),
                "192.0.2.53:53".parse().unwrap(),
                self.dns_protocol,
                (4, 5),
            )
            .with_cookie(101 + u64::from(index))
            .with_test_mark(if self.record.mode.required() { 42 } else { 0 });
            let incoming = super::super::super::super::dns_transport::Incoming::fake(
                raw,
                self.negotiated
                    .borrow()
                    .as_ref()
                    .ok_or(ServiceError::Unavailable)?,
                &self.slots,
                &self.budget.dynamic,
                None,
                Arc::new(std::sync::Mutex::new(facts)),
                Arc::new(AtomicBool::new(true)),
                self.closed.clone(),
                || {},
            )
            .inspect_err(|e| {
                eprintln!(
                    "interop virtual PhysicalBind: {e:?}; budget={}",
                    self.budget.dynamic.used()
                )
            })?;
            self.inbox.borrow_mut().push_back(incoming);
            self.before_reply.set(true);
            return Ok(None);
        }
        if b.len() < 128 {
            return Err(ServiceError::InvalidRequest);
        }
        self.note_phase(u16::from_be_bytes([b[10], b[11]]), false);
        if b[10..12] == 55u16.to_be_bytes() {
            eprintln!(
                "interop Acquire Source budget: {}",
                super::super::super::super::bootstrap_binding::tests::interop_status(
                    &self.diagnostic,
                    u64_at(&b[128..], 16)
                )
            );
        }
        if b[10..12] == 40u16.to_be_bytes() && b.get(265) == Some(&1) {
            let body = &b[128..];
            eprintln!(
                "interop Publish budget: {}",
                super::super::super::super::bootstrap_binding::tests::interop_status(
                    &self.diagnostic,
                    u64_at(body, 12)
                )
            );
            let q = usize::from(u16::from_be_bytes(body[108..110].try_into().unwrap()));
            let r = usize::from(u16::from_be_bytes(body[110..112].try_into().unwrap()));
            eprintln!(
                "interop strict parser: {:?}; dynamic used={}",
                super::super::super::super::dns_rrset::verify_bootstrap_capture(
                    &body[144 + q..144 + q + r],
                    &body[144 + q + r..],
                    &body[144..144 + q],
                    1,
                    9,
                    1232
                ),
                self.budget.dynamic.used()
            );
        }
        if self.no_permit && b[10..12] == 35u16.to_be_bytes() && b.get(130) == Some(&2) {
            self.permit.store(false, Ordering::Release);
        }
        self.credits.borrow_mut().insert(u64_at(&b, 16), credit);
        out[..b.len()].copy_from_slice(&b);
        self.before_reply.set(true);
        Ok(Some(b.len()))
    }
    fn write(&self, b: &[u8]) -> Result<bool, ServiceError> {
        self.note_phase(u16::from_be_bytes([b[10], b[11]]), true);
        self.before_reply.set(false);
        emit(serde_json::json!({"packet":hex(b)}));
        Ok(true)
    }
    fn pause_until(&self, _: Instant) {
        if !self.inbox.borrow().is_empty() {
            return;
        }
        panic!("interop bridge must not wait on OS");
    }
}
#[test]
fn pure_stateful_hosts_stdio_bridge() {
    if std::env::var_os("YONIK_PURE_INTEROP").is_none() {
        return;
    }
    let digest: [u8; 32] = Sha256::digest(b"{}").into();
    let case = std::env::var("YONIK_INTEROP_CASE").unwrap_or_default();
    if case.contains("france-") {
        france::run(&case);
        return;
    }
    if case.contains("udp-hosts-") || case.contains("udp-network-") {
        datagram::run(&case);
        return;
    }
    let network = case.starts_with("network-");
    let mode = if case.starts_with("system-") {
        Mode::System
    } else {
        Mode::Local
    };
    let (mut issuer, f) = fixture_digest(
        mode,
        "203.0.113.80".parse().unwrap(),
        if network { 2 } else { 1 },
        true,
        digest,
    );
    // Исходный USER grant id=1 preseeded на Go стороне; его issuer allocator
    // обязан иметь тот же watermark, иначе permission alias-ится с parent.
    issuer.next_grant = 1;
    emit(
        serde_json::json!({"init":{"launch":hex(&f.launch.encode().unwrap()),"snapshot":hex(&f.asset),"config":"7b7d","path":f.path,"subject":f.subject,
            "user":{"grant":1,"flow":1,"revision":1,"owner_kind":if mode.required(){2}else{0},"owner_id":if mode.required(){77}else{0},"known_ns":if mode.required(){20_000_000}else{0}}}}),
    );
    let scopes = if network {
        vec![
            crate::helper::registry::BootstrapScope::Source,
            crate::helper::registry::BootstrapScope::Wire,
            crate::helper::registry::BootstrapScope::Release,
        ]
    } else {
        vec![crate::helper::registry::BootstrapScope::Source]
    };
    let binding = super::super::super::super::bootstrap_binding::tests::interop_binding(
        issuer.capsule.clone(),
        f.launch,
        f.asset.clone(),
        f.reference,
        issuer.budget.clone(),
        &scopes,
        issuer.authority.now(),
    );
    let closed = Arc::new(AtomicUsize::new(0));
    let io = Stdio {
        tcp5: None,
        diagnostic: binding.clone(),
        source: binding.source(),
        datagram: None,
        datagram_wire: None,
        datagram_release: None,
        dns_protocol: 17,
        physical_count: Cell::new(0),
        phases: std::array::from_fn(|_| Cell::new(0)),
        descriptor: RefCell::new(None),
        negotiated: RefCell::new(None),
        record: f.launch,
        budget: issuer.budget.clone(),
        inbox: Default::default(),
        transcript: binding.transcript(),
        producer: binding.release(),
        closed: closed.clone(),
        permit: issuer.authority.bootstrap_permit_live.clone(),
        no_permit: case == "network-no-permit",
        before_reply: Cell::new(false),
        slots: SidebandCredits::new(),
        credits: Default::default(),
    };
    let _closed = run_issuer(
        &mut issuer,
        &io,
        8,
        997,
        &AtomicBool::new(false),
        &AtomicBool::new(false),
    );
    assert_eq!(issuer.authority.owner_count, 0);
    let expected = if network {
        if case == "network-positive" { 5 } else { 2 }
    } else {
        u64::from(case != "foreign-member")
    };
    assert_eq!(
        issuer.authority.route_count, expected,
        "ровно один durable physical attempt"
    );
    if !network {
        assert!(
            issuer.authority.live.is_empty(),
            "route custody должна быть retired"
        );
        assert_eq!(issuer.authority.release_attempts, expected as usize);
    }
    if !issuer.unknown {
        assert_eq!(
            closed.load(Ordering::Acquire),
            usize::from(network && case != "network-no-permit")
        );
    }
    emit(
        serde_json::json!({"rust_done":true,"routes":issuer.authority.route_count,"owners":issuer.authority.owner_count,"retained_routes":issuer.authority.live,"release_attempts":issuer.authority.release_attempts,"contexts":issuer.dns.count(),"services":issuer.services.keys().copied().collect::<Vec<_>>(),"unknown":issuer.unknown,"receiver_consumed_closes":closed.load(Ordering::Acquire)}),
    );
}
