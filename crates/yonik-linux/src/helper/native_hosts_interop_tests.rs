//! Test-only stdio transport: actual run_issuer, fake Source/route/owner facts.
use super::super::super::super::{Channel, RUNTIME_PACKET, SidebandCredits};
use super::*;
use std::{
    cell::{Cell, RefCell},
    io::{BufRead, Read, Write},
};

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
fn input() -> Result<Vec<u8>, ServiceError> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(140_000)
        .read_line(&mut line)
        .map_err(unavailable)?;
    let value: serde_json::Value = serde_json::from_str(&line).map_err(unavailable)?;
    let text = value["packet"].as_str().ok_or(ServiceError::Unavailable)?;
    if text.len() > 2 * RUNTIME_PACKET
        || text.len() % 2 != 0
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ServiceError::InvalidRequest);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(unavailable))
        .collect()
}
struct Stdio {
    source: Arc<dyn Source>,
    // recvmsg заменён framed stdin; после read drain обязан видеть пустую очередь.
    before_reply: Cell<bool>,
    slots: Arc<SidebandCredits>,
    credits: RefCell<BTreeMap<u64, super::super::super::super::super::memory::ByteLease>>,
}
impl Channel for Stdio {
    fn bootstrap_source(&self, _: LaunchRecord) -> Result<Option<Arc<dyn Source>>, ServiceError> {
        Ok(Some(self.source.clone()))
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
        let b = input()?;
        out[..b.len()].copy_from_slice(&b);
        Ok(Some(b.len()))
    }
    fn setup_write(&self, b: &[u8]) -> Result<bool, ServiceError> {
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
        let b = input()?;
        if b.len() < 128 {
            return Err(ServiceError::InvalidRequest);
        }
        self.credits.borrow_mut().insert(u64_at(&b, 16), credit);
        out[..b.len()].copy_from_slice(&b);
        self.before_reply.set(true);
        Ok(Some(b.len()))
    }
    fn write(&self, b: &[u8]) -> Result<bool, ServiceError> {
        self.before_reply.set(false);
        emit(serde_json::json!({"packet":hex(b)}));
        Ok(true)
    }
    fn pause_until(&self, _: Instant) {
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
    let mode = if case.starts_with("system-") {
        Mode::System
    } else {
        Mode::Local
    };
    let (mut issuer, f) = fixture_digest(mode, "203.0.113.80".parse().unwrap(), 1, true, digest);
    // Исходный USER grant id=1 preseeded на Go стороне; его issuer allocator
    // обязан иметь тот же watermark, иначе permission alias-ится с parent.
    issuer.next_grant = 1;
    emit(
        serde_json::json!({"init":{"launch":hex(&f.launch.encode().unwrap()),"snapshot":hex(&f.asset),"config":"7b7d","path":f.path,"subject":f.subject,
            "user":{"grant":1,"flow":1,"revision":1,"owner_kind":if mode.required(){2}else{0},"owner_id":if mode.required(){77}else{0},"known_ns":if mode.required(){20_000_000}else{0}}}}),
    );
    let source = super::super::super::super::bootstrap_binding::tests::interop_source(
        issuer.capsule.clone(),
        f.launch,
        f.asset.clone(),
        f.reference,
        issuer.budget.clone(),
    );
    let io = Stdio {
        source,
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
    let expected =
        u64::from(std::env::var("YONIK_INTEROP_CASE").as_deref() != Ok("foreign-member"));
    assert_eq!(
        issuer.authority.route_count, expected,
        "ровно один durable physical attempt"
    );
    assert!(
        issuer.authority.live.is_empty(),
        "route custody должна быть retired"
    );
    assert_eq!(issuer.authority.release_attempts, expected as usize);
    emit(
        serde_json::json!({"rust_done":true,"routes":issuer.authority.route_count,"owners":issuer.authority.owner_count}),
    );
}
