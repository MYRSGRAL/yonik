//! Фиксированный fence, не admission API. UNAPPLIED кандидат.
#![allow(unsafe_code)]
use std::{fs::OpenOptions, io::{self, Read}, marker::PhantomData, os::unix::fs::OpenOptionsExt, rc::Rc};

#[repr(C)]
#[derive(Clone, Copy)]
struct Insn { code: u16, jt: u8, jf: u8, k: u32 }
const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn { Insn { code, jt, jf, k } }
// Индексы и переходы доказаны в proposal.md. Нет пользовательской программы.
static PROGRAM: [Insn; 15] = [
    ins(0x20,0,0,4),                   // 0: arch
    ins(0x15,1,0,0xc000003e),          // 1: только native
    ins(0x06,0,0,0x80000000),          // 2: KILL_PROCESS
    ins(0x20,0,0,0),                   // 3: nr
    ins(0x45,0,1,0x40000000),          // 4: x32
    ins(0x06,0,0,0x80000000),          // 5: KILL_PROCESS
    ins(0x15,6,0,308),                 // 6: setns -> 13
    ins(0x15,6,0,435),                 // 7: clone3 -> 14
    ins(0x15,1,0,56),                  // 8: clone -> 10
    ins(0x15,0,2,272),                 // 9: unshare -> 10, прочие -> 12
    ins(0x20,0,0,16),                  // 10: младшие 32 бита args[0]
    ins(0x45,1,0,0x7e020080),          // 11: namespace bits -> 13
    ins(0x06,0,0,0x7fff0000),          // 12: ALLOW
    ins(0x06,0,0,0x00050001),          // 13: ERRNO(EPERM)
    ins(0x06,0,0,0x00050026),          // 14: ERRNO(ENOSYS)
];
#[repr(C)]
struct Program { len: u16, padding: [u8; 6], filter: *const Insn }
const _: () = {
    assert!(std::mem::size_of::<Insn>() == 8);
    assert!(std::mem::align_of::<Insn>() == 4);
    assert!(std::mem::size_of::<Program>() == 16);
    assert!(std::mem::offset_of!(Program, filter) == 8);
};
unsafe extern "C" { static __libc_single_threaded: u8; }

/// Digest точных LE sock_filter bytes; literal сверяется binding.json.
pub const PROGRAM_SHA256: [u8;32] = [0xfe, 0x35, 0x52, 0x7e, 0x65, 0x2e, 0xec, 0x5d, 0x6c, 0xa1, 0x97, 0x99, 0xdc, 0x29, 0x88, 0xde, 0x2b, 0x97, 0x89, 0xc5, 0xb3, 0x9e, 0x30, 0x0b, 0x58, 0x4d, 0xfe, 0x4e, 0x99, 0xb2, 0xea, 0x77];
/// SHA256 canonical profile manifest из binding.json, не caller-provided bool.
pub const PROFILE_DIGEST: [u8;32] = [0xbd, 0x5d, 0x74, 0x74, 0x10, 0x8a, 0x2a, 0x1e, 0x05, 0x17, 0x34, 0xea, 0x4c, 0x90, 0x97, 0xd4, 0x33, 0x80, 0x34, 0x10, 0x25, 0xed, 0x9c, 0xd6, 0x0e, 0x0f, 0x14, 0x42, 0x52, 0x7d, 0x29, 0x83];
const STATUS_LIMIT: usize = 16_384;
#[derive(Debug, PartialEq, Eq)]
struct Status { tgid: u32, tid: u32, tracer: u32, threads: u32, nnp: u32, mode: u32, filters: u32 }
fn unavailable() -> io::Error { io::Error::other("Недостоверное локальное fence evidence") }
fn decimal(bytes: &[u8]) -> io::Result<u32> {
    if bytes.is_empty() { return Err(unavailable()); }
    bytes.iter().try_fold(0u32, |v, b| {
        if !b.is_ascii_digit() { return Err(unavailable()); }
        v.checked_mul(10).and_then(|v| v.checked_add(u32::from(b-b'0'))).ok_or_else(unavailable)
    })
}
fn parse_status(bytes: &[u8]) -> io::Result<Status> {
    if bytes.is_empty() || bytes.len()>STATUS_LIMIT || bytes.last()!=Some(&b'\n') { return Err(unavailable()); }
    let mut fields = [None;7];
    for line in bytes.split(|b| *b==b'\n') {
        let Some(colon)=line.iter().position(|b| *b==b':') else { continue; };
        let slot=match &line[..colon] {
            b"Tgid"=>0, b"Pid"=>1, b"TracerPid"=>2, b"Threads"=>3,
            b"NoNewPrivs"=>4, b"Seccomp"=>5, b"Seccomp_filters"=>6, _=>continue,
        };
        if fields[slot].is_some() { return Err(unavailable()); }
        let value=line[colon+1..].trim_ascii();
        fields[slot]=Some(decimal(value)?);
    }
    let [tgid,tid,tracer,threads,nnp,mode,filters]=fields;
    Ok(Status {tgid:tgid.ok_or_else(unavailable)?,tid:tid.ok_or_else(unavailable)?,
        tracer:tracer.ok_or_else(unavailable)?,threads:threads.ok_or_else(unavailable)?,
        nnp:nnp.ok_or_else(unavailable)?,mode:mode.ok_or_else(unavailable)?,filters:filters.ok_or_else(unavailable)?})
}
fn snapshot() -> io::Result<Status> {
    // Только fixed path. Trusted proc topology — profile premise, fstatfs не аттестация root.
    let mut file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/proc/thread-self/status")?;
    if rustix::fs::fstatfs(&file).map_err(io::Error::from)?.f_type as u64 != 0x9fa0
        || !file.metadata()?.is_file() { return Err(unavailable()); }
    let mut bytes=[0u8;STATUS_LIMIT+1];
    let mut len=0;
    loop {
        if len==bytes.len() { return Err(unavailable()); }
        // EOF обязателен. Даже однобайтные reads ограничены размером; EINTR -> failure.
        let n=file.read(&mut bytes[len..])?;
        if n==0 { return parse_status(&bytes[..len]); }
        len+=n;
    }
}
fn task_ok(s: &Status, pid: u32, tid: u32) -> bool {
    pid==tid && pid!=0 && s.tgid==pid && s.tid==tid && s.tracer==0 && s.threads==1 && s.nnp==1
}
fn delta_ok(before: &Status, after: &Status, pid: u32, tid: u32) -> bool {
    task_ok(before,pid,tid) && task_ok(after,pid,tid)
        && ((before.mode==0 && before.filters==0) || (before.mode==2 && before.filters>0))
        && after.mode==2 && before.filters.checked_add(1)==Some(after.filters)
}
/// Не Clone/Copy/Send/Sync; constructor только после raw0+measured delta1.
/// Drop не снимает fence; remote hash не восстанавливает этот объект.
pub struct Receipt { pid: u32, tid: u32, baseline: u32, current: u32, _local: PhantomData<Rc<()>> }
impl Receipt {
    pub fn is_current(&self) -> bool {
        // SAFETY: fixed no-pointer identity queries; kernel/root trust — profile premise.
        unsafe { libc::getpid() as u32 == self.pid && libc::gettid() as u32 == self.tid }
    }
    /// Только измеренные owning constructor значения, без raw setter.
    pub fn measurements(&self) -> (u32,u32,u32) { (self.pid,self.baseline,self.current) }
}
fn zero(raw: i64) -> io::Result<()> {
    match raw {
        0 => Ok(()),
        -4095..=-1 => Err(io::Error::from_raw_os_error((-raw) as i32)),
        _ => Err(io::Error::other("Неожиданный raw результат fence")),
    }
}
/// Только trusted single-thread worker до payload/engine; не вызывать автоматически.
/// После любой ошибки caller завершает invocation, даже если NNP уже установлен.
pub fn install() -> io::Result<Receipt> {
    // SAFETY: GNU glibc symbol, один байт; libc сохраняет false после создания threads.
    if unsafe { std::ptr::read_volatile(&raw const __libc_single_threaded) } == 0 {
        return Err(io::Error::other("Нет GNU single-thread premise"));
    }
    // SAFETY: fixed identity queries, нет ресурсов или pointers.
    let (pid, tid) = unsafe { (libc::getpid(), libc::gettid()) };
    if pid != tid || pid <= 0 { return Err(io::Error::other("Не исходная task")); }
    let nnp: i64;
    // SAFETY: native prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0), только фиксированные scalars.
    unsafe { core::arch::asm!("syscall", inlateout("rax") 157_i64 => nnp,
        in("rdi") 38_u64, in("rsi") 1_u64, in("rdx") 0_u64,
        in("r10") 0_u64, in("r8") 0_u64, in("r9") 0_u64,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    zero(nnp)?;
    let program = Program { len: 15, padding: [0; 6], filter: PROGRAM.as_ptr() };
    // B после NNP, непосредственно перед единственным install, не PID1 baseline.
    let before=snapshot()?;
    if !task_ok(&before,pid as u32,tid as u32)
        || !((before.mode==0 && before.filters==0) || (before.mode==2 && before.filters>0))
        || before.filters==u32::MAX { return Err(unavailable()); }
    let loaded: i64;
    // SAFETY: repr(C) descriptor и static insns живы до возврата; kernel копирует их
    // синхронно. flags=0, op=SET_MODE_FILTER; нет TSYNC, NEW_LISTENER или FD.
    unsafe { core::arch::asm!("syscall", inlateout("rax") 317_i64 => loaded,
        in("rdi") 1_u64, in("rsi") 0_u64, in("rdx") &program as *const Program,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    zero(loaded)?;
    // Никаких иных install между snapshots; raw0 один недостаточен.
    let after=snapshot()?;
    if !delta_ok(&before,&after,pid as u32,tid as u32) { return Err(unavailable()); }
    Ok(Receipt { pid:pid as u32, tid:tid as u32, baseline:before.filters,
        current:after.filters, _local: PhantomData })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Независимая модель исполнения инструкций, не вызывает install или kernel.
    fn interpret(arch: u32, nr: u32, flags: u64) -> u32 {
        let mut data = [0u8;64];
        data[..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        data[16..24].copy_from_slice(&flags.to_le_bytes());
        let (mut pc, mut a) = (0usize,0u32);
        for _ in 0..PROGRAM.len() {
            let i = PROGRAM[pc];
            match i.code {
                0x20 => { let o=i.k as usize; a=u32::from_le_bytes(data[o..o+4].try_into().expect("load")); pc+=1; }
                0x15 | 0x45 => { let yes=if i.code==0x15 {a==i.k} else {a&i.k!=0}; pc+=1+usize::from(if yes {i.jt} else {i.jf}); }
                0x06 => return i.k,
                _ => panic!("Неизвестный opcode"),
            }
            assert!(pc<PROGRAM.len());
        }
        panic!("Нет termination");
    }
    #[test]
    fn exhaustive_masks_and_unrelated() {
        let bits=[7,17,25,26,27,28,29,30];
        for mask in 0..256u32 {
            let mut flags=0u64;
            for (n,bit) in bits.iter().enumerate() {if mask&(1<<n)!=0 {flags|=1u64<<bit;}}
            for nr in [56,272] {
                let expected=if mask==0 {0x7fff0000} else {0x50001};
                assert_eq!(interpret(0xc000003e,nr,flags),expected);
                assert_eq!(interpret(0xc000003e,nr,flags|(1u64<<63)|0x10000),expected);
            }
            for nr in [39,41,42,44,45,54] {assert_eq!(interpret(0xc000003e,nr,flags),0x7fff0000);}
            assert_eq!(interpret(0xc000003e,308,flags),0x50001);
            assert_eq!(interpret(0xc000003e,435,flags),0x50026);
        }
        for arch in [0,0x40000003,0x4000003e,0xc00000b7] {
            for nr in [20,39,56,272,308,435] {assert_eq!(interpret(arch,nr,0),0x80000000);}
        }
        for nr in [0,39,56,272,308,435] {assert_eq!(interpret(0xc000003e,0x40000000|nr,0),0x80000000);}
        assert_eq!(interpret(0xc000003e,56,1u64<<32),0x7fff0000);
    }
    #[test]
    fn raw_zero_only() {
        assert!(zero(0).is_ok());
        for raw in [-4096,-4095,-38,-1,1,3] {assert!(zero(raw).is_err());}
    }

    #[test]
    fn status_and_delta_fixtures_only() {
        let raw=b"Name:\tworker\nTgid:\t42\nPid:\t42\nTracerPid:\t0\nThreads:\t1\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t7\n";
        let before=parse_status(raw).expect("fixture");
        let mut after=parse_status(raw).expect("fixture");
        // ERRNO(0) install skip: C=B, receipt запрещён.
        assert!(!delta_ok(&before,&after,42,42));
        after.filters=8; assert!(delta_ok(&before,&after,42,42));
        after.tracer=1; assert!(!delta_ok(&before,&after,42,42)); after.tracer=0;
        after.tid=43; assert!(!delta_ok(&before,&after,42,42)); after.tid=42;
        after.nnp=0; assert!(!delta_ok(&before,&after,42,42)); after.nnp=1;
        after.mode=0; assert!(!delta_ok(&before,&after,42,42));
        assert!(parse_status(b"Seccomp_filters: 4294967296\n").is_err());
        assert!(parse_status(b"Seccomp_filters: -1\n").is_err());
        let duplicate=[raw.as_slice(),b"Pid: 42\n"].concat(); assert!(parse_status(&duplicate).is_err());
        assert!(parse_status(&raw[..raw.len()-1]).is_err());
        assert!(parse_status(b"Pid: 42\n").is_err());
        let mut huge=vec![b'x';STATUS_LIMIT+1]; huge[STATUS_LIMIT]=b'\n';
        assert!(parse_status(&huge).is_err());
        let mut overflow=parse_status(raw).expect("fixture"); overflow.filters=u32::MAX;
        assert!(!delta_ok(&overflow,&before,42,42));
    }
}
