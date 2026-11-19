//! Фиксированный seccomp-профиль автономного worker. Устанавливает setpriv.

use super::WorkerSupervisorError as Error;
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

const AUDIT_X86_64: u32 = 0xc000_003e;
const AUDIT_AARCH64: u32 = 0xc000_00b7;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SYSCALL: u32 = 0;
const ARCH: u32 = 4;
const KILL_PROCESS: u32 = 0x8000_0000;
const ALLOW: u32 = 0x7fff_0000;
const EPERM: u32 = 0x0005_0001;
const ENOSYS: u32 = 0x0005_0026;
const CLONE_NAMESPACES: u32 = 0x7e02_0000;
const PROT_WRITE: u32 = 2;
const PROT_EXEC: u32 = 4;
const SHM_EXEC: u32 = 0o100000;
const SUID_SGID: u32 = 0o6000;
// AF_UNIX, AF_INET, AF_INET6 и AF_NETLINK по Linux UAPI.
const SOCKET_FAMILIES: [u32; 4] = [1, 2, 10, 16];

struct Abi {
    audit: u32,
    clone: u32,
    unshare: u32,
    setns: u32,
    socket: u32,
    socketpair: u32,
    mmap: u32,
    mprotect: u32,
    pkey_mprotect: u32,
    shmat: u32,
    personality: u32,
    chmod: Option<u32>,
    fchmod: u32,
    fchmodat: u32,
}

// Linux syscall UAPI для двух 64-битных ABI. clone3, io_uring и fchmodat2
// имеют общие номера в обоих ABI.
const X86_64: Abi = Abi {
    audit: AUDIT_X86_64,
    clone: 56,
    unshare: 272,
    setns: 308,
    socket: 41,
    socketpair: 53,
    mmap: 9,
    mprotect: 10,
    pkey_mprotect: 329,
    shmat: 30,
    personality: 135,
    chmod: Some(90),
    fchmod: 91,
    fchmodat: 268,
};
const AARCH64: Abi = Abi {
    audit: AUDIT_AARCH64,
    clone: 220,
    unshare: 97,
    setns: 268,
    socket: 198,
    socketpair: 199,
    mmap: 222,
    mprotect: 226,
    pkey_mprotect: 288,
    shmat: 196,
    personality: 92,
    chmod: None,
    fchmod: 52,
    fchmodat: 53,
};
const CLONE3: u32 = 435;
const IO_URING: [u32; 3] = [425, 426, 427];
const FCHMODAT2: u32 = 452;

type Instruction = [u8; 8];

const fn instruction(code: u16, yes: u8, no: u8, value: u32) -> Instruction {
    let [code_0, code_1] = code.to_ne_bytes();
    let [a, b, c, d] = value.to_ne_bytes();
    [code_0, code_1, yes, no, a, b, c, d]
}

fn load(offset: u32) -> Instruction {
    instruction(0x20, 0, 0, offset)
}

fn mask(value: u32) -> Instruction {
    instruction(0x54, 0, 0, value)
}

fn equal(value: u32, yes: u8, no: u8) -> Instruction {
    instruction(0x15, yes, no, value)
}

fn any_bit(value: u32, yes: u8, no: u8) -> Instruction {
    instruction(0x45, yes, no, value)
}

fn verdict(value: u32) -> Instruction {
    instruction(0x06, 0, 0, value)
}

fn argument(index: u32) -> Instruction {
    // Младшие 32 бита seccomp_data.args[index] в поддерживаемых LE ABI.
    load(16 + 8 * index)
}

fn on_syscall(
    program: &mut Vec<Instruction>,
    number: u32,
    body: &[Instruction],
) -> Result<(), Error> {
    program.push(equal(
        number,
        0,
        u8::try_from(body.len()).map_err(|_| Error::UnitProofGap)?,
    ));
    program.extend_from_slice(body);
    Ok(())
}

fn deny_bits(index: u32, bits: u32) -> [Instruction; 4] {
    [
        argument(index),
        any_bit(bits, 0, 1),
        verdict(EPERM),
        verdict(ALLOW),
    ]
}

fn program(abi: Abi) -> Result<Vec<Instruction>, Error> {
    let mut instructions = vec![
        load(ARCH),
        equal(abi.audit, 1, 0),
        verdict(KILL_PROCESS),
        load(SYSCALL),
    ];
    if abi.audit == AUDIT_X86_64 {
        instructions.extend([any_bit(X32_SYSCALL_BIT, 0, 1), verdict(KILL_PROCESS)]);
    }
    for number in [abi.unshare, abi.setns].into_iter().chain(IO_URING) {
        on_syscall(&mut instructions, number, &[verdict(EPERM)])?;
    }
    // libc и Go при ENOSYS используют clone, где можно проверить flags.
    on_syscall(&mut instructions, CLONE3, &[verdict(ENOSYS)])?;
    on_syscall(
        &mut instructions,
        abi.clone,
        &deny_bits(0, CLONE_NAMESPACES),
    )?;

    let mut socket = vec![argument(0)];
    for family in SOCKET_FAMILIES {
        socket.extend([equal(family, 0, 1), verdict(ALLOW)]);
    }
    socket.push(verdict(EPERM));
    for number in [abi.socket, abi.socketpair] {
        on_syscall(&mut instructions, number, &socket)?;
    }

    on_syscall(
        &mut instructions,
        abi.mmap,
        &[
            argument(2),
            mask(PROT_WRITE | PROT_EXEC),
            equal(PROT_WRITE | PROT_EXEC, 0, 1),
            verdict(EPERM),
            verdict(ALLOW),
        ],
    )?;
    for number in [abi.mprotect, abi.pkey_mprotect] {
        on_syscall(&mut instructions, number, &deny_bits(2, PROT_EXEC))?;
    }
    on_syscall(&mut instructions, abi.shmat, &deny_bits(2, SHM_EXEC))?;
    on_syscall(
        &mut instructions,
        abi.personality,
        &[
            argument(0),
            equal(u32::MAX, 0, 1),
            verdict(ALLOW),
            verdict(EPERM),
        ],
    )?;
    for number in abi.chmod.into_iter().chain([abi.fchmod]) {
        on_syscall(&mut instructions, number, &deny_bits(1, SUID_SGID))?;
    }
    for number in [abi.fchmodat, FCHMODAT2] {
        on_syscall(&mut instructions, number, &deny_bits(2, SUID_SGID))?;
    }
    instructions.push(verdict(ALLOW));
    Ok(instructions)
}

pub(super) fn write_filter(path: &Path) -> Result<(), Error> {
    let abi = if cfg!(all(target_arch = "x86_64", target_pointer_width = "64")) {
        X86_64
    } else if cfg!(all(
        target_arch = "aarch64",
        target_endian = "little",
        target_pointer_width = "64"
    )) {
        AARCH64
    } else {
        return Err(Error::UnitProofGap);
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    for instruction in program(abi)? {
        file.write_all(&instruction)
            .map_err(|_| Error::Unavailable)?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(super) fn filter_count(status: &str) -> Result<u32, Error> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    let count = field("Seccomp_filters:")
        .and_then(|value| value.parse().ok())
        .ok_or(Error::Untrusted)?;
    match (field("Seccomp:"), count) {
        (Some("0"), 0) | (Some("2"), 1..) => Ok(count),
        _ => Err(Error::Untrusted),
    }
}
