//! Safe DATA producer: единственный receipt поступает от fixed install.
use super::{WorkerError, fixed_fence_receipt::Registry};
use sha2::{Digest, Sha256};
use std::time::Instant;
use yonik_nsfs::fixed_self_fence::{PROFILE_DIGEST, PROGRAM_SHA256};

/// Move-only локальное состояние после owning install; raw bytes его не создают.
pub(super) struct ProducedV4 {
    report: [u8; 512],
    deadline: Instant,
}
impl ProducedV4 {
    pub(super) fn produce(
        request: &[u8; 128],
        helper_pid: u32,
        deadline: Instant,
    ) -> Result<Self, WorkerError> {
        validate_request(request)?;
        if Instant::now() >= deadline || helper_pid == 0 {
            return Err(WorkerError::Timeout);
        }
        let task_pid = std::process::id();
        let task_start = start(task_pid)?;
        let server_start = start(helper_pid)?;
        let receipt = yonik_nsfs::fixed_self_fence::install().map_err(|_| WorkerError::Peer)?;
        let old = yonik_nsfs::kernel_probe::observe().map_err(|_| WorkerError::Peer)?;
        let fixed = yonik_nsfs::kernel_probe_v2::observe_fixed().map_err(|_| WorkerError::Peer)?;
        let mut vector = [1u32; 19];
        if (old.unshare, old.setns, old.clone3) != (1, 1, 38) {
            return Err(WorkerError::Peer);
        }
        vector[..3].copy_from_slice(&[1, 1, 38]);
        let names = [
            "cgroup", "ipc", "net", "mount", "pid", "user", "uts", "time",
        ];
        if fixed.len() != names.len() {
            return Err(WorkerError::Peer);
        }
        let mut seen = [false; 8];
        for item in fixed {
            let i = names
                .iter()
                .position(|n| *n == item.namespace)
                .ok_or(WorkerError::Peer)?;
            if std::mem::replace(&mut seen[i], true)
                || item.unshare_errno != 1
                || item.clone_selector_errno != 1
            {
                return Err(WorkerError::Peer);
            }
        }
        let mut report = [0; 512];
        report[..120].copy_from_slice(&request[..120]);
        report[..8].copy_from_slice(b"YNKNS004");
        for (offset, value) in [(120, task_pid), (136, helper_pid), (216, 2)] {
            report[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [(128, task_start), (144, server_start)] {
            report[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        report[152..184].copy_from_slice(&PROFILE_DIGEST);
        let (_, baseline, current) = receipt.measurements();
        report[220..224].copy_from_slice(&baseline.to_be_bytes());
        report[224..228].copy_from_slice(&current.to_be_bytes());
        for (i, value) in vector.iter().enumerate() {
            report[232 + i * 4..236 + i * 4].copy_from_slice(&value.to_be_bytes());
        }
        let mut hash = Sha256::new();
        hash.update(b"yonik/fixed-self-fence/v2/local-delta1/receipt\0");
        hash.update(PROGRAM_SHA256);
        hash.update(PROFILE_DIGEST);
        hash.update(report);
        let reference: [u8; 32] = hash.finalize().into();
        let registry = Registry::bind(receipt, report, deadline).ok_or(WorkerError::Peer)?;
        let report = registry.consume(&reference).ok_or(WorkerError::Peer)?;
        Ok(Self { report, deadline })
    }
    pub(super) fn report(&self) -> Result<&[u8; 512], WorkerError> {
        if Instant::now() >= self.deadline {
            return Err(WorkerError::Timeout);
        }
        Ok(&self.report)
    }
    pub(super) fn matches(
        &self,
        binding: &super::role_handoff::Binding,
    ) -> Result<(), WorkerError> {
        self.report()?;
        let b = &self.report;
        if b[8..40] != binding.nonce
            || b[40..72] != binding.digest
            || b[72..88] != binding.session
            || b[88..96] != binding.generation.to_be_bytes()
            || b[96..112] != binding.invocation
            || b[112..120] != binding.epoch.to_be_bytes()
            || b[136..140] != binding.server_pid.to_be_bytes()
            || b[144..152] != binding.server_start.to_be_bytes()
        {
            return Err(WorkerError::Peer);
        }
        Ok(())
    }
}
fn start(pid: u32) -> Result<u64, WorkerError> {
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| WorkerError::Peer)?;
    stat.rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .filter(|n| *n != 0)
        .ok_or(WorkerError::Peer)
}
fn validate_request(r: &[u8; 128]) -> Result<(), WorkerError> {
    if &r[..8] != b"YNKCH004"
        || r[8..40] == [0; 32]
        || r[40..72] == [0; 32]
        || r[72..88] == [0; 16]
        || r[88..96] == [0; 8]
        || r[96..112] == [0; 16]
        || r[112..120] == [0; 8]
        || r[120..] != [0; 8]
    {
        return Err(WorkerError::Protocol);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v4_request_rejects_zero_fields_and_reserved() {
        let mut r = [1; 128];
        r[..8].copy_from_slice(b"YNKCH004");
        r[120..].fill(0);
        assert!(validate_request(&r).is_ok());
        for (a, b) in [(8, 40), (40, 72), (72, 88), (88, 96), (96, 112), (112, 120)] {
            let mut bad = r;
            bad[a..b].fill(0);
            assert!(validate_request(&bad).is_err());
        }
        r[127] = 1;
        assert!(validate_request(&r).is_err());
    }
}
