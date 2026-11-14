//! Локальный owning registry optional receipt для private YNKNS004/512.
//! Нет producer/caller activation; не admission authority.
#![allow(dead_code)]
use sha2::{Digest, Sha256};
use std::time::Instant;
use yonik_nsfs::fixed_self_fence::{Receipt, PROFILE_DIGEST, PROGRAM_SHA256};

pub(super) struct Registry {
    receipt: Receipt,
    reference: [u8;32],
    report: [u8;512],
    deadline: Instant,
}
impl Registry {
    // Receipt поступает только от fixed install, frame — от trusted pending producer.
    // Этот объект удерживается producer до закрытия/revoke authenticated pending slot.
    pub(super) fn bind(receipt: Receipt, mut report: [u8;512], deadline: Instant) -> Option<Self> {
        if !receipt.is_current() || Instant::now() >= deadline
            || &report[..8] != b"YNKNS004" || report[184..216] != [0;32] {
            return None;
        }
        let (pid,baseline,current)=receipt.measurements();
        // PID=TID=TGID уже доказано локальным constructor; starttime/invocation — pending custody.
        if report[120..124] != pid.to_be_bytes() || report[152..184] != PROFILE_DIGEST {
            return None;
        }
        // Caller не может задать B/C: всегда перезаписываются owning measurements.
        report[220..224].copy_from_slice(&baseline.to_be_bytes());
        report[224..228].copy_from_slice(&current.to_be_bytes());
        let mut hash=Sha256::new();
        hash.update(b"yonik/fixed-self-fence/v2/local-delta1/receipt\0");
        hash.update(PROGRAM_SHA256);
        hash.update(PROFILE_DIGEST);
        hash.update(report);
        let reference: [u8;32]=hash.finalize().into();
        if reference == [0;32] {return None;}
        report[184..216].copy_from_slice(&reference);
        Some(Self {receipt, reference, report, deadline})
    }
    // Consuming выдача одного exact report. Remote reference остаётся только ссылкой:
    // доверие зависит от authenticated immutable producer + pending custody verifier.
    pub(super) fn consume(self, expected_reference: &[u8;32]) -> Option<[u8;512]> {
        if !self.receipt.is_current() || Instant::now()>=self.deadline
            || &self.reference != expected_reference {return None;}
        Some(self.report)
    }
}
