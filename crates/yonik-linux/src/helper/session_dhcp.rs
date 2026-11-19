use super::{
    ARPHRD_ETHER, Backend, IFF_LOOPBACK, IFF_UP, Journal, LinuxTopology, PublicBlockPolicy,
    PublicPolicyPhase, SafetyTask, diagnostic_result, fresh_cancel,
};
use crate::{
    Cancellation,
    helper::dhcp_networkd::DhcpNetworkdLease,
    managed_network::nft::{NftError, NftExecutor},
    network::RenewedDhcpAddress,
};
use std::{
    collections::BTreeSet,
    num::NonZeroU32,
    sync::{Mutex, TryLockError, Weak},
    time::Duration,
};

const ADMISSION_TIMEOUT: Duration = Duration::from_millis(450);
const REFRESH_INTERVAL: Duration = Duration::from_millis(300);
const REFRESH_BUDGET: Duration = Duration::from_millis(550);
const MAX_CANDIDATES: usize = 8;

pub(super) struct DhcpRefresh {
    _task: SafetyTask,
    initial_lease: u64,
}

pub(super) async fn select_policy(
    baseline: &LinuxTopology,
    policy: &PublicBlockPolicy,
    cancel: &mut Cancellation,
) -> Option<(NonZeroU32, u64, PublicBlockPolicy)> {
    let ipv4: BTreeSet<_> = baseline
        .addresses
        .iter()
        .filter(|address| address.family == 2 && address.scope == 0)
        .map(|address| address.index)
        .collect();
    let candidates: Vec<_> = baseline
        .links
        .iter()
        .filter(|link| {
            link.link_type == ARPHRD_ETHER
                && link.flags & (IFF_UP | IFF_LOOPBACK) == IFF_UP
                && ipv4.contains(&link.index)
                && !matches!(link.kind.as_deref(), Some(b"tun" | b"wireguard"))
        })
        .filter_map(|link| NonZeroU32::new(link.index))
        .take(MAX_CANDIDATES + 1)
        .collect();
    if candidates.len() > MAX_CANDIDATES {
        return None;
    }
    tokio::time::timeout(ADMISSION_TIMEOUT, async {
        let mut selected = None;
        for index in candidates {
            if let Ok(lease) = diagnostic_result(
                "dhcp_admission",
                DhcpNetworkdLease::capture(index, cancel).await,
            ) {
                if let (Some(path), Ok(bound)) =
                    (lease.path(), policy.clone().with_dhcp_renewal_rule(&lease))
                {
                    // Текущий формат политики хранит одно правило. При двух
                    // проверенных лизингах выбор зависел бы от порядка линков.
                    if selected.replace((index, path.acquired, bound)).is_some() {
                        return None;
                    }
                }
            }
        }
        selected
    })
    .await
    .ok()
    .flatten()
}

pub(super) async fn check_policy(nft: &mut NftExecutor, policy: &PublicBlockPolicy) -> bool {
    diagnostic_result(
        "dhcp_nft_preflight",
        tokio::time::timeout(ADMISSION_TIMEOUT, nft.check_public_policy(policy))
            .await
            .unwrap_or(Err(NftError::Timeout)),
    )
    .is_ok()
}

pub(super) fn spawn_refresh(
    backend: Weak<Mutex<Backend>>,
    runtime: &tokio::runtime::Handle,
    epoch: u64,
    index: NonZeroU32,
    initial_lease: u64,
) -> DhcpRefresh {
    let task_runtime = runtime.clone();
    let task = runtime.spawn(async move {
        let mut ticks = tokio::time::interval(REFRESH_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let backend = backend.clone();
            let runtime = task_runtime.clone();
            if !matches!(
                tokio::task::spawn_blocking(move || {
                    let Some(backend) = backend.upgrade() else {
                        return false;
                    };
                    let backend = match backend.try_lock() {
                        Ok(backend) => backend,
                        Err(TryLockError::WouldBlock) => return true,
                        Err(TryLockError::Poisoned(_)) => return false,
                    };
                    if backend.epoch != epoch
                        || backend.active.as_ref().is_none_or(|active| {
                            active.dhcp_refresh.is_none() || active.exit_watch.0.is_finished()
                        })
                    {
                        return false;
                    }
                    runtime.block_on(async {
                        let _tick =
                            tokio::time::timeout(REFRESH_BUDGET, backend.refresh_dhcp(index)).await;
                    });
                    true
                })
                .await,
                Ok(true)
            ) {
                break;
            }
        }
    });
    DhcpRefresh {
        _task: SafetyTask(task),
        initial_lease,
    }
}

impl Backend {
    pub(super) async fn verified_dhcp_address(
        &self,
        cancel: &mut Cancellation,
    ) -> Option<RenewedDhcpAddress> {
        let refresh = self.active.as_ref()?.dhcp_refresh.as_ref()?;
        let (journal, _) = self.dhcp_policy()?;
        let PublicPolicyPhase::Stable { policy } = journal.public_policy()?.phase() else {
            return None;
        };
        let index = policy.dhcp_renewal_ifindex()?;
        let lease =
            tokio::time::timeout(ADMISSION_TIMEOUT, DhcpNetworkdLease::capture(index, cancel))
                .await
                .ok()?
                .ok()?;
        let actual = policy.clone().with_dhcp_renewal_rule(&lease).ok()?;
        if &actual != policy {
            return None;
        }
        let path = lease.path()?;
        if path.acquired <= refresh.initial_lease {
            return None;
        }
        Some(RenewedDhcpAddress {
            index: path.interface,
            local: path.address,
            prefix: path.prefix_len,
            expiries: lease.address_expiries()?,
        })
    }

    async fn refresh_dhcp(&self, index: NonZeroU32) {
        let snapshot = self.watch.current();
        if !snapshot.coverage.routes || snapshot.exhausted {
            return;
        }
        let Some((journal, revision)) = self.dhcp_policy() else {
            return;
        };
        let (_owner, mut cancel) = fresh_cancel();
        let Ok(mut lease) = DhcpNetworkdLease::capture(index, &mut cancel).await else {
            return;
        };
        if let Ok(mut nft) = self.executor(journal.ownership()) {
            let _refresh = diagnostic_result(
                "dhcp_refresh",
                nft.refresh_dhcp_renewal(journal, revision, &mut lease, &mut cancel)
                    .await,
            );
        }
    }

    fn dhcp_policy(&self) -> Option<(&Journal, u64)> {
        let journal = self.journal.as_ref()?;
        let record = journal.public_policy()?;
        let PublicPolicyPhase::Stable { policy } = record.phase() else {
            return None;
        };
        policy.dhcp_renewal_ifindex()?;
        Some((journal, record.revision()))
    }

    pub(super) async fn revoke_session_dhcp(&mut self) {
        if let Some(active) = &mut self.active {
            active.dhcp_refresh = None;
        }
        // После crash элемент может прожить остаток таймера ядра.
        // При восстановлении также пробуем отозвать его сразу.
        if let Some((journal, revision)) = self.dhcp_policy() {
            if let Ok(mut nft) = self.executor(journal.ownership()) {
                let _revoke = diagnostic_result(
                    "dhcp_revoke",
                    tokio::time::timeout(
                        REFRESH_BUDGET,
                        nft.revoke_dhcp_renewal(journal, revision),
                    )
                    .await
                    .unwrap_or(Err(NftError::Timeout)),
                );
            }
        }
    }
}
