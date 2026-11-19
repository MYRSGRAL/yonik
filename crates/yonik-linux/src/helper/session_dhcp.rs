use super::{
    ARPHRD_ETHER, Backend, IFF_LOOPBACK, IFF_UP, Journal, LinuxTopology, PublicBlockPolicy,
    PublicPolicyPhase, SafetyTask, diagnostic_result, fresh_cancel,
};
use crate::{
    Cancellation,
    helper::dhcp_networkd::{DHCP_PROBE_CONCURRENCY, DHCP_PROBE_TIMEOUT, DhcpNetworkdLease},
    managed_network::{
        firewall::MAX_DHCP_RENEWALS,
        nft::{NftError, NftExecutor},
    },
    network::RenewedDhcpAddress,
};
use futures_util::{StreamExt, stream};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    sync::{Mutex, TryLockError, Weak},
    time::Duration,
};

const ADMISSION_TIMEOUT: Duration = Duration::from_millis(450);
const REFRESH_INTERVAL: Duration = Duration::from_millis(300);
// По две волны на чтение и повторную сверку восьми лизингов, отдельно nft.
const REFRESH_BUDGET: Duration = Duration::from_millis(900);
const REVOKE_BUDGET: Duration = Duration::from_millis(550);
pub(super) type DhcpInterfaces = BTreeMap<NonZeroU32, u64>;

pub(super) struct DhcpRefresh {
    _task: SafetyTask,
    initial_leases: DhcpInterfaces,
}

async fn capture_leases(
    indices: impl IntoIterator<Item = NonZeroU32>,
    cancel: &Cancellation,
) -> Vec<DhcpNetworkdLease> {
    stream::iter(indices)
        .map(|index| {
            let mut token = cancel.clone();
            async move {
                diagnostic_result(
                    "dhcp_capture_lease",
                    tokio::time::timeout(
                        DHCP_PROBE_TIMEOUT,
                        DhcpNetworkdLease::capture(index, &mut token),
                    )
                    .await
                    .unwrap_or(Err(crate::NetworkReadError::Timeout)),
                )
                .ok()
            }
        })
        .buffer_unordered(DHCP_PROBE_CONCURRENCY)
        .filter_map(std::future::ready)
        .collect()
        .await
}

pub(super) async fn select_policy(
    baseline: &LinuxTopology,
    policy: &PublicBlockPolicy,
    cancel: &mut Cancellation,
) -> Option<(DhcpInterfaces, PublicBlockPolicy)> {
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
        .take(MAX_DHCP_RENEWALS + 1)
        .collect();
    if candidates.len() > MAX_DHCP_RENEWALS {
        return None;
    }
    let leases = capture_leases(candidates, cancel).await;
    let mut policy = policy.clone();
    let mut selected = BTreeMap::new();
    for lease in &leases {
        if let (Some(path), Ok(bound)) =
            (lease.path(), policy.clone().with_dhcp_renewal_rule(lease))
        {
            if let Some(index) = NonZeroU32::new(path.interface) {
                selected.insert(index, path.acquired);
                policy = bound;
            }
        }
    }
    (!selected.is_empty()).then_some((selected, policy))
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
    initial_leases: DhcpInterfaces,
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
                            tokio::time::timeout(REFRESH_BUDGET, backend.refresh_dhcp()).await;
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
        initial_leases,
    }
}

impl Backend {
    pub(super) async fn verified_dhcp_addresses(
        &self,
        cancel: &Cancellation,
    ) -> Vec<RenewedDhcpAddress> {
        let Some((_, _, policy)) = self.dhcp_policy() else {
            return Vec::new();
        };
        let Some(refresh) = self
            .active
            .as_ref()
            .and_then(|session| session.dhcp_refresh.as_ref())
        else {
            return Vec::new();
        };
        let mut addresses: Vec<_> = capture_leases(refresh.initial_leases.keys().copied(), cancel)
            .await
            .iter()
            .filter_map(|lease| {
                let index = policy.matches_dhcp_lease(lease)?;
                let path = lease.path()?;
                if path.acquired <= *refresh.initial_leases.get(&index)? {
                    return None;
                }
                Some(RenewedDhcpAddress {
                    index: path.interface,
                    local: path.address,
                    prefix: path.prefix_len,
                    expiries: lease.address_expiries()?,
                })
            })
            .collect();
        addresses.sort_unstable_by_key(|address| address.index);
        addresses
    }

    async fn refresh_dhcp(&self) {
        let Some(sleep_ticket) = self.dhcp_sleep.ticket() else {
            return;
        };
        let snapshot = self.watch.current();
        if !snapshot.coverage.routes || snapshot.exhausted {
            return;
        }
        let Some((journal, revision, _)) = self.dhcp_policy() else {
            return;
        };
        let Some(refresh) = self
            .active
            .as_ref()
            .and_then(|session| session.dhcp_refresh.as_ref())
        else {
            return;
        };
        let (_owner, mut cancel) = fresh_cancel();
        let mut leases = capture_leases(refresh.initial_leases.keys().copied(), &cancel).await;
        if let Ok(mut nft) = self.executor(journal.ownership()) {
            let _refresh = diagnostic_result(
                "dhcp_refresh",
                nft.refresh_dhcp_renewals(
                    journal,
                    revision,
                    &mut leases,
                    &mut cancel,
                    Some(&sleep_ticket),
                )
                .await,
            );
        }
    }

    fn dhcp_policy(&self) -> Option<(&Journal, u64, &PublicBlockPolicy)> {
        let journal = self.journal.as_ref()?;
        let record = journal.public_policy()?;
        let PublicPolicyPhase::Stable { policy } = record.phase() else {
            return None;
        };
        (policy.dhcp_rule_count() != 0).then_some((journal, record.revision(), policy))
    }

    pub(super) async fn revoke_session_dhcp(&mut self) {
        if let Some(active) = &mut self.active {
            active.dhcp_refresh = None;
        }
        // После crash элемент может прожить остаток таймера ядра.
        // При восстановлении также пробуем отозвать его сразу.
        if let Some((journal, revision, _)) = self.dhcp_policy() {
            if let Ok(mut nft) = self.executor(journal.ownership()) {
                let _revoke = diagnostic_result(
                    "dhcp_revoke",
                    tokio::time::timeout(REVOKE_BUDGET, nft.revoke_dhcp_renewal(journal, revision))
                        .await
                        .unwrap_or(Err(NftError::Timeout)),
                );
            }
        }
    }
}
