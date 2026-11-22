use super::{
    dhcp_dhcpcd_control::read_lease,
    memory::ByteBudget,
    resolver_stub::CaptureCredits,
    systemd_network_service::{dhcpcd_daemon, same_pid, trusted_connection},
};
use crate::{
    Cancellation,
    attribution::broker::kernel::listener_census,
    network::{read_topology_captured, same_captured_topology},
};
use std::{
    fs, io, net::Ipv4Addr, os::unix::fs::MetadataExt, sync::atomic::AtomicBool, time::Duration,
};
use tokio::time::Instant;

#[tokio::test]
#[ignore = "одноразовая Arch VM со службой dhcpcd@.service и лизингом dhcpcd-probe"]
async fn native_dhcpcd_reads_instance_control_socket() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        std::env::var("YONIK_PRODUCTION_HELPER_VM").as_deref(),
        Ok("1")
    );
    assert_eq!(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim(),
        "QEMU"
    );
    let lease = read_lease("dhcpcd-probe", Instant::now() + Duration::from_secs(1)).await?;
    assert_eq!(lease.address, Ipv4Addr::new(10, 234, 16, 10));
    assert_eq!(lease.server, Ipv4Addr::new(10, 234, 16, 1));
    assert_eq!((lease.prefix, lease.duration), (24, 46));
    assert!(same_pid(&lease.peer_pidfd, lease.peer_pid)?);
    assert_eq!(
        fs::read_to_string(format!("/proc/{}/cgroup", lease.peer_pid))?,
        "0::/system.slice/system-dhcpcd.slice/dhcpcd@dhcpcd\\x2dprobe.service\n"
    );
    let connection = trusted_connection().await?;
    let bus = zbus::fdo::DBusProxy::new(&connection).await?;
    let daemon = dhcpcd_daemon(&connection, &bus, lease.peer_pid, "dhcpcd-probe").await?;
    let group = fs::metadata(
        "/sys/fs/cgroup/system.slice/system-dhcpcd.slice/dhcpcd@dhcpcd\\x2dprobe.service",
    )?;
    assert!(daemon.dhcpcd_instance && daemon.pid == lease.peer_pid);
    assert_eq!(daemon.group.0, group.dev());
    assert_eq!(daemon.group.1.get(), group.ino());
    assert!(
        dhcpcd_daemon(&connection, &bus, lease.peer_pid, "other")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "одноразовая Debian VM с пакетным dhcpcd.service и лизингом dhcpcd-probe"]
async fn native_dhcpcd_proves_control_peer_and_raw_socket() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        std::env::var("YONIK_PRODUCTION_HELPER_VM").as_deref(),
        Ok("1")
    );
    assert_eq!(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim(),
        "QEMU"
    );
    assert_eq!(
        fs::read_to_string("/etc/yonik-production-helper-vm")?.trim(),
        "yonik-production-helper-disposable-v1"
    );
    let expected_cgroup = "/system.slice/dhcpcd.service";
    let cgroup = fs::metadata(format!("/sys/fs/cgroup{expected_cgroup}"))?;
    let pin = fs::File::open("/proc/self/ns/net")?;
    let namespace = pin.metadata()?;
    let (_owner, mut cancellation) = Cancellation::new();
    let (before, before_timing) =
        read_topology_captured(&mut cancellation, Duration::from_secs(1)).await?;
    let lease = read_lease("dhcpcd-probe", Instant::now() + Duration::from_secs(1)).await?;
    assert_eq!(lease.address, Ipv4Addr::new(10, 234, 16, 10));
    assert_eq!(lease.server, Ipv4Addr::new(10, 234, 16, 1));
    assert_eq!((lease.prefix, lease.duration), (24, 42));
    assert!(same_pid(&lease.peer_pidfd, lease.peer_pid)?);
    assert_eq!(
        fs::read_to_string(format!("/proc/{}/cgroup", lease.peer_pid))?,
        format!("0::{expected_cgroup}\n")
    );
    let (topology, timing) =
        read_topology_captured(&mut cancellation, Duration::from_secs(1)).await?;
    assert!(same_captured_topology(
        &before,
        before_timing,
        &topology,
        timing
    ));
    assert_eq!(
        (topology.namespace.device, topology.namespace.inode),
        (namespace.dev(), namespace.ino())
    );
    let mut matching_links = topology
        .links
        .iter()
        .filter(|link| link.name == b"dhcpcd-probe");
    let interface = matching_links.next().expect("Интерфейс стенда").index;
    assert!(matching_links.next().is_none());
    assert!(topology.addresses.iter().any(|address| {
        address.index == interface
            && address.prefix_len == lease.prefix
            && address.local.unwrap_or(address.address) == lease.address
    }));
    let (fds, pending, bytes) = (
        ByteBudget::new(16),
        ByteBudget::new(4),
        ByteBudget::new(256 * 1024),
    );
    let credits = CaptureCredits::reserve_shared(&fds, &pending, &bytes)
        .map_err(|error| io::Error::other(format!("Резерв для SOCK_DIAG: {error:?}")))?;
    let sockets = listener_census(
        255,
        17,
        (namespace.dev(), namespace.ino()),
        (Instant::now() + Duration::from_millis(300)).into_std(),
        &AtomicBool::new(false),
        &credits,
    )
    .map_err(|error| io::Error::other(format!("SOCK_DIAG raw UDP: {error:?}")))?;
    let mut send = sockets
        .iter()
        .filter(|row| row.cgroup == cgroup.ino() && row.uid == 0);
    let raw = send.next().expect("Сокет отправки dhcpcd");
    assert!(send.next().is_none() && raw.inode != 0 && raw.remote_port == 0);
    assert!(same_pid(&lease.peer_pidfd, lease.peer_pid)?);
    eprintln!(
        "Подтверждены peer PID {}, raw inode {}, cgroup {}, TOS {:?}, mark {:?}",
        lease.peer_pid, raw.inode, raw.cgroup, raw.tos, raw.mark
    );
    Ok(())
}
