"""Установка production fixture исключительно внутри собственной одноразовой VM.

Запуск: python3 helper_vm_fixture.py --payload /opt/yonik-payload
Payload: source/ (exact git archive), yonik-helper, yonik-worker, sha256.json.
sha256.json содержит относительные пути и SHA256 всех устанавливаемых файлов.
Host runner отвечает за image provenance, VM 2 CPU/2 GiB и уничтожение overlay.
"""

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
from pathlib import Path


def checked(argv: list[str]) -> None:
    subprocess.run(argv, check=True, timeout=30)


def install(payload: Path) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Требуется VM root")
    if Path("/sys/class/dmi/id/sys_vendor").read_text().strip() != "QEMU":
        raise RuntimeError("Требуется QEMU")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("Требуется systemd PID 1")
    if os.environ.get("YONIK_PRODUCTION_HELPER_VM") != "1":
        raise RuntimeError("Нет явного VM opt-in")
    if os.environ.get("DBUS_SYSTEM_BUS_ADDRESS"):
        raise RuntimeError("Подмена system bus запрещена")
    marker = Path("/etc/yonik-production-helper-vm")
    metadata = marker.lstat()
    if (
        marker.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or marker.read_text() != "yonik-production-helper-disposable-v1\n"
    ):
        raise RuntimeError("Нет безопасного VM marker")
    if not Path("/usr/bin/pkcheck").exists():
        raise RuntimeError(
            "В VM отсутствует polkit; установите подписанный пакет до fixture"
        )
    files = {
        "yonik-helper": ("/usr/lib/yonik/yonik-helper", "0755"),
        "yonik-worker": ("/usr/lib/yonik/yonik-worker", "0755"),
        "source/packaging/dbus/cloud.highpriority.yonik.Network1.conf": (
            "/usr/share/dbus-1/system.d/cloud.highpriority.yonik.Network1.conf",
            "0644",
        ),
        "source/packaging/polkit/cloud.highpriority.yonik.policy": (
            "/usr/share/polkit-1/actions/cloud.highpriority.yonik.policy",
            "0644",
        ),
        "source/packaging/sysusers/yonik-worker.conf": (
            "/usr/lib/sysusers.d/yonik-worker.conf",
            "0644",
        ),
    }
    for name in [
        "yonik-helper.service",
        "yonik-dhcp-sleep.service",
        "sleep.target.d/50-yonik-dhcp-sleep.conf",
        "yonik-worker.service",
        "yonik-worker.socket",
        "yonik-worker-check.service",
        "yonik-worker-check.socket",
    ]:
        files[f"source/packaging/systemd/{name}"] = (
            f"/usr/lib/systemd/system/{name}",
            "0644",
        )
    manifest = json.loads((payload / "sha256.json").read_text())
    # Проверяем весь набор до первого изменения VM.
    for relative, (target, _) in files.items():
        source = payload / relative
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != manifest.get(relative):
            raise RuntimeError(f"Hash mismatch: {relative}")
        if Path(target).exists():
            raise RuntimeError(f"Чужой установленный файл: {target}")
    with Path("/run/yonik-production-helper-fixture.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for relative, (target, mode) in files.items():
            checked(["install", "-D", "-m", mode, str(payload / relative), target])
        checked(["systemd-sysusers", "/usr/lib/sysusers.d/yonik-worker.conf"])
        checked(["useradd", "--system", "--no-create-home", "yonik-vm-allowed"])
        # Реальный polkit, VM-local rule. Отрицательный UID — nobody.
        rule = Path("/etc/polkit-1/rules.d/00-yonik-vm.rules")
        if rule.exists():
            raise RuntimeError("Чужое правило polkit")
        rule.write_text("""polkit.addRule(function(action, subject) {
    if (action.id === "cloud.highpriority.tofu.manage-network" ||
        action.id === "cloud.highpriority.tofu.unlock-network") {
        return (subject.user === "root" || subject.user === "yonik-vm-allowed") ? polkit.Result.YES : polkit.Result.NO;
    }
});
""")
        checked(["systemctl", "reload", "dbus.service"])
        checked(["systemctl", "daemon-reload"])
        checked(["systemctl", "start", "polkit.service", "yonik-helper.service"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args()
    install(args.payload.resolve(strict=True))


if __name__ == "__main__":
    main()
