#!/usr/bin/env python3
"""Проверка таймеров nftables при пробуждении гостя QEMU из ACPI S3."""

import argparse
import errno
import hashlib
import logging
import os
import socket
import stat
import subprocess
import time
from pathlib import Path

TABLE = "yonik_sleep_probe"
ADDRESS = "127.0.0.1"
PORT = 19286
PERMIT_MS = 650
MARKER = "yonik-production-helper-disposable-v1"


def guarded() -> None:
    if (
        os.geteuid() != 0
        or Path("/sys/class/dmi/id/sys_vendor").read_text().strip() != "QEMU"
        or Path("/etc/yonik-production-helper-vm").read_text().strip() != MARKER
    ):
        raise RuntimeError("Требуется одноразовый гостевой стенд Yonik")


def resolver_state() -> tuple[tuple[int, ...], tuple[int, ...], str, str]:
    path = Path("/etc/resolv.conf")
    link = path.lstat()
    target = path.stat()
    link_data = tuple(
        getattr(link, key)
        for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_mtime_ns")
    )
    target_data = tuple(
        getattr(target, key)
        for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_mtime_ns")
    )
    return (
        link_data,
        target_data,
        os.readlink(path) if stat.S_ISLNK(link.st_mode) else "",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def nft(*args: str, script: str | None = None) -> str:
    result = subprocess.run(
        ["/usr/sbin/nft", *args],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        timeout=3,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"nft завершился с кодом {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


def send_is_allowed(packet: bytes) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        try:
            sender.sendto(packet, (ADDRESS, PORT))
        except OSError as error:
            if error.errno != errno.EPERM:
                raise
            return False
    return True


def clock_rollback_reopens_window(original_wall: int) -> bool:
    restore_wall = time.time_ns()
    restore_monotonic = time.monotonic_ns()
    time.clock_settime_ns(time.CLOCK_REALTIME, original_wall)
    try:
        return send_is_allowed(b"clock rollback")
    finally:
        elapsed = time.monotonic_ns() - restore_monotonic
        time.clock_settime_ns(time.CLOCK_REALTIME, restore_wall + elapsed)


def probe(mode: str) -> None:
    before = resolver_state()
    sleep_mode = Path("/sys/power/mem_sleep")
    if "deep" not in sleep_mode.read_text().replace("[", "").replace("]", "").split():
        raise RuntimeError("Гость не поддерживает ACPI S3")
    sleep_mode.write_text("deep\n")
    expect_permission_after_wake = mode == "relative"
    window = "" if expect_permission_after_wake else "meta time @window"
    nft(
        "-f",
        "-",
        script=f"""create table inet {TABLE}
add set inet {TABLE} permits {{ type ipv4_addr; flags timeout; size 4; }}
add set inet {TABLE} window {{ typeof meta time; flags interval; size 4; }}
add chain inet {TABLE} output {{ type filter hook output priority 0; policy accept; }}
add rule inet {TABLE} output udp dport {PORT} ip daddr @permits {window} counter accept
add rule inet {TABLE} output udp dport {PORT} counter drop
""",
    )
    try:
        installed_wall = time.time_ns()
        first_second = installed_wall // 1_000_000_000
        nft(
            "-f",
            "-",
            script=f"""add element inet {TABLE} window {{ {first_second}-{first_second + 2} }}
add element inet {TABLE} permits {{ {ADDRESS} timeout {PERMIT_MS}ms }}
""",
        )
        if not send_is_allowed(b"awake"):
            raise RuntimeError("Разрешение не пропустило пакет перед сном")
        started_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        started_monotonic = time.monotonic_ns()
        logging.info("YONIK_SLEEP_ENTER %s", mode)
        Path("/sys/power/state").write_text("mem\n")
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME) - started_boot
        monotonic = time.monotonic_ns() - started_monotonic
        if boot - monotonic < 2_000_000_000:
            raise RuntimeError("Хост должен держать гостя в S3 не менее двух секунд")
        awake_permission = send_is_allowed(b"after S3")
        if awake_permission != expect_permission_after_wake:
            raise RuntimeError("После S3 получен неожиданный вердикт nftables")
        rolled_back = mode == "rollback" and clock_rollback_reopens_window(
            installed_wall
        )
        active = nft("-n", "list", "set", "inet", TABLE, "permits")
        if ADDRESS not in active:
            raise RuntimeError("Относительный элемент истёк до проверки")
        if mode == "rollback" and not rolled_back:
            raise RuntimeError("Не подтверждено открытие окна при возврате часов")
        logging.info(
            "YONIK_SLEEP_RESULT %s boottime_ms=%d monotonic_ms=%d after_wake=%s after_rollback=%s",
            mode,
            boot // 1_000_000,
            monotonic // 1_000_000,
            awake_permission,
            rolled_back,
        )
        logging.info("%s", active.rstrip())
    finally:
        nft("delete", "table", "inet", TABLE)
    if resolver_state() != before:
        raise RuntimeError("Изменились содержимое или метаданные resolv.conf")
    logging.info("YONIK_SLEEP_RESOLVER_UNCHANGED")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["relative", "wall", "rollback"])
    args = parser.parse_args()
    guarded()
    probe(args.mode)


if __name__ == "__main__":
    main()
