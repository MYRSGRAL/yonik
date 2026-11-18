"""WireGuard и эхо-сервер только для одноразовой VM установленного помощника."""

from __future__ import annotations

import logging
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traffic_echo import TcpEcho, TcpV6, UdpEcho, UdpV6

LINK = "yonik-wg"
PEER = "yonik-peer"
WG = "/opt/yonik-gate/wg"
PORT = 24177
ECHO_PORT = 40000


class TcpEchoV4Server(socketserver.TCPServer):
    allow_reuse_address = True


class TcpEchoV6Server(TcpV6):
    allow_reuse_address = True


class PrivateDns(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, server = self.request
        if not 17 <= len(query) <= 512 or query[4:6] != b"\x00\x01":
            return
        for label in (b"before", b"active", b"after"):
            name = bytes([len(label)]) + label + b"\x02wg\x04test\x00"
            question_end = 12 + len(name) + 4
            if (
                len(query) >= question_end
                and query[12 : question_end - 4].lower() == name
            ):
                break
        else:
            return
        question = query[12:question_end]
        qtype, qclass = struct.unpack("!HH", question[-4:])
        if qclass != 1 or qtype not in (1, 28):
            return
        has_ipv4 = qtype == 1
        response = (
            query[:2] + struct.pack("!HHHHH", 0x8180, 1, has_ipv4, 0, 0) + question
        )
        if has_ipv4:
            response += struct.pack("!HHHIH4B", 0xC00C, 1, 1, 0, 4, 10, 42, 1, 2)
        logging.info("DNS WireGuard ответил на %s, тип %d", label.decode(), qtype)
        server.sendto(response, self.client_address)


def guard_vm() -> None:
    marker = Path("/etc/yonik-production-helper-vm")
    metadata = marker.lstat()
    if (
        os.geteuid() != 0
        or not marker.is_file()
        or marker.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or marker.read_text() != "yonik-production-helper-disposable-v1\n"
        or Path("/sys/class/dmi/id/sys_vendor").read_text().strip() != "QEMU"
    ):
        raise RuntimeError("Нужна одноразовая VM установленного помощника")


def run(*command: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        command, input=data, stdout=subprocess.PIPE, check=True, timeout=10
    ).stdout


def connect() -> None:
    # Конфигурация с приватным ключом передаётся только на stdin wg.
    keys = [run(WG, "genkey").strip() for _ in range(2)]
    public = [run(WG, "pubkey", data=key + b"\n").strip() for key in keys]
    for index, namespace in enumerate(((), ("-n", PEER))):
        run("ip", *namespace, "link", "add", LINK, "type", "wireguard")
        host = index + 1
        remote = 2 - index
        config = (
            b"[Interface]\nPrivateKey = "
            + keys[index]
            + f"\nListenPort = {PORT}\nFwMark = {PORT}\n[Peer]\nPublicKey = ".encode()
            + public[1 - index]
            + f"\nAllowedIPs = 10.42.1.{remote}/32, fd42:1::{remote}/128\n"
            f"Endpoint = 10.203.0.{remote}:{PORT}\n".encode()
        )
        scope = ("ip", "netns", "exec", PEER) if namespace else ()
        run(*scope, WG, "setconf", LINK, "/dev/stdin", data=config)
        run("ip", *namespace, "address", "add", f"10.42.1.{host}/24", "dev", LINK)
        run(
            "ip",
            *namespace,
            "-6",
            "address",
            "add",
            f"fd42:1::{host}/64",
            "dev",
            LINK,
            "nodad",
        )
        run("ip", *namespace, "link", "set", LINK, "up")
    run(
        "systemd-run",
        "--quiet",
        "--unit=yonik-wireguard-echo",
        f"--property=NetworkNamespacePath=/run/netns/{PEER}",
        sys.executable,
        str(Path(__file__).resolve()),
        "echo",
    )


def disconnect() -> None:
    run("systemctl", "stop", "yonik-wireguard-echo.service")
    run("ip", "link", "del", LINK)
    run("ip", "-n", PEER, "link", "del", LINK)


def echo() -> None:
    with ExitStack() as stack:
        for server_type, handler, address in (
            (TcpEchoV4Server, TcpEcho, "10.42.1.2"),
            (socketserver.UDPServer, UdpEcho, "10.42.1.2"),
            (TcpEchoV6Server, TcpEcho, "fd42:1::2"),
            (UdpV6, UdpEcho, "fd42:1::2"),
        ):
            server = stack.enter_context(
                server_type((address, ECHO_PORT), handler, bind_and_activate=False)
            )
            server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, LINK.encode()
            )
            server.server_bind()
            server.server_activate()
            threading.Thread(target=server.serve_forever, daemon=True).start()
        threading.Event().wait()


def configure_split_dns() -> None:
    run(
        "systemd-run",
        "--quiet",
        "--unit=yonik-wireguard-dns",
        "--property=Type=notify",
        f"--property=NetworkNamespacePath=/run/netns/{PEER}",
        sys.executable,
        str(Path(__file__).resolve()),
        "dns",
    )
    run("resolvectl", "default-route", LINK, "no")
    run("resolvectl", "dns", LINK, "10.42.1.2")
    run("resolvectl", "domain", LINK, "~wg.test")


def main() -> None:
    guard_vm()
    operation = sys.argv[1] if len(sys.argv) == 2 else ""
    if operation == "connect":
        connect()
    elif operation == "disconnect":
        disconnect()
    elif operation == "echo":
        echo()
    elif operation == "split-dns":
        configure_split_dns()
    elif operation == "dns":
        logging.basicConfig(level=logging.INFO)
        with socketserver.UDPServer(
            ("10.42.1.2", 53), PrivateDns, bind_and_activate=False
        ) as server:
            server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, LINK.encode()
            )
            server.server_bind()
            address = os.environ["NOTIFY_SOCKET"]
            if address.startswith("@"):
                address = "\0" + address[1:]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                notifier.sendto(b"READY=1", address)
            server.serve_forever()
    elif operation == "stop-dns":
        run("systemctl", "stop", "yonik-wireguard-dns.service")
    else:
        raise ValueError("Неизвестная операция стенда WireGuard")


if __name__ == "__main__":
    main()
