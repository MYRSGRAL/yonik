"""Диагностика stock pinned DNS через actual WG; не production capability."""

from __future__ import annotations

import argparse
import json
import select
import socket
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from dns_fixture import (
    DnsFixture,
    Reply,
    dns_query,
    engine_process,
    make_response,
    read_question,
    validated_binary,
)
from public_block_fixture import guard_namespace, run_ip


def peer() -> None:
    guard_namespace()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("10.42.1.2", 1053))
        print("READY", flush=True)
        for _ in range(128):
            packet, remote = server.recvfrom(4096)
            name, qtype, _ = read_question(packet)
            failure = name.startswith("fail.")
            addresses = (
                () if failure else ("10.42.1.2",) if qtype == 1 else ("fd42:1::2",)
            )
            server.sendto(
                make_response(
                    packet, Reply(addresses=addresses, rcode=2 if failure else 0, ttl=1)
                ),
                remote,
            )
            print(
                json.dumps(
                    {
                        "name": name,
                        "qtype": qtype,
                        "source": remote[0],
                        "failure": failure,
                    }
                ),
                flush=True,
            )


def relay_peer() -> None:
    guard_namespace()

    def reply(query: bytes) -> bytes:
        name, _, question_end = read_question(query)
        if name.startswith("_svc."):
            assert query[10:12] == b"\x00\x01"
            assert (
                query[question_end:] == b"\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00"
            )
        return make_response(query, Reply(addresses=("10.42.1.2",)))

    with ExitStack() as opened:
        listeners = {}
        for family, address, source in (
            (socket.AF_INET, "10.42.1.2", "10.42.1.1"),
            (socket.AF_INET6, "fd42:1::2", "fd42:1::1"),
        ):
            for protocol in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                listener = opened.enter_context(socket.socket(family, protocol))
                listener.bind((address, 1053))
                if protocol == socket.SOCK_STREAM:
                    listener.listen(1)
                listeners[listener] = (protocol, address, source)
        print("READY", flush=True)
        for _ in range(8):
            ready, _, _ = select.select(listeners, [], [], 12)
            if not ready:
                return
            listener = ready[0]
            protocol, address, source = listeners[listener]
            if protocol == socket.SOCK_DGRAM:
                query, peer_address = listener.recvfrom(4096)
                assert peer_address[0] == source
                if read_question(query)[0] == "hold.corp.test":
                    print("HOLD " + address, flush=True)
                    continue
                listener.sendto(reply(query), peer_address)
            else:
                stream, peer_address = listener.accept()
                with stream, stream.makefile("rb") as framed:
                    stream.settimeout(2)
                    assert peer_address[0] == source
                    length = int.from_bytes(framed.read(2))
                    response = reply(framed.read(length))
                    stream.sendall(len(response).to_bytes(2) + response)
            print(f"{protocol.name} {address}", flush=True)


def configure(config: dict, engine: str) -> dict:
    if engine == "sing-box":
        config["dns"]["strategy"] = "prefer_ipv4"
        config["dns"]["servers"][0]["server_port"] = 1153
        config["dns"]["servers"].append(
            {
                "type": "udp",
                "tag": "private",
                "server": "10.42.1.2",
                "server_port": 1053,
                "bind_interface": "vpn",
            }
        )
        config["dns"]["rules"].insert(
            0, {"domain_suffix": ["corp.test"], "action": "route", "server": "private"}
        )
    else:
        config["dns"]["servers"] = [
            {
                "address": "10.42.1.2",
                "port": 1053,
                "domains": ["domain:corp.test"],
                "skipFallback": True,
            },
            {
                "address": "127.0.0.1",
                "port": 1153,
                "domains": ["domain:public.test"],
                "skipFallback": True,
            },
            "fakedns",
        ]
        config["dns"]["queryStrategy"] = "UseIP"
        config["dns"]["disableFallback"] = True
        config["dns"]["disableFallbackIfMatch"] = True
        config["outbounds"].append(
            {
                "tag": "wg-dns",
                "protocol": "freedom",
                "streamSettings": {"sockopt": {"interface": "vpn"}},
            }
        )
        config["routing"]["rules"].insert(
            0, {"type": "field", "ip": ["10.42.1.2/32"], "outboundTag": "wg-dns"}
        )
    return config


def run(baseline: Path) -> None:
    guard_namespace()
    child = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "yonik-peer",
            sys.executable,
            str(Path(__file__).resolve()),
            "peer",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    records: list[dict] = []
    reader: threading.Thread | None = None
    try:
        if (
            child.stdout is None
            or not select.select([child.stdout], [], [], 5)[0]
            or child.stdout.readline().strip() != "READY"
        ):
            raise RuntimeError("Private DNS peer не готов")

        def read_records() -> None:
            for line in child.stdout:
                records.append(json.loads(line))

        reader = threading.Thread(target=read_records)
        reader.start()
        for engine, binary in [
            (
                "xray",
                Path("/home/myrs/projects/yonik/local/engines/xray-26.10.31/xray"),
            ),
            (
                "sing-box",
                Path(
                    "/home/myrs/projects/yonik/local/engines/sing-box-1.14.4/sing-box"
                ),
            ),
        ]:
            binary = validated_binary(binary, engine)
            config = configure(
                json.loads((baseline / f"{engine}.json").read_text()), engine
            )
            start = len(records)
            with DnsFixture(
                lambda *_: Reply(addresses=("203.0.113.9",), ttl=1), 1153
            ) as public:
                with engine_process(binary, engine, config, baseline / engine):
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            addresses = dns_query(
                                "ready.corp.test", 1, 1054, timeout=0.2
                            )
                            if addresses == ["10.42.1.2"]:
                                break
                        except (OSError, ValueError):
                            pass
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"{engine}: private DNS не готов")
                    for qtype, expected in [(1, "10.42.1.2"), (28, "fd42:1::2")]:
                        actual = dns_query("private.corp.test", qtype, 1054, timeout=3)
                        assert actual == [expected], (engine, qtype, actual, expected)
                    try:
                        failure = dns_query("fail.corp.test", 1, 1054, timeout=3)
                    except (OSError, ValueError):
                        failure = []
                    assert not failure, (
                        engine,
                        "private failure returned answer",
                        failure,
                    )
                    assert not public.records, (
                        engine,
                        "private query leaked",
                        public.records,
                    )
                    # Core не получил runtime lease/revoke: это диагностика
                    # отсутствующего host hook, а не нарушение DNS TTL.
                    deadline = time.monotonic() + 0.1
                    threading.Event().wait(0.12)
                    assert time.monotonic() > deadline
                    assert dns_query("after-expiry.corp.test", 1, 1054, timeout=3) == [
                        "10.42.1.2"
                    ]
                    assert not public.records
                    run_ip("link", "set", "vpn", "down")
                    try:
                        down = dns_query("wg-down.corp.test", 1, 1054, timeout=3)
                    except (OSError, ValueError):
                        down = []
                    assert not down
                    assert not public.records
                    run_ip("link", "set", "vpn", "up")
                    assert dns_query(
                        "after-network-epoch.corp.test", 1, 1054, timeout=3
                    ) == ["10.42.1.2"]
                    assert not public.records
            sample = records[start:]
            assert sample and all((r["source"] == "10.42.1.1" for r in sample)), sample
            print(
                json.dumps(
                    {
                        "engine": engine,
                        "private_queries": len(sample),
                        "wg_source": True,
                        "private_before_fake": True,
                        "private_failure_public_queries": 0,
                        "static_core_after_expiry": "still_answers",
                        "static_core_after_network_epoch": "still_answers_without_new_capture",
                        "production_compiler": "Unsupported(DnsContract)",
                    }
                ),
                flush=True,
            )
    finally:
        child.terminate()
        child.wait(timeout=5)
        if reader is not None:
            reader.join(timeout=3)
            if reader.is_alive():
                raise RuntimeError("DNS reader не завершён")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["peer", "relay-peer", "run"])
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    if args.action == "peer":
        peer()
    elif args.action == "relay-peer":
        relay_peer()
    else:
        if args.baseline is None:
            parser.error("Нужен --baseline")
        run(args.baseline)
