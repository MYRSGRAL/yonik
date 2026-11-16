"""Независимый stdlib packer DNS_V2: field tables, без Rust encoder/OS calls."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import struct
import sys
from typing import Any

SIZES = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}
FORMATS = {"u8": ">B", "u16": ">H", "u32": ">I", "u64": ">Q"}


def pack(size: int, fields: list[tuple[int, str, Any]]) -> bytes:
    result = bytearray(size)
    occupied: set[int] = set()
    for offset, kind, value in fields:
        data = (
            bytes([value[0]]) * value[1]
            if kind == "fill"
            else bytes.fromhex(value)
            if kind == "hex"
            else struct.pack(FORMATS[kind], value)
        )
        assert offset >= 0 and offset + len(data) <= size
        positions = set(range(offset, offset + len(data)))
        assert not occupied.intersection(positions), (offset, kind)
        occupied.update(positions)
        result[offset : offset + len(data)] = data
    return bytes(result)


def field(offset: int, value: int, kind: str = "u64") -> tuple[int, str, int]:
    return offset, kind, value


def raw(offset: int, value: bytes) -> tuple[int, str, str]:
    return offset, "hex", value.hex()


def launch(mode: int) -> bytes:
    return pack(
        192,
        [
            raw(0, b"YNKLOC01" if mode == 1 else b"YNKEXT01"),
            field(8, 1, "u16"),
            field(10, 192, "u16"),
            field(12, mode - 1, "u16"),
            raw(16, bytes([4]) * 32),
            raw(48, bytes([1]) * 32),
            raw(80, bytes([2]) * 16),
            raw(96, bytes([3]) * 16),
            field(112, 5),
            field(120, 7),
            field(128, 1001, "u32"),
            field(132, 2002 if mode == 2 else 0, "u32"),
            field(136, 42),
            field(144, 43 if mode == 2 else 0),
            raw(152, bytes([3]) * 32),
        ],
    )


def descriptor(mode: int) -> bytes:
    return pack(
        272,
        [
            raw(0, b"DNSNEG02"),
            field(8, 2, "u16"),
            field(10, 272, "u16"),
            raw(16, launch(mode)),
            raw(208, hashlib.sha256(b"YONIK-DNS-V2-CODEC-1\0").digest()),
            field(240, 4, "u16"),
            field(242, 11, "u16"),
            field(244, 8388608, "u32"),
            *[
                field(at, n, "u16")
                for at, n in [(248, 64), (250, 64), (252, 64), (254, 256), (256, 256)]
            ],
        ],
    )


def destination(ip: str, carrier: int = 6, port: int = 443) -> bytes:
    address = ipaddress.ip_address(ip)
    return pack(
        7 + len(address.packed),
        [
            field(0, address.version, "u8"),
            field(1, carrier, "u8"),
            field(2, port, "u16"),
            field(4, len(address.packed), "u8"),
            raw(7, address.packed),
        ],
    )


def probe(purpose: int = 1) -> bytes:
    return pack(
        8,
        [
            field(0, purpose, "u16"),
            field(2, 0, "u16"),
            field(4, 0, "u16"),
            field(6, 65535 if purpose == 1 else 0, "u16"),
        ],
    )


def legacy_destination(ip: str) -> bytes:
    address = ipaddress.ip_address(ip)
    return pack(
        8 + len(address.packed),
        [
            field(0, address.version, "u8"),
            field(1, 6, "u8"),
            field(2, 443, "u16"),
            field(4, len(address.packed), "u16"),
            raw(8, address.packed),
        ],
    )


def base(class_: int = 1) -> bytes:
    address = legacy_destination("192.0.2.1")
    query = b"resolver.invalid" if class_ == 3 else b""
    return pack(
        20 + 2 * len(address) + 4 + len(query) + 16,
        [
            field(0, 5),
            field(8, class_, "u8"),
            *[field(at, 65535 if class_ == 3 else 0, "u16") for at in [10, 12, 14, 16]],
            raw(20, address),
            raw(20 + len(address), address),
            field(20 + 2 * len(address), 0 if class_ == 3 else 65535, "u16"),
            field(22 + 2 * len(address), len(query), "u16"),
            raw(24 + 2 * len(address), query),
        ],
    )


def header(kind: int, body: bytes, sequence: int, issuer: bool) -> bytes:
    return (
        pack(
            128,
            [
                raw(0, b"YNKCAP01"),
                field(8, 1, "u16"),
                field(10, kind, "u16"),
                field(12, 128 + len(body), "u32"),
                field(16, sequence),
                field(24, 9 if issuer else 0),
                raw(32, bytes([2]) * 16),
                raw(48, bytes([3]) * 16),
                raw(64, bytes([1]) * 32),
                field(96, 5),
                field(104, 7),
            ],
        )
        + body
    )


def corpus() -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    issuer_kinds = {36, 37, 39, 41, 44, 46, 48, 54}

    def add(
        name: str,
        kind: int,
        size: int,
        fields: list[tuple[int, str, Any]],
        mode: int = 1,
    ) -> None:
        body = pack(size, fields)
        issuer = kind in issuer_kinds
        # SCM proof имеет собственный identity envelope192, не Header128+192.
        frame = body if kind == 52 else header(kind, body, 100 + len(vectors), issuer)
        vectors.append(
            {
                "name": name,
                "kind": kind,
                "mode": mode,
                "size": size,
                "direction": "issuer" if issuer else "producer",
                "rights": int(kind == 52),
                "credentials": int(kind == 52),
                "fields": fields,
                "bodyHex": body.hex() if size <= 2048 else None,
                "frameHex": frame.hex() if size <= 2048 else None,
                "bodySha256": hashlib.sha256(body).hexdigest(),
                "frameSha256": hashlib.sha256(frame).hexdigest(),
            }
        )

    def request(
        name: str, kind: int, size: int, fields: list[tuple[int, str, Any]]
    ) -> None:
        add(name, kind, size, [field(0, 2, "u16"), *fields])

    def ack(
        name: str, kind: int, size: int, fields: list[tuple[int, str, Any]]
    ) -> None:
        for status, label in [(1, "allow"), (2, "deny"), (3, "unknown")]:
            add(
                name + "-" + label,
                kind,
                size,
                [
                    field(0, 2, "u16"),
                    field(2, status, "u8"),
                    *(fields if status == 1 else []),
                ],
            )

    original, query, canonical = b"example.invalid", b"example.invalid", base()
    request(
        "reserve-user",
        35,
        96 + len(original + query + canonical),
        [
            field(2, 1, "u8"),
            field(8, 11),
            field(16, 12),
            field(24, 13),
            field(32, 5),
            field(40, 6),
            field(48, 7),
            field(56, 1000),
            *[
                field(at, n, "u16")
                for at, n in [(64, 0), (66, 0), (68, 65535), (70, 0), (72, 1)]
            ],
            *[
                field(at, n, "u8")
                for at, n in [(74, 1), (75, 1), (76, 17), (77, 1), (78, 1)]
            ],
            field(80, len(original), "u16"),
            field(82, len(query), "u16"),
            field(84, len(canonical), "u16"),
            raw(96, original + query + canonical),
        ],
    )
    canonical = probe(2)
    request(
        "reserve-hosts",
        35,
        96 + len(original + canonical),
        [
            field(2, 3, "u8"),
            field(8, 11),
            field(48, 7),
            field(56, 1000),
            field(64, 65535, "u16"),
            *[
                field(at, n, "u8")
                for at, n in [(74, 3), (75, 2), (76, 6), (77, 3), (78, 2)]
            ],
            field(80, len(original), "u16"),
            field(84, len(canonical), "u16"),
            raw(96, original + canonical),
        ],
    )
    for role, label in [(2, "physical"), (3, "waiter")]:
        fields = [
            (at, kind, role if at == 2 else value)
            for at, kind, value in vectors[0]["fields"]
        ]
        if role == 2:
            fields.append(field(88, 21))
        add("reserve-" + label, 35, vectors[0]["size"], fields)
    for hosts in [False, True]:
        ack(
            "reserved-hosts" if hosts else "reserved-network",
            36,
            64,
            [
                field(8, 21),
                field(16, 11),
                field(24, 0 if hosts else 12),
                field(32, 22 if hosts else 25),
                field(40, 7),
                field(48, 1000),
                field(58, 1, "u16"),
                field(60, 3 if hosts else 1, "u8"),
            ],
        )
    ack(
        "reserved-physical",
        36,
        64,
        [
            field(8, 23),
            field(16, 11),
            field(24, 12),
            field(32, 21),
            field(40, 7),
            field(48, 1000),
            field(56, 1, "u16"),
            field(58, 1, "u16"),
            field(60, 2, "u8"),
        ],
    )
    ack(
        "reserved-waiter",
        36,
        64,
        [
            field(8, 72),
            field(16, 73),
            field(24, 12),
            field(40, 7),
            field(48, 1000),
            field(58, 1, "u16"),
            field(60, 3, "u8"),
        ],
    )
    for mode in [1, 2]:
        target = destination("2001:db8::53", 17, 53)
        add(
            "physical-bind-" + str(mode),
            52,
            192,
            [
                raw(0, b"DNSPHY02"),
                field(8, 2, "u16"),
                field(10, 192, "u16"),
                raw(16, bytes([1]) * 32),
                raw(48, bytes([2]) * 16),
                raw(64, bytes([3]) * 16),
                field(80, 5),
                field(88, 7),
                raw(96, bytes([4]) * 32),
                field(128, 21),
                field(136, 11),
                field(144, 12),
                field(152, 23),
                field(164, 17, "u8"),
                field(165, 2, "u8"),
                field(166, mode, "u8"),
                raw(168, target),
            ],
            mode,
        )
    ack(
        "physical-ack",
        37,
        64,
        [
            field(at, n)
            for at, n in [(8, 23), (16, 24), (24, 11), (32, 12), (40, 7), (48, 1000)]
        ],
    )
    for count, logical_kind in [(1, 1), (2, 2), (64, 2)]:
        request(
            "logical-bind-" + str(count),
            38,
            64 + 8 * count,
            [
                field(2, logical_kind, "u8"),
                field(4, count, "u16"),
                *[
                    field(at, n)
                    for at, n in [
                        (8, 21),
                        (16, 11),
                        (24, 12),
                        (32, 25),
                        (48, 1),
                        (56, 1000),
                    ]
                ],
                *[field(64 + 8 * i, 1000 + i) for i in range(count)],
            ],
        )
    ack(
        "logical-ack",
        39,
        64,
        [
            *[
                field(at, n)
                for at, n in [
                    (8, 25),
                    (16, 26),
                    (24, 11),
                    (32, 12),
                    (40, 1),
                    (48, 1000),
                ]
            ],
            field(56, 2, "u16"),
            field(58, 2, "u8"),
        ],
    )
    for count in [1, 64]:
        request(
            "append-" + str(count),
            43,
            48 + count * 8,
            [
                field(4, count, "u16"),
                *[
                    field(at, n)
                    for at, n in [(8, 25), (16, 26), (24, 1), (32, 1), (40, 1000)]
                ],
                *[field(48 + 8 * i, 2000 + i) for i in range(count)],
            ],
        )
    ack(
        "append-ack",
        44,
        56,
        [
            *[
                field(at, n)
                for at, n in [(8, 25), (16, 26), (24, 1), (32, 2), (40, 1000)]
            ],
            field(48, 64, "u16"),
        ],
    )

    dns_request = (
        struct.pack(">HHHHHH", 123, 256, 1, 0, 0, 0)
        + b"\x07example\x07invalid\x00"
        + struct.pack(">HH", 1, 1)
    )
    dns_response = (
        struct.pack(">HHHHHH", 123, 33152, 1, 1, 0, 0)
        + dns_request[12:]
        + b"\xc0\x0c"
        + struct.pack(">HHIH", 1, 1, 60, 4)
        + ipaddress.ip_address("192.0.2.9").packed
    )
    for purpose, maximum in [(1, False), (2, False), (1, True)]:
        question = b"example.invalid" if not maximum else b"a" * 255
        req = dns_request if not maximum else dns_request.ljust(512, b"\0")
        response = dns_response if not maximum else dns_response.ljust(32768, b"\0")
        request(
            "publish-" + str(purpose) + ("-bounds-max" if maximum else ""),
            40,
            144 + len(question + req + response),
            [
                *[
                    field(at, n, "u16")
                    for at, n in [
                        (4, 0),
                        (6, 0),
                        (8, 65535 if purpose == 1 else 0),
                        (10, 1),
                    ]
                ],
                *[
                    field(at, n)
                    for at, n in [
                        (12, 11),
                        (20, 13),
                        (28, 25),
                        (36, 7),
                        (120, 26),
                        (128, 2),
                    ]
                ],
                *(
                    [raw(44, bytes([1]) * 32), raw(76, bytes([2]) * 32)]
                    if purpose == 2
                    else []
                ),
                field(108, len(question), "u16"),
                field(110, len(req), "u16"),
                field(112, len(response), "u32"),
                field(136, purpose, "u8"),
                field(137, 1, "u8"),
                field(140, 65535 if purpose == 1 else 0, "u16"),
                field(142, 17 if purpose == 1 else 6, "u8"),
                *(
                    [raw(144, question + req + response)]
                    if not maximum
                    else [
                        (144, "fill", [97, 255]),
                        raw(399, dns_request),
                        (399 + len(dns_request), "fill", [0, 512 - len(dns_request)]),
                        raw(911, dns_response),
                        (
                            911 + len(dns_response),
                            "fill",
                            [0, 32768 - len(dns_response)],
                        ),
                    ]
                ),
            ],
        )
    for maximum in [False, True]:
        key = (
            b"host"
            if not maximum
            else b"a" * 63
            + b"."
            + b"b" * 63
            + b"."
            + b"c" * 63
            + b"."
            + b"d" * 60
            + b"."
        )
        original = key.upper()
        count = 16 if maximum else 1
        tail = pack(
            128 + len(key + original) + count * 2,
            [
                raw(0, b"DNHOST02"),
                field(8, 2, "u16"),
                field(10, 128 + len(key + original) + count * 2, "u16"),
                raw(16, bytes([1]) * 32),
                raw(48, bytes([2]) * 32),
                field(80, 7),
                field(88, 22),
                field(96, 1000),
                field(108, count, "u16"),
                field(110, len(key), "u16"),
                field(112, len(original), "u16"),
                field(121, 6, "u8"),
                field(122, 443, "u16"),
                raw(128, key + original),
                *[
                    field(128 + len(key + original) + 2 * i, i, "u16")
                    for i in range(count)
                ],
            ],
        )
        request(
            "publish-hosts" + ("-max" if maximum else ""),
            40,
            144 + len(tail),
            [
                field(4, 65535, "u16"),
                field(12, 11),
                field(36, 7),
                raw(44, bytes([1]) * 32),
                raw(76, bytes([2]) * 32),
                field(136, 3, "u8"),
                field(137, 2, "u8"),
                field(142, 6, "u8"),
                raw(144, tail),
            ],
        )
    for hosts in [False, True]:
        ack(
            "published-hosts" if hosts else "published-dns",
            41,
            48,
            [
                field(8, 71),
                field(16, 0 if hosts else 25),
                field(24, 7),
                field(32, 1000 if hosts else 60000000000),
                field(40, 16 if hosts else 256, "u16"),
            ],
        )
    for hosts, user in [(False, True), (False, False), (True, False)]:
        request(
            "waiter-bind-" + ("hosts" if hosts else "user" if user else "service"),
            53,
            64,
            [
                field(8, 72),
                field(16, 71),
                field(24, 0 if hosts else 13),
                field(32, 73),
                field(40, 5 if user else 0),
                field(48, 6 if user else 0),
                field(56, 1000),
            ],
        )
    for hosts in [False, True]:
        ack(
            "waiter-bound-hosts" if hosts else "waiter-bound-dns",
            54,
            64,
            [
                *[
                    field(at, n)
                    for at, n in [
                        (8, 74),
                        (16, 71),
                        (24, 72),
                        (32, 73),
                        (40, 7),
                        (48, 1000),
                    ]
                ],
                field(56, 16 if hosts else 256, "u16"),
                field(58, 2 if hosts else 1, "u8"),
                field(59, 3 if hosts else 1, "u8"),
            ],
        )
    for class_, use, canonical in [
        (1, 1, base()),
        (2, 1, probe()),
        (3, 1, base(3)),
        (3, 2, probe(2)),
    ]:
        target = destination("2001:db8::9")
        request(
            "numeric-class-" + str(class_) + "-use-" + str(use),
            42,
            16 + len(canonical + target),
            [
                field(2, 0, "u16"),
                field(4, 74),
                field(12, len(canonical), "u16"),
                field(14, use, "u8"),
                field(15, class_, "u8"),
                raw(16, canonical + target),
            ],
        )
    for target, revision in [(3, 0), (4, 2)]:
        request(
            "retire-" + str(target),
            45,
            24,
            [field(2, target, "u8"), field(8, 26), field(16, revision)],
        )
        add(
            "retired-" + str(target),
            46,
            40,
            [
                field(0, 2, "u16"),
                field(2, 1, "u8"),
                field(3, target, "u8"),
                field(8, 26),
                field(16, revision),
                field(28, 1, "u8"),
                field(32, 99),
            ],
        )
    add("retired-deny", 46, 40, [field(0, 2, "u16"), field(2, 2, "u8")])
    add(
        "retired-unknown-custody",
        46,
        40,
        [
            field(0, 2, "u16"),
            field(2, 3, "u8"),
            field(3, 4, "u8"),
            field(8, 26),
            field(16, 2),
            field(24, 64, "u16"),
            field(26, 64, "u16"),
            field(32, 99),
        ],
    )
    for target in range(1, 8):
        request(
            "cancel-" + str(target),
            47,
            24,
            [field(2, target, "u8"), field(8, 74), field(16, 1, "u16")],
        )
    ack("canceled", 48, 32, [field(8, 74), field(16, 99)])
    template = next(v for v in vectors if v["name"] == "physical-bind-1")
    for carrier, physical_kind, mode in [(6, 1, 1), (17, 3, 2)]:
        changes = {164: carrier, 165: physical_kind, 166: mode}
        fields = [
            (at, kind, changes.get(at, value))
            for at, kind, value in template["fields"]
            if at != 168
        ]
        fields.append(raw(168, destination("192.0.2.53", carrier, 53)))
        add("physical-kind-" + str(physical_kind), 52, 192, fields, mode)
    long_name = b"a" * 63 + b"." + b"b" * 63 + b"." + b"c" * 63 + b"." + b"d" * 61
    domain = pack(
        261,
        [
            field(0, 3, "u8"),
            field(1, 6, "u8"),
            field(2, 443, "u16"),
            field(4, 253, "u16"),
            raw(8, long_name),
        ],
    )
    maximum_base = pack(
        815,
        [
            field(0, 5),
            field(8, 3, "u8"),
            *[field(at, 65535, "u16") for at in [10, 12, 14, 16]],
            raw(20, domain),
            raw(281, domain),
            field(544, 253, "u16"),
            raw(546, long_name),
        ],
    )
    request(
        "numeric-canonical-base-max",
        42,
        854,
        [
            field(4, 74),
            field(12, 815, "u16"),
            field(14, 1, "u8"),
            field(15, 3, "u8"),
            raw(16, maximum_base + destination("2001:db8::9")),
        ],
    )
    original, query = b"h", b"a" * 63 + b"." + b"b" * 48
    request(
        "reserve-bounds-max",
        35,
        1024,
        [
            field(2, 1, "u8"),
            field(8, 11),
            field(16, 12),
            field(24, 13),
            field(32, 5),
            field(40, 6),
            field(48, 7),
            field(56, 1000),
            field(68, 65535, "u16"),
            field(72, 1, "u16"),
            *[
                field(at, value, "u8")
                for at, value in [(74, 1), (75, 1), (76, 17), (77, 3), (78, 1)]
            ],
            field(80, 1, "u16"),
            field(82, 112, "u16"),
            field(84, 815, "u16"),
            raw(96, original + query + maximum_base),
        ],
    )
    negotiations = [
        {
            "mode": mode,
            "launchHex": launch(mode).hex(),
            "descriptorHex": descriptor(mode).hex(),
            "ackHex": (b"DNSACK02" + hashlib.sha256(descriptor(mode)).digest()).hex(),
        }
        for mode in [1, 2]
    ]
    rejected: list[dict[str, Any]] = []

    def reject(case: str, *patches: tuple[int, str, Any], append: int = 0) -> None:
        rejected.append({"case": case, "patches": patches, "appendZeroBytes": append})

    for v in vectors:
        kind = v["kind"]
        if kind != 52:
            reject(v["name"], field(0, 1, "u16"))
        if kind in issuer_kinds and v["name"].endswith(("deny", "unknown")):
            reject(v["name"], field(8, 1))
    reject("reserve-user", field(2, 4, "u8"))
    reject("reserve-user", field(3, 1, "u8"))
    reject("reserve-physical", field(88, 0))
    reject("reserve-user", field(84, 1025, "u16"))
    reject("reserve-user", field(40, 0))
    reject("reserve-user", field(88, 32, "u16"))
    reject("reserve-user", field(90, 512, "u16"))
    reject("reserve-hosts", field(16, 1))
    reject("reserve-hosts", field(72, 1, "u16"))
    reject("reserved-hosts-allow", field(32, 0))
    reject("reserved-network-allow", field(58, 0, "u16"))
    reject("physical-bind-1", field(164, 6, "u8"))
    reject("physical-bind-1", field(8, 1, "u16"))
    reject("physical-bind-1", raw(0, b"DNSPHY01"))
    reject("physical-bind-1", field(165, 1, "u8"))
    reject("physical-bind-1", field(167, 1, "u8"))
    reject("physical-bind-1", field(191, 1, "u8"))
    reject("physical-bind-1", field(172, 4, "u8"))
    reject("logical-bind-2", field(4, 65, "u16"))
    reject("logical-bind-2", field(72, 1000))
    reject("logical-bind-1", field(56, 1000000001))
    reject("logical-ack-allow", field(40, 2))
    reject("append-64", field(4, 65, "u16"))
    reject("append-64", field(48 + 8 * 63, 2000))
    reject("append-1", field(24, 0))
    reject("append-ack-allow", field(32, 1))
    for at, value, kind in [
        (108, 256, "u16"),
        (110, 513, "u16"),
        (112, 32769, "u32"),
        (112, 4294967295, "u32"),
        (116, 1, "u32"),
        (128, 0, "u64"),
        (136, 3, "u8"),
        (137, 2, "u8"),
        (138, 1, "u16"),
        (143, 1, "u8"),
    ]:
        reject("publish-1", field(at, value, kind))
    reject("publish-2", (76, "fill", [0, 32]))
    reject("publish-hosts", field(20, 1))
    reject("publish-hosts", field(144 + 104, 1, "u16"))
    reject("publish-hosts", field(144 + 124, 1, "u32"))
    reject("publish-hosts", field(144 + 96, 1000000001))
    reject("publish-hosts", field(144 + 128, 72, "u8"))
    reject("publish-hosts-max", field(144 + 108, 17, "u16"))
    reject("publish-hosts-max", field(144 + 664, 0, "u16"))
    reject("published-dns-allow", field(40, 257, "u16"))
    reject("published-dns-allow", field(32, 0))
    reject("waiter-bind-user", field(48, 0))
    reject("waiter-bind-hosts", field(40, 1))
    reject("waiter-bind-user", field(56, 1000000001))
    reject("waiter-bind-user", field(16, 18446744073709551615))
    reject("waiter-bound-hosts-allow", field(58, 1, "u8"))
    reject("waiter-bound-dns-allow", field(56, 257, "u16"))
    reject("numeric-class-1-use-1", field(2, 256, "u16"))
    reject("numeric-class-1-use-1", field(4, 0))
    reject("numeric-class-1-use-1", field(12, 1025, "u16"))
    reject("numeric-class-1-use-1", field(14, 3, "u8"))
    reject("numeric-class-1-use-1", field(15, 2, "u8"))
    reject("numeric-class-1-use-1", append=1064)
    reject("numeric-class-3-use-2", field(16 + len(probe(2)), 3, "u8"))
    reject("retired-3", field(24, 1, "u16"))
    reject("retired-4", field(28, 0, "u8"))
    reject("retired-unknown-custody", field(26, 65, "u16"))
    reject("retire-3", field(16, 1))
    reject("cancel-1", field(2, 8, "u8"))
    reject("cancel-6", field(4, 1, "u32"))
    return {
        "contract": "DNS_V2-CODEC-1",
        "packing": "stdlib struct.pack + explicit offset/type/value tables; no Rust encoder",
        "maximumDnsPayloadIsBoundsOnly": True,
        "negotiations": negotiations,
        "vectors": vectors,
        "rejectedBodies": rejected,
        "rejectedFrames": [
            {"case": "publish-1", "patches": [field(128 + 36, 8)]},
            {"case": "physical-bind-1", "patches": [field(166, 2, "u8")]},
            {"case": "physical-bind-1", "patches": [(16, "fill", [9, 32])]},
            {"case": "physical-bind-1", "patches": [], "rights": 0, "credentials": 0},
            {"case": "logical-bind-1", "patches": [], "rights": 1, "credentials": 1},
            {"case": "published-dns-allow", "patches": [field(24, 0)]},
            {"case": "published-dns-allow", "patches": [field(24, 10)]},
            {"case": "publish-1", "patches": [field(16, 0)]},
            {"case": "publish-1", "patches": [field(16, 18446744073709551615)]},
            {"case": "publish-1", "patches": [field(112, 1)]},
            {"case": "publish-1", "patches": [field(12, 4294967295, "u32")]},
            {"case": "publish-1", "patches": [field(8, 2, "u16")]},
            {"case": "publish-1", "patches": [field(10, 49, "u16")]},
            {"case": "publish-1", "patches": [(64, "fill", [9, 32])]},
        ],
        "snapshotRows": [
            {
                "flags": flags,
                "hex": pack(
                    76,
                    [
                        raw(0, bytes([1]) * 32),
                        raw(32, bytes([2]) * 32),
                        field(64, 170, "u32"),
                        field(68, 1, "u16"),
                        field(72, flags, "u32"),
                    ],
                ).hex(),
            }
            for flags in [2, 3, 4, 5, 6, 7]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = corpus()
    if args.check:
        target = pathlib.Path(__file__).with_name("dns-v2-canonical.json")
        if json.loads(target.read_text()) != json.loads(json.dumps(result)):
            raise SystemExit("DNS_V2 golden corpus отличается от field-table packer")
    else:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
