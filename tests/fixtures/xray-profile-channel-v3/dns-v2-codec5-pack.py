"""Независимые CODEC5 field-table vectors, не dump Rust encoder."""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def pack(size: int, fields: list[list[int | str]]) -> bytes:
    result = bytearray(size)
    for at, kind, value in fields:
        assert isinstance(at, int) and isinstance(kind, str)
        struct.pack_into(
            {"u8": ">B", "u16": ">H", "u32": ">I", "u64": ">Q"}[kind], result, at, value
        )
    return bytes(result)


def corpus() -> dict:
    old = json.loads((ROOT / "dns-v2-codec4.json").read_text())
    negotiations = []
    for item in old["negotiations"]:
        descriptor = bytearray.fromhex(item["descriptorHex"])
        descriptor[208:240] = hashlib.sha256(b"YONIK-DNS-V2-CODEC-5\0").digest()
        negotiations.append(
            {
                "mode": item["mode"],
                "launchHex": item["launchHex"],
                "descriptorHex": descriptor.hex(),
                "ackHex": (b"DNSACK02" + hashlib.sha256(descriptor).digest()).hex(),
            }
        )
    bind = [
        [0, "u16", 2],
        [8, "u64", 31],
        [16, "u64", 21],
        [24, "u64", 11],
        [32, "u64", 1],
        [40, "u64", 7],
        [48, "u16", 1],
        [50, "u8", 0],
        [52, "u32", 20],
    ]
    allow = [
        [0, "u16", 2],
        [2, "u8", 1],
        [8, "u64", 41],
        [16, "u64", 21],
        [24, "u64", 11],
        [32, "u64", 31],
        [40, "u64", 7],
        [48, "u32", 15],
        [52, "u16", 1],
        [54, "u8", 0],
    ]
    cancel = [[0, "u16", 2], [2, "u8", 9], [8, "u64", 41]]
    vectors = []
    for name, kind, size, fields in [
        ("bind", 57, 64, bind),
        ("bound", 58, 64, allow),
        ("deny", 58, 64, [[0, "u16", 2], [2, "u8", 2]]),
        ("unknown", 58, 64, [[0, "u16", 2], [2, "u8", 3]]),
        ("cancel-parent", 47, 24, cancel),
    ]:
        body = pack(size, fields)
        header = bytearray(128)
        header[:8] = b"YNKCAP01"
        for at, fmt, value in [
            (8, ">H", 1),
            (10, ">H", kind),
            (12, ">I", 128 + size),
            (16, ">Q", 10 if kind == 58 else 9),
            (24, ">Q", 9 if kind == 58 else 0),
            (96, ">Q", 5),
            (104, ">Q", 7),
        ]:
            struct.pack_into(fmt, header, at, value)
        header[32:48] = bytes([2]) * 16
        header[48:64] = bytes([3]) * 16
        header[64:96] = bytes([1]) * 32
        vectors.append(
            {
                "name": name,
                "kind": kind,
                "fields": fields,
                "bodyHex": body.hex(),
                "frameHex": (header + body).hex(),
                "rights": 0,
                "credentials": 0,
            }
        )
    rejected = []
    for at, kind, value in [
        (2, "u8", 1),
        (8, "u64", 0),
        (16, "u64", 2**64 - 1),
        (24, "u64", 0),
        (32, "u64", 0),
        (40, "u64", 0),
        (48, "u16", 512),
        (50, "u8", 2),
        (51, "u8", 1),
        (52, "u32", 0),
        (52, "u32", 1001),
        (56, "u8", 1),
    ]:
        body = bytearray(pack(64, bind))
        change = pack(64, [[at, kind, value]])
        length = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}[kind]
        body[at : at + length] = change[at : at + length]
        rejected.append({"kind": 57, "bodyHex": body.hex()})
    return {
        "contract": "DNS_V2-CODEC-5",
        "negotiations": negotiations,
        "vectors": vectors,
        "rejectedBodies": rejected,
        "codec4BasisSha256": hashlib.sha256(
            (ROOT / "dns-v2-codec4.json").read_bytes()
        ).hexdigest(),
    }


def main() -> None:
    data = (json.dumps(corpus(), indent=2) + "\n").encode()
    target = ROOT / "dns-v2-codec5.json"
    if "--check" in sys.argv:
        assert target.read_bytes() == data
    else:
        target.write_bytes(data)


if __name__ == "__main__":
    main()
