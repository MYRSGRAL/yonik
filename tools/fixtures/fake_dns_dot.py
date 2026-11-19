#!/usr/bin/env python3
"""Тестовый DNS-over-TLS сервер для изолированного стенда Fake DNS."""

import argparse
import asyncio
import logging
import ssl
import struct
from contextlib import suppress
from ipaddress import ip_address
from pathlib import Path

MAX_QUERY_BYTES = 4096
DNS_HEADER_BYTES = 12
REAL_ADDRESS = ip_address("192.0.2.99").packed
REAL_NAMES = frozenset({"real.test", "restored.test", "printer.corp.test"})


def response(query: bytes, tls_version: str | None) -> bytes:
    """Отвечает на один обычный IN-вопрос и поддерживает EDNS стенда."""
    flags, questions, answers, authority, additional = struct.unpack_from(
        "!5H", query, 2
    )
    if flags & 0xF800 or questions != 1 or answers or authority or additional > 1:
        raise ValueError("Неподдерживаемый DNS-запрос стенда")

    labels: list[str] = []
    offset = DNS_HEADER_BYTES
    while True:
        if offset >= len(query):
            raise ValueError("Обрезанное имя DNS")
        length = query[offset]
        offset += 1
        if not length:
            break
        if length > 63 or offset + length > len(query):
            raise ValueError("Некорректная метка DNS")
        labels.append(query[offset : offset + length].decode("ascii"))
        offset += length
    qtype, qclass = struct.unpack_from("!2H", query, offset)
    offset += 4
    if qclass != 1:
        raise ValueError("Стенд принимает только класс IN")

    edns = b""
    if additional:
        options = query[offset:]
        if len(options) < 11 or not options.startswith(b"\x00\x00\x29"):
            raise ValueError("Некорректная запись OPT")
        if len(options) != 11 + struct.unpack_from("!H", options, 9)[0]:
            raise ValueError("Некорректная длина записи OPT")
        edns = b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
    elif len(query) != offset:
        raise ValueError("Лишние данные запроса")

    name = ".".join(labels).lower()
    known = name in REAL_NAMES
    if known:
        logging.info("YONIK_DOT_QUERY %s %s", name, tls_version)
    if name == "example.test" or name.endswith(".example.test"):
        logging.error("YONIK_DOT_FAKE_QUERY_LEAK %s", name)

    answer = b""
    if known and qtype == 1:
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + REAL_ADDRESS
    reply_flags = 0x8080 | (flags & 0x0100) | (0 if known else 3)
    header = struct.pack("!5H", reply_flags, 1, bool(answer), 0, bool(edns))
    return query[:2] + header + query[DNS_HEADER_BYTES:offset] + answer + edns


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    tls = writer.get_extra_info("ssl_object")
    assert isinstance(tls, ssl.SSLObject)
    try:
        while True:
            async with asyncio.timeout(12):
                (length,) = struct.unpack("!H", await reader.readexactly(2))
                if not DNS_HEADER_BYTES < length <= MAX_QUERY_BYTES:
                    return
                query = await reader.readexactly(length)
                reply = response(query, tls.version())
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
    except (asyncio.IncompleteReadError, OSError, ValueError, struct.error) as error:
        logging.debug("Тестовое DNS-соединение завершено: %s", error)
    finally:
        writer.close()
        with suppress(OSError):
            async with asyncio.timeout(2):
                await writer.wait_closed()


async def serve(address: str, port: int, certificate: Path, private_key: Path) -> None:
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certificate, private_key)
    server = await asyncio.start_server(
        handle, address, port, ssl=tls, ssl_handshake_timeout=5
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", type=ip_address)
    parser.add_argument("certificate", type=Path)
    parser.add_argument("private_key", type=Path)
    parser.add_argument("--port", type=int, default=1853)
    options = parser.parse_args()
    if not 1 <= options.port <= 65535:
        parser.error("Порт должен быть от 1 до 65535")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(
        serve(
            str(options.address), options.port, options.certificate, options.private_key
        )
    )


if __name__ == "__main__":
    main()
