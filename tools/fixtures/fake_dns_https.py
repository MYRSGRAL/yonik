"""HTTPS и DoH для одноразовой TUN VM. Запускать в namespace тестового peer."""

from __future__ import annotations

import argparse
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DNS_QUERY = bytes.fromhex("000001000001000000000000047265616c04746573740000010001")
DNS_ANSWER = (
    bytes.fromhex("000081800001000100000000")
    + DNS_QUERY[12:]
    + bytes.fromhex("c00c000100010000003c0004c0000263")
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 5

    def reply(self, media_type: str, body: bytes) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/" and self.headers.get("Host") == "example.test":
            self.reply("text/plain", b"YONIK_TLS_FIXTURE")
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if (
            self.path != "/dns-query"
            or self.headers.get("Host") != "doh.test"
            or self.headers.get("Content-Type") != "application/dns-message"
            or self.headers.get("Content-Length") != str(len(DNS_QUERY))
        ):
            self.send_error(HTTPStatus.BAD_REQUEST)
        elif self.rfile.read(len(DNS_QUERY)) != DNS_QUERY:
            self.send_error(HTTPStatus.BAD_REQUEST)
        else:
            self.reply("application/dns-message", DNS_ANSWER)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=Path)
    parser.add_argument("private_key", type=Path)
    options = parser.parse_args()

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(options.certificate, options.private_key)
    with ThreadingHTTPServer(("127.0.0.1", 24444), Handler) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
