#!/usr/bin/env python3
"""Probe the fixed proxy_set_body + HTTP/2 upstream DATA framing bug."""

from __future__ import annotations

import argparse
import re
import socket
import urllib.parse


BODY_RE = re.compile(rb"\r\n\r\n(.*)", re.DOTALL)


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port

    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)

    return value, fallback_port


def dechunk(body: bytes) -> bytes:
    out = bytearray()
    pos = 0

    while pos < len(body):
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            return body
        size_line = body[pos:line_end].split(b";", 1)[0]
        try:
            size = int(size_line, 16)
        except ValueError:
            return body
        pos = line_end + 2
        if size == 0:
            return bytes(out)
        out.extend(body[pos : pos + size])
        pos += size + 2

    return bytes(out)


def post(host: str, port: int, size: int, timeout: float) -> bytes:
    body = b"A" * size
    headers = (
        f"POST /h2-set-body HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: proxy-v2-set-body-probe/0.1\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    chunks: list[bytes] = []

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(headers)
        view = memoryview(body)
        for offset in range(0, len(body), 262144):
            sock.sendall(view[offset : offset + 262144])

        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    response = b"".join(chunks)
    match = BODY_RE.search(response)
    if not match:
        return response

    header = response[: match.start(1)].lower()
    body = match.group(1)
    if b"transfer-encoding: chunked" in header:
        body = dechunk(body)

    return body


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe proxy_set_body HTTP/2 DATA frame sizing.")
    parser.add_argument("--target", default="127.0.0.1:19361", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19361)
    parser.add_argument("--size", type=int, default=17 * 1024 * 1024)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print(f"body_size   {args.size}")
    print("route       POST /h2-set-body -> proxy_set_body $request_body -> proxy_http_version 2")

    result = post(host, port, args.size, args.timeout)
    text = result.decode("ascii", "replace")
    print("capture")
    print(text)

    if "oversized_data=true" in text or "parse=truncated" in text:
        print("verdict     vulnerable-framing")
        return 1

    if "parse=ok" in text and "max_data=16384" in text:
        print("verdict     fixed-framing")
        return 0

    print("verdict     inconclusive")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
