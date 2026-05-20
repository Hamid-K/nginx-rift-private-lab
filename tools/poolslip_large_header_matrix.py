#!/usr/bin/env python3
"""Remote-only large-header and pipelining oracle matrix for NGINX 1.31.1.

This probe targets request/connection-pool behavior around
client_header_buffer_size and large_client_header_buffers. It only observes
HTTP responses, connection close behavior, and fresh health checks.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import time
import urllib.parse
from dataclasses import dataclass


STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})")


@dataclass
class Case:
    name: str
    request: bytes


@dataclass
class Result:
    name: str
    statuses: str
    markers: int
    byte_len: int
    digest: str
    closed: str
    health: str
    note: str


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port

    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)

    return value, fallback_port


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def statuses(data: bytes) -> str:
    found = [match.group(1).decode("ascii") for match in STATUS_RE.finditer(data)]
    return ",".join(found) if found else "-"


def send_raw(
    host: str, port: int, request: bytes, timeout: float, shutdown_write: bool = False
) -> tuple[bytes, bool, str]:
    chunks = []
    closed = False

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            if shutdown_write:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    return b"".join(chunks), closed, "timeout"

                if not chunk:
                    closed = True
                    break

                chunks.append(chunk)

    except OSError as exc:
        return b"".join(chunks), True, f"{type(exc).__name__}: {exc}"

    return b"".join(chunks), closed, "ok"


def request_header(host_header: str, path: str, header_size: int, connection: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"X-Fill: {'A' * header_size}\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    ).encode("ascii")


def request_many_headers(host_header: str, count: int, size: int, connection: str) -> bytes:
    lines = [
        "GET / HTTP/1.1",
        f"Host: {host_header}",
    ]
    for i in range(count):
        lines.append(f"X-Fill-{i:03d}: {'B' * size}")
    lines.append(f"Connection: {connection}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii")


def request_post_pipeline(host_header: str, header_size: int, body_size: int) -> bytes:
    first = (
        "POST /spray HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"X-Fill: {'C' * header_size}\r\n"
        f"Content-Length: {body_size}\r\n"
        "X-Delay: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii") + (b"D" * body_size)
    second = request_header(host_header, "/", 16, "close")
    return first + second


def build_cases(host: str, port: int) -> list[Case]:
    host_header = f"{host}:{port}"
    cases: list[Case] = []

    for size in [3500, 3900, 4096, 8000, 12000, 16000, 16360, 16384, 17000, 24000]:
        first = request_header(host_header, "/", size, "keep-alive")
        second = request_header(host_header, "/", 16, "close")
        cases.append(Case(f"single-{size}", first + second))

    for count, size in [(2, 3900), (4, 3900), (4, 8000), (5, 8000), (4, 16000), (5, 16000)]:
        first = request_many_headers(host_header, count, size, "keep-alive")
        second = request_header(host_header, "/", 16, "close")
        cases.append(Case(f"many-{count}x{size}", first + second))

    for header_size, body_size in [(3900, 1024), (8000, 4096), (16000, 4096), (16360, 8192)]:
        cases.append(Case(f"postpipe-h{header_size}-b{body_size}", request_post_pipeline(host_header, header_size, body_size)))

    return cases


def healthy(host: str, port: int, timeout: float) -> bool:
    host_header = f"{host}:{port}"
    data, _closed, _note = send_raw(host, port, request_header(host_header, "/", 16, "close"), timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote-only large-header/pipeline matrix for NGINX 1.31.1.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print("columns     case statuses markers bytes sha256/16 closed health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    anomalies = 0
    for case in build_cases(host, port):
        data, closed, note = send_raw(host, port, case.request, args.timeout)
        time.sleep(args.delay)
        health = "up" if healthy(host, port, args.timeout) else "down"
        marker_count = data.count(b"HTTP/1.1")
        status_text = statuses(data)

        if health != "up" or marker_count == 0 or note not in {"ok", "timeout"}:
            anomalies += 1

        print(
            f"{case.name:<24} {status_text:<9} {marker_count:<7} {len(data):<7} "
            f"{sha16(data):<16} {'yes' if closed else 'no':<6} {health:<6} {note}"
        )

    print(f"summary     anomalies={anomalies}")
    return 1 if anomalies else 0


if __name__ == "__main__":
    raise SystemExit(main())
