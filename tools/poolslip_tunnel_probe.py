#!/usr/bin/env python3
"""Remote-only CONNECT/tunnel stress probe for NGINX 1.31.1.

This probe exercises the new default HTTP tunnel module with raw HTTP traffic.
It records response shape and post-case health only; it does not read logs,
procfs, core files, debugger output, or container state.
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
    tunnel_payload: bytes | None = None


@dataclass
class Result:
    name: str
    statuses: str
    markers: int
    byte_len: int
    digest: str
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


def statuses(data: bytes) -> str:
    found = [match.group(1).decode("ascii") for match in STATUS_RE.finditer(data)]
    return ",".join(found) if found else "-"


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def send_raw(host: str, port: int, data: bytes, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(data)
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    return b"".join(chunks), "timeout"
                if not chunk:
                    return b"".join(chunks), "ok"
                chunks.append(chunk)
    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def send_case(host: str, port: int, case: Case, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(case.request)

            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    return b"".join(chunks), "ok"
                chunks.append(chunk)

                if case.tunnel_payload and b"\r\n\r\n" in b"".join(chunks):
                    if b"HTTP/1.1 200" not in b"".join(chunks):
                        continue
                    sock.sendall(case.tunnel_payload)
                    case = Case(case.name, case.request, None)

    except socket.timeout:
        return b"".join(chunks), "timeout"
    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def health_request(host: str, port: int) -> bytes:
    return (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


def healthy(host: str, port: int, timeout: float) -> bool:
    data, _note = send_raw(host, port, health_request(host, port), timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def connect_request(authority: str, host_header: str | None = None, extra: bytes = b"") -> bytes:
    if host_header is None:
        host_header = authority
    return (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: poolslip-tunnel-probe/1.0\r\n"
    ).encode("ascii") + extra + b"\r\n"


def build_cases() -> list[Case]:
    tunneled_get = (
        b"GET / HTTP/1.1\r\n"
        b"Host: backend.local\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    long_host = "a" * 240 + ".tunnel.local:19323"
    near_line_limit = "b" * 3900 + ".tunnel.local:19323"

    cases = [
        Case("valid-static-backend", connect_request("tunnel.local:19323"), tunneled_get),
        Case("valid-host-mismatch", connect_request("tunnel.local:19323", "other.local:19323"), tunneled_get),
        Case("missing-port", connect_request("tunnel.local")),
        Case("empty-port", connect_request("tunnel.local:")),
        Case("nondigit-port", connect_request("tunnel.local:x")),
        Case("overflow-port", connect_request("tunnel.local:999999")),
        Case("ipv6-loopback", connect_request("[::1]:19323")),
        Case("unterminated-ipv6", connect_request("[::1:19323")),
        Case("long-host", connect_request(long_host)),
        Case("near-line-limit", connect_request(near_line_limit)),
        Case("proxy-connection", connect_request("tunnel.local:19323", extra=b"Proxy-Connection: keep-alive\r\n")),
        Case("chunked-connect", connect_request("tunnel.local:19323", extra=b"Transfer-Encoding: chunked\r\n")),
    ]

    return cases


def run_case(host: str, port: int, case: Case, timeout: float) -> Result:
    data, note = send_case(host, port, case, timeout)
    time.sleep(0.05)
    health = "up" if healthy(host, port, timeout) else "down"
    return Result(
        name=case.name,
        statuses=statuses(data),
        markers=data.count(b"HTTP/1.1"),
        byte_len=len(data),
        digest=sha16(data),
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote-only NGINX tunnel module probe.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print("columns     case statuses markers bytes sha256/16 health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    anomalies = 0
    for case in build_cases():
        result = run_case(host, port, case, args.timeout)
        if result.health != "up" or result.note not in {"ok", "timeout"}:
            anomalies += 1
        print(
            f"{result.name:<22} {result.statuses:<9} {result.markers:<7} "
            f"{result.byte_len:<7} {result.digest:<16} {result.health:<6} {result.note}"
        )

    print(f"summary     anomalies={anomalies} cases={len(build_cases())}")
    return 1 if anomalies else 0


if __name__ == "__main__":
    raise SystemExit(main())
