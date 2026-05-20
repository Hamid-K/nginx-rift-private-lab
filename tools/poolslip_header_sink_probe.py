#!/usr/bin/env python3
"""Remote-only header/trailer sink stress probe for NGINX 1.31.1.

This probe is for the "new vulnerability" track, not the older Rift/LFI chain.
It exercises response paths that would become useful ASLR disclosure sinks if a
separate corruption can alter NGINX header/trailer metadata:

* final proxied headers
* 103 Early Hints
* chunked response trailers

The tool records only bytes returned by the HTTP service and fresh health
checks. It does not read files, procfs, logs, coredumps, debugger state, or
container metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import time
import urllib.parse
from dataclasses import dataclass


HEX_PTR_RE = re.compile(rb"0x[0-9a-fA-F]{10,16}")


@dataclass
class ProbeResult:
    name: str
    path: str
    statuses: str
    status_markers: int
    byte_len: int
    digest: str
    binary_ratio: float
    canonical_words: int
    text_ptrs: int
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


def raw_request(host: str, port: int, path: str, timeout: float) -> bytes:
    host_header = f"{host}:{port}"
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: poolslip-header-sink-probe/1.0\r\n"
        "Accept: */*\r\n"
        "Early-Hints: 1\r\n"
        "TE: trailers\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(req)
        chunks = []

        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break

            if not chunk:
                break

            chunks.append(chunk)

    return b"".join(chunks)


def healthy(host: str, port: int, timeout: float) -> bool:
    try:
        data = raw_request(host, port, "/", timeout)
    except OSError:
        return False

    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def binary_ratio(data: bytes) -> float:
    if not data:
        return 0.0

    allowed = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    binary = sum(1 for byte in data if byte not in allowed)
    return binary / len(data)


def canonical_word_count(data: bytes) -> int:
    count = 0
    for index in range(0, max(0, len(data) - 7)):
        value = int.from_bytes(data[index : index + 8], "little")
        if 0x0000550000000000 <= value <= 0x00007FFFFFFFFFFF:
            count += 1
    return count


def response_statuses(data: bytes) -> str:
    statuses = []
    for match in re.finditer(rb"HTTP/1\.[01] ([0-9]{3})", data):
        statuses.append(match.group(1).decode("ascii"))

    return ",".join(statuses) if statuses else "-"


def run_probe(host: str, port: int, name: str, path: str, timeout: float) -> ProbeResult:
    note = "ok"
    try:
        data = raw_request(host, port, path, timeout)
    except OSError as exc:
        data = b""
        note = f"{type(exc).__name__}: {exc}"

    time.sleep(0.05)
    health = "up" if healthy(host, port, timeout) else "down"
    return ProbeResult(
        name=name,
        path=path,
        statuses=response_statuses(data),
        status_markers=data.count(b"HTTP/1.1"),
        byte_len=len(data),
        digest=sha16(data),
        binary_ratio=binary_ratio(data),
        canonical_words=canonical_word_count(data),
        text_ptrs=len(HEX_PTR_RE.findall(data)),
        health=health,
        note=note,
    )


def default_cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []

    for count, size in [(8, 64), (32, 128), (96, 64), (160, 32), (12, 1024)]:
        cases.append((f"headers-n{count}-s{size}", f"/delay?case=many-headers&n={count}&size={size}"))

    for count, size in [(4, 64), (16, 128), (48, 64), (96, 32), (8, 1024)]:
        cases.append((f"early-n{count}-s{size}", f"/delay?case=early-hints-many&n={count}&size={size}"))

    for count, size in [(4, 64), (16, 128), (48, 64), (96, 32), (8, 1024)]:
        cases.append((f"trailers-n{count}-s{size}", f"/delay?case=chunked-trailers-many&n={count}&size={size}"))

    return cases


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remote-only NGINX 1.31.1 header/trailer disclosure-sink probe."
    )
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument(
        "--case",
        action="append",
        help="additional NAME=PATH probe case; may be supplied multiple times",
    )
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    cases = default_cases()

    if args.case:
        for item in args.case:
            if "=" not in item:
                parser.error("--case must use NAME=PATH")
            name, path = item.split("=", 1)
            cases.append((name, path))

    print(f"target      {host}:{port}")
    print("scope       remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print("columns     case statuses markers bytes sha256/16 bin% ptr_words text_ptrs health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    suspicious = 0
    for name, path in cases:
        result = run_probe(host, port, name, path, args.timeout)
        if result.binary_ratio > 0.02 or result.canonical_words or result.text_ptrs or result.health != "up":
            suspicious += 1

        print(
            f"{result.name:<18} {result.statuses:<9} {result.status_markers:<7} {result.byte_len:<7} "
            f"{result.digest:<16} {result.binary_ratio:<6.3f} "
            f"{result.canonical_words:<9} {result.text_ptrs:<8} "
            f"{result.health:<6} {result.note}"
        )

    print(f"summary     suspicious={suspicious} cases={len(cases)}")
    return 1 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
