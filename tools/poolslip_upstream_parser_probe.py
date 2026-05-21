#!/usr/bin/env python3
"""Remote-only upstream parser state-machine probe for NGINX 1.31.1."""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass


STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})")
HEX_PTR_RE = re.compile(rb"0x[0-9a-fA-F]{10,16}")


@dataclass
class Case:
    name: str
    path: str


@dataclass
class Result:
    name: str
    statuses: str
    markers: int
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


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def statuses(data: bytes) -> str:
    found = [match.group(1).decode("ascii") for match in STATUS_RE.finditer(data)]
    return ",".join(found) if found else "-"


def binary_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    allowed = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    return sum(1 for byte in data if byte not in allowed) / len(data)


def canonical_word_count(data: bytes) -> int:
    count = 0
    for index in range(0, max(0, len(data) - 7)):
        value = int.from_bytes(data[index : index + 8], "little")
        if 0x0000550000000000 <= value <= 0x00007FFFFFFFFFFF:
            count += 1
    return count


def send_request(host: str, port: int, path: str, timeout: float) -> tuple[bytes, str]:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: poolslip-upstream-parser-probe/1.0\r\n"
        "Early-Hints: 1\r\n"
        "TE: trailers\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    chunks: list[bytes] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
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


def healthy(host: str, port: int, timeout: float) -> bool:
    data, _note = send_request(host, port, "/", timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def cases() -> list[Case]:
    proxy_names = [
        "invalid-status-alpha",
        "split-invalid-status",
        "split-valid-status",
        "header-no-colon",
        "header-control-byte",
        "duplicate-content-length",
        "cl-te-conflict",
        "chunk-overflow",
        "chunk-extension-long",
        "trailers-invalid",
        "trailers-long",
        "early-final-split",
        "early-invalid-final",
        "many-early-then-final",
    ]
    raw_names = [
        "scgi-status-header",
        "scgi-status-header-split",
        "scgi-status-header-onebyte",
        "http-valid-split",
        "http-invalid-split",
        "http-invalid-alpha",
        "header-control",
        "header-long",
        "duplicate-cl",
    ]

    built: list[Case] = []
    for name in proxy_names:
        built.append(Case("proxy-" + name, "/delay?case=raw-upstream&kind=" + urllib.parse.quote(name, safe="")))
    for module in ("scgi", "uwsgi"):
        for name in raw_names:
            built.append(Case(f"{module}-{name}", f"/{module}-raw?kind=" + urllib.parse.quote(name, safe="")))
    return built


def run_case(host: str, port: int, case: Case, timeout: float) -> Result:
    path = case.path
    data, note = send_request(host, port, path, timeout)
    time.sleep(0.05)
    health = "up" if healthy(host, port, timeout) else "down"
    return Result(
        name=case.name,
        statuses=statuses(data),
        markers=data.count(b"HTTP/1.1"),
        byte_len=len(data),
        digest=sha16(data),
        binary_ratio=binary_ratio(data),
        canonical_words=canonical_word_count(data),
        text_ptrs=len(HEX_PTR_RE.findall(data)),
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote-only upstream parser probe for NGINX 1.31.1.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=6.0)
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print("columns     case statuses markers bytes sha256/16 bin% ptr_words text_ptrs health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    suspicious = 0
    all_cases = cases()
    for case in all_cases:
        result = run_case(host, port, case, args.timeout)
        if (
            result.health != "up"
            or result.binary_ratio > 0.02
            or result.canonical_words
            or result.text_ptrs
            or result.note not in {"ok", "timeout"}
        ):
            suspicious += 1
        print(
            f"{result.name:<26} {result.statuses:<9} {result.markers:<7} {result.byte_len:<7} "
            f"{result.digest:<16} {result.binary_ratio:<6.3f} "
            f"{result.canonical_words:<9} {result.text_ptrs:<8} "
            f"{result.health:<6} {result.note}"
        )

    print(f"summary     suspicious={suspicious} cases={len(all_cases)}")
    return 1 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
