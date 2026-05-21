#!/usr/bin/env python3
"""Focused CONNECT/tunnel lifecycle probe for NGINX 1.31.1.

The generic raw fuzzer reaches CONNECT, but this probe targets the new tunnel
module's upgrade boundary directly: request bodies, pipelined bytes before the
200 response, and tunneled bytes sent after upgrade.  It observes only the
client-visible response and optional local ASAN logs.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass


STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})")
HEX_PTR_RE = re.compile(rb"0x[0-9a-fA-F]{10,16}")
ASAN_RE = re.compile(rb"(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|ERROR:)")


@dataclass
class Case:
    name: str
    segments: list[bytes]
    after_200: bytes = b""
    delay: float = 0.0


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


def statuses(data: bytes) -> str:
    found = [match.group(1).decode("ascii") for match in STATUS_RE.finditer(data)]
    return ",".join(found) if found else "-"


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


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


def docker_logs(container: str | None) -> bytes:
    if not container:
        return b""

    try:
        proc = subprocess.run(
            ["docker", "logs", container],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError:
        return b""

    return proc.stdout


def simple_get(host_header: str) -> bytes:
    return (
        "GET / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


def tunneled_get() -> bytes:
    return b"GET / HTTP/1.1\r\nHost: backend.local\r\nConnection: close\r\n\r\n"


def connect_head(extra_headers: list[tuple[str, str]] | None = None) -> bytes:
    headers = [
        "CONNECT tunnel.local:19323 HTTP/1.1",
        "Host: tunnel.local",
        "User-Agent: poolslip-tunnel-lifecycle-probe/1.0",
    ]

    for name, value in extra_headers or []:
        headers.append(f"{name}: {value}")

    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")


def content_length_connect(length: int, body: bytes) -> bytes:
    return connect_head([("Content-Length", str(length))]) + body


def chunked_connect(body: bytes) -> bytes:
    return connect_head([("Transfer-Encoding", "chunked")]) + body


def build_cases() -> list[Case]:
    get = tunneled_get()
    chunked_done = b"4\r\nPING\r\n0\r\n\r\n"

    return [
        Case("plain-after-200", [connect_head()], after_200=get),
        Case("cl-zero-extra", [content_length_connect(0, get)]),
        Case("cl-body-after-200", [content_length_connect(4, b"PING")], after_200=get),
        Case("cl-body-extra", [content_length_connect(4, b"PING" + get)]),
        Case("cl-large-body-after-200", [content_length_connect(12000, b"A" * 12000)], after_200=get),
        Case("cl-short-timeout", [content_length_connect(4096, b"B" * 16)], delay=0.05),
        Case("chunked-after-200", [chunked_connect(chunked_done)], after_200=get),
        Case("chunked-extra", [chunked_connect(chunked_done + get)]),
        Case("chunked-long-ext", [chunked_connect(b"1;" + b"e" * 8192 + b"\r\nx\r\n0\r\n\r\n")], after_200=get),
        Case("expect-continue", [connect_head([("Content-Length", "4"), ("Expect", "100-continue")]), b"PING"], after_200=get, delay=0.05),
        Case("split-headers", [connect_head()[:32], connect_head()[32:]], after_200=get, delay=0.01),
        Case("split-body", [content_length_connect(4, b"PI"), b"NG"], after_200=get, delay=0.01),
    ]


def send_case(host: str, port: int, case: Case, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    sent_after_200 = False

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            for i, segment in enumerate(case.segments):
                sock.sendall(segment)
                if case.delay and i != len(case.segments) - 1:
                    time.sleep(case.delay)

            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    return b"".join(chunks), "timeout"

                if not chunk:
                    return b"".join(chunks), "ok"

                chunks.append(chunk)
                data = b"".join(chunks)

                if case.after_200 and not sent_after_200 and b"HTTP/1.1 200" in data:
                    sock.sendall(case.after_200)
                    sent_after_200 = True

    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def healthy(host: str, port: int, timeout: float) -> bool:
    data, _note = send_case(host, port, Case("health", [simple_get(f"{host}:{port}")]), timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


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
        binary_ratio=binary_ratio(data),
        canonical_words=canonical_word_count(data),
        text_ptrs=len(HEX_PTR_RE.findall(data)),
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Focused NGINX tunnel lifecycle probe.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       remote HTTP traffic; optional Docker log read only for local ASAN lab")
    print("columns     case statuses markers bytes sha256/16 bin% ptr_words text_ptrs health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container)
    suspicious = 0

    for case in build_cases():
        result = run_case(host, port, case, args.timeout)
        is_suspicious = (
            result.health != "up"
            or result.canonical_words
            or result.text_ptrs
            or result.note.startswith(("ConnectionResetError", "ConnectionAbortedError", "BrokenPipeError"))
        )
        suspicious += 1 if is_suspicious else 0
        print(
            f"{result.name:<24} {result.statuses:<11} {result.markers:<7} {result.byte_len:<7} "
            f"{result.digest:<16} {result.binary_ratio:<6.3f} {result.canonical_words:<9} "
            f"{result.text_ptrs:<8} {result.health:<6} {result.note}"
        )

    if args.container:
        end_logs = docker_logs(args.container)
        delta = end_logs[len(start_logs) :] if end_logs.startswith(start_logs) else end_logs
        print(f"asan_log_bytes {len(delta)}")
        if ASAN_RE.search(delta):
            print("asan_status found")
            suspicious += 1
        else:
            print("asan_status clean")

    print(f"summary     suspicious={suspicious} cases={len(build_cases())}")
    return 1 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
