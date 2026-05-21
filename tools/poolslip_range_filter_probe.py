#!/usr/bin/env python3
"""Range/static body filter probe for the Poolslip audit track.

The probe sends remote HTTP traffic only.  It stresses request-controlled
Range and If-Range parsing against a static file so ASAN, pool canaries, and
worker health can catch body-filter pointer/offset mistakes.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import subprocess
import time
import urllib.parse
from dataclasses import dataclass


STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})")
MEMSAFETY_RE = re.compile(
    rb"(AddressSanitizer|ERROR: AddressSanitizer|pool canary|"
    rb"heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV)"
)
UBSAN_RE = re.compile(rb"(UndefinedBehaviorSanitizer|runtime error)")


@dataclass
class Case:
    name: str
    method: str = "GET"
    path: str = "/files/pattern.bin"
    headers: list[tuple[str, str]] | None = None
    pipeline: bytes = b""


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


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def run_capture(argv: list[str]) -> bytes:
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError:
        return b""
    return proc.stdout


def docker_logs(container: str | None) -> bytes:
    if not container:
        return b""

    stream = run_capture(["docker", "logs", container])
    error_log = run_capture(
        ["docker", "exec", container, "sh", "-lc", "cat /app/logs/error.log 2>/dev/null || true"]
    )
    return stream + b"\n--- /app/logs/error.log ---\n" + error_log


def make_request(host: str, port: int, case: Case) -> bytes:
    lines = [
        f"{case.method} {case.path} HTTP/1.1",
        f"Host: {host}:{port}",
        "User-Agent: poolslip-range-filter-probe/1.0",
        "Connection: close" if not case.pipeline else "Connection: keep-alive",
    ]
    for name, value in case.headers or []:
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + case.pipeline


def send(host: str, port: int, payload: bytes, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
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
    request = (
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    data, _note = send(host, port, request, timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def pointerish(data: bytes) -> bool:
    if b"\x7fELF" in data:
        return True
    words = re.findall(rb"\b[0-9a-fA-F]{12,16}\b", data)
    return len(words) >= 2


def build_cases() -> list[Case]:
    huge = "92233720368547758070"
    many_small = ",".join(f"{i}-{i}" for i in range(0, 96, 2))
    many_sparse = ",".join(f"{i}-{i + 1}" for i in range(0, 4096, 257))
    pipelined = (
        "GET /files/pattern.bin HTTP/1.1\r\n"
        "Host: range.pipeline\r\n"
        "Range: bytes=0-0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    return [
        Case("baseline"),
        Case("single-start", headers=[("Range", "bytes=0-31")]),
        Case("single-middle", headers=[("Range", "bytes=1024-2047")]),
        Case("single-tail", headers=[("Range", "bytes=65500-65535")]),
        Case("suffix-small", headers=[("Range", "bytes=-32")]),
        Case("open-ended", headers=[("Range", "bytes=65000-")]),
        Case("unsat-past-end", headers=[("Range", "bytes=65536-65540")]),
        Case("zero-suffix", headers=[("Range", "bytes=-0")]),
        Case("overflow-start", headers=[("Range", f"bytes={huge}-")]),
        Case("overflow-end", headers=[("Range", f"bytes=0-{huge}")]),
        Case("spacey-range", headers=[("Range", "bytes= 0 - 7 , 8 - 15")]),
        Case("multi-small", headers=[("Range", "bytes=0-0,2-2,4-4,6-6")]),
        Case("multi-overlap", headers=[("Range", "bytes=0-31,16-47,32-63")]),
        Case("multi-many-small", headers=[("Range", f"bytes={many_small}")]),
        Case("multi-many-sparse", headers=[("Range", f"bytes={many_sparse}")]),
        Case("bad-unit", headers=[("Range", "items=0-7")]),
        Case("bad-token", headers=[("Range", "bytes=0-a")]),
        Case("if-range-bad-etag", headers=[("Range", "bytes=0-31"), ("If-Range", '"not-the-etag"')]),
        Case("if-range-date", headers=[("Range", "bytes=0-31"), ("If-Range", "Wed, 21 Oct 2015 07:28:00 GMT")]),
        Case("head-range", method="HEAD", headers=[("Range", "bytes=0-31")]),
        Case("pipeline-ranges", headers=[("Range", "bytes=0-31")], pipeline=pipelined),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Range/static body filter probe for NGINX Poolslip audit.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--container", help="optional Docker container for sanitizer/canary log detection")
    parser.add_argument("--strict-ubsan", action="store_true", help="treat UBSAN-only diagnostics as a failing result")
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       static file Range/If-Range header and body filter offsets")
    print("columns     case statuses bytes sha256/16 ptr health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container)
    suspicious = 0

    for case in build_cases():
        payload = make_request(host, port, case)
        data, note = send(host, port, payload, args.timeout)
        time.sleep(0.03)
        health = "up" if healthy(host, port, args.timeout) else "down"
        ptr = pointerish(data)
        status = statuses(data)
        print(f"{case.name:<18} {status:<9} {len(data):<7} {digest(data)} {str(ptr):<5} {health:<6} {note}")
        if health != "up" or ptr or MEMSAFETY_RE.search(data):
            suspicious += 1

    logs = docker_logs(args.container)
    delta = logs[len(start_logs) :] if start_logs and logs.startswith(start_logs) else logs
    memsafety = MEMSAFETY_RE.search(delta)
    ubsan = UBSAN_RE.search(delta)
    print(f"sanitizer_log_bytes {len(delta)}")
    print(f"memsafety_status {'hit' if memsafety else 'clean'}")
    print(f"ubsan_status {'hit' if ubsan else 'clean'}")
    print(f"summary     suspicious={suspicious} cases={len(build_cases())}")

    if suspicious or memsafety or (args.strict_ubsan and ubsan):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
