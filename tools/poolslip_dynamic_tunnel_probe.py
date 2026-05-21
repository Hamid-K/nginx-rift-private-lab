#!/usr/bin/env python3
"""Dynamic tunnel_pass probe for the Poolslip audit track.

This targets the no-argument `tunnel_pass;` mode, where NGINX derives the
upstream from `$host:$request_port`.  It is separate from the fixed-upstream
tunnel lifecycle probe because this path exercises CONNECT authority parsing,
server selection, variable evaluation, and `ngx_parse_url()` together.
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
MEMSAFETY_RE = re.compile(
    rb"(AddressSanitizer|ERROR: AddressSanitizer|pool canary|"
    rb"heap-buffer-overflow|stack-buffer-overflow|use-after-free|SEGV)"
)
UBSAN_RE = re.compile(rb"(UndefinedBehaviorSanitizer|runtime error)")


@dataclass
class Case:
    name: str
    authority: str
    host_header: str
    headers: list[tuple[str, str]] | None = None
    after_200: bytes = b""
    split: int = 0


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


def make_connect(case: Case) -> bytes:
    lines = [
        f"CONNECT {case.authority} HTTP/1.1",
        f"Host: {case.host_header}",
        "User-Agent: poolslip-dynamic-tunnel-probe/1.0",
    ]
    for name, value in case.headers or []:
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", "ignore")


def tunneled_get() -> bytes:
    return b"GET / HTTP/1.1\r\nHost: backend.local\r\nConnection: close\r\n\r\n"


def send(host: str, port: int, payload: bytes, timeout: float, after_200: bytes = b"", split: int = 0) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    sent_after = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if split and split < len(payload):
                sock.sendall(payload[:split])
                time.sleep(0.02)
                sock.sendall(payload[split:])
            else:
                sock.sendall(payload)

            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    return b"".join(chunks), "timeout"
                if not chunk:
                    return b"".join(chunks), "ok"
                chunks.append(chunk)
                data = b"".join(chunks)
                if after_200 and not sent_after and b"HTTP/1.1 200" in data:
                    sock.sendall(after_200)
                    sent_after = True
    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def healthy(host: str, port: int, timeout: float) -> bool:
    payload = (
        "GET / HTTP/1.1\r\nHost: health.local\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    data, _note = send(host, port, payload, timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def pointerish(data: bytes) -> bool:
    if b"\x7fELF" in data:
        return True
    return len(re.findall(rb"\b[0-9a-fA-F]{12,16}\b", data)) >= 2


def build_cases() -> list[Case]:
    return [
        Case("dynamic-ip-ok", "127.0.0.2:19323", "127.0.0.2:19323", after_200=tunneled_get()),
        Case("dynamic-ip-split", "127.0.0.2:19323", "127.0.0.2:19323", after_200=tunneled_get(), split=17),
        Case("host-mismatch", "127.0.0.2:19323", "example.invalid:19323", after_200=tunneled_get()),
        Case("no-port", "127.0.0.2", "127.0.0.2", after_200=tunneled_get()),
        Case("colon-no-port", "127.0.0.2:", "127.0.0.2:", after_200=tunneled_get()),
        Case("non-numeric-port", "127.0.0.2:abc", "127.0.0.2:abc"),
        Case("zero-port", "127.0.0.2:0", "127.0.0.2:0"),
        Case("too-large-port", "127.0.0.2:999999", "127.0.0.2:999999"),
        Case("trailing-dot-ip", "127.0.0.2.:19323", "127.0.0.2.:19323"),
        Case("userinfo-shape", "user@127.0.0.2:19323", "user@127.0.0.2:19323"),
        Case("ipv6-empty-port", "[::1]:", "[::1]:"),
        Case("ipv6-loopback", "[::1]:19323", "[::1]:19323"),
        Case("body-before-tunnel", "127.0.0.2:19323", "127.0.0.2:19323", [("Content-Length", "4")], after_200=tunneled_get()),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Dynamic tunnel_pass parser/eval probe for NGINX Poolslip audit.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--container", help="optional Docker container for sanitizer/canary log detection")
    parser.add_argument("--strict-ubsan", action="store_true", help="treat UBSAN-only diagnostics as a failing result")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       CONNECT authority, $host:$request_port tunnel_pass eval, ngx_parse_url")
    print("columns     case statuses bytes sha256/16 ptr health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container)
    suspicious = 0

    for case in build_cases():
        data, note = send(host, port, make_connect(case), args.timeout, case.after_200, case.split)
        time.sleep(0.04)
        health = "up" if healthy(host, port, args.timeout) else "down"
        ptr = pointerish(data)
        print(f"{case.name:<20} {statuses(data):<9} {len(data):<7} {sha16(data)} {str(ptr):<5} {health:<6} {note}")
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
