#!/usr/bin/env python3
"""CONNECT plus proxy-auth probe for the Poolslip source audit track.

This sends remote HTTP traffic only.  It targets the code added for CONNECT
proxy authentication and tunnel handling, then checks for sanitizer/canary
findings in the local Docker lab when a container name is supplied.
"""

from __future__ import annotations

import argparse
import base64
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
    authority: str
    headers: list[tuple[str, str]]
    body: bytes = b""
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


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def basic(user: bytes, password: bytes) -> str:
    return "Basic " + base64.b64encode(user + b":" + password).decode("ascii")


def make_connect(case: Case) -> bytes:
    lines = [
        f"CONNECT {case.authority} HTTP/1.1",
        f"Host: {case.authority}",
        "User-Agent: poolslip-connect-auth-probe/1.0",
    ]
    lines.extend(f"{name}: {value}" for name, value in case.headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "ignore") + case.body


def send(host: str, port: int, payload: bytes, split: int, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []
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
    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def healthy(host: str, port: int, timeout: float) -> bool:
    request = (
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    data, _note = send(host, port, request, 0, timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


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


def build_cases() -> list[Case]:
    valid = basic(b"pooluser", b"pass")
    long_user = basic(b"A" * 4096, b"pass")
    long_pass = basic(b"pooluser", b"B" * 4096)
    binary = basic(bytes(range(1, 128)), b"pw")
    invalid_b64 = "Basic " + "A" * 8191 + "!"

    return [
        Case("no-auth", "auth.tunnel.local:19323", []),
        Case("authorization-not-proxy", "auth.tunnel.local:19323", [("Authorization", valid)]),
        Case("invalid-scheme", "auth.tunnel.local:19323", [("Proxy-Authorization", "Bearer token")]),
        Case("invalid-base64", "auth.tunnel.local:19323", [("Proxy-Authorization", invalid_b64)]),
        Case("valid-auth", "auth.tunnel.local:19323", [("Proxy-Authorization", valid)]),
        Case("valid-auth-extra-body", "auth.tunnel.local:19323", [("Proxy-Authorization", valid), ("Content-Length", "4")], b"PING"),
        Case("long-user", "auth.tunnel.local:19323", [("Proxy-Authorization", long_user)]),
        Case("long-pass", "auth.tunnel.local:19323", [("Proxy-Authorization", long_pass)]),
        Case("binary-user", "auth.tunnel.local:19323", [("Proxy-Authorization", binary)]),
        Case(
            "duplicate-proxy-auth",
            "auth.tunnel.local:19323",
            [("Proxy-Authorization", "Basic QQ=="), ("Proxy-Authorization", valid)],
        ),
        Case("proxy-connection", "auth.tunnel.local:19323", [("Proxy-Authorization", valid), ("Proxy-Connection", "keep-alive")]),
        Case("split-valid", "auth.tunnel.local:19323", [("Proxy-Authorization", valid)], split=12),
        Case("plain-tunnel-control", "tunnel.local:19323", []),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="CONNECT/proxy-auth ASAN probe for NGINX Poolslip audit.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN/canary log detection")
    parser.add_argument(
        "--strict-ubsan",
        action="store_true",
        help="treat UBSAN-only diagnostics as a failing result",
    )
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       CONNECT, auth_basic, Proxy-Authorization, tunnel boundary")
    print("columns     case statuses bytes sha256/16 health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container)
    suspicious = 0

    for case in build_cases():
        payload = make_connect(case)
        data, note = send(host, port, payload, case.split, args.timeout)
        time.sleep(0.05)
        health = "up" if healthy(host, port, args.timeout) else "down"
        status = statuses(data)
        print(f"{case.name:<24} {status:<9} {len(data):<7} {digest(data)} {health:<6} {note}")

        if health != "up" or MEMSAFETY_RE.search(data):
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
