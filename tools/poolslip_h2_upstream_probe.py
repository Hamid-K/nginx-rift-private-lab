#!/usr/bin/env python3
"""HTTP/2 upstream parser probe for the NGINX Poolslip audit track.

The client speaks ordinary HTTP/1.1 to NGINX.  The lab config uses
`proxy_http_version 2` to a raw local upstream that rotates through controlled
HTTP/2 frame sequences.  This exercises `ngx_http_proxy_v2_module` under ASAN.
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
ASAN_RE = re.compile(rb"(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|ERROR:)")


@dataclass
class Result:
    index: int
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


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def statuses(data: bytes) -> str:
    found = [match.group(1).decode("ascii") for match in STATUS_RE.finditer(data)]
    return ",".join(found) if found else "-"


def request(host: str, port: int, path: str, timeout: float) -> tuple[bytes, str]:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    chunks: list[bytes] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
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
    data, _note = request(host, port, "/", timeout)
    return b"HTTP/1.1 200" in data or b"HTTP/2 200" in data


def docker_logs(container: str) -> bytes:
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


def run_one(index: int, host: str, port: int, timeout: float) -> Result:
    data, note = request(host, port, f"/h2-upstream?i={index}", timeout)
    time.sleep(0.03)
    health = "up" if healthy(host, port, timeout) else "down"
    return Result(
        index=index,
        statuses=statuses(data),
        markers=data.count(b"HTTP/1.1"),
        byte_len=len(data),
        digest=sha16(data),
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="NGINX HTTP/2 upstream parser ASAN probe.")
    parser.add_argument("--target", default="127.0.0.1:19361", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19361)
    parser.add_argument("--iterations", type=int, default=120)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    parser.add_argument("--stop-on-suspicious", action="store_true")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print(f"iterations  {args.iterations}")
    print("scope       client HTTP/1.1 to NGINX; NGINX proxy_http_version 2 to raw local upstream")
    print("columns     idx statuses markers bytes sha256/16 health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container) if args.container else b""
    suspicious = 0

    for index in range(args.iterations):
        result = run_one(index, host, port, args.timeout)
        is_suspicious = result.health != "up" or result.note.startswith(("ConnectionResetError", "ConnectionAbortedError"))
        if is_suspicious:
            suspicious += 1

        print(
            f"{result.index:<5} {result.statuses:<9} {result.markers:<7} {result.byte_len:<7} "
            f"{result.digest:<16} {result.health:<6} {result.note}"
        )

        if is_suspicious and args.stop_on_suspicious:
            break

    if args.container:
        end_logs = docker_logs(args.container)
        delta = end_logs[len(start_logs) :] if end_logs.startswith(start_logs) else end_logs
        print(f"asan_log_bytes {len(delta)}")
        if ASAN_RE.search(delta):
            print("asan_status found")
            suspicious += 1
        else:
            print("asan_status clean")

    print(f"summary     suspicious={suspicious} iterations={args.iterations}")
    return 1 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
