#!/usr/bin/env python3
"""Cache-enabled upstream finalization probe for NGINX 1.31.1.

This targets the clang-analyzer report where `r->cache` is non-null during
upstream finalization.  The lab route enables proxy cache and intercepted error
responses, then drives finalization before buffered body piping has started.
The expected safe behavior is a clean client response and no ASAN output.
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
class Case:
    name: str
    method: str
    path: str
    repeat: int = 1


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


def raw_hex_response(status: str, headers: list[tuple[str, str]], body: bytes) -> str:
    head = f"HTTP/1.1 {status}\r\n".encode("ascii")
    for name, value in headers:
        head += f"{name}: {value}\r\n".encode("ascii")
    return (head + b"\r\n" + body).hex()


def build_cases() -> list[Case]:
    ok = "/cache-lab?case=raw-gen&mode=valid"
    body = b"cache miss body\n"
    not_found = "/cache-lab?case=raw-hex&data=" + raw_hex_response(
        "404 Not Found",
        [("Content-Length", "0"), ("Cache-Control", "max-age=60")],
        b"",
    )
    error = "/cache-lab?case=raw-hex&data=" + raw_hex_response(
        "500 Internal Server Error",
        [("Content-Length", str(len(body))), ("Cache-Control", "max-age=60")],
        body,
    )
    truncated = "/cache-lab?case=raw-hex&data=" + raw_hex_response(
        "200 OK",
        [("Content-Length", "4096"), ("Cache-Control", "max-age=60")],
        b"T" * 64,
    )
    no_body = "/cache-lab?case=raw-hex&data=" + raw_hex_response(
        "204 No Content",
        [("Cache-Control", "max-age=60")],
        b"",
    )

    return [
        Case("get-200-cache-fill", "GET", ok, repeat=2),
        Case("head-200-cache-fill", "HEAD", ok, repeat=2),
        Case("intercept-404-cache", "GET", not_found, repeat=2),
        Case("intercept-500-cache", "GET", error, repeat=2),
        Case("head-intercept-500", "HEAD", error, repeat=2),
        Case("truncated-cacheable", "GET", truncated),
        Case("no-content-cacheable", "GET", no_body, repeat=2),
    ]


def statuses(data: bytes) -> str:
    found = [match.group(1).decode("ascii") for match in STATUS_RE.finditer(data)]
    return ",".join(found) if found else "-"


def sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def request(host: str, port: int, method: str, path: str, timeout: float) -> tuple[bytes, str]:
    req = (
        f"{method} {path} HTTP/1.1\r\n"
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
    data, _note = request(host, port, "GET", "/", timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


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


def run_case(host: str, port: int, case: Case, timeout: float) -> Result:
    combined = bytearray()
    notes = []
    for _ in range(case.repeat):
        data, note = request(host, port, case.method, case.path, timeout)
        combined.extend(data)
        notes.append(note)
        time.sleep(0.05)

    health = "up" if healthy(host, port, timeout) else "down"
    data = bytes(combined)
    return Result(
        name=case.name,
        statuses=statuses(data),
        markers=data.count(b"HTTP/1.1"),
        byte_len=len(data),
        digest=sha16(data),
        health=health,
        note=",".join(notes),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Cache-enabled upstream finalization probe.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       proxy_cache + intercepted upstream responses under ASAN")
    print("columns     case statuses markers bytes sha256/16 health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container)
    suspicious = 0

    for case in build_cases():
        result = run_case(host, port, case, args.timeout)
        is_suspicious = result.health != "up" or result.note.startswith(("ConnectionResetError", "ConnectionAbortedError"))
        suspicious += 1 if is_suspicious else 0
        print(
            f"{result.name:<22} {result.statuses:<15} {result.markers:<7} "
            f"{result.byte_len:<7} {result.digest:<16} {result.health:<6} {result.note}"
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
