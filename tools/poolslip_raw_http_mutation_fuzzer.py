#!/usr/bin/env python3
"""Raw HTTP mutation fuzzer for the NGINX poolslip audit track.

This is intentionally transport-level and remote-only.  It sends malformed
HTTP/1.x request sequences to the lab target and uses worker health plus
optional Docker ASAN logs as the bug signal.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass


STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})")
ASAN_RE = re.compile(rb"(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|ERROR:|pool canary)")


@dataclass
class Result:
    index: int
    kind: str
    statuses: str
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

    try:
        err = subprocess.run(
            ["docker", "exec", container, "sh", "-lc", "cat /app/logs/error.log 2>/dev/null || true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError:
        return proc.stdout

    return proc.stdout + b"\n--- /app/logs/error.log ---\n" + err.stdout


def send_raw(host: str, port: int, payload: bytes, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            midpoint = len(payload) // 2

            if len(payload) > 256 and payload[0] % 5 == 0:
                sock.sendall(payload[:midpoint])
                time.sleep(0.005)
                sock.sendall(payload[midpoint:])
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
                if sum(len(part) for part in chunks) > 131072:
                    return b"".join(chunks), "truncated-client"

    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def healthy(host: str, port: int, timeout: float) -> bool:
    req = b"GET / HTTP/1.1\r\nHost: health.local\r\nConnection: close\r\n\r\n"
    data, _note = send_raw(host, port, req, timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def rand_token(rng: random.Random, min_len: int, max_len: int, alphabet: bytes) -> bytes:
    length = rng.randint(min_len, max_len)
    return bytes(rng.choice(alphabet) for _ in range(length))


def rand_path(rng: random.Random) -> bytes:
    atoms = [
        b"/",
        b"/delay?case=raw-upstream&kind=split-valid-status",
        b"/discard",
        b"/rewrite-old/",
        b"/sticky-cookie?domain=" + b"d" * rng.randint(0, 512),
        b"/" + b"A" * rng.choice([1, 64, 1024, 4096, 12000, 16360]),
        b"http://example.com/" + b"Q" * rng.randint(0, 2048),
    ]
    return rng.choice(atoms)


def header_line(rng: random.Random) -> bytes:
    names = [b"Host", b"X-Fuzz", b"Connection", b"Transfer-Encoding", b"Content-Length"]
    name = rng.choice(names)

    if rng.random() < 0.15:
        name = rand_token(rng, 1, 64, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_:")

    if name == b"Host":
        value = rng.choice([b"127.0.0.1", b"tunnel.local", b"[::1]:80", b"a" * rng.randint(1, 4096)])
    elif name == b"Connection":
        value = rng.choice([b"close", b"keep-alive", b"upgrade", b"TE, keep-alive", b"\x00close"])
    elif name == b"Transfer-Encoding":
        value = rng.choice([b"chunked", b"chunked, chunked", b"gzip, chunked", b"x"])
    elif name == b"Content-Length":
        value = str(rng.choice([0, 1, 2, 8, 1024, 65535, 999999999])).encode("ascii")
    else:
        value = rand_token(rng, 0, rng.choice([8, 64, 512, 4096, 12000]), b"ABCDEFabcdef0123456789_-/.:; ")

    if rng.random() < 0.08:
        return name + b": " + value + b"\r\n " + b"fold" * rng.randint(1, 16) + b"\r\n"

    return name + b": " + value + b"\r\n"


def body_for_headers(rng: random.Random, headers: list[bytes]) -> bytes:
    joined = b"".join(headers).lower()

    if b"transfer-encoding: chunked" in joined:
        chunks = []
        for _ in range(rng.randint(0, 8)):
            data = rand_token(rng, 0, rng.choice([1, 4, 64, 1024]), b"xyzXYZ0123456789")
            ext = b";" + b"e" * rng.randint(0, 1024) if rng.random() < 0.2 else b""
            chunks.append(f"{len(data):x}".encode("ascii") + ext + b"\r\n" + data + b"\r\n")
        chunks.append(rng.choice([b"0\r\n\r\n", b"0\r\nX-T: t\r\n\r\n", b"Z\r\nbad\r\n"]))
        return b"".join(chunks)

    if b"content-length:" in joined:
        return rand_token(rng, 0, rng.choice([0, 1, 8, 1024, 8192]), b"BODYbody0123456789")

    return b""


def make_case(index: int, rng: random.Random) -> tuple[str, bytes]:
    methods = [b"GET", b"POST", b"HEAD", b"CONNECT", b"PUT", b"OPTIONS"]
    method = rng.choice(methods)

    if method == b"CONNECT":
        target = rng.choice(
            [
                b"127.0.0.1:19323",
                b"127.0.0.2:19323",
                b"127.0.0.2:",
                b"127.0.0.2",
                b"backend:80",
                b"[::1]:80",
                b"a" * rng.randint(1, 4096),
            ]
        )
    else:
        target = rand_path(rng)

    version = rng.choice([b"HTTP/1.1", b"HTTP/1.0", b"HTTP/0.9", b"HTTP/2.0", b""])
    request_line = method + b" " + target + (b" " + version if version else b"") + b"\r\n"

    headers = [header_line(rng) for _ in range(rng.randint(1, 24))]
    if not any(h.lower().startswith(b"host:") for h in headers):
        headers.insert(0, b"Host: 127.0.0.1\r\n")

    body = body_for_headers(rng, headers)
    payload = request_line + b"".join(headers) + b"\r\n" + body

    if rng.random() < 0.25:
        payload += b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

    return method.decode("ascii", "ignore").lower(), payload


def run_one(index: int, rng: random.Random, host: str, port: int, timeout: float) -> Result:
    kind, payload = make_case(index, rng)
    data, note = send_raw(host, port, payload, timeout)
    health = "up" if healthy(host, port, timeout) else "down"

    return Result(
        index=index,
        kind=kind,
        statuses=statuses(data),
        byte_len=len(data),
        digest=sha16(data),
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Raw HTTP mutation fuzzer for NGINX ASAN labs.")
    parser.add_argument("--target", default="127.0.0.1:19341", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19341)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0x504f4f4c)
    parser.add_argument("--timeout", type=float, default=0.75)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    parser.add_argument("--log-every", type=int, default=100)
    parser.add_argument("--stop-on-suspicious", action="store_true")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    rng = random.Random(args.seed)

    print(f"target      {host}:{port}")
    print(f"seed        {args.seed}")
    print(f"iterations  {args.iterations}")
    print("scope       raw remote HTTP traffic; optional Docker log read only for local ASAN lab")
    print("columns     idx kind statuses bytes sha256/16 health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container)
    suspicious = 0

    for index in range(args.iterations):
        result = run_one(index, rng, host, port, args.timeout)
        is_suspicious = result.health != "up"

        if is_suspicious:
            suspicious += 1

        if is_suspicious or index % args.log_every == 0 or index == args.iterations - 1:
            print(
                f"{result.index:<5} {result.kind:<8} {result.statuses:<9} {result.byte_len:<7} "
                f"{result.digest:<16} {result.health:<6} {result.note}"
            )

        if args.container and (index + 1) % max(args.log_every, 1) == 0:
            end_logs = docker_logs(args.container)
            delta = end_logs[len(start_logs) :] if end_logs.startswith(start_logs) else end_logs
            if ASAN_RE.search(delta):
                print("asan_status found")
                return 1

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
