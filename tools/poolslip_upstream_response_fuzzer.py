#!/usr/bin/env python3
"""Source-guided upstream response fuzzer for the Poolslip audit track.

This drives NGINX through its proxy upstream parser using a lab backend that
generates caller-selected raw HTTP response shapes.  It is intended for ASAN
validation of parser and response-metadata bugs, not for exploit payloads.
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
HEX_PTR_RE = re.compile(rb"0x[0-9a-fA-F]{10,16}")
ASAN_RE = re.compile(rb"(AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|ERROR:)")


@dataclass
class Result:
    index: int
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
        "User-Agent: poolslip-upstream-response-fuzzer/1.0\r\n"
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


def build_path(rng: random.Random) -> tuple[str, str]:
    mode = rng.choice(
        [
            "valid",
            "split-status",
            "invalid-status",
            "many-early",
            "early-final",
            "header-heavy",
            "chunk-ext",
            "chunk-overflow",
            "trailers",
            "malformed-header",
            "truncated",
        ]
    )

    count = rng.choice([1, 2, 4, 8, 16, 32, 96])
    size = rng.choice([0, 1, 8, 64, 512, 2048, 4096, 8192])
    trailer_size = rng.choice([0, 16, 512, 4096, 8192])
    body_size = rng.choice([0, 1, 16, 512, 4096])
    split = rng.choice([0, 1, 4, 8, 16, 64, 512, 2048, 8192, 16384, 32768])
    pause_ms = rng.choice([0, 1, 10, 50, 100])

    if mode in {"split-status", "invalid-status", "malformed-header", "valid"}:
        count = min(count, 4)
        size = min(size, 64)

    query = urllib.parse.urlencode(
        {
            "case": "raw-gen",
            "mode": "heavy-headers" if mode == "header-heavy" else mode,
            "n": str(count),
            "size": str(size),
            "split": str(split),
            "pause_ms": str(pause_ms),
            "body_size": str(body_size),
            "trailer_size": str(trailer_size),
        }
    )
    return mode, "/delay?" + query


def run_case(index: int, rng: random.Random, host: str, port: int, timeout: float) -> Result:
    name, path = build_path(rng)
    returned, note = send_request(host, port, path, timeout)
    time.sleep(0.02)
    health = "up" if healthy(host, port, timeout) else "down"
    return Result(
        index=index,
        name=name,
        statuses=statuses(returned),
        markers=returned.count(b"HTTP/1.1"),
        byte_len=len(returned),
        digest=sha16(returned),
        binary_ratio=binary_ratio(returned),
        canonical_words=canonical_word_count(returned),
        text_ptrs=len(HEX_PTR_RE.findall(returned)),
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Proxy upstream response fuzzer for NGINX Poolslip source audit.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--seed", type=int, default=0x315550)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    parser.add_argument("--stop-on-suspicious", action="store_true")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    rng = random.Random(args.seed)
    print(f"target      {host}:{port}")
    print(f"seed        {args.seed}")
    print(f"iterations  {args.iterations}")
    print("scope       client-driven upstream parser fuzzing through the local lab backend")
    print("columns     idx case statuses markers bytes sha256/16 bin% ptr_words text_ptrs health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container) if args.container else b""
    suspicious = 0
    by_name: dict[str, int] = {}

    for index in range(args.iterations):
        result = run_case(index, rng, host, port, args.timeout)
        by_name[result.name] = by_name.get(result.name, 0) + 1

        is_suspicious = (
            result.health != "up"
            or result.canonical_words > 0
            or result.text_ptrs > 0
            or result.note.startswith(("ConnectionResetError", "ConnectionAbortedError", "BrokenPipeError"))
        )

        if is_suspicious:
            suspicious += 1

        if is_suspicious or index % 25 == 0 or index == args.iterations - 1:
            print(
                f"{result.index:<5} {result.name:<18} {result.statuses:<11} {result.markers:<7} {result.byte_len:<7} "
                f"{result.digest:<16} {result.binary_ratio:<6.3f} {result.canonical_words:<9} {result.text_ptrs:<8} "
                f"{result.health:<6} {result.note}"
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

    names = ", ".join(f"{name}:{count}" for name, count in sorted(by_name.items()))
    print(f"case_mix    {names}")
    print(f"summary     suspicious={suspicious} iterations={args.iterations}")
    return 1 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
