#!/usr/bin/env python3
"""Probe default-module subrequest/filter surfaces in the Poolslip ASAN lab."""

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
ASAN_RE = re.compile(rb"(AddressSanitizer|runtime error|ERROR:)")


@dataclass(frozen=True)
class Result:
    name: str
    statuses: str
    byte_len: int
    digest: str
    ptr_words: int
    text_ptrs: int
    health: str
    note: str


def split_target(value: str, fallback_port: int) -> tuple[str, int]:
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


def canonical_word_count(data: bytes) -> int:
    count = 0
    for index in range(0, max(0, len(data) - 7)):
        value = int.from_bytes(data[index : index + 8], "little")
        if 0x0000550000000000 <= value <= 0x00007FFFFFFFFFFF:
            count += 1
    return count


def send_request(host: str, port: int, raw: bytes, timeout: float) -> tuple[bytes, str]:
    chunks: list[bytes] = []

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(raw)

            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    return b"".join(chunks), "timeout"
                if not chunk:
                    return b"".join(chunks), "ok"
                chunks.append(chunk)
                if sum(len(part) for part in chunks) > 2 * 1024 * 1024:
                    return b"".join(chunks), "truncated-client"

    except OSError as exc:
        return b"".join(chunks), f"{type(exc).__name__}: {exc}"


def request(host: str, port: int, method: str, path: str, timeout: float, body: bytes = b"", extra: list[str] | None = None) -> tuple[bytes, str]:
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Connection: close",
    ]
    if extra:
        headers.extend(extra)
    if body:
        headers.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
    return send_request(host, port, raw, timeout)


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


def case_path(base: str, params: dict[str, str]) -> str:
    return base + "?" + urllib.parse.urlencode(params)


def build_cases() -> list[tuple[str, str, str, bytes, list[str] | None]]:
    cases: list[tuple[str, str, str, bytes, list[str] | None]] = []

    for kind in ("include", "many-includes", "nested-if", "long-param", "unterminated", "split-token"):
        for framing in ("length", "chunked"):
            path = case_path(
                "/ssi-proxy",
                {
                    "case": "ssi-gen",
                    "kind": kind,
                    "framing": framing,
                    "repeat": "32",
                    "size": "1536",
                    "pause_ms": "2",
                },
            )
            cases.append((f"ssi-{kind}-{framing}", "GET", path, b"", None))

    for body_size in (0, 1, 4096, 65535):
        body = b"M" * body_size
        path = case_path("/mirror-spray", {"case": "raw-gen", "mode": "valid"})
        cases.append((f"mirror-post-{body_size}", "POST", path, body, ["X-Delay: 0"]))

    for size in (0, 1, 255, 256, 4096, 65535):
        key = "K" * size
        cases.append((f"limit-req-key-{size}", "GET", case_path("/limit-req-lab", {"key": key}), b"", None))

    return cases


def run_case(host: str, port: int, timeout: float, case: tuple[str, str, str, bytes, list[str] | None]) -> Result:
    name, method, path, body, extra = case
    data, note = request(host, port, method, path, timeout, body, extra)
    time.sleep(0.02)
    health = "up" if healthy(host, port, timeout) else "down"
    return Result(
        name=name,
        statuses=statuses(data),
        byte_len=len(data),
        digest=sha16(data),
        ptr_words=canonical_word_count(data),
        text_ptrs=len(HEX_PTR_RE.findall(data)),
        health=health,
        note=note,
    )


def run(args: argparse.Namespace) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = split_target(args.target, args.port)
    cases = build_cases() * args.rounds
    start_logs = docker_logs(args.container)

    print(f"target      {host}:{port}")
    print(f"rounds      {args.rounds}")
    print("scope       SSI, mirror, limit_req/limit_conn remote HTTP traffic")
    print("columns     idx case statuses bytes sha256/16 ptr_words text_ptrs health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    suspicious = 0

    for index, case in enumerate(cases):
        result = run_case(host, port, args.timeout, case)
        is_suspicious = result.health != "up" or result.ptr_words or result.text_ptrs
        if is_suspicious:
            suspicious += 1

        print(
            f"{index:<4} {result.name:<28} {result.statuses:<9} {result.byte_len:<7} "
            f"{result.digest:<16} {result.ptr_words:<9} {result.text_ptrs:<8} "
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

    print(f"summary     suspicious={suspicious} cases={len(cases)}")
    return 1 if suspicious else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Subrequest/filter probe for NGINX Poolslip ASAN lab.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    parser.add_argument("--stop-on-suspicious", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
