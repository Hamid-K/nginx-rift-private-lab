#!/usr/bin/env python3
"""Source-guided HTTP/1 request-sequence fuzzer for the Poolslip audit track.

The fuzzer sends only remote HTTP traffic to NGINX.  It is designed for the
local ASAN lab, but the default classification uses only client-visible
responses and fresh health checks.  Supplying --container additionally checks
Docker logs for sanitizer output after the run.
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


def simple_get(host_header: str, path: str = "/", connection: str = "close") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    ).encode("ascii")


def make_request(
    host_header: str,
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes = b"",
    http_version: str = "HTTP/1.1",
) -> bytes:
    lines = [f"{method} {path} {http_version}", f"Host: {host_header}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "ignore") + body


def chunked_body(rng: random.Random, flavor: str) -> bytes:
    if flavor == "tiny":
        count = rng.choice([1, 2, 7, 31, 97, 257])
        return b"".join(b"1\r\nA\r\n" for _ in range(count)) + b"0\r\n\r\n"

    if flavor == "extension":
        size = rng.choice([1, 2, 8, 32])
        ext = b"e" * rng.choice([128, 512, 2048, 8192, 12000])
        return f"{size:x};".encode("ascii") + ext + b"\r\n" + b"B" * size + b"\r\n0\r\n\r\n"

    if flavor == "trailer":
        trailer_size = rng.choice([16, 256, 2048, 8192, 14000])
        return b"4\r\nDATA\r\n0\r\nX-T: " + b"T" * trailer_size + b"\r\n\r\n"

    if flavor == "invalid":
        return rng.choice(
            [
                b"Z\r\nx\r\n0\r\n\r\n",
                b"10000000000000000\r\nx\r\n0\r\n\r\n",
                b"1\r\nx\r\n0\r\nBrokenTrailer\r\n\r\n",
            ]
        )

    size = rng.choice([0, 1, 15, 127, 1024, 4096, 12000])
    return f"{size:x}\r\n".encode("ascii") + b"C" * size + b"\r\n0\r\n\r\n"


def large_header_set(rng: random.Random) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []

    if rng.random() < 0.45:
        headers.append(("X-Fill", "A" * rng.choice([3900, 4095, 4096, 8000, 12000, 16360, 16384, 17000])))

    for i in range(rng.choice([0, 1, 2, 4, 5, 8])):
        headers.append((f"X-Many-{i:03d}", "B" * rng.choice([16, 512, 3900, 8000, 12000, 16000])))

    if rng.random() < 0.20:
        headers.append(("X-Obs", "".join(chr((j % 0x1f) + 1) for j in range(8))))

    return headers


def build_case(rng: random.Random, host: str, port: int) -> tuple[str, list[bytes], float]:
    host_header = f"{host}:{port}"
    flavor = rng.choice(
        [
            "large-get-pipeline",
            "many-large-pipeline",
            "discard-chunk-pipeline",
            "proxy-chunk-pipeline",
            "cl-short-pipeline",
            "cl-long-close",
            "invalid-framing",
            "upstream-edge",
            "rewrite-edge",
            "tunnel-connect",
        ]
    )

    if flavor == "large-get-pipeline":
        first = make_request(
            host_header,
            "GET",
            rng.choice(["/", "/files/pattern.bin", "/api/" + "r" * rng.choice([1, 256, 2048, 8000])]),
            large_header_set(rng) + [("Connection", "keep-alive")],
        )
        second = simple_get(host_header, "/", "close")
        return flavor, [first + second], 0.0

    if flavor == "many-large-pipeline":
        headers = [(f"X-Fill-{i:03d}", "M" * rng.choice([3900, 8000, 16000])) for i in range(rng.choice([2, 3, 4, 5]))]
        first = make_request(host_header, "GET", "/", headers + [("Connection", "keep-alive")])
        return flavor, [first + simple_get(host_header, "/", "close")], 0.0

    if flavor == "discard-chunk-pipeline":
        body = chunked_body(rng, rng.choice(["tiny", "extension", "trailer", "invalid", "plain"]))
        first = make_request(
            host_header,
            "GET",
            "/files/pattern.bin",
            large_header_set(rng) + [("Transfer-Encoding", "chunked"), ("Connection", "keep-alive")],
            body,
        )
        return flavor, [first + simple_get(host_header, "/", "close")], rng.choice([0.0, 0.02])

    if flavor == "proxy-chunk-pipeline":
        body = chunked_body(rng, rng.choice(["tiny", "extension", "trailer", "invalid", "plain"]))
        first = make_request(
            host_header,
            "POST",
            "/spray",
            large_header_set(rng)
            + [
                ("Transfer-Encoding", "chunked"),
                ("X-Delay", str(rng.choice([0, 0.01, 0.05]))),
                ("Connection", "keep-alive"),
            ],
            body,
        )
        return flavor, [first + simple_get(host_header, "/", "close")], rng.choice([0.0, 0.02])

    if flavor == "cl-short-pipeline":
        actual = rng.choice([0, 1, 8, 128, 4096])
        declared = rng.choice([0, 1, 8, 16, 1024])
        first = make_request(
            host_header,
            rng.choice(["GET", "POST"]),
            rng.choice(["/files/pattern.bin", "/spray"]),
            large_header_set(rng) + [("Content-Length", str(declared)), ("X-Delay", "0"), ("Connection", "keep-alive")],
            b"D" * actual,
        )
        return flavor, [first + simple_get(host_header, "/", "close")], 0.0

    if flavor == "cl-long-close":
        declared = rng.choice([1, 64, 4096, 65535])
        actual = rng.choice([0, 1, 16, 256])
        first = make_request(
            host_header,
            "POST",
            "/spray",
            large_header_set(rng) + [("Content-Length", str(declared)), ("X-Delay", "0"), ("Connection", "close")],
            b"E" * actual,
        )
        return flavor, [first], rng.choice([0.0, 0.01, 0.05])

    if flavor == "invalid-framing":
        headers = large_header_set(rng)
        if rng.random() < 0.5:
            headers.extend([("Content-Length", str(rng.choice([0, 1, 8]))), ("Content-Length", str(rng.choice([1, 9, 32])))])
        else:
            headers.extend([("Content-Length", str(rng.choice([1, 32]))), ("Transfer-Encoding", "chunked")])
        headers.append(("Connection", "keep-alive"))
        first = make_request(host_header, "POST", rng.choice(["/spray", "/files/pattern.bin"]), headers, b"0\r\n\r\n")
        return flavor, [first + simple_get(host_header, "/", "close")], 0.0

    if flavor == "upstream-edge":
        kinds = [
            "invalid-status-alpha",
            "split-invalid-status",
            "early-final-split",
            "early-invalid-final",
            "many-early-then-final",
            "chunk-extension-long",
            "trailers-long",
        ]
        path = "/delay?case=raw-upstream&kind=" + urllib.parse.quote(rng.choice(kinds), safe="")
        first = make_request(host_header, "GET", path, large_header_set(rng) + [("Early-Hints", "1"), ("TE", "trailers"), ("Connection", "keep-alive")])
        return flavor, [first + simple_get(host_header, "/", "close")], 0.0

    if flavor == "rewrite-edge":
        path = "/rewrite-old/" + rng.choice(["A" * 256, "%20" * 512, "%25" * 512, "%C3%A9" * 512])
        first = make_request(host_header, "GET", path, large_header_set(rng) + [("Connection", "keep-alive")])
        return flavor, [first + simple_get(host_header, "/", "close")], 0.0

    authority = rng.choice(["127.0.0.1:19323", "localhost:19323", "x" * rng.choice([64, 512, 4096]) + ":80", "[::1]:19323"])
    tunnel_host = "tunnel.local"
    req = make_request(
        tunnel_host,
        "CONNECT",
        authority,
        large_header_set(rng) + [("Host", tunnel_host), ("Connection", "close")],
    )
    return flavor, [req], 0.0


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


def healthy(host: str, port: int, timeout: float) -> bool:
    data, _closed, _note = send_segments(host, port, [simple_get(f"{host}:{port}")], 0.0, timeout)
    return b"HTTP/1.1 200" in data and b"poolslip lab ok" in data


def run_case(index: int, rng: random.Random, host: str, port: int, timeout: float) -> Result:
    name, segments, delay = build_case(rng, host, port)

    if len(segments) == 1 and rng.random() < 0.35 and len(segments[0]) > 64:
        raw = segments[0]
        split = rng.randrange(1, len(raw))
        segments = [raw[:split], raw[split:]]
        delay = rng.choice([0.001, 0.01, 0.05])
        name += "-split"

    data, closed, note = send_segments(host, port, segments, delay, timeout)
    time.sleep(0.02)
    health = "up" if healthy(host, port, timeout) else "down"
    return Result(
        index=index,
        name=name,
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote HTTP/1 request-sequence fuzzer for NGINX Poolslip source audit.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19331)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--seed", type=int, default=0x504f4f4c)
    parser.add_argument("--timeout", type=float, default=4.0)
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
    print("scope       remote HTTP traffic; optional Docker log read only for local ASAN lab")
    print("columns     idx case statuses markers bytes sha256/16 bin% ptr_words text_ptrs closed health note")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    start_logs = docker_logs(args.container) if args.container else b""
    suspicious = 0
    by_name: dict[str, int] = {}

    for index in range(args.iterations):
        result = run_case(index, rng, host, port, args.timeout)
        by_name[result.name.split("-split", 1)[0]] = by_name.get(result.name.split("-split", 1)[0], 0) + 1

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
                f"{result.index:<5} {result.name:<30} {result.statuses:<11} {result.markers:<7} {result.byte_len:<7} "
                f"{result.digest:<16} {result.binary_ratio:<6.3f} {result.canonical_words:<9} {result.text_ptrs:<8} "
                f"{result.closed:<6} {result.health:<6} {result.note}"
            )

        if is_suspicious and args.stop_on_suspicious:
            break

    asan_delta = b""
    if args.container:
        end_logs = docker_logs(args.container)
        asan_delta = end_logs[len(start_logs) :] if end_logs.startswith(start_logs) else end_logs
        print(f"asan_log_bytes {len(asan_delta)}")
        if ASAN_RE.search(asan_delta):
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
