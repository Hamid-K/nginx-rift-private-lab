#!/usr/bin/env python3
"""HTTP-only probes for NGINX 1.31.1 default-module audit leads.

The script intentionally avoids LFI/procfs/core/debugger access.  It only sends
requests and classifies response status, body length, and worker availability.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import socket
import sys
import urllib.parse


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port
    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, fallback_port


def request(host: str, port: int, method: str, path: str, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection(host, port, timeout=8)
    try:
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, dict(resp.getheaders()), body
    finally:
        conn.close()


def alive(host: str, port: int) -> bool:
    try:
        status, _headers, body = request(host, port, "GET", "/")
        return status == 200 and bool(body)
    except Exception:
        return False


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def range_probe(host: str, port: int) -> bool:
    print("[range/static]")
    status, headers, body = request(host, port, "GET", "/files/pattern.bin")
    if status != 200 or len(body) != 65536:
        print(f"  baseline: status={status} len={len(body)} unexpected")
        return False

    tests = [
        "bytes=0-15",
        "bytes=-16",
        "bytes=0-0,2-3",
        "bytes=65520-65535",
        "bytes=0-18446744073709551615",
        "bytes=18446744073709551600-18446744073709551615",
        "bytes=0-0," * 64 + "2-2",
    ]
    ok = True
    for header in tests:
        status, headers, out = request(host, port, "GET", "/files/pattern.bin", {"Range": header})
        sample = out[:64]
        verdict = "ok"
        if status == 206 and out and b"\x00" * 16 in sample:
            verdict = "check-zero-run"
            ok = False
        print(
            f"  {header[:48]:48} status={status:<3} len={len(out):<6} "
            f"cl={headers.get('Content-Length', '-'):<6} sha={digest(out)} {verdict}"
        )
    return ok and alive(host, port)


def range_upstream_probe(host: str, port: int) -> bool:
    print("[range/upstream]")
    expected_status, _headers, expected = request(
        host, port, "GET", "/forced-range?case=pattern-length"
    )
    if expected_status != 200 or len(expected) != 65536:
        print(f"  forced-range baseline: status={expected_status} len={len(expected)} unexpected")
        return False

    tests = [
        ("/forced-range?case=pattern-length", "bytes=0-15", expected[0:16]),
        ("/forced-range?case=pattern-length", "bytes=65520-65535", expected[65520:65536]),
        ("/forced-range?case=pattern-length", "bytes=0-0,2-3", None),
        ("/stream?case=pattern-length", "bytes=0-15", None),
        ("/stream?case=pattern-chunked", "bytes=0-15", None),
    ]
    ok = True
    for path, header, exact in tests:
        try:
            status, headers, out = request(host, port, "GET", path, {"Range": header})
        except Exception as exc:
            ok = False
            print(f"  {path:34} {header:18} exception={exc!r}")
            continue

        verdict = "ok"
        if exact is not None and (status != 206 or out != exact):
            verdict = "mismatch"
            ok = False
        if b"POOLSLIP" in out or b"\x00" * 24 in out:
            verdict = "suspicious-body"
            ok = False
        print(
            f"  {path:34} {header:18} status={status:<3} len={len(out):<6} "
            f"cl={headers.get('Content-Length', '-'):<6} sha={digest(out)} {verdict}"
        )
    return ok and alive(host, port)


def upstream_probe(host: str, port: int) -> bool:
    print("[upstream headers/chunking]")
    paths = [
        "/delay?case=malformed-charset",
        "/delay?case=early-hints-malformed-charset",
        "/delay?case=chunked-trailers",
    ]
    ok = True
    for path in paths:
        try:
            status, headers, body = request(host, port, "GET", path)
            print(
                f"  {path:42} status={status:<3} len={len(body):<5} "
                f"ct={headers.get('Content-Type', '-')!r}"
            )
        except Exception as exc:
            ok = False
            print(f"  {path:42} exception={exc!r}")
    return ok and alive(host, port)


def rewrite_probe(host: str, port: int) -> bool:
    print("[rewrite/set fixed-trigger]")
    ok = True
    payloads = [
        "/api/hello",
        "/api/" + "A" * 127 + "+" * 512,
        "/api/" + "B" * 127 + "+" * 1024,
    ]
    for path in payloads:
        try:
            status, _headers, body = request(host, port, "GET", path)
            print(f"  len(path)={len(path):<5} status={status:<3} body_len={len(body)}")
        except Exception as exc:
            ok = False
            print(f"  len(path)={len(path):<5} exception={exc!r}")
    return ok and alive(host, port)


def pipelined_large_header_probe(host: str, port: int) -> bool:
    print("[large-header keepalive]")
    req = (
        b"GET / HTTP/1.1\r\n"
        b"Host: probe\r\n"
        b"X-Fill: " + b"A" * 12000 + b"\r\n"
        b"Connection: keep-alive\r\n\r\n"
        b"GET / HTTP/1.1\r\n"
        b"Host: probe\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            sock.sendall(req)
            sock.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
    except Exception as exc:
        print(f"  exception={exc!r}")
        return False
    count = data.count(b"HTTP/1.1")
    print(f"  response_markers={count} bytes={len(data)} sha={digest(data)}")
    return count >= 1 and alive(host, port)


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP-only NGINX 1.31.1 audit probes.")
    parser.add_argument("--target", default="127.0.0.1:19331", help="target as HOST:PORT")
    parser.add_argument("--port", type=int, default=19331)
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = parse_target(args.target, args.port)
    print(f"target {host}:{port}")
    print("primitive HTTP responses only; no LFI/procfs/core/debugger")
    print()
    if not alive(host, port):
        print("[!] target is not healthy before probes")
        return 2

    results = [
        ("range/static", range_probe(host, port)),
        ("range/upstream", range_upstream_probe(host, port)),
        ("upstream", upstream_probe(host, port)),
        ("rewrite", rewrite_probe(host, port)),
        ("large-header", pipelined_large_header_probe(host, port)),
    ]
    print()
    failed = [name for name, ok in results if not ok]
    if failed:
        print("[!] probes with anomalies:", ", ".join(failed))
        return 1
    print("[+] no HTTP-visible leak/crash anomaly observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
