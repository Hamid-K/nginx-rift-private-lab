#!/usr/bin/env python3
import argparse
import glob
import json
from pathlib import Path


def shorten(value, width=18):
    text = "" if value is None else str(value)
    if len(text) <= width:
        return text
    return text[: width - 1] + "~"


def load_artifact(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data["_path"] = path
    return data


def reset_summary(data):
    reset = data.get("reset_core") or {}
    return {
        "expected": reset.get("expected_worker_pid"),
        "pids": reset.get("core_pids") or [],
        "pid_match": reset.get("pid_match"),
        "safe": reset.get("safe_slot_count"),
        "unsafe": reset.get("unsafe_slot_count"),
        "matches": len(reset.get("matches") or []),
    }


def candidate_summary(data):
    candidate_filter = data.get("final_candidate_filter") or {}
    return {
        "kept": candidate_filter.get("kept_count"),
        "dropped": candidate_filter.get("dropped_count"),
        "payload_size": candidate_filter.get("payload_size"),
    }


def binary_summary(data):
    fingerprints = data.get("binary_fingerprints") or {}
    items = []
    for name in ("nginx", "libc"):
        fp = fingerprints.get(name) or {}
        if fp.get("error"):
            items.append(f"{name}:err")
            continue
        if fp.get("build_id"):
            items.append(f"{name}:{fp['build_id'][:10]}")
        elif fp.get("sha256"):
            items.append(f"{name}:{fp['sha256'][:10]}")
    return ",".join(items)


def row_for(data):
    reset = reset_summary(data)
    candidates = candidate_summary(data)
    winner = data.get("winner") or {}
    preflight = data.get("preflight") or {}
    proof = data.get("proof") or {}
    target = data.get("target") or {}
    return {
        "file": Path(data["_path"]).name,
        "tool": data.get("tool", ""),
        "status": data.get("status", ""),
        "target": f"{target.get('host', '')}:{target.get('port', '')}",
        "aslr": preflight.get("randomize_va_space", ""),
        "os": preflight.get("os_release", ""),
        "reset_pid": reset["expected"],
        "core_pids": ",".join(str(pid) for pid in reset["pids"]),
        "pid_ok": reset["pid_match"],
        "slots": (
            ""
            if reset["safe"] is None
            else f"{reset['safe']}/{(reset['safe'] or 0) + (reset['unsafe'] or 0)}"
        ),
        "kept": candidates["kept"],
        "drop": candidates["dropped"],
        "win": winner.get("address", ""),
        "off": winner.get("slot_offset", ""),
        "round": winner.get("round", ""),
        "mode": proof.get("mode", ""),
        "output": winner.get("command_output", ""),
        "bins": binary_summary(data),
    }


def print_table(rows, columns):
    widths = {
        column: max(len(column), *(len(shorten(row.get(column, ""), 40)) for row in rows))
        for column in columns
    }
    print("  ".join(column.ljust(widths[column]) for column in columns))
    print("  ".join("-" * widths[column] for column in columns))
    for row in rows:
        print(
            "  ".join(
                shorten(row.get(column, ""), 40).ljust(widths[column]) for column in columns
            )
        )


def main():
    parser = argparse.ArgumentParser(description="Summarize Nginx Rift demo JSON artifacts")
    parser.add_argument("paths", nargs="*", default=["artifacts/demo_v1_*.json"])
    parser.add_argument("--details", action="store_true")
    args = parser.parse_args()

    paths = []
    for pattern in args.paths:
        matches = glob.glob(pattern)
        paths.extend(matches if matches else [pattern])
    paths = sorted(dict.fromkeys(paths))
    artifacts = [load_artifact(path) for path in paths]
    rows = [row_for(data) for data in artifacts]

    if not rows:
        print("No artifacts found.")
        return 1

    columns = ["file", "tool", "status", "aslr", "reset_pid", "core_pids", "pid_ok", "slots", "kept", "drop", "win", "off", "round", "mode"]
    if args.details:
        columns.extend(["target", "os", "bins", "output"])
    print_table(rows, columns)

    wins = sum(1 for row in rows if row["status"] == "success")
    negative = sum(1 for row in rows if row["status"] == "negative_pass")
    failures = len(rows) - wins - negative
    print()
    print(f"artifacts={len(rows)} success={wins} negative_pass={negative} failed_or_other={failures}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
