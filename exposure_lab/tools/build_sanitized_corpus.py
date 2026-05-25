#!/usr/bin/env python3
"""Build an anonymous local-test corpus from public Rift config candidates."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import random
import re
import shlex
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import rift_github_exposure_survey as survey  # noqa: E402


DEFAULT_CASES = Path("exposure_lab/corpus/cases.jsonl")
DEFAULT_SUMMARY = Path("exposure_lab/corpus/summary.json")
DEFAULT_GENERATED = Path("exposure_lab/generated")
DEFAULT_ESCROW = Path("exposure_lab/.private/source_map.jsonl")


@dataclass
class RewriteShape:
    index: int
    regex_shape: str
    replacement_has_query: bool
    flag: str
    capture_count: int
    replacement_kind: str


@dataclass
class SetShape:
    index: int
    capture_refs: list[int]
    rhs_shape: list[dict[str, Any]]


@dataclass
class SanitizedCase:
    schema_version: int
    case_id: str
    case_fingerprint: str
    source_size_bucket: str
    parser_confidence: str
    publicish_static: bool
    blockers: list[str]
    location_kind: str
    directive_order: str
    rewrite: RewriteShape
    set_directive: SetShape
    generated_route: str
    generated_config: str


def eprint(*parts: object) -> None:
    print(*parts, file=sys.stderr, flush=True)


def size_bucket(byte_len: int) -> str:
    if byte_len < 10_000:
        return "lt_10kb"
    if byte_len < 50_000:
        return "10_50kb"
    if byte_len < 250_000:
        return "50_250kb"
    if byte_len < 1_000_000:
        return "250kb_1mb"
    return "gt_1mb"


def count_captures(pattern: str) -> int:
    count = 0
    escaped = False
    in_class = False
    for idx, ch in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "[":
            in_class = True
            continue
        if ch == "]" and in_class:
            in_class = False
            continue
        if ch == "(" and not in_class:
            nxt = pattern[idx + 1 : idx + 2]
            if nxt != "?":
                count += 1
    return count


def split_directive(text: str) -> list[str]:
    try:
        return shlex.split(text, comments=False, posix=True)
    except ValueError:
        return text.split()


def parse_rewrite(text: str, index: int) -> RewriteShape | None:
    parts = split_directive(text)
    if len(parts) < 2:
        return None
    regex = parts[0]
    replacement = parts[1]
    flag = parts[2].lower() if len(parts) >= 3 else "none"
    if replacement.startswith(("http://", "https://")):
        replacement_kind = "absolute_uri"
    elif replacement.startswith("$"):
        replacement_kind = "variable_uri"
    elif replacement.startswith("/"):
        replacement_kind = "relative_uri"
    else:
        replacement_kind = "unknown"
    capture_count = count_captures(regex)
    return RewriteShape(
        index=index,
        regex_shape=regex_shape(regex, capture_count),
        replacement_has_query="?" in replacement,
        flag=flag,
        capture_count=capture_count,
        replacement_kind=replacement_kind,
    )


def regex_shape(pattern: str, capture_count: int) -> str:
    anchored_start = pattern.startswith("^")
    anchored_end = pattern.endswith("$")
    has_tail_capture = bool(re.search(r"\(\.\*\)\$?$", pattern))
    has_path_capture = bool(re.search(r"\(\[\^/\]\+\)|\(\[\^/\]\*\)|\(\.\+\)|\(\.\*\)", pattern))
    parts = [
        "anchored_start" if anchored_start else "unanchored_start",
        "anchored_end" if anchored_end else "unanchored_end",
        f"captures_{capture_count}",
    ]
    if has_tail_capture:
        parts.append("tail_capture")
    elif has_path_capture:
        parts.append("path_capture")
    else:
        parts.append("other_capture_shape")
    return "_".join(parts)


def parse_set(text: str, index: int) -> SetShape | None:
    parts = split_directive(text)
    if len(parts) < 2:
        return None
    rhs = text[len(parts[0]) :].strip()
    refs = sorted({int(match) for match in re.findall(r"\$([1-9])\b", rhs)})
    if not refs:
        return None

    shape: list[dict[str, Any]] = []
    last = 0
    for match in re.finditer(r"\$([1-9])\b", rhs):
        if match.start() > last:
            lit_len = match.start() - last
            shape.append({"literal_len_bucket": literal_bucket(lit_len)})
        shape.append({"capture": f"${match.group(1)}"})
        last = match.end()
    if last < len(rhs):
        shape.append({"literal_len_bucket": literal_bucket(len(rhs) - last)})

    return SetShape(index=index, capture_refs=refs, rhs_shape=shape)


def literal_bucket(length: int) -> str:
    if length <= 0:
        return "0"
    if length <= 8:
        return "1_8"
    if length <= 32:
        return "9_32"
    return "gt_32"


def location_kind(scope: str) -> str:
    bits = scope.split()
    if len(bits) >= 2 and bits[1] == "=":
        return "exact"
    if len(bits) >= 2 and bits[1] in {"~", "~*"}:
        return "regex"
    if len(bits) >= 2 and bits[1] == "^~":
        return "prefix_preferred"
    if len(bits) >= 1 and bits[0] == "location":
        return "prefix"
    return "unknown"


def canonical_case_payload(case: dict[str, Any]) -> str:
    return json.dumps(case, sort_keys=True, separators=(",", ":"))


def generated_regex(case_id: str, captures_needed: int) -> tuple[str, str]:
    captures_needed = max(captures_needed, 1)
    prefix = f"/rift-case/{case_id}"
    suffix = "/".join("([^/]+)" for _ in range(captures_needed))
    return prefix, f"^{prefix}/{suffix}$"


def generated_path(case_id: str, captures_needed: int, payload: str) -> str:
    captures_needed = max(captures_needed, 1)
    return f"/rift-case/{case_id}/" + "/".join(payload for _ in range(captures_needed))


def render_location(case_id: str, rewrite: RewriteShape, set_shape: SetShape) -> tuple[str, str]:
    captures_needed = max([rewrite.capture_count, *set_shape.capture_refs, 1])
    prefix, regex = generated_regex(case_id, captures_needed)
    set_rhs = "".join(f"${idx}" for idx in set_shape.capture_refs)
    rewrite_tail = "" if rewrite.flag == "none" else f" {rewrite.flag}"
    rewrite_line = f"        rewrite {regex} /__rift_sink__?case={case_id}{rewrite_tail};"
    set_line = f"        set $rift_capture_{case_id.replace('-', '_')} {set_rhs};"

    ordered = [rewrite_line, set_line]
    if set_shape.index < rewrite.index:
        ordered = [set_line, rewrite_line]

    body = "\n".join(ordered)
    conf = f"""    location ~ {regex} {{
{body}
    }}
"""
    return prefix, conf


def render_config(case_id: str, rewrite: RewriteShape, set_shape: SetShape) -> tuple[str, str]:
    prefix, location = render_location(case_id, rewrite, set_shape)
    conf = f"""worker_processes 1;
error_log stderr notice;
pid /tmp/rift-exposure-{case_id}.pid;

events {{
    worker_connections 1024;
}}

http {{
    access_log off;
    client_body_temp_path /tmp/rift-exposure-client-body;
    proxy_temp_path /tmp/rift-exposure-proxy;
    fastcgi_temp_path /tmp/rift-exposure-fastcgi;
    uwsgi_temp_path /tmp/rift-exposure-uwsgi;
    scgi_temp_path /tmp/rift-exposure-scgi;

    upstream rift_backend {{
        server 127.0.0.1:8081;
    }}

    server {{
        listen 127.0.0.1:8081;
        location / {{
            return 200 "backend ok\\n";
        }}
    }}

    server {{
        listen 0.0.0.0:8080;
        server_name _;
        request_pool_size 4096;
        connection_pool_size 4096;
        client_header_buffer_size 4096;
        large_client_header_buffers 4 65536;

{location}
        location /__rift_sink__ {{
            internal;
            proxy_pass http://rift_backend;
            proxy_read_timeout 5s;
        }}

        location / {{
            return 200 "case {case_id} ok\\n";
        }}
    }}
}}
"""
    return prefix, conf


def extract_cases_from_text(text: str, byte_len: int, next_id: int) -> list[SanitizedCase]:
    cleaned = survey.strip_comments(text)
    cases: list[SanitizedCase] = []
    source_size = size_bucket(byte_len)

    for block in survey.collect_blocks(cleaned, ("location",)):
        body = "\n".join(block["lines"])
        blockers = survey.block_blockers(body)
        directives: list[tuple[int, str, str]] = []
        for idx, match in enumerate(re.finditer(r"\b(rewrite|set)\s+([^;]+);", body), 1):
            directives.append((idx, match.group(1), match.group(2).strip()))

        rewrites = [
            parse_rewrite(text, idx)
            for idx, kind, text in directives
            if kind == "rewrite"
        ]
        sets = [
            parse_set(text, idx)
            for idx, kind, text in directives
            if kind == "set"
        ]

        for rewrite in [rw for rw in rewrites if rw and rw.replacement_has_query]:
            for set_shape in [sd for sd in sets if sd]:
                assert rewrite is not None
                assert set_shape is not None
                case_id = f"case_{next_id + len(cases):06d}"
                captures_needed = max([rewrite.capture_count, *set_shape.capture_refs, 1])
                route, config = render_config(case_id, rewrite, set_shape)
                order = "rewrite_before_set" if rewrite.index < set_shape.index else "set_before_rewrite"
                canonical = {
                    "blockers": blockers,
                    "captures_needed": captures_needed,
                    "directive_order": order,
                    "location_kind": location_kind(str(block["scope"])),
                    "publicish_static": not blockers,
                    "rewrite": asdict(rewrite),
                    "set": asdict(set_shape),
                }
                fingerprint = hashlib.sha256(canonical_case_payload(canonical).encode()).hexdigest()
                cases.append(
                    SanitizedCase(
                        schema_version=1,
                        case_id=case_id,
                        case_fingerprint=fingerprint,
                        source_size_bucket=source_size,
                        parser_confidence="same_location_rewrite_query_set_capture",
                        publicish_static=not blockers,
                        blockers=blockers,
                        location_kind=location_kind(str(block["scope"])),
                        directive_order=order,
                        rewrite=rewrite,
                        set_directive=set_shape,
                        generated_route=generated_path(case_id, captures_needed, "{payload}"),
                        generated_config=f"generated/{case_id}/nginx.conf",
                    )
                )
    return cases


def write_case_config(case: SanitizedCase, out_dir: Path) -> None:
    captures_needed = max([case.rewrite.capture_count, *case.set_directive.capture_refs, 1])
    _, config = render_config(case.case_id, case.rewrite, case.set_directive)
    case_dir = out_dir / case.case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "nginx.conf").write_text(config, encoding="utf-8")
    (case_dir / "trigger_path.txt").write_text(
        generated_path(case.case_id, captures_needed, "{payload}") + "\n",
        encoding="utf-8",
    )


def write_summary(path: Path, cases: list[SanitizedCase], search_stats: Any, failures: dict[str, int]) -> None:
    summary = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "schema_version": 1,
        "case_count": len(cases),
        "unique_semantic_fingerprint_count": len({case.case_fingerprint for case in cases}),
        "publicish_case_count": sum(1 for case in cases if case.publicish_static),
        "blocked_case_count": sum(1 for case in cases if not case.publicish_static),
        "directive_order_counts": count_by(cases, "directive_order"),
        "location_kind_counts": count_by(cases, "location_kind"),
        "rewrite_flag_counts": count_rewrite_flags(cases),
        "blocker_counts": count_blockers(cases),
        "search_stats": asdict(search_stats),
        "fetch_failures": failures,
        "privacy": {
            "stores_repo_names": False,
            "stores_repo_urls": False,
            "stores_source_paths": False,
            "stores_raw_public_config": False,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")


def count_by(cases: list[SanitizedCase], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for case in cases:
        key = str(getattr(case, attr))
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def count_rewrite_flags(cases: list[SanitizedCase]) -> dict[str, int]:
    out: dict[str, int] = {}
    for case in cases:
        flag = case.rewrite.flag
        out[flag] = out.get(flag, 0) + 1
    return dict(sorted(out.items()))


def count_blockers(cases: list[SanitizedCase]) -> dict[str, int]:
    out: dict[str, int] = {}
    for case in cases:
        for blocker in case.blockers:
            out[blocker] = out.get(blocker, 0) + 1
    return dict(sorted(out.items()))


def case_to_json(case: SanitizedCase) -> str:
    data = asdict(case)
    return json.dumps(data, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a sanitized Rift local-test corpus from GitHub search.")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--generated-dir", type=Path, default=DEFAULT_GENERATED)
    parser.add_argument("--escrow-map", type=Path, default=DEFAULT_ESCROW)
    parser.add_argument("--include-blocked", action="store_true", help="include cases with obvious same-block static blockers")
    parser.add_argument("--sample", type=int, default=0, help="sample N deduped search results before fetching")
    parser.add_argument("--max-size", type=int, default=survey.MAX_SIZE)
    parser.add_argument(
        "--search-sleep",
        type=float,
        default=survey.CODE_SEARCH_SLEEP,
        help="seconds to sleep after each successful GitHub code-search API call",
    )
    parser.add_argument("--captures", default=",".join(survey.CAPTURE_VARS))
    parser.add_argument("--scopes", default=",".join(survey.DEFAULT_SCOPES))
    parser.add_argument("--keep-private-escrow", action="store_true", help="write ignored local case-to-source map")
    parser.add_argument(
        "--fixture-config",
        type=Path,
        action="append",
        default=[],
        help="local NGINX config fixture; skips GitHub search/fetch and builds cases from this file",
    )
    args = parser.parse_args()

    scopes = [item.strip() for item in args.scopes.split(",") if item.strip()]
    captures = [item.strip() for item in args.captures.split(",") if item.strip()]
    survey.CODE_SEARCH_SLEEP = args.search_sleep

    args.cases.parent.mkdir(parents=True, exist_ok=True)
    args.generated_dir.mkdir(parents=True, exist_ok=True)

    search_stats = survey.SearchStats()
    seen_content: set[str] = set()
    failures: dict[str, int] = {}
    cases: list[SanitizedCase] = []
    escrow_lines: list[str] = []

    def ingest_text(text: str, byte_len: int, source_hint: dict[str, Any] | None = None) -> None:
        nonlocal cases
        content_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if content_hash in seen_content:
            return
        seen_content.add(content_hash)

        extracted = extract_cases_from_text(text, byte_len, len(cases) + 1)
        for case in extracted:
            if not args.include_blocked and not case.publicish_static:
                continue
            case.case_id = f"case_{len(cases) + 1:06d}"
            captures_needed = max([case.rewrite.capture_count, *case.set_directive.capture_refs, 1])
            case.generated_route = generated_path(case.case_id, captures_needed, "{payload}")
            case.generated_config = f"generated/{case.case_id}/nginx.conf"
            cases.append(case)
            write_case_config(case, args.generated_dir)

            if args.keep_private_escrow:
                escrow_lines.append(
                    json.dumps(
                        {
                            "case_id": case.case_id,
                            "source_html_url": (source_hint or {}).get("html_url"),
                            "source_path": (source_hint or {}).get("path"),
                        },
                        sort_keys=True,
                    )
                )

    if args.fixture_config:
        for fixture in args.fixture_config:
            text = fixture.read_text(encoding="utf-8", errors="replace")
            ingest_text(text, len(text.encode("utf-8", "replace")), {"path": str(fixture)})
    else:
        items, search_stats = survey.collect_search_items(scopes, captures, args.max_size)
        if args.sample:
            random.seed(42945)
            items = random.sample(items, min(args.sample, len(items)))

        for idx, item in enumerate(items, 1):
            if idx == 1 or idx % 50 == 0:
                eprint(f"[fetch] {idx}/{len(items)} cases={len(cases)} failures={sum(failures.values())}")

            text, byte_len, error = survey.fetch_text(item)
            if error:
                failures[error] = failures.get(error, 0) + 1
                continue
            assert text is not None
            ingest_text(text, byte_len, item)
            time.sleep(0.03)

    with args.cases.open("w", encoding="utf-8") as fh:
        for case in cases:
            fh.write(case_to_json(case) + "\n")

    write_summary(args.summary, cases, search_stats, failures)

    if args.keep_private_escrow:
        args.escrow_map.parent.mkdir(parents=True, exist_ok=True)
        args.escrow_map.write_text("\n".join(escrow_lines) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "cases": len(cases),
                "publicish_cases": sum(1 for case in cases if case.publicish_static),
                "generated_dir": str(args.generated_dir),
                "cases_file": str(args.cases),
                "summary": str(args.summary),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
