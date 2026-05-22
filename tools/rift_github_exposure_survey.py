#!/usr/bin/env python3
"""Aggregate GitHub exposure survey for NGINX Rift-style configs.

The tool intentionally reports aggregate counts only.  It uses GitHub code
search as a candidate prefilter, fetches matching public files, and classifies
them locally for the Rift config shape:

    rewrite <regex> <replacement-with-?>;
    set <var> ...$1...;

within the same NGINX location block.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_SCOPES = [
    "extension:conf",
    "filename:nginx.conf",
    "path:nginx",
    "path:conf.d",
    "path:sites-available",
    "path:sites-enabled",
    "language:Nginx",
]

CAPTURE_VARS = [f"${i}" for i in range(1, 10)]
CODE_SEARCH_SLEEP = 6.25
MAX_SEARCH_RESULTS = 1000
MAX_FETCH_BYTES = 1_500_000
MAX_SIZE = 2_000_000


@dataclass
class SearchStats:
    queries: int = 0
    result_items: int = 0
    dedup_items: int = 0
    capped_partitions: int = 0
    search_errors: int = 0


@dataclass
class Finding:
    line: int
    scope: str
    rewrite: str
    set_directive: str
    publicish: bool
    blockers: list[str] = field(default_factory=list)


@dataclass
class FileClass:
    item_id: str
    sha256: str
    path: str
    bytes: int
    nginx_like: bool
    keyword_prefilter: bool
    file_level_candidate: bool
    high_confidence_count: int
    publicish_count: int
    blocked_count: int
    blocker_kinds: list[str]


def eprint(*parts: object) -> None:
    print(*parts, file=sys.stderr, flush=True)


def run_gh_search(query: str, page: int = 1, per_page: int = 100) -> dict[str, Any]:
    cmd = [
        "gh",
        "api",
        "--method",
        "GET",
        "search/code",
        "-f",
        f"q={query}",
        "-f",
        f"page={page}",
        "-f",
        f"per_page={per_page}",
    ]

    while True:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode == 0:
            time.sleep(CODE_SEARCH_SLEEP)
            return json.loads(proc.stdout)

        text = proc.stderr + proc.stdout
        if "rate limit exceeded" in text.lower():
            wait = 65
            eprint(f"[rate-limit] sleeping {wait}s")
            time.sleep(wait)
            continue

        raise RuntimeError(text.strip())


def size_qualifier(lo: int | None, hi: int | None) -> str:
    if lo is None and hi is not None:
        return f"size:<={hi}"
    if lo is not None and hi is None:
        return f"size:>{lo - 1}"
    assert lo is not None and hi is not None
    return f"size:{lo}..{hi}"


def query_count(query: str, stats: SearchStats) -> tuple[int, bool, list[dict[str, Any]]]:
    data = run_gh_search(query, page=1, per_page=100)
    stats.queries += 1
    return int(data.get("total_count", 0)), bool(data.get("incomplete_results")), data.get("items", [])


def fetch_partition(query: str, stats: SearchStats) -> list[dict[str, Any]]:
    count, incomplete, first_items = query_count(query, stats)
    return fetch_counted_partition(query, count, incomplete, first_items, stats)


def fetch_counted_partition(
    query: str,
    count: int,
    incomplete: bool,
    first_items: list[dict[str, Any]],
    stats: SearchStats,
) -> list[dict[str, Any]]:
    if incomplete:
        stats.capped_partitions += 1

    if count == 0:
        return []

    if count > MAX_SEARCH_RESULTS:
        stats.capped_partitions += 1
        eprint(f"[warn] partition still above GitHub cap count={count}: {query}")
        count = MAX_SEARCH_RESULTS

    pages = (count + 99) // 100
    items = list(first_items)
    for page in range(2, pages + 1):
        data = run_gh_search(query, page=page, per_page=100)
        stats.queries += 1
        items.extend(data.get("items", []))

    stats.result_items += len(items)
    return items


def collect_by_size(base_query: str, lo: int, hi: int, stats: SearchStats) -> list[dict[str, Any]]:
    query = f"{base_query} {size_qualifier(lo, hi)}"
    count, incomplete, first_items = query_count(query, stats)

    if count == 0:
        return []

    if count <= MAX_SEARCH_RESULTS and not incomplete:
        return fetch_counted_partition(query, count, incomplete, first_items, stats)

    if lo >= hi:
        stats.capped_partitions += 1
        return fetch_partition(query, stats)

    mid = (lo + hi) // 2
    return collect_by_size(base_query, lo, mid, stats) + collect_by_size(base_query, mid + 1, hi, stats)


def collect_search_items(scopes: list[str], captures: list[str], max_size: int) -> tuple[list[dict[str, Any]], SearchStats]:
    stats = SearchStats()
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    for capture in captures:
        for scope in scopes:
            base = f'rewrite ? "set $" "{capture}" {scope}'
            eprint(f"[search] {base}")
            try:
                items = collect_by_size(base, 1, max_size, stats)
            except Exception as exc:
                stats.search_errors += 1
                eprint(f"[search-error] {base}: {exc}")
                continue

            for item in items:
                key = item.get("html_url") or item.get("url") or item.get("sha")
                if not key or key in seen:
                    continue
                seen.add(key)
                out.append(item)

            stats.dedup_items = len(out)
            eprint(f"[search] collected={len(out)} raw_items={stats.result_items} queries={stats.queries}")

    return out, stats


def raw_url(item: dict[str, Any]) -> str | None:
    html = item.get("html_url") or ""
    match = re.match(r"https://github.com/([^/]+/[^/]+)/blob/([^/]+)/(.*)", html)
    if not match:
        return None
    repo, ref, path = match.groups()
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def fetch_text(item: dict[str, Any], timeout: float = 15.0) -> tuple[str | None, int, str | None]:
    url = raw_url(item)
    if not url:
        return None, 0, "no_raw_url"

    req = urllib.request.Request(url, headers={"User-Agent": "rift-github-exposure-survey/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return None, 0, f"http_{exc.code}"
    except Exception as exc:
        return None, 0, type(exc).__name__

    if len(data) > MAX_FETCH_BYTES:
        return None, len(data), "too_large"

    return data.decode("utf-8", "replace"), len(data), None


def strip_comments(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        escaped = False
        quote: str | None = None
        keep: list[str] = []
        for ch in line:
            if escaped:
                keep.append(ch)
                escaped = False
                continue
            if ch == "\\":
                keep.append(ch)
                escaped = True
                continue
            if ch in {"'", '"'}:
                keep.append(ch)
                quote = None if quote == ch else (ch if quote is None else quote)
                continue
            if ch == "#" and quote is None:
                break
            keep.append(ch)
        out.append("".join(keep))
    return "\n".join(out)


def collect_blocks(text: str, names: tuple[str, ...]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    depth = 0
    pattern = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b([^\{;]*)\{")

    for idx, line in enumerate(text.splitlines(), 1):
        match = pattern.search(line)
        if current is None and match:
            current = {
                "line": idx,
                "name": match.group(1),
                "scope": match.group(0).rstrip("{").strip(),
                "lines": [line],
                "start_depth": depth,
            }
        elif current is not None:
            current["lines"].append(line)

        depth += line.count("{") - line.count("}")

        if current is not None and depth <= current["start_depth"]:
            blocks.append(current)
            current = None

    return blocks


def parse_replacement(rewrite: str) -> str:
    try:
        parts = shlex.split(rewrite, comments=False, posix=True) if rewrite else []
    except ValueError:
        parts = []
    return parts[1] if len(parts) >= 2 else rewrite


def has_capture_set(set_directive: str) -> bool:
    return bool(re.search(r"\$[1-9]\b", set_directive))


def block_blockers(body: str) -> list[str]:
    blockers: list[str] = []
    if re.search(r"\binternal\s*;", body):
        blockers.append("internal")
    if re.search(r"\bauth_basic\s+(?!off\b)[^;]+;", body):
        blockers.append("auth_basic")
    if re.search(r"\bdeny\s+all\s*;", body):
        blockers.append("deny_all")
    if re.search(r"\ballow\s+", body) and re.search(r"\bdeny\s+", body):
        blockers.append("allow_deny_acl")
    if re.search(r"\bsatisfy\s+", body):
        blockers.append("satisfy")
    return blockers


def classify_text(item_id: str, path: str, text: str, byte_len: int) -> FileClass:
    cleaned = strip_comments(text)
    sha256 = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    nginx_like = bool(
        re.search(r"\b(location|server|http|rewrite|proxy_pass|fastcgi_pass|root|try_files)\b", cleaned)
        and "{" in cleaned
        and "}" in cleaned
    )

    rewrites = re.findall(r"\brewrite\s+([^;]+);", cleaned)
    sets = re.findall(r"\bset\s+([^;]+);", cleaned)
    file_level_candidate = any("?" in parse_replacement(rw) for rw in rewrites) and any(
        has_capture_set(sd) for sd in sets
    )
    keyword_prefilter = "rewrite" in cleaned and "set" in cleaned

    findings: list[Finding] = []
    # Classify location first because it is the strongest route-level evidence.
    for block in collect_blocks(cleaned, ("location",)):
        body = "\n".join(block["lines"])
        block_rewrites = re.findall(r"\brewrite\s+([^;]+);", body)
        block_sets = re.findall(r"\bset\s+([^;]+);", body)
        for rewrite in block_rewrites:
            replacement = parse_replacement(rewrite)
            if "?" not in replacement:
                continue
            for set_directive in block_sets:
                if not has_capture_set(set_directive):
                    continue
                blockers = block_blockers(body)
                findings.append(
                    Finding(
                        line=int(block["line"]),
                        scope=str(block["scope"]),
                        rewrite=rewrite.strip(),
                        set_directive=set_directive.strip(),
                        publicish=not blockers,
                        blockers=blockers,
                    )
                )

    blocker_kinds = sorted({kind for finding in findings for kind in finding.blockers})
    return FileClass(
        item_id=item_id,
        sha256=sha256,
        path=path,
        bytes=byte_len,
        nginx_like=nginx_like,
        keyword_prefilter=keyword_prefilter,
        file_level_candidate=file_level_candidate,
        high_confidence_count=len(findings),
        publicish_count=sum(1 for f in findings if f.publicish),
        blocked_count=sum(1 for f in findings if not f.publicish),
        blocker_kinds=blocker_kinds,
    )


def summarize(classes: list[FileClass], fetch_failures: dict[str, int], search_stats: SearchStats) -> dict[str, Any]:
    unique_files = len(classes)
    high_files = [c for c in classes if c.high_confidence_count > 0]
    publicish_files = [c for c in classes if c.publicish_count > 0]
    blocked_files = [c for c in classes if c.blocked_count > 0 and c.publicish_count == 0]
    file_level = [c for c in classes if c.file_level_candidate and c.high_confidence_count == 0]
    nginx_like = [c for c in classes if c.nginx_like]

    blocker_counts: dict[str, int] = {}
    for c in classes:
        for kind in c.blocker_kinds:
            blocker_counts[kind] = blocker_counts.get(kind, 0) + 1

    return {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "search_stats": asdict(search_stats),
        "fetch_failures": fetch_failures,
        "unique_files_fetched": unique_files,
        "nginx_like_files": len(nginx_like),
        "file_level_candidate_files": len(file_level),
        "high_confidence_vulnerable_shape_files": len(high_files),
        "publicish_high_confidence_files": len(publicish_files),
        "blocked_high_confidence_files": len(blocked_files),
        "total_high_confidence_blocks": sum(c.high_confidence_count for c in classes),
        "total_publicish_blocks": sum(c.publicish_count for c in classes),
        "total_blocked_blocks": sum(c.blocked_count for c in classes),
        "blocker_counts_by_file": dict(sorted(blocker_counts.items())),
    }


def write_report(path: Path, summary: dict[str, Any], scopes: list[str], captures: list[str]) -> None:
    s = summary
    lines = [
        "# NGINX Rift GitHub Exposure Survey",
        "",
        f"Generated: {s['generated_at']}",
        "",
        "## Scope",
        "",
        "This is an aggregate public GitHub code-search survey. It does not list",
        "repositories, URLs, owners, or paths. Candidate files were fetched only after",
        "matching Rift-relevant prefilter terms.",
        "",
        "Prefilter:",
        "",
        "- `rewrite`",
        "- `?` in the searched content",
        "- `set`",
        "- numbered capture references `$1` through `$9`",
        f"- scopes: `{', '.join(scopes)}`",
        "",
        "High-confidence local classifier:",
        "",
        "- same `location` block contains a `rewrite` directive whose replacement",
        "  contains `?`",
        "- the same block contains a `set` directive that consumes a numbered regex",
        "  capture (`$1`..`$9`)",
        "",
        "A high-confidence config shape is potentially vulnerable when deployed on an",
        "affected NGINX version. Static GitHub config review cannot prove production",
        "deployment, exposed routing, runtime NGINX version, WAF behavior, or ASLR",
        "bypass feasibility.",
        "",
        "## Statistics",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| GitHub code-search API calls | {s['search_stats']['queries']} |",
        f"| Raw search result items before dedupe | {s['search_stats']['result_items']} |",
        f"| Unique candidate files after dedupe | {s['search_stats']['dedup_items']} |",
        f"| Unique files fetched and parsed | {s['unique_files_fetched']} |",
        f"| NGINX-looking files | {s['nginx_like_files']} |",
        f"| File-level Rift predicate but not same-location confirmed | {s['file_level_candidate_files']} |",
        f"| High-confidence vulnerable config-shape files | {s['high_confidence_vulnerable_shape_files']} |",
        f"| High-confidence files with no obvious static access blocker | {s['publicish_high_confidence_files']} |",
        f"| High-confidence files only in blocks with static blockers | {s['blocked_high_confidence_files']} |",
        f"| Total high-confidence vulnerable-shape blocks | {s['total_high_confidence_blocks']} |",
        f"| Total high-confidence publicish blocks | {s['total_publicish_blocks']} |",
        f"| Total high-confidence blocked blocks | {s['total_blocked_blocks']} |",
        "",
        "## Vulnerability And Exploitability",
        "",
        "| Class | Files | Blocks | Interpretation |",
        "| --- | ---: | ---: | --- |",
        "| Confirmed deployed and exploitable from GitHub config alone | 0 | 0 | Static public repo config cannot prove deployment, exposed routing, runtime version, or a working exploit chain. |",
        f"| Potentially exploitable config shape, no static access blocker visible | {s['publicish_high_confidence_files']} | {s['total_publicish_blocks']} | Same-location Rift predicate and no obvious `internal`/auth/ACL blocker; exploitable only if deployed on an affected NGINX version and reachable by requests. |",
        f"| Vulnerable config shape but statically blocked | {s['blocked_high_confidence_files']} | {s['total_blocked_blocks']} | Same-location Rift predicate exists, but the block shows an obvious static access blocker. |",
        f"| Needs manual review | {s['file_level_candidate_files']} | n/a | Rewrite-with-query and capture-consuming `set` appear in the same file but not in the same parsed location block. |",
        f"| NGINX-looking files with no Rift predicate confirmed | {max(s['nginx_like_files'] - s['high_confidence_vulnerable_shape_files'] - s['file_level_candidate_files'], 0)} | n/a | Candidate-search hits that did not satisfy the local vulnerable-shape classifier. |",
        "",
        "## Static Blockers",
        "",
        "| Blocker | Files |",
        "| --- | ---: |",
    ]
    if s["blocker_counts_by_file"]:
        for name, count in s["blocker_counts_by_file"].items():
            lines.append(f"| `{name}` | {count} |")
    else:
        lines.append("| none observed | 0 |")

    lines += [
        "",
        "## Fetch Failures",
        "",
        "| Reason | Count |",
        "| --- | ---: |",
    ]
    if s["fetch_failures"]:
        for reason, count in sorted(s["fetch_failures"].items()):
            lines.append(f"| `{reason}` | {count} |")
    else:
        lines.append("| none | 0 |")

    lines += [
        "",
        "## Interpretation",
        "",
        "- `High-confidence vulnerable config-shape files` is the main exposure count",
        "  for CVE-2026-42945/Rift-style configuration risk.",
        "- `Publicish` means no obvious `internal`, `auth_basic`, deny-all ACL,",
        "  allow/deny ACL, or `satisfy` directive was visible in that same location",
        "  block. It is not proof of internet exposure.",
        "- `File-level predicate` means the ingredients appear in the same file but",
        "  were not proven to be in the same location block by the local parser.",
        "- Actual exploitability still requires an affected NGINX version and a",
        "  reachable request path. Reliable RCE also depends on target runtime",
        "  layout and disclosure/bypass conditions.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate GitHub exposure survey for NGINX Rift configs.")
    parser.add_argument("--cache-dir", default="artifacts/rift_github_exposure_cache")
    parser.add_argument("--report", default="docs/RIFT_GITHUB_EXPOSURE_SURVEY.md")
    parser.add_argument("--summary-json", default="artifacts/rift_github_exposure_summary.json")
    parser.add_argument("--max-size", type=int, default=MAX_SIZE)
    parser.add_argument("--scopes", default=",".join(DEFAULT_SCOPES), help="comma-separated GitHub search scopes")
    parser.add_argument("--captures", default=",".join(CAPTURE_VARS), help="comma-separated capture vars")
    parser.add_argument("--sample", type=int, default=0, help="fetch only N deduped items for a smoke run")
    args = parser.parse_args()

    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    captures = [s.strip() for s in args.captures.split(",") if s.strip()]

    items, search_stats = collect_search_items(scopes, captures, args.max_size)
    if args.sample:
        random.seed(42945)
        items = random.sample(items, min(args.sample, len(items)))

    classes: list[FileClass] = []
    failures: dict[str, int] = {}
    seen_content: set[str] = set()

    for idx, item in enumerate(items, 1):
        item_key = item.get("html_url") or item.get("url") or item.get("sha") or str(idx)
        item_id = hashlib.sha256(item_key.encode()).hexdigest()[:20]
        path = item.get("path") or ""
        if idx == 1 or idx % 50 == 0:
            eprint(f"[fetch] {idx}/{len(items)} parsed={len(classes)} failures={sum(failures.values())}")

        text, byte_len, error = fetch_text(item)
        if error:
            failures[error] = failures.get(error, 0) + 1
            continue

        assert text is not None
        content_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if content_hash in seen_content:
            continue
        seen_content.add(content_hash)
        classes.append(classify_text(item_id, path, text, byte_len))
        time.sleep(0.03)

    summary = summarize(classes, failures, search_stats)
    Path(args.summary_json).write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    write_report(Path(args.report), summary, scopes, captures)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
