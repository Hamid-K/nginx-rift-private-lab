#!/usr/bin/env python3
"""Run sanitized Rift cases against the local vulnerable Docker target."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import random
import socket
import string
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_CASES = Path("exposure_lab/corpus/cases.jsonl")
DEFAULT_GENERATED = Path("exposure_lab/generated")
DEFAULT_CORPUS_SUMMARY = Path("exposure_lab/corpus/summary.json")
DEFAULT_REPORT = Path("exposure_lab/reports/local_test_report.md")
DEFAULT_RESULTS = Path("exposure_lab/reports/local_test_results.json")


@dataclass
class TestResult:
    case_id: str
    status: str
    http_status: str
    container_exit: str
    elapsed_ms: int
    docker_name: str
    evidence: list[str]


def run(cmd: list[str], timeout: float = 30.0, check: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{cmd!r} failed: {proc.stderr or proc.stdout}")
    return proc


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def random_suffix(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def http_request(host: str, port: int, path: str, timeout: float = 5.0) -> tuple[str, bytes]:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: rift-exposure-local-runner/1.0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", "ignore")

    data = bytearray()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(req)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data.extend(chunk)

    first_line = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else "no_response"
    return first_line, bytes(data)


def wait_for_http(port: int, deadline: float) -> bool:
    while time.time() < deadline:
        try:
            status, _ = http_request("127.0.0.1", port, "/", timeout=1.0)
            if status.startswith("HTTP/"):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def container_host_port(name: str) -> int:
    proc = run(["docker", "port", name, "8080/tcp"], timeout=10.0, check=True)
    line = proc.stdout.strip().splitlines()[0]
    return int(line.rsplit(":", 1)[1])


def classify(logs: str, exit_status: str, trigger_status: str) -> tuple[str, list[str]]:
    evidence: list[str] = []
    lower = logs.lower()

    if "addresssanitizer" in lower:
        evidence.append("AddressSanitizer output observed")
    if "heap-buffer-overflow" in lower:
        evidence.append("heap-buffer-overflow observed")
    if "segmentation fault" in lower or "segv" in lower:
        evidence.append("segmentation fault/SEGV observed")
    normal_status = exit_status in {"running", "0"} or exit_status.startswith("running ")
    if exit_status and not normal_status:
        evidence.append(f"container exit/status={exit_status}")
    if trigger_status == "no_response":
        evidence.append("trigger connection closed without HTTP response")

    if "addresssanitizer" in lower and ("heap-buffer-overflow" in lower or "segv" in lower):
        return "asan_hit", evidence
    if evidence:
        return "crash_or_abort", evidence
    if trigger_status.startswith("HTTP/"):
        return "no_trigger", [f"trigger returned {trigger_status}"]
    return "unknown", evidence or ["no conclusive signal"]


def run_case(case: dict[str, Any], image: str, generated_dir: Path, payload_len: int, startup_timeout: float) -> TestResult:
    case_id = case["case_id"]
    case_dir = (generated_dir / case_id).resolve()
    name = f"rift-exp-{case_id}-{random_suffix()}"
    start = time.time()
    evidence: list[str] = []
    http_status = "not_started"
    exit_status = "unknown"

    try:
        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                "127.0.0.1::8080",
                "-v",
                f"{case_dir}:/work:ro",
                image,
            ],
            timeout=30.0,
            check=True,
        )
        port = container_host_port(name)
        if not wait_for_http(port, time.time() + startup_timeout):
            log_proc = run(["docker", "logs", name], timeout=10.0)
            logs = log_proc.stdout + log_proc.stderr
            status = "config_error"
            evidence = ["container did not become HTTP-ready"]
            if logs:
                evidence.append(first_log_signal(logs))
            return finish(case_id, status, http_status, exit_status, name, start, evidence)

        payload = "+" * payload_len
        path = case["generated_route"].replace("{payload}", payload)
        try:
            http_status, _ = http_request("127.0.0.1", port, path, timeout=4.0)
        except OSError as exc:
            http_status = "no_response"
            evidence.append(type(exc).__name__)

        time.sleep(0.5)
        inspect = run(["docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", name], timeout=10.0)
        exit_status = inspect.stdout.strip() or "unknown"
        log_proc = run(["docker", "logs", name], timeout=10.0)
        logs = log_proc.stdout + log_proc.stderr
        status, classified = classify(logs, exit_status, http_status)
        evidence.extend(classified)
        return finish(case_id, status, http_status, exit_status, name, start, evidence)
    except Exception as exc:
        evidence.append(f"{type(exc).__name__}: {exc}")
        return finish(case_id, "runner_error", http_status, exit_status, name, start, evidence)
    finally:
        run(["docker", "rm", "-f", name], timeout=10.0)


def first_log_signal(logs: str) -> str:
    for line in logs.splitlines():
        if line.strip():
            return line.strip()[:240]
    return "no logs"


def finish(
    case_id: str,
    status: str,
    http_status: str,
    exit_status: str,
    name: str,
    start: float,
    evidence: list[str],
) -> TestResult:
    return TestResult(
        case_id=case_id,
        status=status,
        http_status=http_status,
        container_exit=exit_status,
        elapsed_ms=int((time.time() - start) * 1000),
        docker_name=name,
        evidence=evidence,
    )


def load_json_if_present(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_report(
    path: Path,
    results: list[TestResult],
    cases: list[dict[str, Any]],
    image: str,
    parallel: int,
    payload_len: int,
    corpus_summary: dict[str, Any],
) -> None:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    cases_by_id = {case["case_id"]: case for case in cases}

    lines = [
        "# Rift Local Exposure Lab Report",
        "",
        f"Generated: {dt.datetime.now(dt.UTC).isoformat()}",
        "",
        "## Scope",
        "",
        "This report covers sanitized local Docker simulations generated from public",
        "GitHub config-shape candidates. It does not identify source repositories,",
        "owners, URLs, or paths.",
        "",
        "A positive result means the generated local case triggered the Rift",
        "memory-corruption primitive under the vulnerable ASAN/debug-palloc NGINX",
        "image. It is not proof of deployment or full RCE for any public system.",
        "",
        "## Corpus Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Sanitized local cases | {corpus_summary.get('case_count', 'n/a')} |",
        f"| Unique sanitized semantic fingerprints | {corpus_summary.get('unique_semantic_fingerprint_count', 'n/a')} |",
        f"| Raw GitHub search hits | {corpus_summary.get('search_stats', {}).get('result_items', 'n/a')} |",
        f"| Deduplicated candidate references | {corpus_summary.get('search_stats', {}).get('dedup_items', 'n/a')} |",
        f"| GitHub code-search API calls | {corpus_summary.get('search_stats', {}).get('queries', 'n/a')} |",
        "",
        "## Run Parameters",
        "",
        "| Parameter | Value |",
        "| --- | --- |",
        f"| Docker image | `{image}` |",
        f"| Parallel containers | {parallel} |",
        f"| Trigger payload length | {payload_len} plus signs |",
        f"| Cases tested | {len(results)} |",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status, count in sorted(counts.items()):
        lines.append(f"| `{status}` | {count} |")

    lines += [
        "",
        "## Trigger Breakdown",
        "",
        "By preserved directive order:",
        "",
        "| Directive order | ASAN hits | No trigger | Other |",
        "| --- | ---: | ---: | ---: |",
    ]
    for key, row in breakdown(results, cases_by_id, lambda case: case.get("directive_order", "unknown")).items():
        lines.append(f"| `{key}` | {row.get('asan_hit', 0)} | {row.get('no_trigger', 0)} | {row.get('other', 0)} |")

    lines += [
        "",
        "By rewrite flag:",
        "",
        "| Rewrite flag | ASAN hits | No trigger | Other |",
        "| --- | ---: | ---: | ---: |",
    ]
    for key, row in breakdown(results, cases_by_id, lambda case: case.get("rewrite", {}).get("flag", "unknown")).items():
        lines.append(f"| `{key}` | {row.get('asan_hit', 0)} | {row.get('no_trigger', 0)} | {row.get('other', 0)} |")

    lines += [
        "",
        "## Status Meaning",
        "",
        "- `asan_hit`: local generated route produced AddressSanitizer",
        "  heap-buffer-overflow evidence in the vulnerable NGINX build.",
        "- `no_trigger`: the static ingredients were present, but the preserved-order",
        "  local route did not reach the vulnerable execution path under this",
        "  trigger. Common reasons include `set` before `rewrite`, redirect-style",
        "  rewrite flags, or a normal HTTP response path.",
        "- `config_error` or `runner_error`: local harness failure rather than a",
        "  vulnerability conclusion.",
        "",
        "## Case Results",
        "",
        "| Case | Status | HTTP result | Container status | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in sorted(results, key=lambda item: item.case_id):
        evidence = "; ".join(result.evidence).replace("|", "\\|")
        lines.append(
            f"| `{result.case_id}` | `{result.status}` | `{result.http_status}` | "
            f"`{result.container_exit}` | {evidence} |"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def breakdown(
    results: list[TestResult],
    cases_by_id: dict[str, dict[str, Any]],
    key_fn: Any,
) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for result in results:
        case = cases_by_id.get(result.case_id, {})
        key = str(key_fn(case))
        status = result.status if result.status in {"asan_hit", "no_trigger"} else "other"
        out.setdefault(key, {"asan_hit": 0, "no_trigger": 0, "other": 0})[status] += 1
    return dict(sorted(out.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run sanitized Rift cases in parallel Docker containers.")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--generated-dir", type=Path, default=DEFAULT_GENERATED)
    parser.add_argument("--image", default="rift-exposure-nginx:asan")
    parser.add_argument("--parallel", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--payload-len", type=int, default=8192)
    parser.add_argument("--startup-timeout", type=float, default=8.0)
    parser.add_argument("--corpus-summary", type=Path, default=DEFAULT_CORPUS_SUMMARY)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--results-json", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()

    cases = load_cases(args.cases)
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        raise SystemExit("no cases to test")

    random.seed(os.getpid() ^ int(time.time()))
    results: list[TestResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = [
            executor.submit(
                run_case,
                case,
                args.image,
                args.generated_dir,
                args.payload_len,
                args.startup_timeout,
            )
            for case in cases
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            print(f"{result.case_id}: {result.status} ({result.http_status})", flush=True)
            results.append(result)

    args.results_json.parent.mkdir(parents=True, exist_ok=True)
    args.results_json.write_text(
        json.dumps([result.__dict__ for result in sorted(results, key=lambda item: item.case_id)], indent=2),
        encoding="utf-8",
    )
    write_report(
        args.report,
        results,
        cases,
        args.image,
        args.parallel,
        args.payload_len,
        load_json_if_present(args.corpus_summary),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
