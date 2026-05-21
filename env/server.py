#!/usr/bin/env python3
"""Simple HTTP backend with deterministic edge-case responses."""
import http.server
import time
import re
import socket
import socketserver
import threading
import urllib.parse


def int_param(params, name, default, minimum=0, maximum=4096):
    try:
        value = int(params.get(name, [str(default)])[0], 0)
    except ValueError:
        value = default

    return max(minimum, min(maximum, value))


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        case = params.get("case", [""])[0]
        if case == "raw-upstream":
            kind = params.get("kind", ["ok"])[0]
            write = self.wfile.write
            flush = self.wfile.flush

            responses = {
                "invalid-status-alpha": [
                    b"HTTX/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                ],
                "split-invalid-status": [
                    b"HTTP/1.1 20",
                    b"X OK\r\nContent-Length: 0\r\n\r\n",
                ],
                "split-valid-status": [
                    b"HTTP/1.1 20",
                    b"0 OK\r\nContent-Length: 2\r\n\r\nok",
                ],
                "header-no-colon": [
                    b"HTTP/1.1 200 OK\r\nBrokenHeader\r\nContent-Length: 0\r\n\r\n",
                ],
                "header-control-byte": [
                    b"HTTP/1.1 200 OK\r\nX-Test: abc\x01def\r\nContent-Length: 0\r\n\r\n",
                ],
                "duplicate-content-length": [
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nX",
                ],
                "cl-te-conflict": [
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                ],
                "chunk-overflow": [
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                    b"10000000000000000\r\nx\r\n0\r\n\r\n",
                ],
                "chunk-extension-long": [
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                    b"1;" + b"a" * 4096 + b"\r\nx\r\n0\r\n\r\n",
                ],
                "trailers-invalid": [
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n",
                    b"1\r\nx\r\n0\r\nBadTrailer\r\n\r\n",
                ],
                "trailers-long": [
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n",
                    b"1\r\nx\r\n0\r\nX-T: " + b"t" * 8192 + b"\r\n\r\n",
                ],
                "early-final-split": [
                    b"HTTP/1.1 103 Early Hints\r\nX-E: one\r\n\r\nHTTP/1.1 20",
                    b"0 OK\r\nContent-Length: 2\r\n\r\nok",
                ],
                "early-invalid-final": [
                    b"HTTP/1.1 103 Early Hints\r\nX-E: one\r\n\r\nHTTX/1.1 200 OK\r\n\r\n",
                ],
                "many-early-then-final": [
                    (b"HTTP/1.1 103 Early Hints\r\nX-E: x\r\n\r\n" * 16)
                    + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                ],
            }

            parts = responses.get(kind, [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"])
            for part in parts:
                write(part)
                flush()
                time.sleep(0.02)
            return
        if case == "raw-hex":
            data_hex = params.get("data", [""])[0]
            split_at = int_param(params, "split", 0, maximum=8192)
            pause_ms = int_param(params, "pause_ms", 0, maximum=1000)

            try:
                data = bytes.fromhex(data_hex[:16384])
            except ValueError:
                data = b"HTTP/1.1 500 Bad Hex\r\nContent-Length: 0\r\n\r\n"

            if split_at and split_at < len(data):
                self.wfile.write(data[:split_at])
                self.wfile.flush()
                time.sleep(pause_ms / 1000)
                self.wfile.write(data[split_at:])
            else:
                self.wfile.write(data)

            self.wfile.flush()
            return
        if case == "raw-gen":
            mode = params.get("mode", ["valid"])[0]
            count = int_param(params, "n", 4, maximum=512)
            size = int_param(params, "size", 32, maximum=5242880)
            split_at = int_param(params, "split", 0, maximum=65535)
            pause_ms = int_param(params, "pause_ms", 0, maximum=1000)
            body_size = int_param(params, "body_size", 2, maximum=65535)
            trailer_size = int_param(params, "trailer_size", 0, maximum=8192)
            fill = params.get("fill", ["A"])[0].encode("latin1", "ignore")[:1] or b"A"

            def headers(prefix=b"X-Fuzz"):
                out = []
                for i in range(count):
                    marker = f"{i:04d}:".encode("ascii")
                    value = (marker + b"A" * size)[:size]
                    out.append(prefix + f"-{i:04d}: ".encode("ascii") + value + b"\r\n")
                return b"".join(out)

            if mode == "split-status":
                data = b"HTTP/1.1 20X Bad\r\nContent-Length: 0\r\n\r\n"
            elif mode == "invalid-status":
                data = b"HTTX/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            elif mode == "many-early":
                data = (
                    (b"HTTP/1.1 103 Early Hints\r\n" + headers(b"X-Early") + b"\r\n") * count
                    + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                )
            elif mode == "early-final":
                data = (
                    b"HTTP/1.1 103 Early Hints\r\n" + headers(b"X-Early") + b"\r\n"
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" + headers(b"X-Final") + b"\r\nok"
                )
            elif mode == "chunk-ext":
                data = (
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"1;" + b"e" * size + b"\r\nx\r\n0\r\n\r\n"
                )
            elif mode == "chunk-overflow":
                data = (
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"10000000000000000\r\nx\r\n0\r\n\r\n"
                )
            elif mode == "trailers":
                data = (
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n"
                    b"4\r\nBODY\r\n0\r\nX-T: " + b"T" * trailer_size + b"\r\n\r\n"
                )
            elif mode == "heavy-headers":
                data = (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    + headers(b"X-Heavy") + b"\r\nok"
                )
            elif mode == "malformed-header":
                data = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"BrokenHeader\r\nX-Control: abc\x01def\r\nContent-Length: 2\r\n\r\nok"
                )
            elif mode == "huge-content-type":
                data = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; x="
                    + fill * size
                    + b"\r\nContent-Length: 2\r\n\r\nok"
                )
            elif mode == "huge-location":
                data = (
                    b"HTTP/1.1 302 Found\r\nLocation: /"
                    + fill * size
                    + b"\r\nContent-Length: 0\r\n\r\n"
                )
            elif mode == "truncated":
                data = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n" + b"Z" * body_size
            else:
                data = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

            if split_at and split_at < len(data):
                self.wfile.write(data[:split_at])
                self.wfile.flush()
                time.sleep(pause_ms / 1000)
                self.wfile.write(data[split_at:])
            else:
                self.wfile.write(data)

            self.wfile.flush()
            return
        if case == "many-headers":
            count = int_param(params, "n", 64, maximum=1024)
            size = int_param(params, "size", 64, maximum=8192)
            body = b"many headers body\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            for i in range(count):
                marker = f"H{i:04d}:".encode()
                fill = (marker + b"A" * size)[:size]
                self.send_header(f"X-Fill-{i:04d}", fill.decode("ascii"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if case == "early-hints-many":
            count = int_param(params, "n", 32, maximum=512)
            size = int_param(params, "size", 64, maximum=4096)
            self.wfile.write(b"HTTP/1.1 103 Early Hints\r\n")
            for i in range(count):
                marker = f"E{i:04d}:".encode()
                fill = (marker + b"B" * size)[:size]
                self.wfile.write(f"X-Early-{i:04d}: ".encode() + fill + b"\r\n")
            self.wfile.write(b"\r\n")
            self.wfile.flush()

            body = b"early hints final body\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if case == "chunked-trailers-many":
            count = int_param(params, "n", 32, maximum=512)
            size = int_param(params, "size", 64, maximum=4096)
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Trailer: X-Trail-0000\r\n"
                b"\r\n"
                b"10\r\ntrailer body ok\n\r\n"
                b"0\r\n"
            )
            for i in range(count):
                marker = f"T{i:04d}:".encode()
                fill = (marker + b"C" * size)[:size]
                self.wfile.write(f"X-Trail-{i:04d}: ".encode() + fill + b"\r\n")
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return
        if case == "early-hints-malformed-charset":
            self.wfile.write(
                b"HTTP/1.1 103 Early Hints\r\n"
                b"Content-Type: text/plain; charset=\"\r\n"
                b"Link: </x>; rel=preload\r\n"
                b"\r\n"
            )
            self.wfile.flush()
        if case in {"malformed-charset", "early-hints-malformed-charset"}:
            body = b"malformed charset upstream body\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=\"")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if case == "chunked-trailers":
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Trailer: X-Trail\r\n"
                b"\r\n"
                b"5\r\nhello\r\n"
                b"6\r\n world\r\n"
                b"0\r\n"
                b"X-Trail: done\r\n"
                b"\r\n"
            )
            return

        delay = float(self.headers.get('X-Delay', '5'))
        time.sleep(delay)
        body = b'backend ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        delay = float(self.headers.get('X-Delay', '5'))
        time.sleep(delay)
        body = b'backend ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def raw_upstream_parts(kind):
    responses = {
        "scgi-status-header": [
            b"Status: 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        ],
        "scgi-status-header-split": [
            b"Sta",
            b"tus: 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        ],
        "scgi-status-header-onebyte": [
            b"S",
            b"tatus: 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        ],
        "http-valid-split": [
            b"HTTP/1.1 20",
            b"0 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        ],
        "http-invalid-split": [
            b"HTTP/1.1 20",
            b"X OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        ],
        "http-invalid-alpha": [
            b"HTTX/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        ],
        "header-control": [
            b"Status: 200 OK\r\nX-Test: abc\x01def\r\nContent-Length: 2\r\n\r\nok",
        ],
        "header-long": [
            b"Status: 200 OK\r\nX-Test: " + b"a" * 8192 + b"\r\nContent-Length: 2\r\n\r\nok",
        ],
        "duplicate-cl": [
            b"Status: 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nX",
        ],
    }
    return responses.get(kind, responses["scgi-status-header"])


def extract_kind(data):
    for regex in (
        rb"(?:^|[?&\x00])kind=([A-Za-z0-9_.:-]+)",
        rb"POOLSLIP_KIND\x00([A-Za-z0-9_.:-]+)",
    ):
        match = re.search(regex, data)
        if match:
            return match.group(1).decode("ascii", "replace")
    return "scgi-status-header"


class RawUpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.2)
        chunks = []
        while True:
            try:
                chunk = self.request.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(part) for part in chunks) > 65536:
                break

        kind = extract_kind(b"".join(chunks))
        for part in raw_upstream_parts(kind):
            self.request.sendall(part)
            time.sleep(0.02)


def serve_raw_upstream():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", 19324), RawUpstreamHandler) as rawd:
        print("Raw upstream on :19324")
        rawd.serve_forever()


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_MODES = (
    "valid_headers_end",
    "valid_data",
    "early_then_final",
    "duplicate_status",
    "no_status",
    "split_continuation",
    "invalid_hpack",
    "data_before_headers",
    "large_header",
    "padded_too_long",
    "rst_after_headers",
    "goaway_after_headers",
    "hpack_name_len_inflate",
    "hpack_value_len_inflate",
    "hpack_name_truncated",
    "hpack_value_truncated",
    "hpack_continuation_empty",
    "hpack_dynamic_table_update_ext",
    "hpack_index_ext",
    "many_ping",
    "many_settings",
    "zero_window_update",
    "window_shrink",
    "priority_padding_edge",
)
_h2_counter = 0
_h2_lock = threading.Lock()


def h2_next_mode():
    global _h2_counter
    with _h2_lock:
        mode = H2_MODES[_h2_counter % len(H2_MODES)]
        _h2_counter += 1
    return mode


def h2_frame(frame_type, flags, stream_id, payload=b""):
    length = len(payload)
    return (
        bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff, frame_type & 0xff, flags & 0xff])
        + ((stream_id & 0x7fffffff).to_bytes(4, "big"))
        + payload
    )


def hpack_int(value, prefix_bits, first_prefix):
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([first_prefix | value])

    out = bytearray([first_prefix | limit])
    value -= limit
    while value >= 128:
        out.append((value % 128) + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def hpack_string(value):
    return hpack_int(len(value), 7, 0x00) + value


def hpack_len_only(length, huffman=False):
    return hpack_int(length, 7, 0x80 if huffman else 0x00)


def hpack_status(value):
    if value == b"200":
        return b"\x88"
    return hpack_int(8, 4, 0x00) + hpack_string(value)


def hpack_literal(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def hpack_literal_with_declared_lengths(
    name_len, name_bytes, value_len, value_bytes, huffman=False
):
    return (
        b"\x00"
        + hpack_len_only(name_len, huffman)
        + name_bytes
        + hpack_len_only(value_len, huffman)
        + value_bytes
    )


class H2UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.5)
        chunks = []
        try:
            while sum(len(chunk) for chunk in chunks) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\x01" in chunk or b"\x00\x00\x04\x08" in b"".join(chunks):
                    break
        except socket.timeout:
            pass

        mode = h2_next_mode()
        send = self.request.sendall
        send(h2_frame(0x4, 0x0, 0))

        if mode == "valid_headers_end":
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))
            return

        if mode == "valid_data":
            send(h2_frame(0x1, 0x4, 1, hpack_status(b"200")))
            send(h2_frame(0x0, 0x1, 1, b"ok"))
            return

        if mode == "early_then_final":
            send(h2_frame(0x1, 0x4, 1, hpack_status(b"103") + hpack_literal(b"link", b"</x>; rel=preload")))
            send(h2_frame(0x1, 0x4, 1, hpack_status(b"200")))
            send(h2_frame(0x0, 0x1, 1, b"ok"))
            return

        if mode == "duplicate_status":
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200") + hpack_status(b"204")))
            return

        if mode == "no_status":
            send(h2_frame(0x1, 0x5, 1, hpack_literal(b"x-test", b"missing-status")))
            return

        if mode == "split_continuation":
            block = hpack_status(b"200") + hpack_literal(b"x-split", b"S" * 128)
            send(h2_frame(0x1, 0x0, 1, block[:8]))
            time.sleep(0.01)
            send(h2_frame(0x9, 0x5, 1, block[8:]))
            return

        if mode == "invalid_hpack":
            send(h2_frame(0x1, 0x5, 1, b"\xff\xff\xff"))
            return

        if mode == "data_before_headers":
            send(h2_frame(0x0, 0x0, 1, b"bad"))
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))
            return

        if mode == "large_header":
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200") + hpack_literal(b"x-large", b"L" * 12000)))
            return

        if mode == "padded_too_long":
            send(h2_frame(0x1, 0x0c, 1, b"\xff" + hpack_status(b"200")))
            return

        if mode == "rst_after_headers":
            send(h2_frame(0x1, 0x4, 1, hpack_status(b"200")))
            send(h2_frame(0x3, 0x0, 1, (0).to_bytes(4, "big")))
            return

        if mode == "goaway_after_headers":
            send(h2_frame(0x1, 0x4, 1, hpack_status(b"200")))
            send(h2_frame(0x7, 0x0, 0, (1).to_bytes(4, "big") + (0).to_bytes(4, "big")))
            return

        if mode == "hpack_name_len_inflate":
            block = hpack_status(b"200") + hpack_literal_with_declared_lengths(
                0x1fffff, b"x-inflate", 1, b"v"
            )
            send(h2_frame(0x1, 0x5, 1, block))
            return

        if mode == "hpack_value_len_inflate":
            block = hpack_status(b"200") + hpack_literal_with_declared_lengths(
                6, b"x-val", 0x1fffff, b"v" * 16
            )
            send(h2_frame(0x1, 0x5, 1, block))
            return

        if mode == "hpack_name_truncated":
            block = hpack_status(b"200") + b"\x00" + hpack_len_only(4096) + b"x" * 8
            send(h2_frame(0x1, 0x5, 1, block))
            return

        if mode == "hpack_value_truncated":
            block = (
                hpack_status(b"200")
                + b"\x00"
                + hpack_string(b"x-trunc")
                + hpack_len_only(4096)
                + b"v" * 8
            )
            send(h2_frame(0x1, 0x5, 1, block))
            return

        if mode == "hpack_continuation_empty":
            block = hpack_status(b"200") + hpack_literal(b"x-empty", b"E" * 64)
            send(h2_frame(0x1, 0x0, 1, block[:3]))
            send(h2_frame(0x9, 0x0, 1, b""))
            send(h2_frame(0x9, 0x4, 1, block[3:]))
            return

        if mode == "hpack_dynamic_table_update_ext":
            block = b"\x3f\x80\x00" + hpack_status(b"200")
            send(h2_frame(0x1, 0x5, 1, block))
            return

        if mode == "hpack_index_ext":
            block = b"\x0f\x2f" + hpack_string(b"v")
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200") + block))
            return

        if mode == "many_ping":
            for i in range(128):
                send(h2_frame(0x6, 0x0, 0, i.to_bytes(8, "big")))
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))
            return

        if mode == "many_settings":
            for i in range(128):
                payload = (
                    (0x04).to_bytes(2, "big")
                    + (65535 + (i % 3)).to_bytes(4, "big")
                )
                send(h2_frame(0x4, 0x0, 0, payload))
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))
            return

        if mode == "zero_window_update":
            send(h2_frame(0x8, 0x0, 1, (0).to_bytes(4, "big")))
            send(h2_frame(0x8, 0x0, 0, (0).to_bytes(4, "big")))
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))
            return

        if mode == "window_shrink":
            payload = (0x04).to_bytes(2, "big") + (0).to_bytes(4, "big")
            send(h2_frame(0x4, 0x0, 0, payload))
            send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))
            return

        if mode == "priority_padding_edge":
            block = hpack_status(b"200")
            payload = b"\x00" + (0).to_bytes(4, "big") + b"\xff" + block
            send(h2_frame(0x1, 0x2c, 1, payload))
            return

        send(h2_frame(0x1, 0x5, 1, hpack_status(b"200")))


class H2CaptureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1.0)
        chunks = []
        total = 0
        max_capture = 36 * 1024 * 1024

        try:
            self.request.sendall(h2_frame(0x4, 0x0, 0))
        except OSError:
            return

        while total < max_capture:
            try:
                chunk = self.request.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        received = b"".join(chunks)
        summary = summarize_h2_capture(received)
        body = summary.encode("ascii", "replace")

        try:
            self.request.sendall(
                h2_frame(
                    0x1,
                    0x4,
                    1,
                    hpack_status(b"200")
                    + hpack_literal(b"content-type", b"text/plain")
                    + hpack_literal(b"content-length", str(len(body)).encode("ascii")),
                )
            )
            self.request.sendall(h2_frame(0x0, 0x1, 1, body))
        except OSError:
            return


def summarize_h2_capture(data):
    if not data.startswith(H2_PREFACE):
        return f"preface=no received={len(data)} parse=bad"

    pos = len(H2_PREFACE)
    frames = []
    data_total = 0
    parse = "ok"

    while pos + 9 <= len(data):
        length = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
        frame_type = data[pos + 3]
        flags = data[pos + 4]
        stream_id = int.from_bytes(data[pos + 5 : pos + 9], "big") & 0x7fffffff
        end = pos + 9 + length

        if end > len(data):
            parse = f"truncated(type={frame_type},len={length},remaining={len(data) - pos - 9})"
            frames.append((frame_type, flags, stream_id, length))
            break

        frames.append((frame_type, flags, stream_id, length))

        if frame_type == 0x0 and stream_id == 1:
            data_total += length

        pos = end

    if pos + 9 > len(data) and pos != len(data) and parse == "ok":
        parse = f"trailing={len(data) - pos}"

    data_lengths = [str(length) for frame_type, _flags, stream_id, length in frames if frame_type == 0x0 and stream_id == 1]
    max_data = max((length for frame_type, _flags, stream_id, length in frames if frame_type == 0x0 and stream_id == 1), default=0)
    bad_data = any(length > 16384 for frame_type, _flags, stream_id, length in frames if frame_type == 0x0 and stream_id == 1)

    if len(data_lengths) > 12:
        shown = ",".join(data_lengths[:8]) + ",...," + ",".join(data_lengths[-3:])
    else:
        shown = ",".join(data_lengths)

    return (
        f"preface=yes received={len(data)} frames={len(frames)} parse={parse} "
        f"data_frames={len(data_lengths)} data_total={data_total} "
        f"max_data={max_data} oversized_data={str(bad_data).lower()} "
        f"data_lengths={shown}"
    )


def serve_h2_upstream():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", 19325), H2UpstreamHandler) as h2d:
        print("Raw H2 upstream on :19325")
        h2d.serve_forever()


def serve_h2_capture():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", 19326), H2CaptureHandler) as h2d:
        print("Raw H2 capture upstream on :19326")
        h2d.serve_forever()


socketserver.ThreadingTCPServer.allow_reuse_address = True
threading.Thread(target=serve_raw_upstream, daemon=True).start()
threading.Thread(target=serve_h2_upstream, daemon=True).start()
threading.Thread(target=serve_h2_capture, daemon=True).start()
with socketserver.ThreadingTCPServer(("127.0.0.1", 19323), BackendHandler) as httpd:
    print("Backend on :19323")
    httpd.serve_forever()
