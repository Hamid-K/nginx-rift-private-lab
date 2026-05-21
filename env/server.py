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


socketserver.ThreadingTCPServer.allow_reuse_address = True
threading.Thread(target=serve_raw_upstream, daemon=True).start()
with socketserver.ThreadingTCPServer(("127.0.0.1", 19323), BackendHandler) as httpd:
    print("Backend on :19323")
    httpd.serve_forever()
