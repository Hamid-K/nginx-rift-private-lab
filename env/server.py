#!/usr/bin/env python3
"""Simple HTTP backend with deterministic edge-case responses."""
import http.server
import time
import socketserver
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
        if case == "many-headers":
            count = int_param(params, "n", 64, maximum=1024)
            size = int_param(params, "size", 64, maximum=8192)
            body = b"many headers body\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
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
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 19323), BackendHandler) as httpd:
    print("Backend on :19323")
    httpd.serve_forever()
