#!/usr/bin/env python3
"""Simple HTTP backend with deterministic edge-case responses."""
import http.server
import time
import socketserver
import urllib.parse

PATTERN_SIZE = 65536


def pattern_bytes(size=PATTERN_SIZE):
    return bytes((i * 37 + 11) & 0xff for i in range(size))


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.close_connection = True
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        case = params.get("case", [""])[0]
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
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if case == "chunked-trailers":
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n"
                b"Trailer: X-Trail\r\n"
                b"\r\n"
                b"5\r\nhello\r\n"
                b"6\r\n world\r\n"
                b"0\r\n"
                b"X-Trail: done\r\n"
                b"\r\n"
            )
            return
        if case == "pattern-length":
            body = pattern_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if case == "pattern-chunked":
            body = pattern_bytes()
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Accept-Ranges: bytes\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            for offset in range(0, len(body), 1024):
                chunk = body[offset:offset + 1024]
                self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
                self.wfile.write(chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            return

        delay = float(self.headers.get('X-Delay', '5'))
        time.sleep(delay)
        body = b'backend ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.close_connection = True
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        delay = float(self.headers.get('X-Delay', '5'))
        time.sleep(delay)
        body = b'backend ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


with ThreadingTCPServer(("127.0.0.1", 19323), BackendHandler) as httpd:
    print("Backend on :19323")
    httpd.serve_forever()
