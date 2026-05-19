#!/usr/bin/env python3
import socketserver
import http.server
import threading
import time
from urllib.parse import parse_qs, urlparse


def parse_hex_csv(value, default):
    if not value:
        return default
    chunks = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        chunks.append(bytes.fromhex(item))
    return chunks or default


class CharsetOobHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(8192).decode("latin-1", errors="replace").strip()
        if not line:
            return
        parts = line.split()
        path = parts[1] if len(parts) >= 2 else "/"
        while True:
            header = self.rfile.readline(8192)
            if not header or header in (b"\r\n", b"\n"):
                break

        parsed = urlparse(path)
        qs = parse_qs(parsed.query)
        delay = float(qs.get("delay", ["0.03"])[0])
        tail = qs.get("tail", ["58"])[0]
        prefix_len = int(qs.get("prefix", ["0"])[0])
        mode = qs.get("mode", ["euro3"])[0]
        framing = qs.get("framing", ["chunked"])[0]

        if mode == "euro3":
            chunks = [b"A" * prefix_len + bytes.fromhex("e2"), bytes.fromhex("82"), bytes.fromhex("ac"), bytes.fromhex(tail)]
        elif mode == "euro4":
            chunks = [b"A" * prefix_len + bytes.fromhex("f0"), bytes.fromhex("9f"), bytes.fromhex("98"), bytes.fromhex("80"), bytes.fromhex(tail)]
        elif mode == "custom":
            chunks = parse_hex_csv(qs.get("chunks", [""])[0], [bytes.fromhex("e2"), bytes.fromhex("82"), bytes.fromhex("ac"), bytes.fromhex(tail)])
        else:
            chunks = [b"plain\n"]

        headers = [
            b"HTTP/1.1 200 OK",
            b"Content-Type: text/plain; charset=utf-8",
            b"Connection: close",
        ]

        if framing == "chunked":
            headers.append(b"Transfer-Encoding: chunked")
        elif framing == "length":
            headers.append(b"Content-Length: " + str(sum(len(c) for c in chunks)).encode("ascii"))
        elif framing != "close":
            headers.append(b"X-Rift-Warning: unknown framing, using close-delimited body")

        self.wfile.write(b"\r\n".join(headers) + b"\r\n\r\n")
        self.wfile.flush()

        for chunk in chunks:
            if framing == "chunked":
                self.wfile.write(("%x\r\n" % len(chunk)).encode("ascii") + chunk + b"\r\n")
            else:
                self.wfile.write(chunk)
            self.wfile.flush()
            if delay:
                time.sleep(delay)

        if framing == "chunked":
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()


class ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class DelayBackendHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self._respond()

    def _respond(self):
        delay = float(self.headers.get("X-Delay", "5"))
        if delay:
            time.sleep(delay)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"backend ok\n")

    def log_message(self, _fmt, *_args):
        return


def serve_delay_backend():
    with ReuseTCPServer(("127.0.0.1", 19323), DelayBackendHandler) as server:
        print("Delay backend on :19323", flush=True)
        server.serve_forever()


def serve_charset_backend():
    with ReuseTCPServer(("127.0.0.1", 19325), CharsetOobHandler) as server:
        print("Charset OOB backend on :19325", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve_delay_backend, daemon=True).start()
    serve_charset_backend()
