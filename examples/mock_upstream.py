#!/usr/bin/env python3
"""Disposable upstream for examples/dev.yaml. It never returns the secret."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


EXPECTED = "Bearer " + os.environ.get("MOCK_SECRET", "upstream-demo-key")


class Handler(BaseHTTPRequestHandler):
    server_version = "forcefield-example"

    def authenticated(self):
        if self.headers.get("Authorization") == EXPECTED:
            return True
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"bad upstream credential"}\n')
        return False

    def do_GET(self):
        if not self.authenticated():
            return
        target = urlsplit(self.path)
        if target.path != "/v1/resources":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"resources":[]}\n')

    def do_POST(self):
        if not self.authenticated():
            return
        if urlsplit(self.path).path != "/v1/resources":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            document = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        encoded = json.dumps({"created": document.get("kind")}).encode() + b"\n"
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler logs request lines, never request headers.
        super().log_message(fmt, *args)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
