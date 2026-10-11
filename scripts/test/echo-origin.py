#!/usr/bin/env python3
"""Minimal echo origin for the all-rules test harness.

Usage: echo-origin.py <port> <origin_id>
Responds to every request with a JSON dump of what it received and
Cache-Control: public, max-age=60 so cache rules have something to store.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
ORIGIN = sys.argv[2]


class Echo(BaseHTTPRequestHandler):
    def _respond(self):
        body = json.dumps({
            "origin": ORIGIN,
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "public, max-age=60")
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _respond

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Echo).serve_forever()
