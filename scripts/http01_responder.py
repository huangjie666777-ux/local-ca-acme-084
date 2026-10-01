#!/usr/bin/env python3
"""Minimal HTTP-01 challenge responder for the ACME demo.

Serves files from a webroot under ``/.well-known/acme-challenge/`` on
127.0.0.1. The CA server must be started with ``ACME_CHALLENGE_PORT`` set to
the same port.

Usage:
  .venv/bin/python scripts/http01_responder.py --port 8099 --webroot ./webroot
"""

from __future__ import annotations

import argparse
import http.server
import os
import socketserver


class _Handler(http.server.BaseHTTPRequestHandler):
    webroot = "./webroot"

    def do_GET(self):
        prefix = "/.well-known/acme-challenge/"
        if not self.path.startswith(prefix):
            self.send_response(404)
            self.end_headers()
            return
        token = self.path[len(prefix) :].split("/")[0]
        if not token or "/" in self.path[len(prefix) :]:
            self.send_response(404)
            self.end_headers()
            return
        # webroot is the directory that contains .well-known/acme-challenge/.
        path = os.path.join(self.webroot, ".well-known", "acme-challenge", token)
        if not os.path.isfile(path):
            self.send_response(404)
            self.end_headers()
            return
        with open(path, "rb") as handle:
            data = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP-01 challenge responder")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--webroot", default="./webroot")
    args = parser.parse_args()
    os.makedirs(args.webroot, exist_ok=True)
    _Handler.webroot = args.webroot
    with socketserver.TCPServer(("127.0.0.1", args.port), _Handler) as httpd:
        print(f"serving {args.webroot} on 127.0.0.1:{args.port}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
