#!/usr/bin/env python3
"""Read-only LAN server for an explicitly pinned, preverified Termi repository."""
import argparse
import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

from verify import safe_file, sha


class Snapshot:
    def __init__(self, root, verification, expected_hash):
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or sha(verification) != expected_hash:
            raise ValueError("Verification report differs from explicit pin")
        self.root = root.resolve()
        self.report = json.loads(verification.read_text())
        if self.report.get("schema") != 1 or not 1 <= len(self.report["routes"]) <= 100000:
            raise ValueError("Invalid serving report")
        self.expires = datetime.datetime.fromisoformat(self.report["valid_until"])
        if self.expires.tzinfo is None or self.expired():
            raise ValueError("Repository metadata expired")
        self.files = {}
        for route, item in self.report["routes"].items():
            path = safe_file(self.root, item["relative"])
            if sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
                raise ValueError("Repository changed since signature verification")
            stat = path.stat()
            self.files[route] = (path, item, (stat.st_size, stat.st_mtime_ns))

    def expired(self):
        return datetime.datetime.now(datetime.timezone.utc) >= self.expires


def handler(snapshot):
    class Handler(BaseHTTPRequestHandler):
        server_version = "TermiLocal/1"

        def do_HEAD(self):
            self.respond(head=True)

        def do_GET(self):
            self.respond(head=False)

        def respond(self, head):
            url = urlsplit(self.path)
            if url.query or url.fragment:
                self.send_error(404)
                return
            try:
                route = unquote(url.path, errors="strict")
            except (UnicodeError, ValueError):
                self.send_error(404)
                return
            if snapshot.expired():
                self.send_error(503, "Repository metadata expired; signed renewal required")
                return
            if route in ("/", "/healthz"):
                data = json.dumps({k: v for k, v in snapshot.report.items() if k != "routes"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if not head:
                    self.wfile.write(data)
                return
            entry = snapshot.files.get(url.path) or snapshot.files.get(route)
            if entry is None:
                self.send_error(404)
                return
            path, item, expected_stat = entry
            try:
                if safe_file(snapshot.root, item["relative"]) != path:
                    raise ValueError("Changed path")
                stream = path.open("rb")
                stat = os.fstat(stream.fileno())
                if (stat.st_size, stat.st_mtime_ns) != expected_stat:
                    stream.close()
                    raise ValueError("Changed snapshot")
            except (OSError, ValueError):
                self.send_error(503, "Snapshot changed; verify and restart the server")
                return
            with stream:
                start, end = 0, item["bytes"] - 1
                requested = self.headers.get("Range")
                if requested:
                    match = re.fullmatch(r"bytes=(\d+)-(\d*)", requested)
                    if match:
                        start = int(match[1])
                        end = min(int(match[2]), end) if match[2] else end
                    if not match or start > end or start >= item["bytes"]:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{item['bytes']}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                self.send_response(206 if requested else 200)
                if requested:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{item['bytes']}")
                self.send_header("Content-Length", str(end - start + 1))
                self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("ETag", '"' + item["sha256"] + '"')
                self.send_header("Cache-Control", "public, max-age=31536000, immutable" if "/pool/" in route or "/by-hash/" in route else "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if not head:
                    stream.seek(start)
                    remaining = end - start + 1
                    try:
                        while remaining:
                            block = stream.read(min(65536, remaining))
                            if not block:
                                break
                            self.wfile.write(block)
                            remaining -= len(block)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--verification-sha256", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    snapshot = Snapshot(args.root, args.verification, args.verification_sha256)
    with ThreadingHTTPServer((args.bind, args.port), handler(snapshot)) as server:
        print(f"Termi local repository: http://{args.bind}:{args.port}/apt/{snapshot.report['channel']}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
