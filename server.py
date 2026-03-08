#!/usr/bin/env python3
"""
OSS Watchdog Server

Usage:
    uv run server.py [port]
    python3 server.py [port]

Serves static files from ./site and handles POST /api/submit
"""

import json
import os
import re
import hashlib
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = int(os.environ.get("PORT", 8080))
SITE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")
QUEUE_FILE = os.path.join(SITE_DIR, "data", "queue", "jobs.json")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_queue():
    try:
        with open(QUEUE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"jobs": []}


def save_queue(q):
    os.makedirs(os.path.dirname(QUEUE_FILE), exist_ok=True)
    with open(QUEUE_FILE, "w") as f:
        json.dump(q, f, indent=2)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=SITE_DIR, **kw)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        if self.path != "/api/submit":
            return self.send_error(404)

        try:
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
            )
        except Exception:
            return self.respond(400, {"error": "Invalid JSON"})

        url = body.get("url", "").strip()
        if not url.startswith("http"):
            url = "https://" + url

        m = re.search(r"(?:github|gitlab)\.com/([^/]+)/([^/?\#]+)", url, re.I)
        if not m:
            return self.respond(400, {"error": "Invalid repo URL"})

        owner, repo = m.group(1), m.group(2).rstrip(".git")
        job_id = f"{owner}-{repo}-{hashlib.sha256(f'{owner}{repo}{now()}'.encode()).hexdigest()[:8]}"

        job = {
            "id": job_id,
            "url": url,
            "owner": owner,
            "repo": repo,
            "status": "pending",
            "submitted": now(),
            "options": {
                "ecosystem": body.get("ecosystem", "auto"),
                "severity": body.get("severity", "low"),
                "depth": body.get("depth", "shallow"),
            },
        }

        q = load_queue()
        q["jobs"].insert(0, job)
        q["lastUpdated"] = now()
        save_queue(q)

        print(f"[+] Queued: {owner}/{repo} ({job_id})")
        self.respond(201, {"job": job})

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print(f"http://localhost:{port}")
    HTTPServer(("", port), Handler).serve_forever()
