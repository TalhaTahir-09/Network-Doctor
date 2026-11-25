"""
Network Doctor web server.

Serves index.html and runs network-doctor.py on request, returning
the results as JSON. Binds to localhost only.

Run from an admin terminal (Scapy needs packet privileges):
    Windows:      python server.py
    macOS/Linux:  sudo python3 server.py
Then open http://127.0.0.1:8000
"""

import importlib.util
import json
import re
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
HOST, PORT = "127.0.0.1", 8000

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

run_lock = threading.Lock()


def load_doctor():
    # The file name has a hyphen, so a normal import won't work.
    spec = importlib.util.spec_from_file_location(
        "network_doctor", HERE / "network-doctor.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


doctor = load_doctor()


class Handler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_body(status, body, "application/json")

    def do_GET(self):
        url = urlparse(self.path)

        if url.path in ("/", "/index.html"):
            page = (HERE / "index.html").read_bytes()
            self.send_body(200, page, "text/html; charset=utf-8")
        elif url.path == "/api/run":
            self.handle_run(parse_qs(url.query))
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_run(self, query):
        domain = (query.get("domain", [doctor.TEST_DOMAIN])[0]).strip().lower()

        if not DOMAIN_RE.match(domain):
            self.send_json(400, {"error": "Enter a valid domain, like example.com"})
            return

        if not run_lock.acquire(blocking=False):
            self.send_json(429, {"error": "A check is already running. Try again in a moment."})
            return

        try:
            start = time.perf_counter()
            results = doctor.run_diagnostics(domain)
            self.send_json(200, {
                "domain": domain,
                "ran_at": datetime.now(timezone.utc).isoformat(),
                "duration_s": round(time.perf_counter() - start, 1),
                "results": results,
            })
        except Exception as error:
            self.send_json(500, {"error": f"The check failed to run: {error}"})
        finally:
            run_lock.release()


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Network Doctor is running at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
