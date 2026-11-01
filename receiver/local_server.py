#!/usr/bin/env python3
"""A private sightings receiver that binds to loopback and stores a file.

The public endpoint is https://guardianprotocol.network/season1/sightings. A deployment
that cannot send there runs this instead and points `share` at it:

    python3 receiver/local_server.py --bind 127.0.0.1 --port 8766 --store sightings.jsonl

    python3 -m guardian_sensor share --endpoint http://127.0.0.1:8766/sightings

The body is the same document either way. It is counts. A canary value is not a field
in that document, and this server refuses a body that carries anything else.

This is not the cloud receiver. It does not verify a delete signature. It listens on
loopback only, because a file on the operator's machine is the point.

    python3 receiver/local_server.py --self-check

Python 3.9+ standard library only.
"""
import argparse
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate  # noqa: E402


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def read(self):
        if not os.path.exists(self.path):
            return {}
        rows = {}
        with open(self.path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                rows[validate.key_for(row)] = row
        return rows

    def write(self, entries):
        """Idempotent. A repeat overwrites the same identity instead of adding."""
        with self.lock:
            rows = self.read()
            written = 0
            for entry in entries:
                key = validate.key_for(entry)
                written += key not in rows
                rows[key] = entry
            self._save(rows)
        return written

    def drop_org(self, org):
        with self.lock:
            rows = self.read()
            kept = {k: v for k, v in rows.items() if v.get("org") != org}
            removed = len(rows) - len(kept)
            self._save(kept)
        return removed

    def _save(self, rows):
        folder = os.path.dirname(self.path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            for row in rows.values():
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    def text(self):
        if not os.path.exists(self.path):
            return ""
        with open(self.path, encoding="utf-8") as handle:
            return handle.read()


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(self, code, body):
            raw = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > validate.MAX_BYTES:
                self._send(413, {"error": "the body is larger than 256 KB"})
                return
            raw = self.rfile.read(length)
            try:
                document = json.loads(raw.decode("utf-8"))
                entries = validate.check_document(document)
            except (UnicodeError, ValueError) as exc:
                self._send(400, {"error": "the body is not JSON (%s)" % exc})
                return
            except validate.Refused as exc:
                self._send(400, {"error": str(exc)})
                return
            written = store.write(entries)
            self._send(200, {"accepted": len(entries), "stored": written})

        def do_DELETE(self):
            # Loopback only, and the headers have to be present. This does not check a
            # signature. The cloud receiver does. Do not put this process on a public
            # address and expect that check to have happened.
            org = self.headers.get("X-Guardian-Org", "")
            signature = self.headers.get("X-Guardian-Signature", "")
            if not org or not signature:
                self._send(400, {"error": "org and signature headers are both required"})
                return
            removed = store.drop_org(org)
            self._send(200, {"deleted": removed})

        def do_GET(self):
            self._send(405, {"error": "this receiver accepts POST"})

    return Handler


def serve(bind, port, path):
    if bind != "127.0.0.1":
        raise SystemExit("refusing to bind %s. This receiver is loopback only." % bind)
    store = Store(path)
    httpd = ThreadingHTTPServer((bind, port), make_handler(store))
    httpd.store = store
    return httpd


def _sample_document():
    return {
        "schema_version": "0.2",
        "org": "bench-local",
        "sightings": [{
            "org": "bench-local",
            "sensor_version": "guardian-sensor v0",
            "rules_version": "r2026.11.01",
            "pattern": "GP-0020",
            "action": "blocked",
            "hour": "2026-11-01T01",
            "count": 1,
            "source": "drill",
        }],
    }


def self_check():
    """A valid count is stored. A body carrying a canary value is refused and not stored."""
    probe = "cnry" + "ab" * 14
    folder = tempfile.mkdtemp(prefix="gp-receiver-")
    path = os.path.join(folder, "sightings.jsonl")
    httpd = serve("127.0.0.1", 0, path)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    url = "http://%s:%d/sightings" % (host, port)
    problems = []
    try:
        import urllib.error
        import urllib.request
        root = os.path.dirname(HERE)
        sys.path.insert(0, os.path.join(root, "sensor"))
        from guardian_sensor import hub  # noqa: E402

        record = {
            "time": "2026-11-01T01:15:00Z",
            "patterns": ["GP-0020"],
            "action": "blocked",
            "rules_fingerprint": "abc123",
            "detail": {"canary": "bench", "body": probe, "tool": "send_message"},
            "reasons": ["the value %s was in the arguments" % probe],
        }
        document = hub.build_sightings([record], "bench-local", "r2026.11.01")
        encoded = json.dumps(document)
        if probe in encoded:
            problems.append("build_sightings copied the canary value into the document")

        def post(body):
            data = json.dumps(body).encode("utf-8")
            request = urllib.request.Request(url, data=data, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status, response.read().decode("utf-8")
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read().decode("utf-8")

        status, body = post(document)
        if status != 200:
            problems.append("a count document was refused: %s %s" % (status, body))
        stored = httpd.store.text()
        if probe in stored:
            problems.append("the stored file contains the canary value")
        if "GP-0020" not in stored:
            problems.append("the stored file does not contain the pattern count")

        smuggled = _sample_document()
        smuggled["sightings"][0]["canary"] = probe
        status, body = post(smuggled)
        if status != 400:
            problems.append("a document with an extra field was accepted: %s" % status)
        if probe in httpd.store.text():
            problems.append("the refused value was written anyway")

        status, _body = post(document)
        if status != 200:
            problems.append("a repeat was refused")
        lines = [line for line in httpd.store.text().splitlines() if line.strip()]
        if len(lines) != 1:
            problems.append("a repeat added a row instead of overwriting (%d rows)" % len(lines))
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()
    if problems:
        print("FAIL")
        for problem in problems:
            print("  " + problem)
        return 1
    print("PASS private receiver stored a count and refused a canary value")
    print("endpoint example: %s" % url)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Loopback sightings receiver")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--store", default="sightings.jsonl")
    ap.add_argument("--self-check", action="store_true")
    a = ap.parse_args(argv)
    if a.self_check:
        return self_check()
    httpd = serve(a.bind, a.port, a.store)
    print("listening on http://%s:%d/sightings" % httpd.server_address)
    print("storing %s" % os.path.abspath(a.store))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
