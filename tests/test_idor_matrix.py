#!/usr/bin/env python3
"""Tests for idor-matrix. Run: python3 -m unittest discover -s tests -v"""
import sys, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import idor_matrix as m

CFG = {
    "base_url": "http://127.0.0.1:0",
    "accounts": {
        "alice": {"headers": {"X-User": "alice"}, "ids": [101]},
        "bob": {"headers": {"X-User": "bob"}, "ids": [201]},
    },
    "endpoints": [{"name": "inv", "path": "/api/invoices/{id}"}],
}


class TestMatrix(unittest.TestCase):
    def test_cartesian_rows(self):
        rows = m.build_matrix(CFG)
        # 1 endpoint x 2 requesters x 2 owners x 1 id each = 4
        self.assertEqual(len(rows), 4)
        self.assertTrue(all("{id}" not in r["path"] for r in rows))

    def test_marks_same_account(self):
        rows = m.build_matrix(CFG)
        self.assertEqual(sum(r["same_account"] for r in rows), 2)

    def test_path_substitution(self):
        rows = m.build_matrix(CFG)
        self.assertIn("/api/invoices/201", {r["path"] for r in rows})


class TestVerdict(unittest.TestCase):
    R = {"same_account": False}

    def test_denied(self):
        for code in (401, 403):
            self.assertEqual(m.verdict(self.R, code, 10, 10), "denied")

    def test_candidate(self):
        self.assertEqual(m.verdict(self.R, 200, 500, 300), "CANDIDATE_IDOR")

    def test_same_size_flagged_separately(self):
        self.assertEqual(m.verdict(self.R, 200, 500, 500), "CHECK_SAME_SIZE")

    def test_baseline(self):
        self.assertEqual(m.verdict({"same_account": True}, 200, 10, None), "baseline_ok")
        self.assertEqual(m.verdict({"same_account": True}, 403, 0, None), "baseline_403")

    def test_error(self):
        self.assertEqual(m.verdict(self.R, None, None, None), "ERROR")


class _Handler(BaseHTTPRequestHandler):
    """vuln: any id returns 200. safe: only the owner's id returns 200."""
    def do_GET(self):
        user = self.headers.get("X-User", "")
        ep, _, oid = self.path.strip("/").partition("/")
        if ep == "vuln":
            code = 200
        elif ep == "safe":
            code = 200 if (user == "alice" and oid == "101") or (user == "bob" and oid == "201") else 403
        else:
            code = 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        # pad so different objects have different sizes (some APIs really do return
        # identical lengths, which is why verdict() has a separate same-size branch)
        pad = b"x" * (int(oid) % 37 if oid.isdigit() else 0)
        self.wfile.write(b'{"id": %s, "secret": "s", "pad": "%s"}' % (oid.encode(), pad))

    def log_message(self, *a):
        pass


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _cfg(self, ep):
        cfg = {k: (v if k != "base_url" else f"http://127.0.0.1:{self.port}") for k, v in CFG.items()}
        cfg["endpoints"] = [{"name": ep, "path": f"/{ep}/{{id}}"}]
        return cfg

    def test_vulnerable_endpoint_detected(self):
        res = m.run(self._cfg("vuln"), allow_write=False, delay=0)
        s = m.summarise(res)
        self.assertEqual(len(s["candidate_idor"]), 2)   # alice->bob, bob->alice
        self.assertEqual(len(s["errors"]), 0)

    def test_safe_endpoint_not_flagged(self):
        res = m.run(self._cfg("safe"), allow_write=False, delay=0)
        s = m.summarise(res)
        self.assertEqual(len(s["candidate_idor"]), 0)
        self.assertTrue(all(r["verdict"] == "denied" for r in res if not r["same_account"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
