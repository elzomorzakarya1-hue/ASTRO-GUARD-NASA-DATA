#!/usr/bin/env python3
"""Smoke tests for ASTRO-GUARD's localhost account API.

Uses only the Python standard library. The test launches an isolated copy of the
server and database so it never touches a user's real local `instance/` data.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

SOURCE = Path(__file__).resolve().parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class AstroGuardServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="astro_guard_test_")
        cls.root = Path(cls.temp.name)
        for name in ("app.py", "index.html", "mission_ops.js", "earth-hero.webp"):
            shutil.copy2(SOURCE / name, cls.root / name)
        cls.port = free_port()
        env = os.environ.copy()
        env["PORT"] = str(cls.port)
        cls.proc = subprocess.Popen(
            [sys.executable, "app.py"], cwd=cls.root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.jar = http.cookiejar.CookieJar()
        cls.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cls.jar))
        for _ in range(60):
            try:
                cls.request("GET", "/api/health")
                break
            except Exception:
                if cls.proc.poll() is not None:
                    output = cls.proc.stdout.read() if cls.proc.stdout else ""
                    raise RuntimeError(f"Server exited early:\n{output}")
                time.sleep(0.15)
        else:
            raise RuntimeError("Server did not become ready.")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None):
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if getattr(cls, "temp", None):
            cls.temp.cleanup()

    @classmethod
    def request(cls, method, path, payload=None, headers=None, opener=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(cls.base + path, data=data, method=method, headers=headers or {})
        client = opener or cls.opener
        try:
            with client.open(req, timeout=4) as response:
                raw = response.read()
                content_type = response.headers.get("Content-Type", "")
                return response.status, json.loads(raw) if "json" in content_type else raw
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            content_type = exc.headers.get("Content-Type", "")
            if "json" in content_type and raw:
                return exc.code, json.loads(raw)
            return exc.code, raw

    def test_health_and_front_page(self):
        status, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["database"], "ready")
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"ASTRO-GUARD", body)

    def test_registration_duplicate_login_and_workspace_isolation(self):
        status, body = self.request("POST", "/api/register", {
            "display_name": "Demo Crew A", "email": "crew-a@example.test", "password": "test-password-123"
        })
        self.assertEqual(status, 200, body)
        status, me = self.request("GET", "/api/me")
        self.assertTrue(me["authenticated"])
        self.assertEqual(me["user"]["email"], "crew-a@example.test")
        csrf_a = me["csrf"]
        workspace_a = {"appState": {"xp": 25, "checkins": [{"mission_day": 88}]}, "missionOps": {"profile": "mars"}}
        status, body = self.request("PUT", "/api/workspace", workspace_a, {"X-CSRF-Token": csrf_a})
        self.assertEqual(status, 200, body)
        status, body = self.request("GET", "/api/workspace")
        self.assertEqual(body["workspace"], workspace_a)

        status, body = self.request("POST", "/api/register", {
            "display_name": "Duplicate", "email": "CREW-A@example.test", "password": "test-password-456"
        })
        self.assertEqual(status, 409)

        status, body = self.request("POST", "/api/logout", {}, {"X-CSRF-Token": csrf_a})
        self.assertEqual(status, 200)
        status, me = self.request("GET", "/api/me")
        self.assertFalse(me["authenticated"])

        status, body = self.request("POST", "/api/login", {"email": "crew-a@example.test", "password": "wrong-password"})
        self.assertEqual(status, 401)
        status, body = self.request("POST", "/api/login", {"email": "crew-a@example.test", "password": "test-password-123"})
        self.assertEqual(status, 200, body)
        status, me = self.request("GET", "/api/me")
        self.assertTrue(me["authenticated"])
        status, body = self.request("GET", "/api/workspace")
        self.assertEqual(body["workspace"], workspace_a)

        # A different browser cookie jar represents a separate user session.
        jar_b = http.cookiejar.CookieJar()
        opener_b = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar_b))
        status, body = self.request("POST", "/api/register", {
            "display_name": "Demo Crew B", "email": "crew-b@example.test", "password": "test-password-789"
        }, opener=opener_b)
        self.assertEqual(status, 200, body)
        status, body = self.request("GET", "/api/workspace", opener=opener_b)
        self.assertIsNone(body["workspace"])

    def test_private_database_is_not_served(self):
        status, _ = self.request("GET", "/instance/astro_guard.sqlite3")
        self.assertEqual(status, 404)

    def test_validation_and_csrf(self):
        status, body = self.request("POST", "/api/register", {
            "display_name": "A", "email": "not-an-email", "password": "short"
        })
        self.assertEqual(status, 400)
        status, body = self.request("PUT", "/api/workspace", {"appState": {}}, {"X-CSRF-Token": "bad"})
        self.assertIn(status, (401, 403))

    def test_nasa_research_catalog_cards_present(self):
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        for accession in ("OSD-569", "OSD-570", "OSD-575", "OSD-656", "OSD-574"):
            self.assertIn(accession, page)
        self.assertIn("data-study-select", page)
        self.assertIn("data.nasa.gov/dataset/?q=health", page)
        self.assertIn("NASA Open Science Data Repository", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
