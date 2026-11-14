#!/usr/bin/env python3
"""ASTRO-GUARD local account server (student prototype).
Accounts and per-user workspace are stored in SQLite on this computer.
Run only on localhost unless you add a reviewed production deployment layer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "instance"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "astro_guard.sqlite3"
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8000"))
SESSION_COOKIE = "AG_SESSION"
SESSION_TTL = 7 * 24 * 60 * 60
PASSWORD_ITERATIONS = 310_000
MAX_BODY = 6 * 1024 * 1024
LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL,
            password_salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspaces (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            data_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        """)


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, dklen=32)


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Handler(SimpleHTTPRequestHandler):
    server_version = "ASTRO-GUARD-Local/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def translate_path(self, path: str) -> str:
        # Keep private server files and the SQLite account database outside the static web root.
        from urllib.parse import unquote
        from posixpath import normpath
        clean = normpath(unquote(urlparse(path).path)).lstrip("/")
        parts = [part for part in clean.split("/") if part and part not in (".", "..")]
        if not parts:
            return str(BASE_DIR / "index.html")
        if parts[0] in {"instance", "__pycache__"} or parts[0] in {"app.py", ".gitignore"}:
            return str(BASE_DIR / "__private_not_served__")
        candidate = (BASE_DIR / Path(*parts)).resolve()
        try:
            candidate.relative_to(BASE_DIR.resolve())
        except ValueError:
            return str(BASE_DIR / "__private_not_served__")
        return str(candidate)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def send_json(self, status: int, payload: dict, extra_headers: dict | None = None):
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request length.")
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Request body is empty or larger than 6 MB.")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Request must contain valid JSON.")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object.")
        return value

    def same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True  # browser same-origin form/navigation compatibility
        try:
            return urlparse(origin).netloc.lower() == self.headers.get("Host", "").lower()
        except Exception:
            return False

    def session_record(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie[SESSION_COOKIE].value
        except (KeyError, Exception):
            return None
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = int(time.time())
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            row = conn.execute("""
                SELECT s.csrf_token, s.expires_at, u.id, u.email, u.display_name
                FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=? AND s.expires_at>=?
            """, (token_hash, now)).fetchone()
        if not row:
            return None
        return {"token_hash": token_hash, "csrf": row["csrf_token"], "user_id": row["id"],
                "email": row["email"], "display_name": row["display_name"]}

    def require_user(self, csrf: bool = False):
        if not self.same_origin():
            self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Cross-origin request rejected."})
            return None
        record = self.session_record()
        if not record:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Please sign in again."})
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), record["csrf"]):
            self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Session security check failed. Refresh and try again."})
            return None
        return record

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            try:
                with db() as conn:
                    conn.execute("SELECT 1").fetchone()
                self.send_json(HTTPStatus.OK, {"ok": True, "service": "ASTRO-GUARD", "database": "ready"})
            except sqlite3.Error:
                self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "The local account database is unavailable."})
            return
        if path == "/api/me":
            record = self.session_record()
            if not record:
                self.send_json(HTTPStatus.OK, {"authenticated": False})
            else:
                self.send_json(HTTPStatus.OK, {"authenticated": True, "csrf": record["csrf"],
                    "user": {"id": record["user_id"], "email": record["email"], "display_name": record["display_name"]}})
            return
        if path == "/api/workspace":
            record = self.require_user()
            if not record:
                return
            with db() as conn:
                row = conn.execute("SELECT data_json FROM workspaces WHERE user_id=?", (record["user_id"],)).fetchone()
            workspace = json.loads(row["data_json"]) if row else None
            self.send_json(HTTPStatus.OK, {"workspace": workspace})
            return
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})
            return
        if not self.same_origin():
            self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Cross-origin request rejected."})
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return

        if path == "/api/register":
            display_name = str(data.get("display_name", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            password = data.get("password", "")
            if not (2 <= len(display_name) <= 40):
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Display name must be 2–40 characters."}); return
            if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Enter a valid email address."}); return
            if not isinstance(password, str) or not 8 <= len(password) <= 128:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Password must be 8–128 characters."}); return
            salt = secrets.token_bytes(16)
            digest = password_digest(password, salt)
            try:
                with db() as conn:
                    cur = conn.execute("INSERT INTO users(email,display_name,password_salt,password_hash,created_at) VALUES(?,?,?,?,?)",
                                       (email, display_name, salt, digest, int(time.time())))
                    user_id = cur.lastrowid
            except sqlite3.IntegrityError:
                self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "An account with this email already exists. Sign in instead."}); return
            self.create_session(user_id)
            return

        if path == "/api/login":
            ip = self.client_address[0]
            now = time.time()
            attempts = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 60]
            if len(attempts) >= 10:
                self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"ok": False, "error": "Too many sign-in attempts. Wait one minute and try again."}); return
            email = str(data.get("email", "")).strip().lower()
            password = data.get("password", "")
            with db() as conn:
                row = conn.execute("SELECT id,email,display_name,password_salt,password_hash FROM users WHERE email=?", (email,)).fetchone()
            valid = bool(row and isinstance(password, str) and hmac.compare_digest(password_digest(password, row["password_salt"]), row["password_hash"]))
            if not valid:
                attempts.append(now); LOGIN_ATTEMPTS[ip] = attempts
                self.send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Email or password is incorrect."}); return
            LOGIN_ATTEMPTS[ip] = []
            self.create_session(row["id"])
            return

        if path == "/api/logout":
            record = self.require_user(csrf=True)
            if not record:
                return
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (record["token_hash"],))
            self.send_json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unknown API endpoint."})

    def do_PUT(self):
        if urlparse(self.path).path != "/api/workspace":
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."}); return
        record = self.require_user(csrf=True)
        if not record:
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}); return
        serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > MAX_BODY:
            self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error": "Workspace is too large to save."}); return
        with db() as conn:
            conn.execute("""INSERT INTO workspaces(user_id,data_json,updated_at) VALUES(?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET data_json=excluded.data_json, updated_at=excluded.updated_at""",
                (record["user_id"], serialized, int(time.time())))
        self.send_json(HTTPStatus.OK, {"ok": True, "saved_at": int(time.time())})

    def create_session(self, user_id: int):
        raw_token = secrets.token_urlsafe(40)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        csrf = secrets.token_urlsafe(24)
        now = int(time.time())
        with db() as conn:
            conn.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",
                         (token_hash, user_id, csrf, now + SESSION_TTL, now))
            row = conn.execute("SELECT id,email,display_name FROM users WHERE id=?", (user_id,)).fetchone()
        cookie = f"{SESSION_COOKIE}={raw_token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax"
        self.send_json(HTTPStatus.OK, {"ok": True, "authenticated": True,
            "user": {"id": row["id"], "email": row["email"], "display_name": row["display_name"]}}, {"Set-Cookie": cookie})


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("\nASTRO-GUARD local account server is running.")
    print(f"Open: http://{HOST}:{PORT}")
    print(f"Database: {DB_PATH}")
    print("Keep this terminal open. Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
