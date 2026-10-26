"""Small, auditable persistence layer for identities, cases, audit events and rate limits.

SQLite is intended for local development and deployments with a persistent mounted
volume. Set PACKETWHISPERER_DB_PATH to a persistent path. For multi-instance
production, use a shared transactional database and shared rate-limit store.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

DB_PATH = os.getenv("PACKETWHISPERER_DB_PATH", "packetwhisperer-data.sqlite3")
PBKDF2_ROUNDS = 310_000
ROLES = {"admin", "analyst", "viewer"}


def _connect() -> sqlite3.Connection:
    path = Path(DB_PATH)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_store() -> None:
    with _connect() as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, salt TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
          active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cases (
          id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
          severity TEXT NOT NULL, evidence_sha256 TEXT, summary_json TEXT NOT NULL,
          created_by TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
          FOREIGN KEY(created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at REAL NOT NULL,
          actor_id TEXT, actor_name TEXT, action TEXT NOT NULL, resource_type TEXT,
          resource_id TEXT, outcome TEXT NOT NULL, details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events(occurred_at);
        CREATE INDEX IF NOT EXISTS cases_created_idx ON cases(created_at);
        CREATE TABLE IF NOT EXISTS rate_windows (
          bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, hits INTEGER NOT NULL
        );
        """)


def _password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS).hex()


def create_user(username: str, password: str, role: str) -> dict[str, Any]:
    username = username.strip().lower()
    if not 3 <= len(username) <= 64 or not username.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Username must be 3-64 characters using letters, digits, hyphens or underscores")
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be 12-256 characters")
    if role not in ROLES:
        raise ValueError("Invalid role")
    salt = secrets.token_bytes(16)
    user_id = secrets.token_hex(16)
    with _connect() as db:
        db.execute(
            "INSERT INTO users(id,username,password_hash,salt,role,created_at) VALUES(?,?,?,?,?,?)",
            (user_id, username, _password(password, salt), salt.hex(), role, time.time()),
        )
    return {"id": user_id, "username": username, "role": role}


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
    if row is None:
        # Equalize the expensive work for unknown usernames.
        _password(password, b"packetwhisperer!")
        return None
    valid = hmac.compare_digest(_password(password, bytes.fromhex(row["salt"])), row["password_hash"])
    if not valid or not row["active"]:
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def get_user(user_id: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT id,username,role,active FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None or not row["active"]:
        return None
    return dict(row)


def user_count() -> int:
    with _connect() as db:
        return int(db.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0])


def allow_request(bucket: str, limit: int, window_seconds: int, now: int | None = None) -> bool:
    """Atomic fixed-window limiter. A shared DB is required across instances."""
    now = int(time.time()) if now is None else int(now)
    start = now - (now % window_seconds)
    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT window_start,hits FROM rate_windows WHERE bucket=?", (bucket,)).fetchone()
        if row is None or int(row["window_start"]) != start:
            db.execute(
                "INSERT INTO rate_windows(bucket,window_start,hits) VALUES(?,?,1) "
                "ON CONFLICT(bucket) DO UPDATE SET window_start=excluded.window_start,hits=1",
                (bucket, start),
            )
            db.execute("COMMIT")
            return True
        if int(row["hits"]) >= limit:
            db.execute("COMMIT")
            return False
        db.execute("UPDATE rate_windows SET hits=hits+1 WHERE bucket=?", (bucket,))
        db.execute("COMMIT")
        return True


def audit(actor: dict[str, Any] | None, action: str, resource_type: str | None = None,
          resource_id: str | None = None, outcome: str = "success",
          details: dict[str, Any] | None = None) -> None:
    # Never pass passwords, tokens, raw packet payloads or uploaded file contents here.
    with _connect() as db:
        db.execute(
            "INSERT INTO audit_events(occurred_at,actor_id,actor_name,action,resource_type,resource_id,outcome,details_json) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), actor.get("id") if actor else None,
             actor.get("username") if actor else "anonymous", action, resource_type,
             resource_id, outcome, json.dumps(details or {}, sort_keys=True)),
        )


def create_case(title: str, severity: str, summary: dict[str, Any], evidence_sha256: str | None,
                actor: dict[str, Any]) -> dict[str, Any]:
    title = title.strip()
    if not 3 <= len(title) <= 160:
        raise ValueError("Case title must be 3-160 characters")
    if severity not in {"informational", "low", "medium", "high", "critical"}:
        raise ValueError("Invalid severity")
    case_id = secrets.token_hex(12)
    now = time.time()
    with _connect() as db:
        db.execute(
            "INSERT INTO cases(id,title,status,severity,evidence_sha256,summary_json,created_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (case_id, title, "open", severity, evidence_sha256,
             json.dumps(summary, sort_keys=True), actor["id"], now, now),
        )
    audit(actor, "case.create", "case", case_id, details={"severity": severity})
    return get_case(case_id)


def get_case(case_id: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["summary"] = json.loads(result.pop("summary_json"))
    return result


def list_cases(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    with _connect() as db:
        rows = db.execute("SELECT id,title,status,severity,evidence_sha256,created_by,created_at,updated_at "
                          "FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
    return [dict(row) for row in rows]


def update_case(case_id: str, status: str, actor: dict[str, Any]) -> dict[str, Any] | None:
    if status not in {"open", "investigating", "resolved", "closed"}:
        raise ValueError("Invalid case status")
    now = time.time()
    with _connect() as db:
        cursor = db.execute("UPDATE cases SET status=?,updated_at=? WHERE id=?", (status, now, case_id))
    if cursor.rowcount == 0:
        return None
    audit(actor, "case.update", "case", case_id, details={"status": status})
    return get_case(case_id)


def list_audit(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with _connect() as db:
        rows = db.execute(
            "SELECT id,occurred_at,actor_id,actor_name,action,resource_type,resource_id,outcome,details_json "
            "FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        result.append(item)
    return result


init_store()
