"""
7scrown RTP — hardened Flask API + static frontend
- hashed admin password
- login rate-limit
- atomic JSON writes + rolling backups
- revision (optimistic concurrency)
- strict validation + audit log
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
DATA_FILE = DATA_DIR / "games.json"
BACKUP_DIR = DATA_DIR / "backups"
AUDIT_FILE = DATA_DIR / "audit.log"
STATIC = BASE / "static"

MAX_GAMES = 80
MAX_NAME_LEN = 80
MAX_IMG_LEN = 500
MAX_DISCLAIMER_LEN = 2000
MAX_PLAY_URL_LEN = 500
MAX_LOGIN_ATTEMPTS = 8
LOGIN_WINDOW_SEC = 300  # 5 min
SESSION_HOURS = 12
MAX_BACKUPS = 20

app = Flask(__name__, static_folder=str(STATIC), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() in ("1", "true"),
    PERMANENT_SESSION_LIFETIME=SESSION_HOURS * 3600,
)

_lock = threading.RLock()
_login_hits: dict[str, list[float]] = {}

DEFAULT_PASS = os.environ.get("ADMIN_PASSWORD", "admin123")
DEFAULTS = {
    "playUrl": "http://mgkikitk1.7scrown48.xyz/?referralCode=qhk8992",
    "disclaimer": (
        "ဖော်ပြနေသော RTP ရာခိုင်နှုန်း အတက်အကျသည် စမ်းသပ်ပြသမှုသာဖြစ်ပြီး "
        "တကယ့်ဂိမ်းဒေတာ သို့မဟုတ် ရလဒ်များမှ တိုင်းတာထားခြင်း မဟုတ်ပါ။ "
        "ထိန်းထိန်းသိမ်းသိမ်း ကစားပါ။"
    ),
    "adminPasswordHash": generate_password_hash(DEFAULT_PASS),
    "revision": 1,
    "updatedAt": None,
    "games": [],
}


# ─── helpers ─────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "unknown")[:64]


def _audit(action: str, detail: str = "") -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        line = f"{_now_iso()}\t{_client_ip()}\t{action}\t{detail}\n"
        with _lock:
            with AUDIT_FILE.open("a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


def _ensure_data() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        payload = deepcopy(DEFAULTS)
        payload["updatedAt"] = _now_iso()
        # seed default games if empty file
        seed = DATA_DIR / "games.seed.json"
        if seed.exists():
            try:
                extra = json.loads(seed.read_text(encoding="utf-8"))
                if isinstance(extra.get("games"), list):
                    payload["games"] = extra["games"]
                if extra.get("playUrl"):
                    payload["playUrl"] = extra["playUrl"]
                if extra.get("disclaimer"):
                    payload["disclaimer"] = extra["disclaimer"]
            except Exception:
                pass
        DATA_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _normalize_loaded(raw: dict) -> dict:
    data = deepcopy(DEFAULTS)
    if not isinstance(raw, dict):
        return data
    data["playUrl"] = str(raw.get("playUrl") or data["playUrl"])[:MAX_PLAY_URL_LEN]
    data["disclaimer"] = str(raw.get("disclaimer") or data["disclaimer"])[:MAX_DISCLAIMER_LEN]
    data["revision"] = int(raw.get("revision") or 1)
    data["updatedAt"] = raw.get("updatedAt")
    # password: prefer hash; migrate plain if present
    if raw.get("adminPasswordHash"):
        data["adminPasswordHash"] = str(raw["adminPasswordHash"])
    elif raw.get("adminPassword"):
        data["adminPasswordHash"] = generate_password_hash(str(raw["adminPassword"]))
    if isinstance(raw.get("games"), list):
        data["games"] = raw["games"]
    return data


def load_data() -> dict:
    _ensure_data()
    with _lock:
        try:
            raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except Exception:
            raw = {}
    return _normalize_loaded(raw)


def _rotate_backups() -> None:
    try:
        files = sorted(BACKUP_DIR.glob("games-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[MAX_BACKUPS:]:
            try:
                old.unlink()
            except Exception:
                pass
    except Exception:
        pass


def save_data(data: dict) -> dict:
    """Atomic write with backup. Bumps revision + updatedAt."""
    _ensure_data()
    data = deepcopy(data)
    data["revision"] = int(data.get("revision") or 1) + 1
    data["updatedAt"] = _now_iso()
    # never persist plain password field
    data.pop("adminPassword", None)

    text = json.dumps(data, ensure_ascii=False, indent=2)
    with _lock:
        # backup current
        if DATA_FILE.exists():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            bak = BACKUP_DIR / f"games-{ts}-r{data['revision']}.json"
            try:
                bak.write_text(DATA_FILE.read_text(encoding="utf-8"), encoding="utf-8")
            except Exception:
                pass
            _rotate_backups()
        # atomic replace
        tmp = DATA_FILE.with_suffix(".json.tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(DATA_FILE)
    return data


def public_payload(data: dict) -> dict:
    return {
        "playUrl": data.get("playUrl") or DEFAULTS["playUrl"],
        "disclaimer": data.get("disclaimer") or DEFAULTS["disclaimer"],
        "games": data.get("games") or [],
        "revision": int(data.get("revision") or 1),
        "updatedAt": data.get("updatedAt"),
    }


def _safe_url(value: str, allow_empty: bool = True) -> tuple[str | None, str | None]:
    v = (value or "").strip()
    if not v:
        return ("", None) if allow_empty else (None, "URL လိုအပ်ပါသည်။")
    if len(v) > MAX_PLAY_URL_LEN:
        return None, "URL ရှည်လွန်းသည်။"
    try:
        u = urlparse(v)
    except Exception:
        return None, "URL မမှန်ပါ။"
    if u.scheme not in ("http", "https"):
        return None, "URL သည် http/https သာ ဖြစ်ရမည်။"
    if not u.netloc:
        return None, "URL host မရှိပါ။"
    return v, None


def _clean_game(g: dict) -> tuple[dict | None, str | None]:
    if not isinstance(g, dict):
        return None, "ဂိမ်း item မမှန်ပါ။"
    name = re.sub(r"\s+", " ", str(g.get("name") or "").strip())
    if not name:
        return None, "ဂိမ်းအမည် လိုအပ်ပါသည်။"
    if len(name) > MAX_NAME_LEN:
        return None, f"အမည် ရှည်လွန်းသည် (max {MAX_NAME_LEN})။"
    # strip control chars
    name = "".join(ch for ch in name if ch.isprintable())

    img = str(g.get("img") or "").strip()
    if len(img) > MAX_IMG_LEN:
        return None, "ပုံ URL ရှည်လွန်းသည်။"
    if img:
        img_ok, img_err = _safe_url(img, allow_empty=False)
        if img_err:
            return None, f"{name}: ပုံ {img_err}"
        img = img_ok or ""

    mode = "manual" if g.get("rtpMode") == "manual" else "auto"
    rtp_raw = str(g.get("rtp") if g.get("rtp") is not None else "").strip()
    if mode == "manual":
        try:
            n = float(rtp_raw)
        except ValueError:
            return None, f"{name}: RTP ဂဏန်းဖြစ်ရမည်။"
        if not (0 <= n <= 100):
            return None, f"{name}: RTP 0–100 ကြား။"
        rtp = f"{n:.2f}".rstrip("0").rstrip(".")
    else:
        if rtp_raw:
            try:
                n = float(rtp_raw)
                if not (0 <= n <= 100):
                    return None, f"{name}: RTP 0–100 ကြား။"
                rtp = f"{n:.2f}".rstrip("0").rstrip(".")
            except ValueError:
                rtp = ""
        else:
            rtp = ""

    return {"name": name, "img": img, "rtp": rtp, "rtpMode": mode}, None


def _rate_limited(ip: str) -> bool:
    now = time.time()
    with _lock:
        hits = [t for t in _login_hits.get(ip, []) if now - t < LOGIN_WINDOW_SEC]
        _login_hits[ip] = hits
        return len(hits) >= MAX_LOGIN_ATTEMPTS


def _record_login_hit(ip: str) -> None:
    with _lock:
        hits = _login_hits.get(ip, [])
        hits.append(time.time())
        _login_hits[ip] = hits


def _issue_csrf() -> str:
    token = secrets.token_urlsafe(24)
    session["csrf"] = token
    return token


def _check_csrf() -> bool:
    sent = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("csrf")
    return bool(sent) and sent == session.get("csrf")


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({"ok": False, "message": "Admin login လိုအပ်ပါသည်။", "code": "UNAUTHORIZED"}), 401
        # idle timeout
        last = session.get("admin_at") or 0
        if time.time() - last > SESSION_HOURS * 3600:
            session.clear()
            return jsonify({"ok": False, "message": "Session သက်တမ်းကုန်ပါပြီ။ ပြန် login ပါ။", "code": "SESSION_EXPIRED"}), 401
        session["admin_at"] = time.time()
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not _check_csrf():
                return jsonify({"ok": False, "message": "CSRF token မမှန်ပါ။ Page ပြန်ဖွင့်ပါ။", "code": "CSRF"}), 403
        return fn(*args, **kwargs)

    return wrapper


# ─── static ──────────────────────────────────────────────────
@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/health")
def health():
    data = load_data()
    return jsonify({"ok": True, "status": "up", "revision": data.get("revision"), "games": len(data.get("games") or [])})


# ─── public ──────────────────────────────────────────────────
@app.get("/api/games")
def api_games():
    return jsonify({"ok": True, **public_payload(load_data())})


# ─── auth ────────────────────────────────────────────────────
@app.post("/api/admin/login")
def api_login():
    ip = _client_ip()
    if _rate_limited(ip):
        _audit("login_blocked", ip)
        return jsonify({"ok": False, "message": "ကြိုးစားမှု များလွန်းသည်။ ၅ မိနစ် စောင့်ပါ။", "code": "RATE_LIMIT"}), 429

    body = request.get_json(silent=True) or {}
    password = str(body.get("password") or "")
    data = load_data()
    pw_hash = data.get("adminPasswordHash") or DEFAULTS["adminPasswordHash"]

    ok = bool(password) and check_password_hash(pw_hash, password)
    if not ok:
        _record_login_hit(ip)
        _audit("login_fail", ip)
        return jsonify({"ok": False, "message": "Password မမှန်ပါ။", "code": "BAD_PASSWORD"}), 401

    session.clear()
    session.permanent = True
    session["admin"] = True
    session["admin_at"] = time.time()
    csrf = _issue_csrf()
    _audit("login_ok", ip)
    return jsonify({"ok": True, "message": "Login အောင်မြင်ပါသည်။", "csrf": csrf, "revision": data.get("revision")})


@app.post("/api/admin/logout")
def api_logout():
    _audit("logout", _client_ip())
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/admin/me")
def api_me():
    if not session.get("admin"):
        return jsonify({"ok": True, "admin": False})
    last = session.get("admin_at") or 0
    if time.time() - last > SESSION_HOURS * 3600:
        session.clear()
        return jsonify({"ok": True, "admin": False})
    # refresh csrf on me check
    csrf = session.get("csrf") or _issue_csrf()
    if not session.get("csrf"):
        session["csrf"] = csrf
    return jsonify({"ok": True, "admin": True, "csrf": csrf, "revision": load_data().get("revision")})


# ─── admin data ──────────────────────────────────────────────
@app.get("/api/admin/data")
@admin_required
def api_admin_data():
    data = load_data()
    return jsonify({"ok": True, "csrf": session.get("csrf"), **public_payload(data)})


@app.put("/api/admin/games")
@admin_required
def api_save_games():
    body = request.get_json(silent=True) or {}
    games_in = body.get("games")
    if not isinstance(games_in, list):
        return jsonify({"ok": False, "message": "games သည် array ဖြစ်ရပါမည်။"}), 400
    if len(games_in) > MAX_GAMES:
        return jsonify({"ok": False, "message": f"ဂိမ်း အများဆုံး {MAX_GAMES} ခု။"}), 400

    # optimistic concurrency
    client_rev = body.get("revision")
    data = load_data()
    server_rev = int(data.get("revision") or 1)
    if client_rev is not None:
        try:
            client_rev = int(client_rev)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "revision မမှန်ပါ။"}), 400
        if client_rev != server_rev:
            return jsonify({
                "ok": False,
                "message": "အခြား admin က ပြင်ထားပြီးသား။ Page ပြန်ဖွင့်ပြီး ထပ်လုပ်ပါ။",
                "code": "CONFLICT",
                "revision": server_rev,
            }), 409

    cleaned: list[dict] = []
    seen_names: set[str] = set()
    for g in games_in:
        item, err = _clean_game(g)
        if err:
            return jsonify({"ok": False, "message": err}), 400
        key = item["name"].casefold()
        if key in seen_names:
            return jsonify({"ok": False, "message": f"နာမည် ထပ်နေသည်: {item['name']}"}), 400
        seen_names.add(key)
        cleaned.append(item)

    data["games"] = cleaned

    if "playUrl" in body and isinstance(body["playUrl"], str):
        url, err = _safe_url(body["playUrl"], allow_empty=False)
        if err:
            return jsonify({"ok": False, "message": f"Play URL: {err}"}), 400
        data["playUrl"] = url
    if "disclaimer" in body and isinstance(body["disclaimer"], str):
        disc = body["disclaimer"].strip()
        if len(disc) > MAX_DISCLAIMER_LEN:
            return jsonify({"ok": False, "message": "Disclaimer ရှည်လွန်းသည်။"}), 400
        data["disclaimer"] = disc

    data = save_data(data)
    _audit("save_games", f"count={len(cleaned)} rev={data['revision']}")
    return jsonify({
        "ok": True,
        "message": f"သိမ်းပြီး · ဂိမ်း {len(cleaned)} ခု · rev {data['revision']}",
        "games": cleaned,
        "count": len(cleaned),
        "revision": data["revision"],
        "updatedAt": data["updatedAt"],
        "csrf": session.get("csrf"),
    })


@app.post("/api/admin/settings")
@admin_required
def api_settings():
    body = request.get_json(silent=True) or {}
    data = load_data()
    client_rev = body.get("revision")
    if client_rev is not None and int(client_rev) != int(data.get("revision") or 1):
        return jsonify({"ok": False, "message": "Conflict — ပြန်ဖွင့်ပါ။", "code": "CONFLICT", "revision": data.get("revision")}), 409

    if "playUrl" in body and isinstance(body["playUrl"], str):
        url, err = _safe_url(body["playUrl"], allow_empty=False)
        if err:
            return jsonify({"ok": False, "message": f"Play URL: {err}"}), 400
        data["playUrl"] = url
    if "disclaimer" in body and isinstance(body["disclaimer"], str):
        disc = body["disclaimer"].strip()
        if len(disc) > MAX_DISCLAIMER_LEN:
            return jsonify({"ok": False, "message": "Disclaimer ရှည်လွန်းသည်။"}), 400
        data["disclaimer"] = disc

    data = save_data(data)
    _audit("save_settings", f"rev={data['revision']}")
    return jsonify({"ok": True, "message": "Settings သိမ်းပြီး။", "csrf": session.get("csrf"), **public_payload(data)})


@app.post("/api/admin/password")
@admin_required
def api_change_password():
    body = request.get_json(silent=True) or {}
    current = str(body.get("current") or "")
    new_pass = str(body.get("newPassword") or "")
    data = load_data()
    pw_hash = data.get("adminPasswordHash") or DEFAULTS["adminPasswordHash"]

    if not check_password_hash(pw_hash, current):
        _audit("password_fail", _client_ip())
        return jsonify({"ok": False, "message": "လက်ရှိ password မမှန်ပါ။"}), 400
    if len(new_pass) < 6:
        return jsonify({"ok": False, "message": "Password အသစ် အနည်းဆုံး ၆ လုံး။"}), 400
    if len(new_pass) > 128:
        return jsonify({"ok": False, "message": "Password ရှည်လွန်းသည်။"}), 400
    if new_pass == current:
        return jsonify({"ok": False, "message": "Password အဟောင်းနဲ့ မတူအောင် ထည့်ပါ။"}), 400
    if new_pass.lower() in ("admin", "admin123", "password", "123456"):
        return jsonify({"ok": False, "message": "Password အားနည်းလွန်းသည်။"}), 400

    data["adminPasswordHash"] = generate_password_hash(new_pass)
    data = save_data(data)
    # force re-login elsewhere by rotating csrf
    csrf = _issue_csrf()
    _audit("password_changed", _client_ip())
    return jsonify({"ok": True, "message": "Password ပြောင်းပြီးပါပြီ။", "csrf": csrf, "revision": data["revision"]})


@app.get("/api/admin/backups")
@admin_required
def api_backups():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(BACKUP_DIR.glob("games-*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:15]:
        items.append({"name": p.name, "size": p.stat().st_size, "mtime": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()})
    return jsonify({"ok": True, "backups": items})


@app.post("/api/admin/restore")
@admin_required
def api_restore():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "")
    if not re.fullmatch(r"games-\d{8}-\d{6}-r\d+\.json", name):
        return jsonify({"ok": False, "message": "Backup ဖိုင်အမည် မမှန်ပါ။"}), 400
    path = BACKUP_DIR / name
    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "message": "Backup မတွေ့ပါ။"}), 404
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return jsonify({"ok": False, "message": "Backup ဖတ်မရပါ။"}), 400
    data = _normalize_loaded(raw)
    # keep current password hash (don't roll back credentials accidentally)
    current = load_data()
    data["adminPasswordHash"] = current.get("adminPasswordHash") or data.get("adminPasswordHash")
    data = save_data(data)
    _audit("restore", name)
    return jsonify({"ok": True, "message": f"Restore ပြီး · {name}", "csrf": session.get("csrf"), **public_payload(data)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
