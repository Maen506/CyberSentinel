"""
HoneyTrack - HTTP Honeypot
---------------------------
Emulates a vulnerable web server on port 8080.
Detects SQLi, XSS, path traversal, scanners.
Pushes events to the shared queue.
"""

import socket
import threading
import logging
import json
import re
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime

from core.event_queue import push


# وفي دالة _handle أو أي مكان بترسل فيه الأحداث:
def _handle_request(ip, method, path, headers, body):
    event = {
        "type": "http_request",
        "src_ip": ip,
        "method": method,
        "path": path,
        "headers": headers,
        "user_agent": headers.get("User-Agent", ""),
        "body_snippet": body[:5000] if body else "",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    push(event)  # ✅ هذا السطر المهم
# ── Logging ───────────────────────────────────
LOG_DIR = Path(__file__).parent.parent / "logs"
logger = logging.getLogger("http_honeypot")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = RotatingFileHandler(LOG_DIR / "http.log", maxBytes=5*1024*1024, backupCount=3)
    h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(h)

# ── Attack Pattern Detection ──────────────────
PATTERNS = {
    "sql_injection":   [r"union.*select", r"' or '", r"1=1", r"drop table", r"insert into"],
    "path_traversal":  [r"\.\./", r"etc/passwd", r"win/system32"],
    "xss":             [r"<script", r"javascript:", r"onerror=", r"onload="],
    "cmd_injection":   [r"cmd=", r"exec\(", r";ls", r"&&cat", r"\|whoami"],
    "scanner":         [r"/wp-admin", r"/phpmyadmin", r"/.env", r"/config", r"/.git"],
    "webshell":        [r"/shell", r"base64_decode", r"eval\(", r"system\("],
}

def _detect(text: str) -> dict:
    text = text.lower()
    found = {}
    for category, rules in PATTERNS.items():
        hits = [r for r in rules if re.search(r, text, re.I)]
        if hits:
            found[category] = hits
    return found

# ── Fake Responses ────────────────────────────
def _fake_response(path: str, method: str) -> bytes:
    if any(x in path.lower() for x in ["admin", "login", "wp-admin"]):
        body = b"<html><body><h2>Admin Panel</h2><form method='POST'><input name='user'><input type='password' name='pass'><button>Login</button></form></body></html>"
        return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body
    elif any(x in path.lower() for x in ["passwd", ".env", "config"]):
        return b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>403 Forbidden</h1>"
    else:
        return b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>"

# ── Parse HTTP Request ────────────────────────
def _parse(raw: bytes):
    try:
        text   = raw.decode(errors="ignore")
        lines  = text.split("\r\n")
        parts  = lines[0].split(" ") if lines else []
        method = parts[0] if len(parts) > 0 else "UNKNOWN"
        path   = parts[1] if len(parts) > 1 else "/"
        headers = {}
        i = 1
        while i < len(lines) and lines[i]:
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                headers[k.strip().lower()] = v.strip()
            i += 1
        body = "\r\n".join(lines[i+1:]) if i < len(lines) else ""
        return method, path, headers, body
    except Exception:
        return "UNKNOWN", "/", {}, ""

def _handle(sock, ip):
    """
    Handle a single HTTP connection for the honeypot.

    Behavior:
    - Read the raw HTTP request from the socket.
    - Parse method, path, headers, and body via _parse(raw).
    - Preserve the socket-derived IP as src_ip_raw.
    - If X-Forwarded-For header exists, use its first value as src_ip_reported
      and use that reported IP for downstream processing (ip variable).
    - Detect attack patterns via _detect(full_text).
    - Build an event containing both raw and reported IPs, headers, and other metadata.
    - push(event) to the event bus (if available) and log the event.
    - Persist the request to DB via database.db_manager.upsert_attacker and log_http_request,
      passing src_ip_raw and src_ip_reported (ensure DB functions accept these fields).
    - Send a fake response via _fake_response(path, method).
    - Close the socket in all cases.
    """
    try:
        sock.settimeout(10)
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                break

        if not raw:
            return

        # Parse request (assumes _parse returns method, path, headers, body)
        method, path, headers, body = _parse(raw)

        # Normalize header keys to lowercase for reliable lookup
        headers = {k.lower(): v for k, v in (headers or {}).items()}

        # Preserve the socket-derived IP
        src_ip_raw = ip

        # Read X-Forwarded-For if present and use first IP as reported IP
        xff = headers.get("x-forwarded-for", "").strip()
        if xff:
            src_ip_reported = xff.split(",")[0].strip()
            # Use reported IP for downstream processing
            ip = src_ip_reported
        else:
            src_ip_reported = src_ip_raw

        # Detect attacks
        full_text = f"{method} {path} {body}"
        attack_patterns = _detect(full_text)
        is_attack = len(attack_patterns) > 0

        # Build event
        event = {
            "type": "http_request",
            "src_ip_raw": src_ip_raw,
            "src_ip_reported": src_ip_reported,
            "src_ip": ip,
            "method": method,
            "path": path,
            "user_agent": headers.get("user-agent", "unknown"),
            "attack_patterns": attack_patterns,
            "is_attack": is_attack,
            "body_snippet": body[:300],
            "headers": headers,
        }

        # Push event (best-effort)
        try:
            push(event)
        except Exception:
            # Do not fail the handler if push fails
            logger.debug("push(event) failed", exc_info=True)

        logger.info(json.dumps(event))

        # Persist to DB (best-effort)
        try:
            from database.db_manager import log_http_request, upsert_attacker

            attack_patterns_list = list(attack_patterns.keys())

            if is_attack:
                mapping = {
                    "sql_injection": "SQLi",
                    "xss": "XSS",
                    "path_traversal": "Path Traversal",
                    "cmd_injection": "Command Injection",
                    "scanner": "Suspicious Scan",
                    "webshell": "Webshell",
                }
                attack_type = ", ".join(mapping.get(p, p) for p in attack_patterns_list)
            else:
                attack_type = "Normal HTTP"

            # Upsert attacker using the reported IP (policy choice)
            attacker_id = upsert_attacker(src_ip_reported)

            if attacker_id:
                # Ensure log_http_request accepts these keyword args in your DB layer
                log_http_request(
                    attacker_id=attacker_id,
                    method=method,
                    path=path,
                    user_agent=headers.get("user-agent", ""),
                    attack_patterns=attack_patterns_list,
                    is_attack=is_attack,
                    body_snippet=body[:300],
                    attack_type=attack_type,
                    raw_body=body[:300],
                    headers=headers,
                    src_ip_raw=src_ip_raw,
                    src_ip_reported=src_ip_reported,
                )
                print(f"  [DB SAVE] {src_ip_reported} (reported) ← raw {src_ip_raw} → {attack_type}")
        except Exception as db_err:
            print(f"  [DB ERROR] {db_err}")

        # Console output
        if is_attack:
            print(f"  [HTTP ATTACK] {src_ip_reported} {method} {path} → {list(attack_patterns.keys())}")
        else:
            print(f"  [HTTP] {src_ip_reported} {method} {path}")

        # Send fake response (best-effort)
        try:
            sock.send(_fake_response(path, method))
        except Exception:
            logger.debug("Failed to send fake response", exc_info=True)

    except Exception:
        logger.debug("Unhandled exception in _handle", exc_info=True)
    finally:
        try:
            sock.close()
        except Exception:
            pass

# ── Main Listener ─────────────────────────────
def start(host="0.0.0.0", port=8080):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    print(f"  [HTTP] Listening on {host}:{port}")

    while True:
        try:
            sock, addr = srv.accept()
            threading.Thread(target=_handle, args=(sock, addr[0]), daemon=True).start()
        except Exception:
            break
    srv.close()
