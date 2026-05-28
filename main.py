"""
╔══════════════════════════════════════════════════════════════╗
║                  HoneyTrack v1.0                            ║
║     Service-Emulating Honeypot for Proactive Attack Analysis ║
║     Jordan University of Science and Technology - 2026       ║
╠══════════════════════════════════════════════════════════════╣
║  HOW IT WORKS:                                              ║
║                                                              ║
║  1. SSH Honeypot  (port 2222) ─┐                            ║
║  2. HTTP Honeypot (port 8080) ─┼──► Event Queue             ║
║                                │         │                  ║
║                           Pipeline Worker▼                  ║
║                                │                            ║
║                    ┌───────────┼───────────┐                ║
║                    ▼           ▼           ▼                ║
║               Database        ML       VirusTotal           ║
║               (MySQL)    (RF+IForest)    (API)              ║
║                    └───────────┼───────────┘                ║
║                                ▼                            ║
║                         Dashboard :5000                     ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  python main.py

REQUIREMENTS:
  1. MySQL running (run setup_database.py first)
  2. .env file with DB credentials and VT API key
  3. pip install -r requirements.txt
"""

import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

# ── Load .env ─────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass   # dotenv optional — use system env vars

# ── Imports ───────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from core.event_queue        import pop_all, size as queue_size
from core.ssh_honeypot       import start as start_ssh
from core.http_honeypot      import start as start_http
from database.db_manager     import (
    initialize_database, upsert_attacker,
    log_credential_attempt, log_http_request,
    log_command, create_session, close_session,
    save_ml_result, save_vt_report, create_alert,
    update_vt_result, get_dashboard_stats, get_attacker_detail
)
from ml.predictor            import predict as ml_predict
from virustotal.vt_client    import vt_queue

# Flask dashboard
from flask       import Flask, jsonify, send_from_directory, request
from flask_cors  import CORS

DASHBOARD_DIR = str(Path(__file__).parent / "dashboard")
app = Flask(__name__, static_folder=DASHBOARD_DIR)
CORS(app)

# ── In-memory buffer: events per IP ───────────
_ip_events   = {}
_ip_sessions = {}
_events_lock = threading.Lock()


# ══════════════════════════════════════════════
# PIPELINE WORKER
# Runs every 5 seconds — drains the event queue,
# saves to DB, runs ML, enqueues VT
# ══════════════════════════════════════════════
def _pipeline_worker():
    print("  [Pipeline] Worker started")
    while True:
        time.sleep(5)
        events = pop_all()
        if not events:
            continue

        # Group by IP
        by_ip: dict[str, list] = {}
        for e in events:
            ip = e.get("src_ip", "unknown")
            by_ip.setdefault(ip, []).append(e)

        for ip, ip_events in by_ip.items():

            # 1 ── Upsert attacker in DB
            attacker_id = upsert_attacker(ip)
            if not attacker_id:
                continue

            # 2 ── Save each event to DB
            for e in ip_events:
                etype = e.get("type")

                if etype == "ssh_auth":
                    log_credential_attempt(
                        attacker_id,
                        e.get("username", ""),
                        e.get("password", ""),
                        "SSH"
                    )

                elif etype == "ssh_command":
                    sid = _ip_sessions.get(ip)
                    if not sid:
                        sid = create_session(attacker_id, "SSH")
                        _ip_sessions[ip] = sid
                    log_command(sid, attacker_id,
                                e.get("command", ""), "command not found")

                elif etype == "ssh_session_end":
                    sid = _ip_sessions.pop(ip, None)
                    if sid:
                        close_session(sid, e.get("count", 0))

                elif etype == "http_request":
                    patterns = e.get("attack_patterns", {})
                    flat_patterns = list(patterns.keys())
                    log_http_request(
                        attacker_id,
                        e.get("method", "GET"),
                        e.get("path", "/"),
                        e.get("user_agent", ""),
                        flat_patterns,
                        e.get("is_attack", False),
                        e.get("body_snippet", ""),
                    )

            # 3 ── Accumulate events for ML
            with _events_lock:
                _ip_events.setdefault(ip, []).extend(ip_events)
                all_events = list(_ip_events[ip])

            # 4 ── ML prediction
            try:
                result = ml_predict(all_events, ip)
                save_ml_result(
                    attacker_id,
                    anomaly_score = result["anomaly_score"],
                    is_anomaly    = result["is_anomaly"],
                    features      = result["features"],
                    mitre_tactics = result["mitre_tactics"],
                    attack_type   = result["attack_type"],
                    attack_prob   = result["attack_probability"] / 100,
                    severity      = result["severity"],
                )

                # 5 ── Create alert if anomaly
                if result["is_anomaly"] or result["is_attack"]:
                    tactics_str = ", ".join(
                        t["technique_id"] for t in result["mitre_tactics"]
                    ) or "—"
                    create_alert(
                        attacker_id,
                        alert_type = f"ML_{result['attack_type'].upper()}",
                        severity   = result["severity"],
                        message    = (
                            f"Attack detected from {ip}. "
                            f"Type: {result['attack_type']}. "
                            f"Confidence: {result['attack_probability']}%. "
                            f"MITRE: {tactics_str}"
                        )
                    )

            except Exception as e:
                print(f"  [Pipeline] ML error for {ip}: {e}")

            # 6 ── Enqueue IP for VirusTotal
            vt_queue.enqueue(ip)


# ══════════════════════════════════════════════
# VT CALLBACK
# Called by vt_queue after each IP is checked
# ══════════════════════════════════════════════
def _vt_callback(result: dict):
    """Save VT result to DB"""
    try:
        ip          = result.get("ip", "")
        attacker_id = upsert_attacker(ip)
        if attacker_id:
            save_vt_report(attacker_id, result)
            print(f"  [VT→DB] {ip} saved — verdict: {result.get('verdict')}")
    except Exception as e:
        print(f"  [VT Callback] Error: {e}")


# ══════════════════════════════════════════════
# FLASK API ROUTES
# ══════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "dashboard.html")


@app.route("/api/stats")
def api_stats():
    try:
        return jsonify(get_dashboard_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/attacker/<ip>")
def api_attacker(ip):
    try:
        return jsonify(get_attacker_detail(ip))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def api_health():
    return jsonify({
        "status":        "running",
        "queue_size":    queue_size(),
        "vt_queue_size": vt_queue.size(),
        "uptime":        str(datetime.utcnow()),
    })


# ══════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════
def main():
    print("\n" + "╔" + "═"*58 + "╗")
    print("║" + "  HoneyTrack v1.0 — Starting...".center(58) + "║")
    print("╚" + "═"*58 + "╝\n")

    # ── 1. Database ────────────────────────────
    print("[1/5] Initializing database...")
    try:
        initialize_database()
        print("      ✔ Database ready\n")
    except Exception as e:
        print(f"      ✗ Database error: {e}")
        print("      → Run setup_database.py first!\n")
        sys.exit(1)

    # ── 2. SSH Honeypot ────────────────────────
    print("[2/5] Starting SSH Honeypot (port 2222)...")
    threading.Thread(target=start_ssh,  kwargs={"port": 2222}, daemon=True).start()
    time.sleep(0.3)
    print("      ✔ SSH Honeypot running\n")

    # ── 3. HTTP Honeypot ───────────────────────
    print("[3/5] Starting HTTP Honeypot (port 8080)...")
    threading.Thread(target=start_http, kwargs={"port": 8080}, daemon=True).start()
    time.sleep(0.3)
    print("      ✔ HTTP Honeypot running\n")

    # ── 4. Pipeline Worker ─────────────────────
    print("[4/5] Starting event pipeline...")
    threading.Thread(target=_pipeline_worker, daemon=True).start()
    print("      ✔ Pipeline worker running\n")

    # ── 5. VirusTotal Worker ───────────────────
    print("[5/5] Starting VirusTotal queue...")
    vt_queue.set_callback(_vt_callback)
    threading.Thread(target=vt_queue.run_forever, daemon=True).start()
    vt_key = os.getenv("VT_API_KEY", "")
    if not vt_key or vt_key == "YOUR_VT_API_KEY_HERE":
        print("      ⚠  No VT API key — add to .env to enable")
    else:
        print("      ✔ VirusTotal queue running")

    # ── Summary ────────────────────────────────
    print("\n" + "─"*60)
    print(f"  🍯 SSH  Honeypot  →  port 2222")
    print(f"  🌐 HTTP Honeypot  →  port 8080")
    print(f"  📊 Dashboard      →  http://localhost:5000")
    print(f"  📡 API Health     →  http://localhost:5000/api/health")
    print("─"*60)
    print("  Press Ctrl+C to stop\n")

    # ── Start Flask (blocking) ──────────────────
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
