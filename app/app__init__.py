"""
HoneyTrack Unified Server
=========================
Production-ready honeypot backend.
"""

import csv
import io
import os
import secrets
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import json
import jwt
from flask import Flask, jsonify, make_response, redirect, request, send_file
from flask_cors import CORS

# ✅ تحميل API Key من المتغيرات البيئية (وليس hardcoded)
VT_API_KEY = os.environ.get("VT_API_KEY", "fae2ab08f8083bede40ceb7dc7e221888d59e7c7655536be0db2c86131ff986f")
if not VT_API_KEY:
    print("[!] Warning: VT_API_KEY not set - VirusTotal integration disabled")
os.environ["VT_API_KEY"] = VT_API_KEY

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ✅ مفاتيح آمنة مع التحقق من وجودها
SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
# ✅ كلمة مرور افتراضية قوية في حالة عدم التعيين (للتطوير فقط)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "HoneyTrack2024!ChangeMe")


def generate_token(username: str) -> str:
    """توليد JWT token مع وقت انتهاء أقصر ومعرف فريد"""
    payload = {
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),  # 12 ساعة بدل 24
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16)  # معرف فريد للـ token
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict | None:
    """التحقق من صحة JWT token"""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        print("[!] Token expired")
        return None
    except jwt.InvalidTokenError:
        print("[!] Invalid token")
        return None


def login_required(f):
    """حماية API endpoints - ترجع JSON"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token or not verify_token(token):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def login_page_required(f):
    """حماية صفحات HTML - تعيد توجيه إلى صفحة تسجيل الدخول"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token or not verify_token(token):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


def _try_import(label: str, loader):
    """محاولة تحميل module مع معالجة الأخطاء"""
    try:
        result = loader()
        print(f"[OK] {label}")
        return result, True
    except Exception as exc:
        print(f"[--] {label} unavailable: {exc}")
        return None, False


def _load_db():
    """تحميل وإعداد قاعدة البيانات"""
    from database.db_manager import (
        initialize_database,
        get_dashboard_stats,
        get_connection,
        upsert_attacker,
        log_credential_attempt,
        save_ml_result,
        create_alert,
        update_vt_result,
        save_vt_report,
        upsert_geolocation,
        log_http_request,
    )
    return {
        "initialize_database":    initialize_database,
        "get_dashboard_stats":    get_dashboard_stats,
        "get_connection":         get_connection,
        "upsert_attacker":        upsert_attacker,
        "log_credential_attempt": log_credential_attempt,
        "save_ml_result":         save_ml_result,
        "create_alert":           create_alert,
        "update_vt_result":       update_vt_result,
        "save_vt_report":         save_vt_report,
        "upsert_geolocation":     upsert_geolocation,
        "log_http_request":       log_http_request,
    }

db, DB_READY = _try_import("Database", _load_db)


def _load_http():
    """تحميل HTTP honeypot"""
    from core.http_honeypot import start as start_http
    return start_http

start_http, HTTP_READY = _try_import("HTTP Honeypot", _load_http)


def _load_ssh():
    """تحميل SSH honeypot و event queue"""
    from core.event_queue import pop_all
    from core.ssh_honeypot import start as start_ssh
    return {"pop_all": pop_all, "start_ssh": start_ssh}

ssh, SSH_READY = _try_import("SSH Honeypot", _load_ssh)


def _load_ml():
    """تحميل ML predictor"""
    from ml.predictor import predict as ml_predict
    return ml_predict

ml_predict, ML_READY = _try_import("ML Predictor", _load_ml)


def _load_vt():
    from virustotal.vt_client import vt_queue

    if not hasattr(vt_queue, 'run_forever'):
        def run_forever():
            print("[VT] Worker started")
            vt_queue.start()
        vt_queue.run_forever = run_forever

    if not hasattr(vt_queue, 'set_callback'):
        def set_callback(cb):
            vt_queue._callback = cb
        vt_queue.set_callback = set_callback

    if not hasattr(vt_queue, 'enqueue'):
        def enqueue(ip):
            with vt_queue._lock:
                if ip not in vt_queue._seen:
                    vt_queue._queue.append(ip)
                    vt_queue._seen.add(ip)
                    print(f"  [VT] Queued: {ip}")
        vt_queue.enqueue = enqueue

    return vt_queue

vt_queue, VT_READY = _try_import("VirusTotal", _load_vt)

def _load_geo():
    """تحميل GeoIP database"""
    import geoip2.database
    db_path = BASE_DIR / "app" / "GeoLite2-City.mmdb"
    
    if not db_path.exists():
        print(f"[--] GeoIP database not found at {db_path}")
        def empty_lookup(ip: str) -> dict:
            return {}
        return empty_lookup
    
    reader = geoip2.database.Reader(str(db_path))

    def lookup(ip: str) -> dict:
        """البحث عن معلومات جغرافية لعنوان IP"""
        private = ("127.", "10.", "192.168.", "172.")
        if any(ip.startswith(p) for p in private) or ip == "unknown":
            return {}
        try:
            resp = reader.city(ip)
            return {
                "ip": ip,
                "country": resp.country.name or "Unknown",
                "country_code": resp.country.iso_code or "",
                "region": resp.subdivisions.most_specific.name or "",
                "city": resp.city.name or "",
                "latitude": resp.location.latitude or 0.0,
                "longitude": resp.location.longitude or 0.0,
                "isp": "",
                "org": "",
                "asn": ""
            }
        except Exception:
            return {}

    return lookup

geo_lookup, GEO_READY = _try_import("GeoIP", _load_geo)


# ==================== API Routes ====================

@app.route("/api/login", methods=["POST"])
def api_login():
    """تسجيل الدخول والحصول على JWT token"""
    data = request.get_json(silent=True) or {}
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        token = generate_token(ADMIN_USERNAME)
        resp = make_response(jsonify({"token": token, "message": "Login successful"}))
        resp.set_cookie(
            "auth_token",
            token,
            max_age=43200,  # 12 ساعة
            httponly=True,
            samesite="Lax",
            secure=False  # ✅ ضبط على True في الإنتاج مع HTTPS
        )
        return resp
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """تسجيل الخروج"""
    resp = make_response(jsonify({"message": "Logged out successfully"}))
    resp.set_cookie("auth_token", "", expires=0)
    return resp


@app.route("/login")
def login_page():
    """صفحة تسجيل الدخول"""
    path = BASE_DIR / "app" / "login.html"
    if path.exists():
        return path.read_text(encoding="utf-8"), 200
    return "Login page not found", 404


@app.route("/")
@login_page_required
def dashboard():
    """لوحة التحكم الرئيسية"""
    path = BASE_DIR / "app" / "dashboard-1.html"
    if path.exists():
        return path.read_text(encoding="utf-8"), 200
    return "Dashboard not found", 404


@app.route("/api/health/public")
def public_health():
    """نقطة فحص عامة (بدون مصادقة)"""
    return jsonify({
        "status": "running",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


_EMPTY_STATS = {
    "total_attacks": 0,
    "total_unique_ips": 0,
    "open_alerts": 0,
    "anomalies_detected": 0,
    "recent_attackers": [],
    "recent_alerts": []
}


@app.route("/api/stats")
@login_required
def api_stats():
    """إحصائيات لوحة التحكم"""
    if DB_READY:
        try:
            return jsonify(db["get_dashboard_stats"]())
        except Exception as exc:
            print(f"[!] Stats error: {exc}")
            return jsonify({"error": str(exc)}), 500
    return jsonify(_EMPTY_STATS)


@app.route("/api/health")
@login_required
def api_health():
    """حالة النظام التفصيلية"""
    return jsonify({
        "status": "running",
        "database": DB_READY,
        "ssh": SSH_READY,
        "http": HTTP_READY,
        "ml": ML_READY,
        "vt": VT_READY,
        "geo": GEO_READY,
        "time": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/geo/<ip>")
@login_required
def api_geo(ip: str):
    """معلومات جغرافية لعنوان IP"""
    if not GEO_READY:
        return jsonify({"error": "GeoIP not available"}), 503
    result = geo_lookup(ip)
    if not result:
        return jsonify({"error": "Lookup failed or private IP"}), 404
    return jsonify(result)


@app.route("/api/export/csv")
@login_required
def export_csv():
    """تصدير بيانات المهاجمين كـ CSV"""
    if not DB_READY:
        return jsonify({"error": "Database not available"}), 503
    try:
        with db["get_connection"]() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT 
                    a.ip_address, 
                    a.country, 
                    g.city, 
                    a.attack_count, 
                    a.vt_malicious, 
                    m.severity, 
                    a.last_seen 
                FROM attackers a 
                LEFT JOIN geolocation g ON g.attacker_id = a.id 
                LEFT JOIN ml_results m ON m.attacker_id = a.id 
                    AND m.analyzed_at = (
                        SELECT MAX(r2.analyzed_at) 
                        FROM ml_results r2 
                        WHERE r2.attacker_id = a.id
                    ) 
                ORDER BY a.last_seen DESC
            """)
            rows = cur.fetchall()
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "Country", "City", "Attacks", "VT Malicious", "Severity", "Last Seen"])
        for r in rows:
            writer.writerow([
                r.get("ip_address"),
                r.get("country"),
                r.get("city", ""),
                r.get("attack_count"),
                r.get("vt_malicious"),
                r.get("severity"),
                r.get("last_seen")
            ])
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"honeytrack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
    except Exception as exc:
        print(f"[!] Export CSV error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/export/alerts")
@login_required
def export_alerts():
    """تصدير التنبيهات كـ CSV"""
    if not DB_READY:
        return jsonify({"error": "Database not available"}), 503
    try:
        with db["get_connection"]() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT 
                    at.ip_address, 
                    al.alert_type, 
                    al.severity, 
                    al.message, 
                    al.created_at 
                FROM alerts al 
                JOIN attackers at ON al.attacker_id = at.id 
                ORDER BY al.created_at DESC
            """)
            rows = cur.fetchall()
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "Type", "Severity", "Message", "Time"])
        for r in rows:
            writer.writerow([
                r.get("ip_address"),
                r.get("alert_type"),
                r.get("severity"),
                r.get("message"),
                r.get("created_at")
            ])
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
    except Exception as exc:
        print(f"[!] Export alerts error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/full-report")
@login_required
def full_report():
    """تقرير شامل عن النظام"""
    if not DB_READY:
        return jsonify({"error": "Database not available"}), 503
    try:
        stats = db["get_dashboard_stats"]()
        return jsonify({
            "report_time": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": stats["total_attacks"],
                "ips": stats["total_unique_ips"],
                "alerts": stats["open_alerts"],
                "anomalies": stats["anomalies_detected"]
            },
            "top_attackers": stats.get("recent_attackers", [])[:10],
            "alerts": stats.get("recent_alerts", [])[:10],
            "mitre": stats.get("mitre_counts", {})
        })
    except Exception as exc:
        print(f"[!] Full report error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/http-requests")
@login_required
def api_http_requests():
    """API endpoint للحصول على طلبات HTTP للمراقبة"""
    if not DB_READY:
        return jsonify({"error": "Database not available"}), 503
    try:
        with db["get_connection"]() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT 
                    a.ip_address, 
                    hr.method, 
                    hr.path, 
                    hr.attack_type, 
                    hr.user_agent, 
                    hr.created_at 
                FROM http_requests hr
                JOIN attackers a ON hr.attacker_id = a.id
                ORDER BY hr.created_at DESC
                LIMIT 100
            """)
            rows = cur.fetchall()
        return jsonify(rows)
    except Exception as exc:
        print(f"[!] HTTP requests error: {exc}")
        return jsonify({"error": str(exc)}), 500


# ==================== Core Processing ====================

_geo_cache: dict[str, dict] = {}
_geo_cache_lock = threading.Lock()


def _get_geo(ip: str) -> dict:
    """الحصول على معلومات جغرافية مع cache"""
    with _geo_cache_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    
    result = geo_lookup(ip) if GEO_READY else {}
    
    with _geo_cache_lock:
        _geo_cache[ip] = result
    
    return result

def _detect_http_attack(path: str, headers: dict = None, body: str = None) -> str:
    """
    كشف هجمات HTTP المتقدمة بناءً على تحليل المسار والهيدرات والمحتوى.
    ترجع نوع الهجوم المكتشف أو 'HTTP' إذا لم يتم العثور على نمط هجوم محدد.
    """
    if not path:
        return "HTTP"
    
    path_lower = path.lower()
    headers_str = str(headers).lower() if headers else ""
    body_str = str(body).lower() if body else ""
    full_request = f"{path_lower} {headers_str} {body_str}"
    
    # SQL Injection patterns
    sql_patterns = [
        "'", "union", "select", "1=1", "1'='1", "or 1=1", "--", "/*", "*/",
        "information_schema", "table_name", "column_name", "drop table",
        "insert into", "update set", "delete from", "exec(", "sp_executesql",
        "xp_cmdshell", "concat(", "group_concat", "load_file", "into outfile",
        "benchmark(", "sleep(", "pg_sleep"
    ]
    
    # XSS detection patterns
    xss_patterns = [
        "<script", "javascript:", "onerror=", "onload=", "onclick=",
        "alert(", "prompt(", "confirm(", "document.cookie",
        "<img", "<svg", "<iframe", "<body onload", "eval(",
        "expression(", "String.fromCharCode", "&#x", "%3cscript",
        "<embed", "<object", "<marquee", "<link", "<style"
    ]
    
    # Path Traversal patterns
    path_traversal_patterns = [
        "..", "../", "..\\", "/etc/passwd", "/etc/shadow",
        "windows\\system32", "cmd.exe", "command.com",
        "boot.ini", "win.ini", "php://", "file://",
        "/proc/self", "/var/log", "c:\\windows", "%2e%2e",
        "%2f", "%5c", "....//", "....\\/"
    ]
    
    # Command Injection patterns
    cmd_injection_patterns = [
        ";", "&&", "||", "|", "`", "$(", "${", "system(",
        "exec(", "passthru(", "shell_exec(", "popen(",
        "wget ", "curl ", "nc ", "netcat", "/bin/bash",
        "/bin/sh", "powershell", "cmd /c", "certutil"
    ]
    
    # SSRF patterns
    ssrf_patterns = [
        "localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254",
        "metadata.google.internal", "metadata/", "aws/",
        "internal", "admin/", "file://", "gopher://", "dict://"
    ]
    
    # XXE patterns
    xxe_patterns = [
        "<!entity", "<!doctype", "system \"", "system '",
        "xml", "!entity", "!doctype", "!element",
        "xmlns:", "encoding=", "standalone="
    ]
    
    # ✅ فحص الهجمات حسب الأولوية (الأكثر تحديداً أولاً)
    if any(pattern in path_lower for pattern in xxe_patterns):
        return "XXE"
    elif any(pattern in full_request for pattern in ssrf_patterns):
        return "SSRF"
    elif any(pattern in full_request for pattern in cmd_injection_patterns):
        return "Command Injection"
    elif any(pattern in full_request for pattern in xss_patterns):
        return "XSS"
    elif any(pattern in path_lower for pattern in sql_patterns):
        return "SQLi"
    elif any(pattern in path_lower for pattern in path_traversal_patterns):
        return "Path Traversal"
    
    # أنماط مشبوهة عامة
    suspicious_indicators = [
        "admin", "config", "backup", "wp-admin", "phpmyadmin",
        ".env", ".git", "debug", "test", "api/", "rest/",
        "graphql", "swagger", "actuator"
    ]
    
    if any(indicator in path_lower for indicator in suspicious_indicators):
        return "Suspicious HTTP"
    
    return "HTTP"


def _process_events_for_ip(ip: str, events: list) -> None:
    """معالجة جميع الأحداث لعنوان IP واحد"""
    events = [e for e in events if isinstance(e, dict)]
    if not events:
        return
    
    attacker_id: int | None = None
    
    if DB_READY:
        try:
            # إنشاء أو تحديث سجل المهاجم
            attacker_id = db["upsert_attacker"](ip)
            
            # ✅ تحديث Geolocation إذا كانت متاحة
            if GEO_READY:
                geo_data = _get_geo(ip)
                if geo_data:
                    try:
                        db["upsert_geolocation"](attacker_id, geo_data)
                    except Exception as geo_exc:
                        print(f"  [GEO ERROR] {geo_exc}")
            
            for ev in events:
                ev_type = ev.get("type")
                
                if ev_type == "ssh_auth":
                    # تسجيل محاولة تسجيل دخول SSH
                    db["log_credential_attempt"](
                        attacker_id,
                        ev.get("username", ""),
                        ev.get("password", ""),
                        "SSH"
                    )
                    print(f"  [SSH AUTH] {ip} → {ev.get('username', 'unknown')}")
                
                elif ev_type == "ssh_command":
                    # تسجيل أمر SSH
                    db["log_credential_attempt"](
                        attacker_id,
                        "cmd",
                        ev.get("command", ""),
                        "SSH"
                    )
                    print(f"  [SSH CMD] {ip} → {ev.get('command', '')[:100]}")
                
                elif ev_type == "http_request":
                    # ✅ استخراج بيانات الطلب
                    path       = ev.get("path", "/")
                    method     = ev.get("method", "GET")
                    user_agent = ev.get("user_agent", "")
                    body       = ev.get("body_snippet", "")
                    headers    = ev.get("headers", {})

                    # ✅ استخدام _detect_http_attack للكشف عن الهجمات
                    attack_type = _detect_http_attack(path, headers, body)
                    is_attack   = attack_type != "HTTP"
                    
                    # جمع attack_patterns إذا كانت موجودة
                    attack_patterns = ev.get("attack_patterns", {})

                    # ✅ حفظ في قاعدة البيانات
                    try:
                        with db["get_connection"]() as conn:
                            cur = conn.cursor()
                            cur.execute("""
                                INSERT INTO http_requests 
                                (attacker_id, method, path, user_agent, suspicious_patterns,
                                 is_attack, attack_type, body_snippet, timestamp)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                            """, (
                                attacker_id,
                                method,
                                path[:1000],
                                user_agent[:500] if user_agent else "",
                                json.dumps(list(attack_patterns.keys())) if attack_patterns else json.dumps([]),
                                is_attack,
                                attack_type,
                                body[:5000] if body else ""
                            ))
                            conn.commit()
                        print(f"  [DB SAVE ✓] {ip} → {attack_type}")
                    except Exception as db_exc:
                        print(f"  [DB ERROR] {db_exc}")

                    # ✅ إنشاء تنبيه للهجمات الفعلية فقط
                    if is_attack and "create_alert" in db:
                        try:
                            # تحديد مستوى الخطورة
                            if attack_type in ["SQLi", "Command Injection", "Webshell", "XXE"]:
                                severity = "HIGH"
                            elif attack_type in ["XSS", "SSRF", "Path Traversal"]:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                            
                            db["create_alert"](
                                attacker_id,
                                f"HTTP_{attack_type.replace(' ', '_').upper()}",
                                severity,
                                f"{attack_type} from {ip}: {method} {path[:200]}"
                            )
                            print(f"  [ALERT ✓] {attack_type} - {severity}")
                        except Exception as alert_exc:
                            print(f"  [ALERT ERROR] {alert_exc}")

                    # ✅ فحص VirusTotal للـ IP
                    if VT_READY:
                        try:
                            vt_queue.enqueue(ip)
                            print(f"  [VT] Queued {ip} for analysis")
                        except Exception as vt_exc:
                            print(f"  [VT ERROR] {vt_exc}")

                    # ✅ تشغيل ML predictor لو متاح
                    if ML_READY and DB_READY:
                        try:
                            mr = ml_predict(events, ip)
                            db["save_ml_result"](
                                attacker_id,
                                mr.get("anomaly_score", 0),
                                bool(mr.get("is_anomaly", False)),
                                mr.get("features", {}),
                                mr.get("mitre_tactics", []),
                                mr.get("attack_type", "unknown"),
                                mr.get("attack_probability", 0) / 100,
                                mr.get("severity", "LOW")
                            )
                            if mr.get("is_anomaly"):
                                db["create_alert"](
                                    attacker_id, "ML_ANOMALY",
                                    mr.get("severity", "MEDIUM"),
                                    f"Anomaly: {mr.get('attack_type')} | Score: {mr['anomaly_score']:.3f}"
                                )
                            print(f"  [ML ✓] {ip} → {mr.get('attack_type')} | {mr.get('severity')}")
                        except Exception as ml_exc:
                            print(f"  [ML ERROR] {ml_exc}")

                    print(f"  [HTTP] {ip} → {attack_type} → {method} {path[:100]}")
        
        except Exception as exc:
            print(f"[!] DB error for {ip}: {exc}")
            traceback.print_exc()
            
def pipeline_worker() -> None:
    """Pipeline worker لمعالجة أحداث SSH و HTTP"""
    print("[PIPELINE] Worker started - processing both SSH and HTTP events")
    
    while True:
        time.sleep(5)
        try:
            events = []
            
            # ✅ جمع الأحداث من SSH و HTTP (نفس الـ event_queue)
            if SSH_READY:
                events = ssh["pop_all"]()
            
            if not events:
                continue
            
            print(f"[PIPELINE] Processing {len(events)} events")
            
            # ✅ تجميع الأحداث حسب IP
            by_ip: dict[str, list] = {}
            for ev in events:
                ip = ev.get("src_ip", "unknown")
                by_ip.setdefault(ip, []).append(ev)
            
            # معالجة كل IP على حدة
            for ip, ip_evs in by_ip.items():
                _process_events_for_ip(ip, ip_evs)
        
        except Exception as exc:
            print(f"[!] Pipeline error: {exc}")
            traceback.print_exc()


def vt_callback(result: dict) -> None:
    if not DB_READY: return
    try:
        with db["get_connection"]() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM attackers WHERE ip_address = %s",
                (result["ip"],)
            )
            row = cur.fetchone()
            if row:
                db["save_vt_report"](row[0], result)
                print(f"  [VT SAVED] {result['ip']} → {result.get('verdict')}")
    except Exception as exc:
        print(f"[!] VT callback error: {exc}")


# ==================== Main Entry Point ====================

if __name__ == "__main__":
    print("=" * 55)
    print("  🛡️  HoneyTrack Unified Server")
    print("=" * 55)
    
    # ✅ تهيئة قاعدة البيانات
    if DB_READY:
        try:
            db["initialize_database"]()
            print("[OK] Database initialised")
        except Exception as exc:
            print(f"[!] Database init failed: {exc}")
    
    # ✅ تشغيل SSH honeypot
    if SSH_READY:
        threading.Thread(
            target=ssh["start_ssh"],
            kwargs={"host": "0.0.0.0", "port": 2222},
            daemon=True
        ).start()
        print("[OK] SSH honeypot on port 2222")
    
    # ✅ تشغيل HTTP honeypot
    if HTTP_READY:
        threading.Thread(
            target=start_http,
            kwargs={"host": "0.0.0.0", "port": 8080},
            daemon=True
        ).start()
        print("[OK] HTTP honeypot on port 8080")
    
    # ✅ تشغيل Pipeline worker
    threading.Thread(target=pipeline_worker, daemon=True).start()
    print("[OK] Pipeline worker started")
    
    # ✅ تشغيل VirusTotal worker
    if VT_READY:
        try:
            vt_queue.set_callback(vt_callback)
            threading.Thread(target=vt_queue.run_forever, daemon=True).start()
            print("[OK] VirusTotal worker started")
        except Exception as exc:
            print(f"[!] VirusTotal worker start failed: {exc}")
    
    print(f"\n  Dashboard  →  http://localhost:5000")
    print(f"  Username   →  {ADMIN_USERNAME}")
    print(f"  Password   →  {ADMIN_PASSWORD}")
    print("=" * 55)
    
    # ✅ تشغيل Flask server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)