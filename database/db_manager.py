"""
╔══════════════════════════════════════════════════════════════╗
║         HoneyTrack - Database Manager                       ║
║         MySQL External Database                             ║
║         Professional Edition - All Attack Types             ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import os
from contextlib import contextmanager
from datetime import datetime

import mysql.connector
from mysql.connector import Error

# ── Config ────────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", "3306")),
    "user":     os.getenv("DB_USER", "honeypot_user"),
    "password": os.getenv("DB_PASS", "1234"),
    "database": os.getenv("DB_NAME", "honeypot_db"),
    "autocommit": False,
}


# ── Connection ────────────────────────────────────────────────────────────────
@contextmanager
def get_connection():
    """Yield a MySQL connection; commit on success, rollback on error."""
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        yield conn
        conn.commit()
    except Error as e:
        if conn:
            conn.rollback()
        print(f"  [DB] Error: {e}")
        raise
    finally:
        if conn and conn.is_connected():
            conn.close()


# ── Schema ────────────────────────────────────────────────────────────────────
_TABLES = {
    "attackers": """
        CREATE TABLE IF NOT EXISTS attackers (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            ip_address   VARCHAR(45)  NOT NULL,
            country      VARCHAR(100),
            city         VARCHAR(100),
            first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
            attack_count INT DEFAULT 1,
            vt_malicious INT DEFAULT 0,
            vt_checked   BOOLEAN DEFAULT FALSE,
            UNIQUE KEY uq_ip      (ip_address),
            INDEX      idx_last   (last_seen),
            INDEX      idx_country(country)
        )
    """,

    "geolocation": """
        CREATE TABLE IF NOT EXISTS geolocation (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id  INT NOT NULL,
            ip_address   VARCHAR(45),
            country      VARCHAR(100),
            country_code VARCHAR(5),
            region       VARCHAR(100),
            city         VARCHAR(100),
            latitude     FLOAT,
            longitude    FLOAT,
            isp          VARCHAR(255),
            org          VARCHAR(255),
            asn          VARCHAR(100),
            updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            UNIQUE KEY uq_attacker_geo (attacker_id)
        )
    """,

    "credential_attempts": """
        CREATE TABLE IF NOT EXISTS credential_attempts (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id INT NOT NULL,
            username    VARCHAR(255),
            password    VARCHAR(255),
            protocol    ENUM('SSH','HTTP','FTP','TELNET','RDP') DEFAULT 'SSH',
            success     BOOLEAN DEFAULT FALSE,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            INDEX idx_attacker  (attacker_id),
            INDEX idx_timestamp (timestamp)
        )
    """,

    "sessions": """
        CREATE TABLE IF NOT EXISTS sessions (
            id                INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id       INT NOT NULL,
            protocol          ENUM('SSH','HTTP','FTP','TELNET','RDP'),
            start_time        DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time          DATETIME,
            duration_seconds  FLOAT DEFAULT 0,
            commands_executed INT DEFAULT 0,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            INDEX idx_attacker (attacker_id)
        )
    """,

    "command_logs": """
        CREATE TABLE IF NOT EXISTS command_logs (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            session_id  INT NOT NULL,
            attacker_id INT NOT NULL,
            command     TEXT,
            response    TEXT,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id)  REFERENCES sessions(id),
            FOREIGN KEY (attacker_id) REFERENCES attackers(id)
        )
    """,

    "http_requests": """
        CREATE TABLE IF NOT EXISTS http_requests (
            id                  INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id         INT NOT NULL,
            method              VARCHAR(10),
            path                TEXT,
            user_agent          TEXT,
            suspicious_patterns JSON,
            is_attack           BOOLEAN DEFAULT FALSE,
            attack_type         VARCHAR(100),
            body_snippet        TEXT,
            payload             TEXT,
            headers             JSON,
            timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            INDEX idx_attacker  (attacker_id),
            INDEX idx_is_attack (is_attack),
            INDEX idx_attack_type (attack_type),
            INDEX idx_timestamp (timestamp)
        )
    """,

    "ml_results": """
        CREATE TABLE IF NOT EXISTS ml_results (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id   INT NOT NULL,
            anomaly_score FLOAT,
            is_anomaly    BOOLEAN,
            attack_type   VARCHAR(100),
            attack_prob   FLOAT,
            severity      ENUM('LOW','MEDIUM','HIGH','CRITICAL') DEFAULT 'LOW',
            features      JSON,
            mitre_tactics JSON,
            analyzed_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            INDEX idx_attacker (attacker_id),
            INDEX idx_anomaly  (is_anomaly),
            INDEX idx_severity (severity)
        )
    """,

    "vt_reports": """
        CREATE TABLE IF NOT EXISTS vt_reports (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id  INT NOT NULL,
            ip_address   VARCHAR(45),
            malicious    INT DEFAULT 0,
            suspicious   INT DEFAULT 0,
            harmless     INT DEFAULT 0,
            undetected   INT DEFAULT 0,
            reputation   INT DEFAULT 0,
            verdict      VARCHAR(50),
            country      VARCHAR(100),
            as_owner     VARCHAR(255),
            tags         JSON,
            raw_response JSON,
            checked_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            UNIQUE KEY uq_attacker_vt (attacker_id)
        )
    """,

    "alerts": """
        CREATE TABLE IF NOT EXISTS alerts (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            attacker_id INT,
            alert_type  VARCHAR(100),
            severity    ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
            message     TEXT,
            resolved    BOOLEAN DEFAULT FALSE,
            resolved_at DATETIME,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attacker_id) REFERENCES attackers(id),
            INDEX idx_severity   (severity),
            INDEX idx_resolved   (resolved),
            INDEX idx_created_at (created_at)
        )
    """,
}

_TABLE_ORDER = [
    "attackers", "geolocation", "credential_attempts",
    "sessions", "command_logs", "http_requests",
    "ml_results", "vt_reports", "alerts",
]


# ── Init ──────────────────────────────────────────────────────────────────────
def initialize_database() -> None:
    """Create all tables in correct foreign-key order."""
    with get_connection() as conn:
        cur = conn.cursor()
        for table in _TABLE_ORDER:
            cur.execute(_TABLES[table])
            print(f"  [DB] ✔ Table ready: {table}")
    print(f"  [DB] All {len(_TABLE_ORDER)} tables initialized successfully.")


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  WRITE helpers
# ╚══════════════════════════════════════════════════════════════════════════════

def upsert_attacker(ip: str,
                    country: str | None = None,
                    city:    str | None = None) -> int | None:
    """Insert or increment attacker row; return its primary key."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO attackers (ip_address, country, city, attack_count)
            VALUES (%s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                attack_count = attack_count + 1,
                last_seen    = CURRENT_TIMESTAMP,
                country      = COALESCE(%s, country),
                city         = COALESCE(%s, city)
            """,
            (ip, country, city, country, city),
        )
        cur.execute("SELECT id FROM attackers WHERE ip_address = %s", (ip,))
        row = cur.fetchone()
        return row[0] if row else None


def upsert_geolocation(attacker_id: int, geo: dict) -> None:
    """
    Insert or update geolocation row for an attacker.
    Also backfills country / city on the attackers table.
    """
    if not geo:
        return
    with get_connection() as conn:
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO geolocation
                (attacker_id, ip_address, country, country_code,
                 region, city, latitude, longitude, isp, org, asn)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                country      = VALUES(country),
                country_code = VALUES(country_code),
                region       = VALUES(region),
                city         = VALUES(city),
                latitude     = VALUES(latitude),
                longitude    = VALUES(longitude),
                isp          = VALUES(isp),
                org          = VALUES(org),
                asn          = VALUES(asn),
                updated_at   = CURRENT_TIMESTAMP
            """,
            (
                attacker_id,
                geo.get("ip"),
                geo.get("country"),
                geo.get("country_code"),
                geo.get("region"),
                geo.get("city"),
                geo.get("latitude"),
                geo.get("longitude"),
                geo.get("isp"),
                geo.get("org"),
                geo.get("asn"),
            ),
        )

        cur.execute(
            """
            UPDATE attackers
            SET country = COALESCE(%s, country),
                city    = COALESCE(%s, city)
            WHERE id = %s
            """,
            (geo.get("country"), geo.get("city"), attacker_id),
        )


def log_credential_attempt(attacker_id: int,
                           username:    str,
                           password:    str,
                           protocol:    str = "SSH") -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO credential_attempts
                (attacker_id, username, password, protocol)
            VALUES (%s,%s,%s,%s)
            """,
            (attacker_id, username, password, protocol),
        )


def create_session(attacker_id: int, protocol: str) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO sessions (attacker_id, protocol) VALUES (%s,%s)",
            (attacker_id, protocol),
        )
        return cur.lastrowid


def close_session(session_id: int, commands_count: int = 0) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE sessions
            SET end_time         = CURRENT_TIMESTAMP,
                duration_seconds = TIMESTAMPDIFF(SECOND, start_time, CURRENT_TIMESTAMP),
                commands_executed = %s
            WHERE id = %s
            """,
            (commands_count, session_id),
        )


def log_command(session_id:  int, attacker_id: int,
                command:     str, response:    str = "") -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO command_logs
                (session_id, attacker_id, command, response)
            VALUES (%s,%s,%s,%s)
            """,
            (session_id, attacker_id, command, response),
        )


def log_http_request(attacker_id:         int,
                     method:               str,
                     path:                 str,
                     user_agent:           str,
                     suspicious_patterns:  list = None,
                     is_attack:            bool = False,
                     body_snippet:         str = "",
                     attack_type:          str | None = None,
                     attack_patterns:      list = None,      # ✅ جديد
                     payload:              str = "",
                     headers:              dict = None,
                     raw_body:             str = "",         # ✅ جديد
                     src_ip_raw:           str = None,       # ✅ جديد
                     src_ip_reported:      str = None) -> None:  # ✅ جديد
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO http_requests
                (attacker_id, method, path, user_agent,
                 suspicious_patterns, is_attack, attack_type, 
                 body_snippet, payload, headers)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                attacker_id, method, path, user_agent,
                json.dumps(suspicious_patterns or attack_patterns or []),
                is_attack, attack_type, body_snippet or raw_body,
                payload, json.dumps(headers or {}),
            ),
        )


def save_ml_result(attacker_id:   int,
                   anomaly_score: float,
                   is_anomaly:    bool,
                   features:      dict,
                   mitre_tactics: list,
                   attack_type:   str   = None,
                   attack_prob:   float = 0.0,
                   severity:      str   = "LOW") -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ml_results
                (attacker_id, anomaly_score, is_anomaly, attack_type,
                 attack_prob, severity, features, mitre_tactics)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                attacker_id, anomaly_score, is_anomaly, attack_type,
                attack_prob, severity,
                json.dumps(features),
                json.dumps(mitre_tactics),
            ),
        )


def save_vt_report(attacker_id: int, vt_result: dict) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vt_reports
                (attacker_id, ip_address, malicious, suspicious,
                 harmless, undetected, reputation, verdict,
                 country, as_owner, tags, raw_response)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                malicious   = VALUES(malicious),
                suspicious  = VALUES(suspicious),
                harmless    = VALUES(harmless),
                undetected  = VALUES(undetected),
                reputation  = VALUES(reputation),
                verdict     = VALUES(verdict),
                country     = VALUES(country),
                as_owner    = VALUES(as_owner),
                tags        = VALUES(tags),
                raw_response = VALUES(raw_response),
                checked_at  = CURRENT_TIMESTAMP
            """,
            (
                attacker_id,
                vt_result.get("ip"),
                vt_result.get("malicious",  0),
                vt_result.get("suspicious", 0),
                vt_result.get("harmless",   0),
                vt_result.get("undetected", 0),
                vt_result.get("reputation", 0),
                vt_result.get("verdict"),
                vt_result.get("country"),
                vt_result.get("as_owner"),
                json.dumps(vt_result.get("tags", [])),
                json.dumps(vt_result),
            ),
        )
    update_vt_result(vt_result.get("ip", ""), vt_result.get("malicious", 0))


def update_vt_result(ip: str, malicious_count: int) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE attackers
            SET vt_malicious = %s, vt_checked = TRUE
            WHERE ip_address = %s
            """,
            (malicious_count, ip),
        )


def create_alert(attacker_id: int,
                 alert_type:  str,
                 severity:    str,
                 message:     str) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts (attacker_id, alert_type, severity, message)
            VALUES (%s,%s,%s,%s)
            """,
            (attacker_id, alert_type, severity, message),
        )


def resolve_alert(alert_id: int) -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE alerts
            SET resolved = TRUE, resolved_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (alert_id,),
        )


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  READ helpers — Dashboard
# ╚══════════════════════════════════════════════════════════════════════════════

def _serialize(data):
    """Recursively convert datetime values to ISO strings."""
    if data is None:
        return None
    if isinstance(data, dict):
        return {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in data.items()
        }
    return [
        {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()}
        for row in data
    ]

def get_dashboard_stats() -> dict:
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)

        # ── KPIs ──────────────────────────────────────────────────────────────
        cur.execute("SELECT COALESCE(SUM(attack_count),0) AS v FROM attackers")
        total_attacks = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM attackers")
        total_ips = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM alerts WHERE resolved = FALSE")
        open_alerts = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM ml_results WHERE is_anomaly = TRUE")
        anomalies = int(cur.fetchone()["v"])

        # ── Protocol counts ───────────────────────────────────────────────────
        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='SSH'")
        ssh_count = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='FTP'")
        ftp_count = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='TELNET'")
        telnet_count = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='RDP'")
        rdp_count = int(cur.fetchone()["v"])

        cur.execute("SELECT COUNT(*) AS v FROM http_requests")
        http_count = int(cur.fetchone()["v"])

        # ── Brute Force Attacks ───────────────────────────────────────────────
        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='SSH'")
        brute_force_ssh = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='FTP'")
        brute_force_ftp = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol IN ('SSH','FTP','TELNET','RDP')")
        brute_force_total = int(cur.fetchone()['v'])

        # ── Web Attacks ───────────────────────────────────────────────────────
        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='SQLi' 
               OR JSON_CONTAINS(suspicious_patterns, '"sql_injection"')
        """)
        sqli_count = int(cur.fetchone()['v'])

        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='XSS' 
               OR JSON_CONTAINS(suspicious_patterns, '"xss"')
        """)
        xss_count = int(cur.fetchone()['v'])

        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='Path Traversal' 
               OR JSON_CONTAINS(suspicious_patterns, '"path_traversal"')
        """)
        traversal_count = int(cur.fetchone()['v'])

        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='Command Injection' 
               OR JSON_CONTAINS(suspicious_patterns, '"command_injection"')
        """)
        command_injection_count = int(cur.fetchone()['v'])

        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='File Inclusion' 
               OR JSON_CONTAINS(suspicious_patterns, '"file_inclusion"')
        """)
        file_inclusion_count = int(cur.fetchone()['v'])

        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='XXE' 
               OR JSON_CONTAINS(suspicious_patterns, '"xxe"')
        """)
        xxe_count = int(cur.fetchone()['v'])

        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='CSRF' 
               OR JSON_CONTAINS(suspicious_patterns, '"csrf"')
        """)
        csrf_count = int(cur.fetchone()['v'])

        # ── DoS/DDoS Attacks ──────────────────────────────────────────────────
        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='DoS' 
               OR JSON_CONTAINS(suspicious_patterns, '"dos"')
               OR JSON_CONTAINS(suspicious_patterns, '"ddos"')
        """)
        dos_count = int(cur.fetchone()['v'])

        # ── Exploitation Attempts ─────────────────────────────────────────────
        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='Exploit' 
               OR JSON_CONTAINS(suspicious_patterns, '"exploit"')
               OR JSON_CONTAINS(suspicious_patterns, '"cve"')
        """)
        exploit_count = int(cur.fetchone()['v'])

        # ── Scanner Detection ─────────────────────────────────────────────────
        cur.execute("""
            SELECT COUNT(*) AS v FROM http_requests 
            WHERE attack_type='Scanner' 
               OR JSON_CONTAINS(suspicious_patterns, '"scanner"')
               OR user_agent LIKE '%nmap%'
               OR user_agent LIKE '%nikto%'
               OR user_agent LIKE '%sqlmap%'
               OR user_agent LIKE '%burp%'
               OR user_agent LIKE '%nessus%'
               OR user_agent LIKE '%openvas%'
        """)
        scanner_count = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM http_requests WHERE is_attack = TRUE")
        http_attacks = int(cur.fetchone()["v"])

        # ── Timeline (last 24 h) ──────────────────────────────────────────────
        cur.execute(
            """
            SELECT DATE_FORMAT(last_seen,'%Y-%m-%d %H:00') AS hour,
                   SUM(attack_count) AS count
            FROM attackers
            WHERE last_seen >= NOW() - INTERVAL 24 HOUR
            GROUP BY hour
            ORDER BY hour
            """
        )
        timeline = _serialize(cur.fetchall())

        # ── Attack Type Distribution ──────────────────────────────────────────
        cur.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM http_requests
            WHERE is_attack = TRUE AND attack_type IS NOT NULL
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 10
        """)
        attack_distribution = cur.fetchall()

        # ── Recent attackers with geo + latest ML result ───────────────────────
        cur.execute(
            """
            SELECT
                a.ip_address, a.country, a.attack_count,
                a.vt_malicious, a.vt_checked,
                a.first_seen,  a.last_seen,
                g.latitude,    g.longitude,
                g.city,        g.isp,
                m.attack_type, m.severity, m.anomaly_score
            FROM attackers a
            LEFT JOIN geolocation g ON g.attacker_id = a.id
            LEFT JOIN ml_results  m ON m.attacker_id = a.id
                AND m.analyzed_at = (
                    SELECT MAX(r2.analyzed_at)
                    FROM   ml_results r2
                    WHERE  r2.attacker_id = a.id
                )
            ORDER BY a.last_seen DESC
            LIMIT 20
            """
        )
        recent_attackers = _serialize(cur.fetchall())

        # ── Recent alerts ─────────────────────────────────────────────────────
        cur.execute(
            """
            SELECT al.id, al.alert_type, al.severity,
                   al.message, al.created_at, al.resolved,
                   at.ip_address, at.country
            FROM   alerts    al
            JOIN   attackers at ON al.attacker_id = at.id
            ORDER  BY al.created_at DESC
            LIMIT  15
            """
        )
        recent_alerts = _serialize(cur.fetchall())

        # ── MITRE technique counts ────────────────────────────────────────────
        mitre_counts = {}

        # MITRE from http_requests (NEW)
        try:
            cur.execute("""
                SELECT 
                    CASE 
                        WHEN attack_type = 'SQLi' THEN 'T1190'
                        WHEN attack_type = 'XSS' THEN 'T1189'
                        WHEN attack_type = 'Path Traversal' THEN 'T1003'
                        WHEN attack_type = 'Command Injection' THEN 'T1059'
                        WHEN attack_type = 'Suspicious Scan' THEN 'T1595'
                        WHEN attack_type = 'Webshell' THEN 'T1505'
                        WHEN attack_type = 'SSRF' THEN 'T1190'
                        WHEN attack_type = 'XXE Injection' THEN 'T1190'
                        WHEN attack_type = 'LFI/RFI' THEN 'T1190'
                        ELSE 'T1190'
                    END as technique_id,
                    COUNT(*) as count
                FROM http_requests
                WHERE is_attack = 1 AND attack_type IS NOT NULL
                GROUP BY technique_id
                ORDER BY count DESC
            """)
            for row in cur.fetchall():
                mitre_counts[row['technique_id']] = row['count']
        except Exception:
            pass

        # Keep ML-based MITRE if exists (merge)
        try:
            cur.execute("""
                SELECT mitre_tactics FROM ml_results 
                WHERE is_anomaly = TRUE AND mitre_tactics IS NOT NULL
            """)
            for row in cur.fetchall():
                if row['mitre_tactics']:
                    try:
                        tactics = json.loads(row['mitre_tactics']) if isinstance(row['mitre_tactics'], str) else row['mitre_tactics']
                        for t in tactics:
                            tid = t.get('technique_id', '')
                            if tid:
                                mitre_counts[tid] = mitre_counts.get(tid, 0) + 1
                    except Exception:
                        pass
        except Exception:
            pass

        # Fallback: keep old MITRE if empty
        if not mitre_counts:
            mitre_counts = {"T1190": 0, "T1189": 0, "T1003": 0, "T1059": 0, "T1595": 0}

        # ── Top credentials ───────────────────────────────────────────────────
        cur.execute(
            """
            SELECT username, password, COUNT(*) AS count
            FROM   credential_attempts
            GROUP  BY username, password
            ORDER  BY count DESC
            LIMIT  10
            """
        )
        top_creds = _serialize(cur.fetchall())

        # ── Top Attacked Paths ────────────────────────────────────────────────
        cur.execute("""
            SELECT path, COUNT(*) as count
            FROM http_requests
            WHERE is_attack = TRUE
            GROUP BY path
            ORDER BY count DESC
            LIMIT 10
        """)
        top_attacked_paths = cur.fetchall()

        # ── Geo points for map ────────────────────────────────────────────────
        cur.execute(
            """
            SELECT a.ip_address, a.attack_count, a.country,
                   g.latitude, g.longitude, g.city
            FROM   attackers   a
            JOIN   geolocation g ON g.attacker_id = a.id
            WHERE  g.latitude IS NOT NULL
            """
        )
        geo_points = _serialize(cur.fetchall())

        # ── Hourly Attack Rate ────────────────────────────────────────────────
        cur.execute("""
            SELECT HOUR(last_seen) as hour, COUNT(*) as count
            FROM attackers
            WHERE last_seen >= NOW() - INTERVAL 24 HOUR
            GROUP BY HOUR(last_seen)
            ORDER BY hour
        """)
        hourly_rate = cur.fetchall()

        return {
            # KPIs
            "total_attacks":      total_attacks,
            "total_unique_ips":   total_ips,
            "open_alerts":        open_alerts,
            "anomalies_detected": anomalies,
            
            # Protocol Stats
            "ssh_count":          ssh_count,
            "ftp_count":          ftp_count,
            "telnet_count":       telnet_count,
            "rdp_count":          rdp_count,
            "http_count":         http_count,
            
            # Brute Force
            "brute_force_ssh":    brute_force_ssh,
            "brute_force_ftp":    brute_force_ftp,
            "brute_force_total":  brute_force_total,
            
            # Web Attacks
            "sqli_count":             sqli_count,
            "xss_count":              xss_count,
            "traversal_count":        traversal_count,
            "command_injection_count": command_injection_count,
            "file_inclusion_count":   file_inclusion_count,
            "xxe_count":              xxe_count,
            "csrf_count":             csrf_count,
            
            # DoS/DDoS
            "dos_count":          dos_count,
            
            # Exploits & Scanners
            "exploit_count":      exploit_count,
            "scanner_count":      scanner_count,
            
            # Total
            "http_attack_count":  http_attacks,
            
            # Charts & Data
            "timeline":           timeline,
            "attack_distribution": attack_distribution,
            "hourly_rate":        hourly_rate,
            "mitre_counts":       mitre_counts,
            "top_credentials":    top_creds,
            "top_attacked_paths": top_attacked_paths,
            "geo_points":         geo_points,
            "recent_attackers":   recent_attackers,
            "recent_alerts":      recent_alerts,
        }

def get_attacker_detail(ip: str) -> dict:
    """Full profile for a single attacker IP."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT * FROM attackers WHERE ip_address = %s", (ip,))
        attacker = cur.fetchone()
        if not attacker:
            return {}
        aid = attacker["id"]

        cur.execute("SELECT * FROM geolocation WHERE attacker_id = %s", (aid,))
        geo = cur.fetchone()

        cur.execute("SELECT * FROM vt_reports WHERE attacker_id = %s", (aid,))
        vt = cur.fetchone()

        cur.execute(
            "SELECT * FROM credential_attempts WHERE attacker_id=%s ORDER BY timestamp DESC LIMIT 50",
            (aid,),
        )
        creds = cur.fetchall()

        cur.execute(
            "SELECT * FROM sessions WHERE attacker_id=%s ORDER BY start_time DESC LIMIT 20",
            (aid,),
        )
        sessions = cur.fetchall()

        cur.execute(
            "SELECT * FROM command_logs WHERE attacker_id=%s ORDER BY timestamp DESC LIMIT 50",
            (aid,),
        )
        commands = cur.fetchall()

        cur.execute(
            "SELECT * FROM http_requests WHERE attacker_id=%s ORDER BY timestamp DESC LIMIT 50",
            (aid,),
        )
        http_reqs = cur.fetchall()

        cur.execute(
            "SELECT * FROM ml_results WHERE attacker_id=%s ORDER BY analyzed_at DESC LIMIT 1",
            (aid,),
        )
        ml = cur.fetchone()

        # Attack summary
        cur.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM http_requests
            WHERE attacker_id = %s AND is_attack = TRUE
            GROUP BY attack_type
        """, (aid,))
        attack_summary = cur.fetchall()

        return {
            "attacker":       _serialize(attacker),
            "geolocation":    _serialize(geo),
            "vt_report":      _serialize(vt),
            "credentials":    _serialize(creds),
            "sessions":       _serialize(sessions),
            "commands":       _serialize(commands),
            "http_requests":  _serialize(http_reqs),
            "ml_result":      _serialize(ml),
            "attack_summary": attack_summary,
        }


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    initialize_database()
    stats = get_dashboard_stats()
    print(f"✅ Dashboard ready: {stats['total_unique_ips']} unique IPs tracked.")
    print(f"   - SQLi: {stats['sqli_count']}")
    print(f"   - XSS: {stats['xss_count']}")
    print(f"   - Brute Force: {stats['brute_force_total']}")
    print(f"   - Scanners: {stats['scanner_count']}")