"""
HoneyTrack - ML Predictor
--------------------------
Loads the trained models (.pkl) and predicts on live traffic.
Uses: Isolation Forest + Random Forest + MITRE ATT&CK mapping.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path

# ── Model paths ───────────────────────────────────────────────────────────────
MODELS_DIR = Path(__file__).parent / "models"

# Anomaly threshold — scores below this are flagged as anomalies.
# Isolation Forest returns negative scores; more negative = more anomalous.
ANOMALY_THRESHOLD = -0.35

_models: dict = {}


def _load() -> None:
    """Lazy-load all models exactly once."""
    global _models
    if _models:
        return
    try:
        _models = {
            "scaler":       joblib.load(MODELS_DIR / "scaler.pkl"),
            "iforest":      joblib.load(MODELS_DIR / "isolation_forest.pkl"),
            "rf_binary":    joblib.load(MODELS_DIR / "rf_binary.pkl"),
            "rf_multi":     joblib.load(MODELS_DIR / "rf_multiclass.pkl"),
            "le_attack":    joblib.load(MODELS_DIR / "label_encoder.pkl"),
            "feature_cols": joblib.load(MODELS_DIR / "feature_cols.pkl"),
            "encoders":     joblib.load(MODELS_DIR / "encoders.pkl"),
        }
        print("  [ML] ✔ Models loaded successfully")
    except Exception as exc:
        print(f"  [ML] ✗ Could not load models: {exc}")
        _models = {}


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
MITRE_MAP: dict[str, list[dict]] = {
    "Reconnaissance": [
        {"technique_id": "T1595",     "technique": "Active Scanning",              "tactic": "Reconnaissance"},
        {"technique_id": "T1590",     "technique": "Gather Victim Network Info",   "tactic": "Reconnaissance"},
    ],
    "Exploits": [
        {"technique_id": "T1190",     "technique": "Exploit Public-Facing App",    "tactic": "Initial Access"},
        {"technique_id": "T1203",     "technique": "Exploitation for Execution",   "tactic": "Execution"},
    ],
    "DoS": [
        {"technique_id": "T1499",     "technique": "Endpoint Denial of Service",   "tactic": "Impact"},
        {"technique_id": "T1498",     "technique": "Network Denial of Service",    "tactic": "Impact"},
    ],
    "Generic": [
        {"technique_id": "T1110",     "technique": "Brute Force",                  "tactic": "Credential Access"},
        {"technique_id": "T1071",     "technique": "Application Layer Protocol",   "tactic": "Command and Control"},
    ],
    "Fuzzers": [
        {"technique_id": "T1595.002", "technique": "Vulnerability Scanning",       "tactic": "Reconnaissance"},
        {"technique_id": "T1190",     "technique": "Exploit Public-Facing App",    "tactic": "Initial Access"},
    ],
    "Backdoor": [
        {"technique_id": "T1543",     "technique": "Create/Modify System Process", "tactic": "Persistence"},
        {"technique_id": "T1078",     "technique": "Valid Accounts",               "tactic": "Defense Evasion"},
    ],
    "Analysis": [
        {"technique_id": "T1046",     "technique": "Network Service Discovery",    "tactic": "Discovery"},
        {"technique_id": "T1040",     "technique": "Network Sniffing",             "tactic": "Credential Access"},
    ],
    "Shellcode": [
        {"technique_id": "T1055",     "technique": "Process Injection",            "tactic": "Defense Evasion"},
        {"technique_id": "T1059",     "technique": "Command and Scripting",        "tactic": "Execution"},
    ],
    "Worms": [
        {"technique_id": "T1210",     "technique": "Exploitation of Remote Svc",  "tactic": "Lateral Movement"},
        {"technique_id": "T1570",     "technique": "Lateral Tool Transfer",        "tactic": "Lateral Movement"},
    ],
}


# ── Feature Builder ───────────────────────────────────────────────────────────
def build_features(events: list[dict]) -> dict:
    """
    Convert raw honeypot events for one IP into the same
    feature space used during model training.
    """
    ssh_events  = [e for e in events if e.get("type") == "ssh_auth"]
    http_events = [e for e in events if e.get("type") == "http_request"]
    cmd_events  = [e for e in events if e.get("type") == "ssh_command"]
    atk_http    = [e for e in http_events if e.get("is_attack")]

    usernames = {e.get("username", "") for e in ssh_events}  # noqa: F841
    passwords = {e.get("password", "") for e in ssh_events}  # noqa: F841
    paths     = {e.get("path",     "") for e in http_events}

    attack_patterns: list[str] = []
    for e in atk_http:
        attack_patterns.extend(e.get("attack_patterns", {}).keys())

    n_ssh   = len(ssh_events)
    n_http  = len(http_events)
    n_cmd   = len(cmd_events)
    n_atk   = len(atk_http)
    n_total = len(events)
    n_paths = len(paths)
    n_ips   = len({e.get("src_ip", "") for e in events}) or 1

    return {
        # Traffic volume
        "dur":               n_total * 0.5,
        "spkts":             n_ssh + n_http,
        "dpkts":             n_total,
        "sbytes":            n_ssh  * 50,
        "dbytes":            n_http * 200,
        "rate":              n_total / n_ips,
        # TTL
        "sttl":              64,
        "dttl":              64,
        # Load
        "sload":             n_ssh  * 100.0,
        "dload":             n_http * 100.0,
        # Loss
        "sloss":             0,
        "dloss":             0,
        # Inter-packet timing
        "sinpkt":            1.0,
        "dinpkt":            1.0,
        # Jitter
        "sjit":              float(n_cmd),
        "djit":              float(n_atk),
        # TCP window / base sequence numbers
        "swin":              255,
        "stcpb":             0,
        "dtcpb":             0,
        "dwin":              255,
        # Round-trip timing
        "tcprtt":            0.0,
        "synack":            0.0,
        "ackdat":            0.0,
        # Mean packet sizes
        "smean":             50,
        "dmean":             200,
        # HTTP
        "trans_depth":       0,
        "response_body_len": 0,
        # Connection counts
        "ct_srv_src":        n_ssh,
        "ct_state_ttl":      1,
        "ct_dst_ltm":        1,
        "ct_src_dport_ltm":  1,
        "ct_dst_sport_ltm":  1,
        "ct_dst_src_ltm":    n_total,
        # FTP
        "is_ftp_login":      0,
        "ct_ftp_cmd":        0,
        # HTTP method count
        "ct_flw_http_mthd":  n_http,
        "ct_src_ltm":        n_total,
        "ct_srv_dst":        n_paths,
        # Same source IP/port flag
        "is_sm_ips_ports":   1 if n_ssh > 5 else 0,
        # Protocol / service / state (TCP approximation)
        "proto":             6,
        "service":           0,
        "state":             2,
        # Engineered ratios
        "byte_ratio":        (n_ssh * 50) / max(1, n_http * 200),
        "pkt_diff":          n_ssh - n_http,
        "load_ratio":        n_ssh / max(1, n_http),
        "jit_ratio":         float(n_cmd) / max(1, n_atk),
        "conn_intensity":    n_ssh * n_paths,
    }


# ── Severity Calculator ───────────────────────────────────────────────────────
_HIGH_RISK_TYPES = {"Exploits", "Backdoor", "Shellcode", "Worms"}

def _severity(prob: float, attack_type: str) -> str:
    if attack_type in _HIGH_RISK_TYPES or prob >= 0.9:
        return "CRITICAL"
    if prob >= 0.7:
        return "HIGH"
    if prob >= 0.5:
        return "MEDIUM"
    return "LOW"


# ── Fallback (models not loaded) ──────────────────────────────────────────────
def _fallback_predict(events: list[dict], ip: str) -> dict:
    ssh_count  = sum(1 for e in events if e.get("type") == "ssh_auth")
    http_atk   = sum(1 for e in events if e.get("is_attack"))
    is_anomaly = ssh_count > 5 or http_atk > 0
    return {
        "ip":                 ip,
        "is_attack":          is_anomaly,
        "attack_probability": 90.0 if is_anomaly else 10.0,
        "attack_type":        "Generic" if is_anomaly else "Normal",
        "anomaly_score":      -0.5 if is_anomaly else 0.5,
        "is_anomaly":         is_anomaly,
        "mitre_tactics":      MITRE_MAP.get("Generic", []) if is_anomaly else [],
        "severity":           "HIGH" if is_anomaly else "LOW",
        "features":           {},
    }


# ── Main Predict Function ─────────────────────────────────────────────────────
def predict(events: list[dict], ip: str) -> dict:
    """
    Analyze honeypot events for a single IP address.

    Args:
        events: List of raw event dicts from the SSH/HTTP honeypot.
        ip:     Source IP string (used for logging and result tagging).

    Returns:
        Full prediction result dict ready for DB storage and dashboard display.
    """
    # Sanitise — drop anything that isn't a plain dict
    events = [e for e in events if isinstance(e, dict)]

    _load()

    if not _models:
        return _fallback_predict(events, ip)

    # ── Feature extraction ────────────────────────────────────────────────────
    raw_features = build_features(events)
    feature_cols = _models["feature_cols"]

    vec        = pd.DataFrame([raw_features]).reindex(columns=feature_cols, fill_value=0)
    vec_scaled = _models["scaler"].transform(vec)

    # ── Isolation Forest ──────────────────────────────────────────────────────
    if_score   = float(_models["iforest"].score_samples(vec_scaled)[0])
    # Use a manual threshold instead of the model's built-in one,
    # which is often too conservative for honeypot traffic patterns.
    is_anomaly = if_score < ANOMALY_THRESHOLD

    # ── Random Forest — binary (attack / not-attack) ──────────────────────────
    is_attack   = bool(_models["rf_binary"].predict(vec_scaled)[0])
    attack_prob = float(_models["rf_binary"].predict_proba(vec_scaled)[0][1])

    # ── Random Forest — multi-class (attack type) ─────────────────────────────
    attack_type = "Normal"
    mitre: list[dict] = []

    if is_attack or is_anomaly:
        enc         = _models["rf_multi"].predict(vec_scaled)[0]
        attack_type = _models["le_attack"].inverse_transform([enc])[0]
        mitre       = MITRE_MAP.get(attack_type, MITRE_MAP["Generic"])

        # Ensure is_attack reflects anomaly detection too
        if not is_attack:
            is_attack   = True
            attack_prob = max(attack_prob, 0.6)   # minimum confidence floor

    severity = _severity(attack_prob, attack_type)

    result = {
        "ip":                 ip,
        "is_attack":          is_attack,
        "attack_probability": round(attack_prob * 100, 1),
        "attack_type":        attack_type,
        "anomaly_score":      round(if_score, 4),
        "is_anomaly":         is_anomaly,
        "mitre_tactics":      mitre,
        "severity":           severity,
        "features":           raw_features,
    }

    print(
        f"  [ML] {ip} → {attack_type} ({severity}) "
        f"prob={attack_prob:.0%} anomaly={is_anomaly}"
    )
    return result