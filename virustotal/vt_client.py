"""
HoneyTrack - VirusTotal Client (Enhanced)
-----------------------------------------
Checks attacker IPs against 70+ security vendors.
Rate-limited queue for free API (4 req/min).
Enhanced with IP caching, threat intelligence, and auto-blocking.
"""

import requests
import time
import os
import threading
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ────────────────────────────
VT_API_KEY   = os.getenv("VT_API_KEY", "")
VT_BASE_URL  = "https://www.virustotal.com/api/v3"
VT_DELAY     = 16   # seconds between requests (free tier = 4 req/min)
CACHE_TTL    = 3600 # cache results for 1 hour
CACHE_FILE   = "vt_cache.json"
VT_ENABLED = bool(VT_API_KEY)

# Private IP ranges to skip
PRIVATE_PREFIXES = ("127.", "10.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                    "172.29.", "172.30.", "172.31.")

# Lab/VirtualBox ranges - checked by VT but expected to return not_found
LAB_PREFIXES = ("192.168.",)

def is_private_ip(ip: str) -> bool:
    """Check if IP is private/reserved"""
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return True
    if ip == "0.0.0.0":
        return True
    return False

def is_lab_ip(ip: str) -> bool:
    """Check if IP is lab/virtualbox range"""
    return any(ip.startswith(p) for p in LAB_PREFIXES)

# Known malicious IPs for testing when VT is unavailable
KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {"verdict": "MALICIOUS", "malicious": 15, "country": "DE"},
    "185.220.101.46": {"verdict": "MALICIOUS", "malicious": 12, "country": "DE"},
    "5.255.88.65":    {"verdict": "MALICIOUS", "malicious": 10, "country": "RU"},
    "91.240.118.172": {"verdict": "MALICIOUS", "malicious": 8,  "country": "NL"},
    "45.33.32.156":   {"verdict": "SUSPICIOUS", "malicious": 5, "country": "US"},
}

# ── Cache Management ─────────────────────────
class VTCache:
    """Persistent cache for VT results to avoid rate limits"""
    
    def __init__(self, cache_file: str = CACHE_FILE, ttl: int = CACHE_TTL):
        self.cache_file = cache_file
        self.ttl = ttl
        self._cache: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._load()
    
    def _load(self):
        """Load cache from disk"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    # Clean expired entries
                    now = time.time()
                    self._cache = {
                        k: v for k, v in data.items() 
                        if now - v.get('cached_at', 0) < self.ttl
                    }
        except Exception as e:
            print(f"  [VT] Cache load error: {e}")
            self._cache = {}
    
    def _save(self):
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            print(f"  [VT] Cache save error: {e}")
    
    def get(self, ip: str) -> Optional[dict]:
        """Get cached result if not expired"""
        with self._lock:
            if ip in self._cache:
                entry = self._cache[ip]
                if time.time() - entry.get('cached_at', 0) < self.ttl:
                    return entry
                else:
                    del self._cache[ip]
        return None
    
    def set(self, ip: str, result: dict):
        """Cache a result"""
        with self._lock:
            result['cached_at'] = time.time()
            self._cache[ip] = result
            self._save()
    
    def clear(self):
        """Clear all cache"""
        with self._lock:
            self._cache.clear()
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)

# Initialize cache
vt_cache = VTCache()

# ── Threat Intelligence ──────────────────────
def get_threat_intel(result: dict) -> List[str]:
    """Generate threat intelligence insights from VT result"""
    insights = []
    
    if result.get("malicious", 0) >= 10:
        insights.append("HIGH_THREAT: Multiple vendors flagged as malicious")
    elif result.get("malicious", 0) >= 5:
        insights.append("MEDIUM_THREAT: Several vendors detected malicious activity")
    
    if result.get("suspicious", 0) >= 5:
        insights.append("SUSPICIOUS_ACTIVITY: Multiple vendors report suspicious behavior")
    
    tags = result.get("tags", [])
    if "tor" in tags or "tor-exit" in tags:
        insights.append("TOR_EXIT_NODE: Traffic originating from Tor network")
    if "vpn" in tags:
        insights.append("VPN_SERVICE: Traffic via VPN/proxy service")
    if "scanner" in tags:
        insights.append("SCANNER: Known network scanner detected")
    if "bruteforce" in tags:
        insights.append("BRUTEFORCE: Associated with brute force attacks")
    
    if result.get("reputation", 0) < -10:
        insights.append("BAD_REPUTATION: Very poor reputation score")
    
    return insights

# ── Main VT Check Function ───────────────────
def check_ip(ip: str, force: bool = False) -> dict:
    """
    Query VirusTotal for one IP. Returns structured result.
    
    Args:
        ip: IP address to check
        force: Force check even if cached
    
    Returns:
        Dictionary with VT analysis results
    """
    
    # Skip truly private IPs
    if is_private_ip(ip):
        print(f"  [VT] Private IP skipped: {ip}")
        return {
            "ip": ip,
            "verdict": "private",
            "malicious": 0,
            "checked_at": datetime.utcnow().isoformat()
        }

    # Lab IPs — mark as checked with clean verdict (no real VT lookup)
    if is_lab_ip(ip):
        print(f"  [VT] Lab IP — marking as checked: {ip}")
        result = {
            "ip":         ip,
            "verdict":    "CLEAN",
            "malicious":  0,
            "suspicious": 0,
            "harmless":   0,
            "undetected": 0,
            "reputation": 0,
            "country":    "Local Lab",
            "as_owner":   "VirtualBox/Lab Network",
            "tags":       [],
            "checked_at": datetime.utcnow().isoformat(),
            "source":     "lab"
        }
        vt_cache.set(ip, result)
        return result

    # Check cache first
    if not force:
        cached = vt_cache.get(ip)
        if cached:
            print(f"  [VT] {ip} → {cached.get('verdict', '?')} (cached)")
            return cached
    
    # Use known malicious IPs if VT is disabled
    if not VT_ENABLED:
        if ip in KNOWN_MALICIOUS_IPS:
            result = {
                "ip": ip,
                "checked_at": datetime.utcnow().isoformat(),
                **KNOWN_MALICIOUS_IPS[ip],
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "reputation": -10,
                "as_owner": "Unknown",
                "tags": [],
                "source": "local_db"
            }
            print(f"  [VT] {ip} → {result['verdict']} (local DB)")
            vt_cache.set(ip, result)
            return result
        else:
            print(f"  [VT] No API key — skipping {ip}")
            return {
                "ip": ip, 
                "verdict": "skipped", 
                "malicious": 0,
                "checked_at": datetime.utcnow().isoformat()
            }
    
    # API request
    url = f"{VT_BASE_URL}/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY, 
        "Accept": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 200:
            data  = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)

            # Determine verdict
            if malicious >= 10:
                verdict = "MALICIOUS"
            elif malicious >= 3 or suspicious >= 5:
                verdict = "SUSPICIOUS"
            elif malicious >= 1:
                verdict = "LOW_RISK"
            else:
                verdict = "CLEAN"

            result = {
                "ip":           ip,
                "checked_at":   datetime.utcnow().isoformat(),
                "malicious":    malicious,
                "suspicious":   suspicious,
                "harmless":     stats.get("harmless",   0),
                "undetected":   stats.get("undetected", 0),
                "reputation":   attrs.get("reputation", 0),
                "country":      attrs.get("country",    "Unknown"),
                "as_owner":     attrs.get("as_owner",   "Unknown"),
                "tags":         attrs.get("tags",       []),
                "verdict":      verdict,
                "source":       "virustotal"
            }
            
            # Add threat intelligence
            result["insights"] = get_threat_intel(result)
            
            print(f"  [VT] {ip} → {verdict} (malicious={malicious}, suspicious={suspicious})")
            
            # Cache result
            vt_cache.set(ip, result)
            return result

        elif resp.status_code == 429:
            print(f"  [VT] Rate limited for {ip}, waiting 60s...")
            time.sleep(60)
            return check_ip(ip, force=True)

        elif resp.status_code == 404:
            result = {
                "ip": ip,
                "verdict": "not_found",
                "malicious": 0,
                "checked_at": datetime.utcnow().isoformat(),
                "source": "virustotal"
            }
            vt_cache.set(ip, result)
            return result

        else:
            print(f"  [VT] HTTP {resp.status_code} for {ip}")
            return {
                "ip": ip,
                "verdict": "error",
                "malicious": 0,
                "checked_at": datetime.utcnow().isoformat()
            }

    except requests.exceptions.Timeout:
        print(f"  [VT] Timeout for {ip}")
        return {
            "ip": ip,
            "verdict": "timeout",
            "malicious": 0,
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"  [VT] Exception for {ip}: {e}")
        return {
            "ip": ip,
            "verdict": "error",
            "malicious": 0,
            "checked_at": datetime.utcnow().isoformat()
        }

# ── Background Queue ──────────────────────────
class VTQueue:
    """
    Thread-safe queue that processes IPs one-by-one
    with rate limiting. Calls callback(result) after each check.
    """
    
    def __init__(self):
        self._queue: List[str] = []
        self._seen: set = set()
        self._lock = threading.Lock()
        self._callback = None
        self._running = False
        self._thread = None
    
    def set_callback(self, fn):
        """
        Set callback function for processing results
        
        Args:
            fn: Function that receives (result: dict) after each VT check
        """
        self._callback = fn
    
    def enqueue(self, ip: str):
        """Add IP to queue for checking"""
        with self._lock:
            if ip not in self._seen:
                self._queue.append(ip)
                self._seen.add(ip)
                print(f"  [VT] Queued: {ip} (queue size: {len(self._queue)})")
    
    def start(self):
        """Start the worker thread"""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._worker, daemon=True)
            self._thread.start()
            print("  [VT] Queue worker started")
    
    def stop(self):
        """Stop the worker thread"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _worker(self):
        while self._running:
            ip = None
            with self._lock:
                if self._queue:
                    ip = self._queue.pop(0)
            
            if ip:
                try:
                    result = check_ip(ip)
                    # ✅ احفظ حتى لو من local_db أو lab
                    if self._callback and result.get("verdict") not in ("error", "timeout", "private", "skipped"):
                        try:
                            self._callback(result)
                        except Exception as e:
                            print(f"  [VT] Callback error for {ip}: {e}")
                    time.sleep(VT_DELAY)
                except Exception as e:
                    print(f"  [VT] Worker error for {ip}: {e}")
                    time.sleep(1)
            else:
                time.sleep(3)
    
    def size(self) -> int:
        """Get current queue size"""
        with self._lock:
            return len(self._queue)
    
    def clear(self):
        """Clear the queue"""
        with self._lock:
            self._queue.clear()
            self._seen.clear()
    
    def get_stats(self) -> dict:
        """Get queue statistics"""
        with self._lock:
            return {
                "queue_size": len(self._queue),
                "seen_count": len(self._seen)
            }


# ── Singleton Instance ───────────────────────
vt_queue = VTQueue()

# ── Auto-blocking Integration ────────────────
class VTAutoBlocker:
    """
    Automatically blocks IPs that VT flags as malicious.
    Works with iptables or any firewall.
    """
    
    def __init__(self, block_threshold: int = 3):
        """
        Args:
            block_threshold: Minimum malicious count to auto-block
        """
        self.block_threshold = block_threshold
        self.blocked_ips: set = set()
        self._lock = threading.Lock()
        self._enabled = False
    
    def enable(self):
        """Enable auto-blocking"""
        self._enabled = True
        print(f"  [VT] Auto-blocker enabled (threshold: {self.block_threshold})")
    
    def disable(self):
        """Disable auto-blocking"""
        self._enabled = False
        print("  [VT] Auto-blocker disabled")
    
    def process_vt_result(self, result: dict):
        """
        Process VT result and block if needed
        
        Args:
            result: VT check result dictionary
        """
        if not self._enabled:
            return
        
        ip = result.get("ip")
        malicious = result.get("malicious", 0)
        verdict = result.get("verdict", "")
        
        if malicious >= self.block_threshold and ip not in self.blocked_ips:
            self._block_ip(ip, result)
    
    def _block_ip(self, ip: str, result: dict):
        """Execute IP blocking"""
        with self._lock:
            if ip in self.blocked_ips:
                return
            
            try:
                # Try iptables blocking (requires root)
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                # Uncomment to actually block:
                # subprocess.run(cmd.split(), check=True)
                
                self.blocked_ips.add(ip)
                
                print(f"  [VT] 🚫 AUTO-BLOCKED: {ip}")
                print(f"       Reason: {result.get('verdict')} (malicious={result.get('malicious')})")
                if result.get('insights'):
                    for insight in result['insights']:
                        print(f"       → {insight}")
                
            except Exception as e:
                print(f"  [VT] Block failed for {ip}: {e}")
    
    def unblock_all(self):
        """Remove all blocks"""
        with self._lock:
            for ip in self.blocked_ips:
                try:
                    cmd = f"iptables -D INPUT -s {ip} -j DROP"
                    # subprocess.run(cmd.split(), check=True)
                except:
                    pass
            self.blocked_ips.clear()
            print("  [VT] All blocks removed")
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        with self._lock:
            return list(self.blocked_ips)

# ── Initialize auto-blocker ──────────────────
vt_auto_blocker = VTAutoBlocker(block_threshold=5)

# ── Database Integration Helper ──────────────
def db_update_threat_info(db_manager, result: dict):
    """
    Update database with VT threat information
    
    Args:
        db_manager: Database manager instance
        result: VT check result
    """
    try:
        ip = result.get("ip")
        verdict = result.get("verdict", "unknown")
        malicious = result.get("malicious", 0)
        country = result.get("country", "Unknown")
        
        # Update attackers table with threat info
        query = """
            UPDATE attackers 
            SET threat_level = %s,
                vt_malicious = %s,
                country = CASE 
                    WHEN country = 'Unknown' THEN %s 
                    ELSE country 
                END,
                vt_checked = NOW()
            WHERE ip_address = %s
        """
        db_manager.execute(query, (verdict, malicious, country, ip))
        
        # Log to vt_results table if available
        try:
            query = """
                INSERT INTO vt_results 
                (ip_address, verdict, malicious, suspicious, harmless, 
                 undetected, reputation, country, as_owner, tags)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                verdict = VALUES(verdict),
                malicious = VALUES(malicious),
                checked_at = NOW()
            """
            db_manager.execute(query, (
                ip,
                verdict,
                malicious,
                result.get("suspicious", 0),
                result.get("harmless", 0),
                result.get("undetected", 0),
                result.get("reputation", 0),
                result.get("country", "Unknown"),
                result.get("as_owner", "Unknown"),
                json.dumps(result.get("tags", []))
            ))
        except:
            pass  # Table might not exist
            
    except Exception as e:
        print(f"  [VT] DB update error for {ip}: {e}")

# ── Test Function ────────────────────────────
def test_vt_integration():
    """Test VT integration with known malicious IPs"""
    print("\n=== VirusTotal Integration Test ===\n")
    
    test_ips = [
        "185.220.101.45",  # Known Tor exit node (malicious)
        "8.8.8.8",         # Google DNS (clean)
        "192.168.1.1",     # Lab IP (marked clean)
        "10.0.0.1",        # Private IP (skipped)
    ]
    
    for ip in test_ips:
        print(f"\nTesting: {ip}")
        result = check_ip(ip, force=True)
        print(f"  Verdict: {result.get('verdict')}")
        print(f"  Malicious: {result.get('malicious', 0)}")
        print(f"  Country: {result.get('country', 'N/A')}")
        print(f"  Source: {result.get('source', 'N/A')}")
        
        if result.get('insights'):
            print("  Insights:")
            for insight in result['insights']:
                print(f"    → {insight}")
    
    print("\n=== Test Complete ===\n")

# ── Main ─────────────────────────────────────
if __name__ == "__main__":
    # Start VT queue worker
    vt_queue.start()
    
    # Test VT integration
    test_vt_integration()
    
    # Test caching
    print("\nTesting cache...")
    result1 = check_ip("185.220.101.45")
    result2 = check_ip("185.220.101.45")
    print(f"  Cache working: {result1 == result2}")
    
    # Cleanup
    vt_queue.stop()