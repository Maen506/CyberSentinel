"""
HoneyTrack - SSH Honeypot
--------------------------
Emulates an SSH server on port 2222.
Captures brute-force attempts and commands.
Pushes events to the shared queue.
"""

import socket
import threading
import paramiko
import logging
import json
import os
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler

from core.event_queue import push

# ── Logging ───────────────────────────────────
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("ssh_honeypot")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = RotatingFileHandler(LOG_DIR / "ssh.log", maxBytes=5*1024*1024, backupCount=3)
    h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(h)

# ── Host Key ──────────────────────────────────
KEY_PATH = Path(__file__).parent / "host.key"

def _get_host_key():
    if not KEY_PATH.exists():
        paramiko.RSAKey.generate(2048).write_private_key_file(str(KEY_PATH))
    return paramiko.RSAKey(filename=str(KEY_PATH))


# ── Fake SSH Server ───────────────────────────
class _FakeSSH(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        event = {
            "type":     "ssh_auth",
            "src_ip":   self.ip,
            "username": username,
            "password": password,
        }
        push(event)
        logger.info(json.dumps(event))
        print(f"  [SSH] {self.ip}  {username}:{password}")
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


# ── Client Handler ────────────────────────────
def _handle(sock, ip):
    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.add_server_key(_get_host_key())
        server = _FakeSSH(ip)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if not chan:
            return

        chan.send(b"\r\nUbuntu 22.04.2 LTS\r\n$ ")
        buf = b""
        chan.settimeout(15)
        commands = []

        try:
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data
                chan.send(data)
                if b"\n" in buf or b"\r" in buf:
                    cmd = buf.strip().decode(errors="ignore")
                    if cmd:
                        commands.append(cmd)
                        event = {"type": "ssh_command", "src_ip": ip, "command": cmd}
                        push(event)
                        print(f"  [SSH CMD] {ip}: {cmd}")
                        chan.send(b"\r\ncommand not found\r\n$ ")
                    buf = b""
        except Exception:
            pass

        if commands:
            push({"type": "ssh_session_end", "src_ip": ip,
                  "commands": commands, "count": len(commands)})
        chan.close()

    except Exception as e:
        pass
    finally:
        if transport:
            transport.close()
        sock.close()


# ── Main Listener ─────────────────────────────
def start(host="0.0.0.0", port=2222):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    print(f"  [SSH] Listening on {host}:{port}")

    while True:
        try:
            sock, addr = srv.accept()
            threading.Thread(target=_handle, args=(sock, addr[0]), daemon=True).start()
        except Exception:
            break
    srv.close()
