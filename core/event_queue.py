"""
HoneyTrack - Shared Event Queue
--------------------------------
Central message bus used by all modules.
SSH/HTTP honeypots push events here.
The pipeline worker reads and processes them.
"""

import threading
from datetime import datetime

_queue = []
_lock  = threading.Lock()


def push(event: dict):
    """Called by SSH/HTTP honeypot when an event happens"""
    event.setdefault("timestamp", datetime.utcnow().isoformat())
    with _lock:
        _queue.append(event)


def pop_all() -> list:
    """Called by pipeline worker every N seconds"""
    with _lock:
        events = list(_queue)
        _queue.clear()
        return events


def size() -> int:
    with _lock:
        return len(_queue)
