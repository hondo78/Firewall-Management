"""Weiterleitung von Audit-Ereignissen als RFC-5424-Syslog (UDP oder TCP mit Octet-Counting)."""
import json
import logging
import socket
from datetime import datetime

from . import config

log = logging.getLogger("fwm.syslog")
_HOSTNAME = socket.gethostname()
# facility authpriv (10), severity notice (5)
_PRI = 10 * 8 + 5


def format_message(ts: datetime, action: str, payload: dict) -> str:
    msg = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return f"<{_PRI}>1 {ts.isoformat()} {_HOSTNAME} {config.SYSLOG_APP_NAME} - {action[:32]} - {msg}"


def send(ts: datetime, action: str, payload: dict) -> None:
    if not config.SYSLOG_HOST:
        return
    data = format_message(ts, action, payload).encode()
    try:
        if config.SYSLOG_PROTOCOL == "tcp":
            with socket.create_connection((config.SYSLOG_HOST, config.SYSLOG_PORT), timeout=3) as s:
                s.sendall(f"{len(data)} ".encode() + data)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, (config.SYSLOG_HOST, config.SYSLOG_PORT))
    except OSError as e:
        log.warning("Syslog-Versand an %s:%s fehlgeschlagen: %s", config.SYSLOG_HOST, config.SYSLOG_PORT, e)
