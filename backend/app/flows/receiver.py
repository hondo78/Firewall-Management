"""Syslog-Empfang der Sophos-Firewall-Logs (UDP und TCP) und Zusammenfassung zu Verbindungen.

SFOS sendet Logs als Schlüssel=Wert-Paare, je nach Version etwa
  device_name="SFW" … device_serial_id="X2100…" log_type="Firewall" log_component="Firewall Rule"
  log_subtype="Allowed" fw_rule_id="5" fw_rule_name="LAN nach Internet" src_zone="LAN" dst_zone="WAN"
  src_ip="192.168.10.20" dst_ip="8.8.8.8" protocol="UDP" src_port=53211 dst_port=53 bytes_sent=80 bytes_received=120
(ältere Versionen: device_id=…, status="Allow", sent_bytes/recv_bytes). Ausgewertet werden nur Firewall-Logs mit
Quell- und Ziel-IP. Gespeichert werden keine Rohlogs, sondern stündliche Summen je Verbindung (FlowBucket).

Zuordnung zur Firewall: über die Absender-IP (SyslogSender); ein noch unbekannter Absender wird automatisch
zugeordnet, wenn die Seriennummer im Log zu einer Firewall passt. Sonst wartet er auf die Zuordnung durch einen Admin.
"""
import logging
import re
import socket
import socketserver
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .. import config, settings
from ..db import SessionLocal
from ..models import Firewall, FlowBucket, SyslogSender, utcnow

log = logging.getLogger("fwm.flows")

_PAIR = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')
_PROTO = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPV6", "47": "GRE", "50": "ESP"}
_DENY = ("denied", "deny", "drop", "dropped", "reject", "rejected", "invalid")


def parse(line: str) -> dict:
    """Schlüssel=Wert-Paare einer Logzeile (Anführungszeichen entfernt)."""
    out = {}
    for k, v in _PAIR.findall(line):
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1].replace('\\"', '"')
        out[k.lower()] = v
    return out


def _int(v) -> int:
    try:
        return int(str(v).strip() or 0)
    except ValueError:
        return 0


def flow_of(kv: dict) -> dict | None:
    """Verbindung aus einem Firewall-Log oder None (anderer Logtyp, unvollständig)."""
    if (kv.get("log_type") or "").lower() != "firewall":
        return None
    src, dst = kv.get("src_ip") or "", kv.get("dst_ip") or ""
    if not src or not dst:
        return None
    proto = (kv.get("protocol") or "").upper()
    proto = _PROTO.get(proto, proto)[:12] or "?"
    port = _int(kv.get("dst_port")) if proto in ("TCP", "UDP") else 0
    status = f"{kv.get('log_subtype', '')} {kv.get('status', '')}".lower()
    action = "deny" if any(w in status for w in _DENY) else "allow"
    sent = _int(kv.get("bytes_sent") or kv.get("sent_bytes"))
    recv = _int(kv.get("bytes_received") or kv.get("recv_bytes"))
    return {"src_ip": src[:45], "dst_ip": dst[:45], "protocol": proto, "dst_port": port,
            "src_zone": (kv.get("src_zone") or "")[:60], "dst_zone": (kv.get("dst_zone") or "")[:60],
            "action": action, "rule_id": (kv.get("fw_rule_id") or "")[:20],
            "rule_name": (kv.get("fw_rule_name") or kv.get("policy_name") or "")[:200], "bytes": sent + recv}


# --- Sammeln und regelmäßig schreiben ------------------------------------------------------------------------

_KEY = ("src_ip", "dst_ip", "protocol", "dst_port", "src_zone", "dst_zone", "action", "rule_id")


class Collector:
    """Summiert Verbindungen im Speicher und schreibt sie alle FLOW_FLUSH_SECONDS gebündelt in die Datenbank."""

    def __init__(self):
        self.lock = threading.Lock()
        self.flows: dict[tuple, dict] = {}
        self.senders: dict[str, dict] = {}
        self._sender_map: dict[str, str | None] = {}
        self._serials: dict[str, str] = {}
        self._map_loaded = 0.0
        self.enabled = True

    # Zuordnung Absender → Firewall (alle 30 s neu laden, damit Zuordnungen aus der Oberfläche greifen)
    def _refresh_map(self) -> None:
        if time.time() - self._map_loaded < 30:
            return
        with SessionLocal() as db:
            self._sender_map = {s.ip: s.firewall_id for s in db.execute(select(SyslogSender)).scalars()}
            self._serials = {f.serial.upper(): f.id for f in db.execute(
                select(Firewall).where(Firewall.archived.is_(False), Firewall.serial != "")).scalars()}
            self.enabled = bool(settings.get(db, "flows_enabled"))
        self._map_loaded = time.time()

    def feed(self, sender_ip: str, line: str, now: datetime | None = None) -> None:
        now = now or utcnow()
        kv = parse(line)
        with self.lock:
            self._refresh_map()
            serial = (kv.get("device_serial_id") or kv.get("device_id") or "").upper()
            fw_id = self._sender_map.get(sender_ip)
            if fw_id is None and serial in self._serials:
                fw_id = self._serials[serial]
            s = self.senders.setdefault(sender_ip, {"messages": 0, "ignored": 0, "serial": "", "device": "",
                                                    "sample": "", "fw": None, "first": now, "last": now})
            s["messages"] += 1
            s["last"] = now
            s["serial"] = serial or s["serial"]
            s["device"] = kv.get("device_name") or kv.get("device") or s["device"]
            if fw_id:
                s["fw"] = fw_id
            flow = flow_of(kv) if self.enabled else None
            if not fw_id or flow is None:
                s["ignored"] += 1
                if not s["sample"] and (kv.get("log_type") or "").lower() == "firewall":
                    s["sample"] = line[:2000]
                return
            hour = now.replace(minute=0, second=0, microsecond=0)
            key = (fw_id, hour) + tuple(flow[k] for k in _KEY)
            agg = self.flows.get(key)
            if agg is None:
                self.flows[key] = {"count": 1, "bytes": flow["bytes"], "first": now, "last": now,
                                   "rule_name": flow["rule_name"]}
            else:
                agg["count"] += 1
                agg["bytes"] += flow["bytes"]
                agg["last"] = now
                agg["rule_name"] = flow["rule_name"] or agg["rule_name"]

    def flush(self) -> int:
        with self.lock:
            flows, senders = self.flows, self.senders
            self.flows, self.senders = {}, {}
        if not flows and not senders:
            return 0
        with SessionLocal() as db:
            for key, agg in flows.items():
                _upsert_bucket(db, key, agg)
            for ip, s in senders.items():
                row = db.get(SyslogSender, ip)
                if row is None:
                    row = SyslogSender(ip=ip, messages=0, ignored=0, first_seen=s["first"])
                    db.add(row)
                row.messages = (row.messages or 0) + s["messages"]
                row.ignored = (row.ignored or 0) + s["ignored"]
                row.last_seen = s["last"]
                row.serial = s["serial"] or row.serial or ""
                row.device_name = (s["device"] or row.device_name or "")[:200]
                if s["sample"] and not row.sample:
                    row.sample = s["sample"]
                if row.firewall_id is None and s["fw"]:
                    row.firewall_id = s["fw"]          # automatisch über die Seriennummer zugeordnet
            db.commit()
        with self.lock:
            self._map_loaded = 0                      # neue Zuordnungen sofort nutzen
        return len(flows)


def _upsert_bucket(db, key: tuple, agg: dict) -> None:
    fw_id, hour, src, dst, proto, port, sz, dz, action, rule = key
    row = db.execute(select(FlowBucket).where(
        FlowBucket.firewall_id == fw_id, FlowBucket.hour == hour, FlowBucket.src_ip == src, FlowBucket.dst_ip == dst,
        FlowBucket.protocol == proto, FlowBucket.dst_port == port, FlowBucket.src_zone == sz, FlowBucket.dst_zone == dz,
        FlowBucket.action == action, FlowBucket.rule_id == rule)).scalar()
    if row is None:
        db.add(FlowBucket(firewall_id=fw_id, hour=hour, src_ip=src, dst_ip=dst, protocol=proto, dst_port=port,
                          src_zone=sz, dst_zone=dz, action=action, rule_id=rule, rule_name=agg["rule_name"],
                          count=agg["count"], bytes=agg["bytes"], first_seen=agg["first"], last_seen=agg["last"]))
        db.flush()
        return
    row.count += agg["count"]
    row.bytes += agg["bytes"]
    row.last_seen = max(row.last_seen, agg["last"])
    row.rule_name = agg["rule_name"] or row.rule_name


collector = Collector()


# --- Netzwerk ------------------------------------------------------------------------------------------------

def _lines(data: bytes) -> list[str]:
    text = data.decode("utf-8", errors="replace")
    out = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip().lstrip("\x00")
        # TCP mit Octet-Counting (RFC 6587): „123 <134>…“
        m = re.match(r"^\d+ (<\d+>.*)$", line)
        if m:
            line = m.group(1)
        if line:
            out.append(line)
    return out


def _udp_loop(sock: socket.socket, stop: threading.Event) -> None:
    """Ein Thread, der Datagramme direkt verarbeitet – ein Thread je Paket wäre bei Lastspitzen zu langsam,
    der Kernel-Puffer liefe über und Logs gingen verloren."""
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, (ip, _) = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            for line in _lines(data):
                collector.feed(ip, line)
        except Exception:
            log.exception("Syslog-Nachricht von %s nicht verarbeitet", ip)


class _UdpServer:
    """Schnittstelle wie socketserver (shutdown), damit lifespan beide Empfänger gleich behandelt."""
    def __init__(self, port: int, stop: threading.Event):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        self.sock.bind(("0.0.0.0", port))
        self.stop = stop

    def serve_forever(self):
        _udp_loop(self.sock, self.stop)

    def shutdown(self):
        self.stop.set()
        self.sock.close()


class _TCP(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(300)
        try:
            for raw in self.rfile:
                for line in _lines(raw):
                    collector.feed(self.client_address[0], line)
        except (OSError, socket.timeout):
            pass


class _ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _flush_forever(stop: threading.Event) -> None:
    while not stop.wait(config.FLOW_FLUSH_SECONDS):
        try:
            collector.flush()
        except Exception:
            log.exception("Verbindungen konnten nicht gespeichert werden")


def start(stop: threading.Event) -> list:
    """UDP- und TCP-Empfänger plus Schreib-Thread starten (Port SYSLOG_LISTEN_PORT, 0 = aus)."""
    port = config.SYSLOG_LISTEN_PORT
    if not port:
        return []
    servers = []
    for name in ("udp", "tcp"):
        try:
            srv = _UdpServer(port, stop) if name == "udp" else _ThreadingTCP(("0.0.0.0", port), _TCP)
        except OSError as e:
            log.error("Syslog-Empfang (%s/%s) nicht möglich: %s", port, name, e)
            continue
        threading.Thread(target=srv.serve_forever, daemon=True, name=f"syslog-{name}").start()
        servers.append(srv)
        log.info("Syslog-Empfang aktiv auf Port %s/%s", port, name)
    threading.Thread(target=_flush_forever, args=(stop,), daemon=True, name="flow-flush").start()
    return servers


def cleanup() -> int:
    """Zusammengefasste Verbindungen älter als flows_retention_days löschen (Worker)."""
    from sqlalchemy import delete
    with SessionLocal() as db:
        days = int(settings.get(db, "flows_retention_days"))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        n = db.execute(delete(FlowBucket).where(FlowBucket.hour < cutoff)).rowcount
        db.commit()
    return n or 0
