"""Verbindungsanalyse aus Syslog-Firewall-Logs: Netzwerkplan, Einstufung, Regel-Vorlagen, Syslog-Absender."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from .. import config, settings, sync, template_plan
from ..audit import audit
from ..db import get_db
from ..flows import analysis
from ..i18n import tr
from ..models import ChangeTemplate, Firewall, FlowBucket, SyslogSender, User
from ..permissions import firewall_or_404, require_global
from ..security import client_ip, get_current_user
from ..sophos import entities

router = APIRouter(prefix="/api", tags=["flows"])
admin_only = require_global("admin")


def _range(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    end = end or datetime.now(timezone.utc)
    start = start or end - timedelta(hours=24)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if start >= end:
        raise HTTPException(400, tr('Der Beginn muss vor dem Ende liegen'))
    if end - start > timedelta(days=366):
        raise HTTPException(400, tr('Zeitraum höchstens ein Jahr'))
    return start, end


@router.get("/firewalls/{firewall_id}/flows")
def get_flows(firewall_id: str, start: datetime | None = None, end: datetime | None = None, level: str = "host",
              user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    if level not in analysis.LEVELS:
        raise HTTPException(400, tr('Ebene muss host oder net sein'))
    start, end = _range(start, end)
    result = analysis.query(db, fw.id, start, end, level, sync.cached_config(db, fw))
    last = db.execute(select(func.max(FlowBucket.last_seen)).where(FlowBucket.firewall_id == fw.id)).scalar()
    senders = [s.ip for s in db.execute(select(SyslogSender).where(SyslogSender.firewall_id == fw.id)).scalars()]
    return {**result, "start": start, "end": end, "level": level, "last_received": last, "senders": senders,
            "receiver_port": config.SYSLOG_PUBLIC_PORT if config.SYSLOG_LISTEN_PORT else 0, "enabled": bool(settings.get(db, "flows_enabled")),
            "rule_prefix": settings.get(db, "flows_rule_prefix")}


class FlowRef(BaseModel):
    src: str = Field(max_length=50)
    dst: str = Field(max_length=50)
    protocol: str = Field(max_length=12)
    dst_port: int = 0


class DecisionIn(BaseModel):
    items: list[FlowRef] = Field(min_length=1, max_length=5000)
    verdict: str | None = None                    # legit | illegit | None (Einstufung entfernen)
    note: str = Field(default="", max_length=2000)


@router.post("/firewalls/{firewall_id}/flows/decisions")
def set_decisions(firewall_id: str, body: DecisionIn, request: Request, user: User = Depends(get_current_user),
                  db: DbSession = Depends(get_db)):
    """Verbindungen einstufen – Grundlage für Regeln, daher mit dem Recht „Beantragen“."""
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    if body.verdict not in ("legit", "illegit", None):
        raise HTTPException(400, tr('Einstufung muss legit oder illegit sein'))
    try:
        n = analysis.decide(db, fw.id, user.id, [i.model_dump() for i in body.items], body.verdict, body.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(db, "flows.classified", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "verdict": body.verdict or "reset", "connections": n, "note": body.note[:300],
                   "examples": [f"{i.src} → {i.dst} {i.protocol}/{i.dst_port}" for i in body.items[:10]]})
    return {"updated": n}


class TemplateFromFlowsIn(BaseModel):
    start: datetime
    end: datetime
    level: str = "host"
    name: str = Field(default="", max_length=200)
    prefix: str | None = Field(default=None, max_length=20)
    include_allow: bool = True
    include_deny: bool = True
    log_traffic: bool = True
    position: str = "top"
    per_connection: bool = False
    preview: bool = False


@router.post("/firewalls/{firewall_id}/flows/template")
def template_from_flows(firewall_id: str, body: TemplateFromFlowsIn, request: Request,
                        user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Regeln (und fehlende Objekte) aus den eingestuften Verbindungen des Zeitraums als Vorlage.
    Ausgerollt wird die Vorlage wie jede andere: als Antrag mit Vier-Augen-Prinzip."""
    import re
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    if not fw.last_sync_at:
        raise HTTPException(409, tr('„{0}“ wurde noch nie synchronisiert', fw.name))
    prefix = (body.prefix if body.prefix is not None else settings.get(db, "flows_rule_prefix")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{0,20}", prefix):
        raise HTTPException(400, tr('Präfix: nur Buchstaben, Ziffern, _ . - (höchstens 20 Zeichen)'))
    start, end = _range(body.start, body.end)
    if body.level not in analysis.LEVELS:
        raise HTTPException(400, tr('Ebene muss host oder net sein'))
    cfg = sync.cached_config(db, fw)
    fmt = entities.fmt_for(fw.connector)
    edges = analysis.query(db, fw.id, start, end, body.level, cfg)["edges"]
    items, notes, counts = analysis.build_template_items(
        edges, cfg, fmt, prefix=prefix, include_allow=body.include_allow, include_deny=body.include_deny,
        log_traffic=body.log_traffic, position=body.position, per_connection=body.per_connection)
    summary = [{"entity": i["entity"], "label": entities.LABELS.get(i["entity"], i["entity"]), "name": i["name"]}
               for i in items]
    if body.preview:
        return {"items": summary, "notes": notes, "counts": counts}
    if not counts["rules"]:
        raise HTTPException(400, tr('Keine eingestuften Verbindungen im Zeitraum – erst Verbindungen als legitim bzw. nicht legitim einstufen'))
    name = body.name.strip() or tr('{0}Verbindungen {1} {2:%Y-%m-%d}', prefix, fw.name, end)
    if db.execute(select(ChangeTemplate).where(ChangeTemplate.name == name)).scalar():
        raise HTTPException(409, tr('Eine Vorlage mit diesem Namen existiert bereits'))
    template_plan.validate_items(fmt, items)
    desc = tr('Aus der Verbindungsanalyse von „{0}“, {1:%d.%m.%Y %H:%M} – {2:%d.%m.%Y %H:%M} (UTC): {3} Allow-, {4} Drop-Regeln.',
              fw.name, start, end, counts["allow"], counts["deny"])
    t = ChangeTemplate(name=name, description=desc, operations=items, format=fmt, created_by=user.id)
    db.add(t)
    db.flush()
    audit(db, "template.created", actor=user, target_type="template", target_id=t.id, ip=client_ip(request),
          details={"name": t.name, "format": fmt, "items": len(items), "from_flows": fw.name, "prefix": prefix,
                   "rules": counts["rules"], "range": [start.isoformat(), end.isoformat()]})
    return {"id": t.id, "name": t.name, "items": summary, "notes": notes, "counts": counts}


# --- Syslog-Absender (Administration) ------------------------------------------------------------------------

def _sender_out(s: SyslogSender, fws: dict[str, str]) -> dict:
    return {"ip": s.ip, "firewall_id": s.firewall_id, "firewall": fws.get(s.firewall_id or ""), "serial": s.serial,
            "device_name": s.device_name, "messages": s.messages, "ignored": s.ignored, "first_seen": s.first_seen,
            "last_seen": s.last_seen, "sample": s.sample}


@router.get("/flows/senders")
def list_senders(_: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    fws = {f.id: f.name for f in db.execute(select(Firewall).where(Firewall.archived.is_(False))).scalars()}
    rows = db.execute(select(SyslogSender).order_by(SyslogSender.last_seen.desc())).scalars()
    return {"senders": [_sender_out(s, fws) for s in rows],
            "receiver_port": config.SYSLOG_PUBLIC_PORT if config.SYSLOG_LISTEN_PORT else 0}


class SenderIn(BaseModel):
    firewall_id: str | None = None


@router.put("/flows/senders/{ip}")
def assign_sender(ip: str, body: SenderIn, request: Request, actor: User = Depends(admin_only),
                  db: DbSession = Depends(get_db)):
    s = db.get(SyslogSender, ip)
    if not s:
        raise HTTPException(404, tr('Absender nicht gefunden'))
    fw = db.get(Firewall, body.firewall_id) if body.firewall_id else None
    if body.firewall_id and (not fw or fw.archived):
        raise HTTPException(404, tr('Firewall nicht gefunden'))
    s.firewall_id = fw.id if fw else None
    # Seriennummer aus dem Log übernehmen, falls die Anbindung sie nicht liefert (REST) – dann greift die
    # automatische Zuordnung auch für weitere Absender derselben Firewall (z. B. HA-Partner)
    if fw and not fw.serial and s.serial:
        fw.serial = s.serial
    audit(db, "flows.sender_assigned", actor=actor, target_type="syslog_sender", target_id=ip, ip=client_ip(request),
          details={"sender": ip, "firewall": fw.name if fw else None, "serial": s.serial})
    from ..flows.receiver import collector
    collector._map_loaded = 0
    return {"ok": True}


@router.delete("/flows/senders/{ip}")
def delete_sender(ip: str, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    s = db.get(SyslogSender, ip)
    if not s:
        raise HTTPException(404, tr('Absender nicht gefunden'))
    db.delete(s)
    audit(db, "flows.sender_deleted", actor=actor, target_type="syslog_sender", target_id=ip, ip=client_ip(request),
          details={"sender": ip})
    return {"ok": True}
