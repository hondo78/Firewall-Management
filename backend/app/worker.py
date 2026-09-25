"""Hintergrund-Worker: genehmigte Anträge ausrollen, Firewalls und Central-Inventar periodisch synchronisieren."""
import asyncio
import logging
import threading
from datetime import timedelta

from sqlalchemy import or_, select

from . import changes, config, notify, settings, sync
from .db import SessionLocal
from .models import CentralAccount, ChangeRequest, Firewall, User, utcnow
from .sophos import connector
from .sophos.central import CentralError

log = logging.getLogger("fwm.worker")


def deploy_in_background(change_id: str, actor_id: str | None) -> None:
    def run():
        with SessionLocal() as db:
            actor = db.get(User, actor_id) if actor_id else None
            changes.deploy(db, change_id, actor)
    threading.Thread(target=run, name=f"deploy-{change_id[:8]}", daemon=True).start()


def _deploy_due() -> None:
    with SessionLocal() as db:
        if not settings.get(db, "auto_deploy"):
            return
        now = utcnow()
        ids = db.execute(select(ChangeRequest.id).where(
            ChangeRequest.status == "approved",
            or_(ChangeRequest.deploy_after.is_(None), ChangeRequest.deploy_after <= now),
        ).order_by(ChangeRequest.number)).scalars().all()
    for cid in ids:
        with SessionLocal() as db:
            if changes.claim_for_deploy(db, cid):
                changes.deploy(db, cid)


def _expire_due() -> None:
    """Befristete Anträge nach Ablauf zurücknehmen (Rücknahme wird je nach Einstellung vorab genehmigt)."""
    with SessionLocal() as db:
        ids = db.execute(select(ChangeRequest.id).where(
            ChangeRequest.status == "deployed", ChangeRequest.expires_at.is_not(None),
            ChangeRequest.expires_at <= utcnow(), ChangeRequest.expiry_state == "")).scalars().all()
    for cid in ids:
        with SessionLocal() as db:
            cr = db.get(ChangeRequest, cid)
            rev = changes.expire(db, cr)
            if rev:
                log.info("Befristung von CR-%04d abgelaufen – Rücknahme CR-%04d angelegt", cr.number, rev.number)


def _sync_due() -> None:
    with SessionLocal() as db:
        minutes = int(settings.get(db, "sync_interval_minutes"))
        if minutes <= 0:
            return
        cutoff = utcnow() - timedelta(minutes=minutes)
        busy = set(db.execute(select(ChangeRequest.firewall_id).where(ChangeRequest.status == "deploying")).scalars())
        acc_ids = db.execute(select(CentralAccount.id).where(
            or_(CentralAccount.last_sync_at.is_(None), CentralAccount.last_sync_at < cutoff))).scalars().all()
        fw_ids = db.execute(select(Firewall.id).where(
            Firewall.archived.is_(False),
            or_(Firewall.last_sync_at.is_(None), Firewall.last_sync_at < cutoff))).scalars().all()
    for aid in acc_ids:
        with SessionLocal() as db:
            acc = db.get(CentralAccount, aid)
            try:
                sync.sync_central_inventory(db, acc)
            except CentralError as e:
                log.warning("Central-Konto %s: %s", acc.name, e)
                acc.last_sync_at = utcnow()  # nicht bei jedem Durchlauf erneut versuchen
                db.commit()
    for fid in fw_ids:
        if fid in busy:
            continue
        with SessionLocal() as db:
            fw = db.get(Firewall, fid)
            try:
                sync.sync_firewall(db, fw)
            except connector.ConnectorError as e:
                log.warning("Synchronisation von %s fehlgeschlagen: %s", fw.name, e)
                fw.last_sync_at = utcnow()
                db.commit()


def _recover_stuck() -> None:
    """Nach einem Neustart hängen gebliebene Ausrollvorgänge als fehlgeschlagen markieren."""
    with SessionLocal() as db:
        for cr in db.execute(select(ChangeRequest).where(ChangeRequest.status == "deploying")).scalars():
            cr.status = "failed"
            cr.error = "Ausrollen durch Neustart des Dienstes unterbrochen – Stand auf der Firewall prüfen"
            changes.event(db, cr, "failed", cr.error)
        db.commit()


async def run_forever() -> None:
    await asyncio.to_thread(_recover_stuck)
    stop = threading.Event()
    threading.Thread(target=notify.run_telegram_forever, args=(stop,), daemon=True, name="telegram").start()
    while True:
        for step in (_expire_due, _deploy_due, _sync_due, notify.check_reminders):
            try:
                await asyncio.to_thread(step)
            except Exception:
                log.exception("Worker-Schritt %s fehlgeschlagen", step.__name__)
        await asyncio.sleep(config.WORKER_INTERVAL_SECONDS)
