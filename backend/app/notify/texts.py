"""Nachrichtentexte für alle Kanäle – mit tr() übersetzt (Sprache setzt notify.deliver je Empfänger)."""
from ..i18n import tr
from ..models import ChangeRequest

# Schlüssel bleiben deutsch; übersetzt wird beim Erzeugen der Nachricht
STATUS = {"pending": "wartet auf Genehmigung", "approved": "genehmigt", "rejected": "abgelehnt",
          "deployed": "ausgerollt", "failed": "fehlgeschlagen", "conflict": "Konflikt – nicht ausgerollt",
          "withdrawn": "zurückgezogen"}

SUBJECT = {
    "pending": "Genehmigung benötigt",
    "approved": "Antrag genehmigt",
    "rejected": "Antrag abgelehnt",
    "deployed": "Änderung ausgerollt",
    "failed": "Ausrollen fehlgeschlagen",
    "conflict": "Konflikt beim Ausrollen",
    "expiry_soon": "Befristung läuft bald ab",
    "expiry_failed": "Automatische Rücknahme fehlgeschlagen",
}
ACTION = {"add": "Neu", "update": "Ändern", "remove": "Löschen"}


def cr_no(cr: ChangeRequest) -> str:
    return f"CR-{cr.number:04d}"


def link(public_url: str, cr: ChangeRequest) -> str:
    return f"{public_url}/changes/{cr.id}" if public_url else ""


def change_lines(cr: ChangeRequest, kind: str) -> list[str]:
    from sqlalchemy import select
    from sqlalchemy.orm import object_session
    from ..sophos import entities
    fws = cr.firewall.name
    if cr.batch_id:
        members = object_session(cr).execute(select(ChangeRequest).where(
            ChangeRequest.batch_id == cr.batch_id)).scalars().all()
        fws = ", ".join(m.firewall.name for m in members) + tr(' (Sammelantrag, {0} Firewalls)', len(members))
    lines = [f"{cr_no(cr)} · {cr.title}", tr('Firewall: {0}', fws),
             tr('Antragsteller: {0}', cr.creator.username if cr.creator else tr('System'))]
    if kind == "pending":
        lines.append(tr('Begründung: {0}', cr.justification))
        if cr.expires_at:
            lines.append(tr('Befristet bis {0:%d.%m.%Y %H:%M} UTC', cr.expires_at))
        lines.append(tr('Änderungen:'))
        lines += [f"  • {tr(ACTION.get(o['action'], o['action']))} {tr(entities.LABELS.get(o['entity'], o['entity']))} „{o['name']}“"
                  for o in (cr.operations or [])[:15]]
        if len(cr.operations or []) > 15:
            lines.append(tr('  … und {0} weitere', len(cr.operations) - 15))
    elif kind == "rejected":
        reason = next((e.text for e in reversed(cr.events) if e.kind == "rejected"), "")
        lines.append(tr('Begründung der Ablehnung: {0}', reason))
    elif kind in ("failed", "conflict", "expiry_failed"):
        lines.append(tr('Fehler: {0}', cr.error or next((e.text for e in reversed(cr.events) if e.kind == kind), '')))
    elif kind == "expiry_soon":
        lines.append(tr('Die Änderung wird am {0:%d.%m.%Y %H:%M} UTC automatisch zurückgenommen.', cr.expires_at))
    return lines


def change_message(cr: ChangeRequest, kind: str, public_url: str) -> tuple[str, str]:
    subject = f"[Firewall] {tr(SUBJECT.get(kind, kind))}: {cr_no(cr)} {cr.title}"[:200]
    body = "\n".join(change_lines(cr, kind))
    url = link(public_url, cr)
    if url:
        body += tr('\n\nIm Browser öffnen: {0}', url)
    return subject, body
