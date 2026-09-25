"""Nachrichtentexte (deutsch) für alle Kanäle."""
from ..models import ChangeRequest

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


def cr_no(cr: ChangeRequest) -> str:
    return f"CR-{cr.number:04d}"


def link(public_url: str, cr: ChangeRequest) -> str:
    return f"{public_url}/changes/{cr.id}" if public_url else ""


def change_lines(cr: ChangeRequest, kind: str) -> list[str]:
    lines = [f"{cr_no(cr)} · {cr.title}", f"Firewall: {cr.firewall.name}",
             f"Antragsteller: {cr.creator.username if cr.creator else 'System'}"]
    if kind == "pending":
        lines.append(f"Begründung: {cr.justification}")
        if cr.expires_at:
            lines.append(f"Befristet bis {cr.expires_at:%d.%m.%Y %H:%M} UTC")
        lines.append("Änderungen:")
        lines += [f"  • {o['action']} {o['entity']} „{o['name']}“" for o in (cr.operations or [])[:15]]
        if len(cr.operations or []) > 15:
            lines.append(f"  … und {len(cr.operations) - 15} weitere")
    elif kind == "rejected":
        reason = next((e.text for e in reversed(cr.events) if e.kind == "rejected"), "")
        lines.append(f"Begründung der Ablehnung: {reason}")
    elif kind in ("failed", "conflict", "expiry_failed"):
        lines.append(f"Fehler: {cr.error or next((e.text for e in reversed(cr.events) if e.kind == kind), '')}")
    elif kind == "expiry_soon":
        lines.append(f"Die Änderung wird am {cr.expires_at:%d.%m.%Y %H:%M} UTC automatisch zurückgenommen.")
    return lines


def change_message(cr: ChangeRequest, kind: str, public_url: str) -> tuple[str, str]:
    subject = f"[Firewall] {SUBJECT.get(kind, kind)}: {cr_no(cr)} {cr.title}"[:200]
    body = "\n".join(change_lines(cr, kind))
    url = link(public_url, cr)
    if url:
        body += f"\n\nIm Browser öffnen: {url}"
    return subject, body
