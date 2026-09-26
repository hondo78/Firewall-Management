"""Laufzeit-Einstellungen (Tabelle settings), änderbar über die Administration."""
from sqlalchemy.orm import Session as DbSession

from .models import Setting

DEFAULTS: dict = {
    # Anzahl unterschiedlicher Genehmiger pro Antrag (Vier-Augen-Prinzip: mindestens 1, nie der Antragsteller)
    "required_approvals": 1,
    # Genehmigte Anträge automatisch ausrollen (sonst manuell durch jemanden mit change.deploy)
    "auto_deploy": True,
    # Periodische Synchronisation aller Firewalls (Minuten, 0 = aus) – erkennt Änderungen außerhalb des Tools
    "sync_interval_minutes": 30,
    # Pflichtfeld Ticket-Referenz beim Einreichen
    "require_ticket": False,
    # Befristete Anträge: automatische Rücknahme nach Ablauf ohne erneute Freigabe ausrollen
    # (die Befristung wurde mit dem ursprünglichen Antrag im Vier-Augen-Prinzip genehmigt)
    "temp_revert_preapproved": True,
    # Maximale Befristung in Tagen (0 = unbegrenzt)
    "temp_max_days": 90,
    # Zwei-Faktor-Pflicht: "none" | "privileged" (Genehmigen/Verwalten/Admin) | "all"
    "require_mfa": "none",
    # Vor dem Genehmigen/Ablehnen erneut anmelden, wenn die Anmeldung länger zurückliegt (Minuten, 0 = aus)
    "reauth_minutes": 30,
    # Anmeldungen per SSO (OIDC) erfüllen die Zwei-Faktor-Pflicht (MFA erledigt der Identity Provider)
    "oidc_counts_as_mfa": True,
    # Standardsprache für Hintergrundaufgaben (Ausroll-Protokoll, Worker), Teams/Slack und Benutzer ohne eigene Wahl
    "language": "de",
    # Automatische Sicherung der Firewall-Konfigurationen im Tool
    "backup_enabled": True,
    "backup_frequency": "daily",       # daily | weekly | monthly
    "backup_time": "02:00",            # Ortszeit (TZ des Containers)
    "backup_weekday": 0,               # 0 = Montag (wöchentlich)
    "backup_monthday": 1,              # 1–31 (monatlich; kürzere Monate → letzter Tag)
    "backup_keep": 30,                 # je Firewall aufbewahrte, nicht angeheftete Sicherungen
    "backup_to_directory": False,      # zusätzlich als Datei in BACKUP_DIR (Volume) ablegen
}


def get(db: DbSession, key: str):
    row = db.get(Setting, key)
    return DEFAULTS.get(key) if row is None else row.value


def get_all(db: DbSession) -> dict:
    return {k: get(db, k) for k in DEFAULTS}


def set_many(db: DbSession, values: dict) -> dict:
    changed = {}
    for key, value in values.items():
        if key not in DEFAULTS:
            continue
        default = DEFAULTS[key]
        value = type(default)(value)
        if key == "require_mfa" and value not in ("none", "privileged", "all"):
            raise ValueError("require_mfa")
        if key == "required_approvals":
            value = max(1, min(value, 5))
        if key == "sync_interval_minutes":
            value = max(0, value)
        if key == "language":
            from .i18n import LANGS
            if value not in LANGS:
                raise ValueError("language")
        if key == "backup_frequency" and value not in ("daily", "weekly", "monthly"):
            raise ValueError("backup_frequency")
        if key == "backup_time":
            import re
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", value):
                raise ValueError("backup_time")
        if key == "backup_weekday":
            value = max(0, min(value, 6))
        if key == "backup_monthday":
            value = max(1, min(value, 31))
        if key == "backup_keep":
            value = max(1, min(value, 1000))
        if get(db, key) != value:
            changed[key] = value
        row = db.get(Setting, key)
        if row is None:
            db.add(Setting(key=key, value=value))
        else:
            row.value = value
    return changed
