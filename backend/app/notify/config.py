"""Konfiguration der Benachrichtigungskanäle (Tabelle settings, Schlüssel „notifications“).

Geheimnisse (SMTP-Passwort, Bot-Token, Webhook-URL) werden mit FWM_MASTER_KEY verschlüsselt gespeichert
und nie an die Oberfläche ausgeliefert (nur „gesetzt ja/nein“).
"""
import copy
import os

from sqlalchemy.orm import Session as DbSession

from .. import crypto
from ..i18n import tr
from ..models import Setting

KEY = "notifications"
SECRETS = {"email": ("password",), "telegram": ("bot_token",), "teams": ("webhook_url",), "slack": ("webhook_url",)}
DEFAULTS = {
    # Adresse der Web-Oberfläche für Links in Nachrichten, z. B. http://10.0.1.111:8096
    "public_url": "",
    "email": {"enabled": False, "host": "", "port": 587, "security": "starttls", "username": "", "password": "",
              "sender": ""},
    "telegram": {"enabled": False, "bot_token": "", "bot_username": "", "allow_approve": True},
    "teams": {"enabled": False, "webhook_url": ""},
    # Slack: Incoming Webhook einer Slack-App; mention = "" | "here" | "channel" (nur bei neuen Anträgen)
    "slack": {"enabled": False, "webhook_url": "", "mention": ""},
}
# Nur für Tests mit Attrappen überschreiben
TELEGRAM_API_BASE = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")


def _merged(stored: dict | None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    for k, v in (stored or {}).items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


def load(db: DbSession) -> dict:
    """Konfiguration mit entschlüsselten Geheimnissen – nur serverseitig verwenden."""
    row = db.get(Setting, KEY)
    cfg = _merged(row.value if row else None)
    for channel, fields in SECRETS.items():
        for f in fields:
            enc = cfg[channel].pop(f"{f}_enc", "")
            cfg[channel][f] = crypto.decrypt(enc, f"notify:{channel}.{f}") if enc else ""
    cfg["public_url"] = (cfg.get("public_url") or "").rstrip("/")
    return cfg


def public_view(cfg: dict) -> dict:
    out = copy.deepcopy(cfg)
    for channel, fields in SECRETS.items():
        for f in fields:
            out[channel][f"{f}_set"] = bool(out[channel].pop(f, ""))
    return out


def save(db: DbSession, incoming: dict) -> dict:
    """Leere Geheimnis-Felder = unverändert; clear_<feld>=True entfernt ein Geheimnis. Liefert geänderte Schlüssel."""
    row = db.get(Setting, KEY)
    stored = _merged(row.value if row else None)
    changed = []
    if "public_url" in incoming:
        url = (incoming.get("public_url") or "").strip().rstrip("/")
        if url != stored.get("public_url"):
            changed.append("public_url")
        stored["public_url"] = url
    for channel in ("email", "telegram", "teams", "slack"):
        data = incoming.get(channel) or {}
        target = stored[channel]
        for k, v in data.items():
            if k.startswith("clear_") and v:
                field = k[len("clear_"):]
                if f"{field}_enc" in target:
                    target.pop(f"{field}_enc")
                    changed.append(f"{channel}.{field}")
                continue
            if k in SECRETS[channel]:
                if v and channel in ("teams", "slack") and k == "webhook_url" and not str(v).startswith("https://"):
                    raise ValueError(tr('Die Webhook-URL muss mit https:// beginnen'))
                if v:
                    target[f"{k}_enc"] = crypto.encrypt(str(v), f"notify:{channel}.{k}")
                    changed.append(f"{channel}.{k}")
                continue
            if channel == "slack" and k == "mention" and v not in ("", "here", "channel"):
                raise ValueError(tr('Slack-Erwähnung muss leer, „here“ oder „channel“ sein'))
            if k in DEFAULTS[channel] and target.get(k) != v:
                target[k] = int(v) if k == "port" else v
                changed.append(f"{channel}.{k}")
        for f in SECRETS[channel]:
            target.pop(f, None)
    if row is None:
        db.add(Setting(key=KEY, value=stored))
    else:
        row.value = stored
    return {"changed": changed}
