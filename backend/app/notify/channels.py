"""Versand über E-Mail (SMTP), Microsoft Teams (Workflow-Webhook), Slack (Incoming Webhook) und Telegram (Bot)."""
import logging
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from . import config as ncfg
from ..i18n import tr

log = logging.getLogger("fwm.notify")


# --- E-Mail --------------------------------------------------------------------------------------------------

def send_mail(cfg: dict, to: list[str], subject: str, body: str) -> None:
    m = cfg["email"]
    if not to:
        return
    msg = EmailMessage()
    msg["From"] = m["sender"] or m["username"]
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    port = int(m.get("port") or 587)
    if m.get("security") == "ssl":
        smtp = smtplib.SMTP_SSL(m["host"], port, timeout=15, context=ssl.create_default_context())
    else:
        smtp = smtplib.SMTP(m["host"], port, timeout=15)
    with smtp:
        if m.get("security") == "starttls":
            smtp.starttls(context=ssl.create_default_context())
        if m.get("username"):
            smtp.login(m["username"], m["password"])
        smtp.send_message(msg)


# --- Microsoft Teams -----------------------------------------------------------------------------------------

def send_teams(cfg: dict, title: str, lines: list[str], url: str = "") -> None:
    """Adaptive Card an einen Teams-Workflow („Post to a channel when a webhook request is received“)."""
    card = {
        "type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4",
        "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True}]
        + [{"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"} for line in lines],
        "actions": [{"type": "Action.OpenUrl", "title": tr('Im Browser öffnen'), "url": url}] if url else [],
    }
    payload = {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
    r = httpx.post(cfg["teams"]["webhook_url"], json=payload, timeout=15)
    if r.status_code >= 300:
        raise RuntimeError(f"Teams-Webhook: HTTP {r.status_code} {r.text[:200]}")


# --- Slack ---------------------------------------------------------------------------------------------------

def _slack_escape(text: str) -> str:
    # Slack-mrkdwn: nur &, < und > müssen maskiert werden (sonst Links/Erwähnungen)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(title: str, lines: list[str], url: str = "", mention: str = "") -> dict:
    """Block-Kit-Nachricht: Überschrift, Zeilen, Knopf „Im Browser öffnen“; optional @here/@channel."""
    body = "\n".join(_slack_escape(line) for line in lines if line)
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": title[:150], "emoji": True}}]
    if mention in ("here", "channel"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"<!{mention}>"}})
    if body:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}})
    if url:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": tr('Im Browser öffnen')}, "url": url, "style": "primary"}]})
    # „text“ ist der Fallback für Benachrichtigungen auf dem Telefon/Sperrbildschirm
    fallback = (f"<!{mention}> " if mention in ("here", "channel") else "") + _slack_escape(title)
    return {"text": fallback, "blocks": blocks, "unfurl_links": False}


def send_slack(cfg: dict, title: str, lines: list[str], url: str = "", urgent: bool = False) -> None:
    s = cfg["slack"]
    r = httpx.post(s["webhook_url"], json=slack_payload(title, lines, url, s.get("mention", "") if urgent else ""), timeout=15)
    if r.status_code >= 300:
        raise RuntimeError(f"Slack-Webhook: HTTP {r.status_code} {r.text[:200]}")


# --- Telegram ------------------------------------------------------------------------------------------------

def tg_call(cfg: dict, method: str, http_timeout: float = 15, **params) -> dict:
    r = httpx.post(f"{ncfg.TELEGRAM_API_BASE}/bot{cfg['telegram']['bot_token']}/{method}", json=params,
                   timeout=http_timeout)
    body = r.json() if r.content else {}
    if not body.get("ok"):
        raise RuntimeError(f"Telegram {method}: {body.get('description') or r.status_code}")
    return body.get("result") or {}


def send_telegram(cfg: dict, chat_id: str, text: str, buttons: list[list[dict]] | None = None) -> None:
    params = {"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True}
    if buttons:
        params["reply_markup"] = {"inline_keyboard": buttons}
    tg_call(cfg, "sendMessage", **params)
