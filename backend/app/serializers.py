from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import diff, permissions
from .models import ChangeRequest, Firewall, FirewallGroup, User
from .sophos import connector, entities, restapi, xmlapi


def user_out(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "display_name": u.display_name, "email": u.email,
        "is_superadmin": u.is_superadmin, "active": u.active, "created_at": u.created_at,
        "last_login_at": u.last_login_at, "notify_email": u.notify_email,
        "totp_enabled": u.totp_enabled, "auth_source": u.auth_source,
        "telegram_linked": bool(u.telegram_chat_id),
        "assignments": [{"id": a.id, "role_id": a.role_id, "role": a.role.name, "group_id": a.group_id}
                        for a in u.assignments],
    }


def group_out(g: FirewallGroup) -> dict:
    return {"id": g.id, "name": g.name, "description": g.description, "central": bool(g.central_id),
            "central_account_id": g.central_account_id}


def firewall_out(db: DbSession, fw: Firewall, user: User) -> dict:
    # Verbindungsdaten (Adresse, Benutzer, Key-Status, TLS) sieht nur ein Superadmin
    conn = user.is_superadmin
    return {
        "id": fw.id, "name": fw.name, "hostname": fw.hostname, "serial": fw.serial, "model": fw.model,
        "firmware": fw.firmware, "group_id": fw.group_id, "group": fw.group.name if fw.group else None,
        "connector": fw.connector, "connector_label": connector.capabilities(fw)["label"],
        "capabilities": connector.capabilities(fw),
        "central_account_id": fw.central_account_id if conn else None, "central_id": fw.central_id,
        "central_status": fw.central_status or {}, "external_ips": fw.external_ips or [],
        "api_url": fw.api_url if conn else None, "api_username": fw.api_username if conn else None,
        "xml_username": fw.xml_username if conn else None, "has_xml_password": bool(fw.xml_password_enc) if conn else None,
        "xml_status": fw.xml_status if conn else None,
        # WAF-Regeln vollständig bearbeitbar (XML-API-Zugang hinterlegt) – ohne Zugangsdaten preiszugeben
        "waf_xml": connector.has_waf_xml(fw),
        "has_api_password": bool(fw.api_password_enc) if conn else None,
        "api_key_expires_at": fw.api_key_expires_at if conn else None,
        "verify_tls": fw.verify_tls if conn else None, "api_version": fw.api_version, "may_edit_connection": conn,
        "last_sync_at": fw.last_sync_at, "last_sync_error": fw.last_sync_error,
        "permissions": sorted(p for p in permissions.PERMISSIONS
                              if p not in permissions.GLOBAL_ONLY and permissions.can(db, user, p, fw)),
    }


def op_out(fw: Firewall, o: dict) -> dict:
    return {
        **o,
        "label": entities.LABELS.get(o["entity"], o["entity"]),
        "diff": diff.diff_objects(o.get("before"), o.get("data")) if o["action"] != "remove" else [],
        "xml": (xmlapi.request_preview(entities.REST_XML_ENTITIES[o["entity"]][0], o["action"], o.get("data"), o["name"],
                                       o.get("position"))
                if o["entity"] in entities.REST_XML_ENTITIES else
                restapi.request_preview(entities.REST_RESOURCES[o["entity"]][0], o["action"], o.get("data"), o["name"],
                                        o.get("position"), o.get("before"), o["entity"] in entities.RULE_ENTITIES,
                                        o["entity"] in entities.REST_SINGLETONS)
                if o["entity"] in entities.REST_RESOURCES else
                xmlapi.request_preview(o["entity"], o["action"], o.get("data"), o["name"], o.get("position"))),
    }


def change_summary(cr: ChangeRequest) -> dict:
    return {
        "id": cr.id, "number": cr.number, "title": cr.title, "status": cr.status,
        "firewall_id": cr.firewall_id, "firewall": cr.firewall.name if cr.firewall else "",
        "firewall_archived": bool(cr.firewall and cr.firewall.archived),
        "created_by": cr.creator.username if cr.creator else "system", "created_by_id": cr.created_by,
        "expires_at": cr.expires_at, "expiry_state": cr.expiry_state, "reverts_id": cr.reverts_id,
        "created_at": cr.created_at, "submitted_at": cr.submitted_at, "decided_at": cr.decided_at,
        "deployed_at": cr.deployed_at, "deploy_after": cr.deploy_after, "ticket_ref": cr.ticket_ref,
        "operations_count": len(cr.operations or []),
        "approvals": len({e.user_id for e in cr.events if e.kind == "approved"}),
        "required_approvals": cr.required_approvals,
        "entities": sorted({o["entity"] for o in cr.operations or []}),
        "batch_id": cr.batch_id,
    }


def _analysis(db: DbSession, cr: ChangeRequest) -> list[dict]:
    """Regel-Analyse: Befunde, die dieser Antrag gegenüber dem aktuellen Stand neu einführt."""
    from . import changes, lint, sync
    if not cr.operations:
        return []
    before = sync.cached_config(db, cr.firewall)
    return lint.for_change(before, changes.effective_config(before, cr.operations), cr.operations)


def change_out(db: DbSession, cr: ChangeRequest, user: User) -> dict:
    from . import changes
    fw = cr.firewall
    # Verknüpfung Rücknahme ⇄ Original
    reverted_by = db.execute(select(ChangeRequest).where(
        ChangeRequest.reverts_id == cr.id,
        ChangeRequest.status.notin_(("rejected", "withdrawn", "failed", "conflict")))).scalar()
    reverts = db.get(ChangeRequest, cr.reverts_id) if cr.reverts_id else None
    approved_by = {e.user_id for e in cr.events if e.kind == "approved"}
    is_owner = cr.created_by == user.id
    return {
        **change_summary(cr),
        "justification": cr.justification, "error": cr.error, "deploy_log": cr.deploy_log or [],
        "operations": [op_out(fw, o) for o in cr.operations or []],
        "connector": fw.connector,
        "events": [{"ts": e.ts, "kind": e.kind, "text": e.text, "actor": e.actor_name} for e in cr.events],
        "can": {
            "approve": cr.status == "pending" and not is_owner and user.id not in approved_by
            and permissions.can(db, user, "change.approve", fw),
            "withdraw": cr.status in ("draft", "pending", "approved")
            and (is_owner or permissions.has_global(db, user, "admin")),
            "deploy": cr.status in ("approved", "failed") and permissions.can(db, user, "change.deploy", fw),
            "revert": changes.can_revert(db, user, cr) and not reverted_by,
            "submit": cr.status == "draft" and is_owner,
        },
        "own": is_owner,
        "analysis": _analysis(db, cr) if cr.status in ("draft", "pending", "approved") else [],
        "batch": [{"id": m.id, "number": m.number, "firewall": m.firewall.name, "status": m.status,
                   "error": m.error} for m in changes.batch_members(db, cr)] if cr.batch_id else [],
        "reverts": {"id": reverts.id, "number": reverts.number} if reverts else None,
        "reverted_by": {"id": reverted_by.id, "number": reverted_by.number, "status": reverted_by.status}
        if reverted_by else None,
    }
