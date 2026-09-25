"""Schema-Änderungen an bestehenden Tabellen (kein Alembic): idempotentes SQL, läuft nach create_all."""
from sqlalchemy import text

from .db import engine

POSTGRES = [
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS api_key_expires_at TIMESTAMPTZ",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS reverts_id VARCHAR(36)",
    "CREATE INDEX IF NOT EXISTS ix_change_requests_reverts_id ON change_requests (reverts_id)",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS expiry_state VARCHAR(20) NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS ix_change_requests_expires_at ON change_requests (expires_at)",
    "ALTER TABLE change_requests ALTER COLUMN created_by DROP NOT NULL",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS expiry_warned BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_email BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id VARCHAR(40) NOT NULL DEFAULT ''",
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS api_key_warned_days INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS batch_id VARCHAR(36)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_enc TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source VARCHAR(10) NOT NULL DEFAULT 'local'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject VARCHAR(255) NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS ix_users_oidc_subject ON users (oidc_subject)",
    "CREATE INDEX IF NOT EXISTS ix_change_requests_batch_id ON change_requests (batch_id)",
]


def run() -> None:
    if engine.dialect.name != "postgresql":
        return  # SQLite (Tests) wird immer frisch per create_all angelegt
    with engine.begin() as conn:
        for stmt in POSTGRES:
            conn.execute(text(stmt))
    strip_rest_read_only()


def strip_rest_read_only() -> None:
    """Nachträglich als nur-lesend erkannte REST-Felder (z. B. ruleId) aus dem Cache entfernen und den Hash neu
    berechnen – sonst meldet die nächste Synchronisation fälschlich eine Änderung außerhalb des Tools."""
    from . import diff, sync
    from .db import SessionLocal
    from .models import ConfigObject, Firewall
    from .sophos import entities
    with SessionLocal() as db:
        for fw in db.query(Firewall).filter(Firewall.connector == "rest", Firewall.archived.is_(False)):
            rows = db.query(ConfigObject).filter(ConfigObject.firewall_id == fw.id).all()
            dirty = [r for r in rows if any(k in r.data for k in entities.REST_READ_ONLY)]
            if not dirty:
                continue
            for r in dirty:
                r.data = {k: v for k, v in r.data.items() if k not in entities.REST_READ_ONLY}
            db.flush()
            fw.config_hash = diff.config_hash(sync.cached_config(db, fw))
            db.commit()
