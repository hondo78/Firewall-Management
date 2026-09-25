"""Schema-Änderungen an bestehenden Tabellen (kein Alembic): idempotentes SQL, läuft nach create_all."""
from sqlalchemy import text

from .db import engine

POSTGRES = [
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS api_key_expires_at TIMESTAMPTZ",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS reverts_id VARCHAR(36)",
    "CREATE INDEX IF NOT EXISTS ix_change_requests_reverts_id ON change_requests (reverts_id)",
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
