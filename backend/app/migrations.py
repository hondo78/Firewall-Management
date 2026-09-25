"""Schema-Änderungen an bestehenden Tabellen (kein Alembic): idempotentes SQL, läuft nach create_all."""
from sqlalchemy import text

from .db import engine

POSTGRES = [
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE",
]


def run() -> None:
    if engine.dialect.name != "postgresql":
        return  # SQLite (Tests) wird immer frisch per create_all angelegt
    with engine.begin() as conn:
        for stmt in POSTGRES:
            conn.execute(text(stmt))
