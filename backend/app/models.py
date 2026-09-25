import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, TypeDecorator,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class TZDateTime(TypeDecorator):
    """DateTime mit Zeitzone; SQLite (Tests) liefert naive Werte → als UTC interpretieren."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        if isinstance(value, datetime) and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    def process_bind_param(self, value, dialect):
        if isinstance(value, datetime) and value.tzinfo is not None and dialect.name == "sqlite":
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    email: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    # Superadmins haben alle Rechte auf allen Firewalls (unabhängig von Rollen)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)

    assignments: Mapped[list["RoleAssignment"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Role(Base):
    """Benannte Menge von Rechten (siehe permissions.PERMISSIONS)."""
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)


class RoleAssignment(Base):
    """Rolle eines Benutzers – global (group_id NULL) oder beschränkt auf eine Firewall-Gruppe."""
    __tablename__ = "role_assignments"
    __table_args__ = (UniqueConstraint("user_id", "role_id", "group_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"))
    group_id: Mapped[str | None] = mapped_column(ForeignKey("firewall_groups.id", ondelete="CASCADE"), nullable=True)

    user: Mapped[User] = relationship(back_populates="assignments")
    role: Mapped[Role] = relationship()


class CentralAccount(Base):
    """API-Zugang (Service Principal) zu Sophos Central."""
    __tablename__ = "central_accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    client_id: Mapped[str] = mapped_column(String(200))
    client_secret_enc: Mapped[str] = mapped_column(Text)
    id_url: Mapped[str] = mapped_column(String(300))
    api_url: Mapped[str] = mapped_column(String(300))
    # Ergebnis von whoami: tenant | partner | organization
    id_type: Mapped[str] = mapped_column(String(20), default="")
    principal_id: Mapped[str] = mapped_column(String(100), default="")
    # Ziel-Tenant (bei Partner/Organisation ausgewählt) und seine Daten-Region
    tenant_id: Mapped[str] = mapped_column(String(100), default="")
    data_region: Mapped[str] = mapped_column(String(300), default="")
    last_sync_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)


class FirewallGroup(Base):
    __tablename__ = "firewall_groups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    # Gespiegelt aus Sophos Central (dann nur dort umbenennbar)
    central_account_id: Mapped[str | None] = mapped_column(ForeignKey("central_accounts.id", ondelete="SET NULL"),
                                                           nullable=True)
    central_id: Mapped[str] = mapped_column(String(100), default="")


class Firewall(Base):
    __tablename__ = "firewalls"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    hostname: Mapped[str] = mapped_column(String(200), default="")
    serial: Mapped[str] = mapped_column(String(100), default="")
    model: Mapped[str] = mapped_column(String(200), default="")
    firmware: Mapped[str] = mapped_column(String(100), default="")
    group_id: Mapped[str | None] = mapped_column(ForeignKey("firewall_groups.id", ondelete="SET NULL"), nullable=True)
    # Schreibweg: "rest" (SFOS REST-API), "central" (Import über Sophos Central) oder "xmlapi" (alte XML-API)
    connector: Mapped[str] = mapped_column(String(20), default="rest")
    central_account_id: Mapped[str | None] = mapped_column(ForeignKey("central_accounts.id", ondelete="SET NULL"),
                                                           nullable=True)
    central_id: Mapped[str] = mapped_column(String(100), default="")
    central_status: Mapped[dict] = mapped_column(JSON, default=dict)
    # Lokale API (REST oder XML): https://<host>:4444 (oder volle Basis-URL)
    api_url: Mapped[str] = mapped_column(String(300), default="")
    api_username: Mapped[str] = mapped_column(String(200), default="")
    api_password_enc: Mapped[str] = mapped_column(Text, default="")
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    # REST-API: Ablaufdatum des API-Keys (in SFOS beim Erzeugen angezeigt) – für rechtzeitige Warnung
    api_key_expires_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    external_ips: Mapped[list] = mapped_column(JSON, default=list)
    last_sync_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    last_sync_error: Mapped[str] = mapped_column(Text, default="")
    config_hash: Mapped[str] = mapped_column(String(64), default="")
    api_version: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    # Aus der Verwaltung entfernt: bleibt für Antragshistorie und Versionsstände erhalten, ist aber unsichtbar
    archived: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    group: Mapped[FirewallGroup | None] = relationship()


class ConfigObject(Base):
    """Zwischengespeicherte Konfiguration (Stand der letzten Synchronisation)."""
    __tablename__ = "config_objects"
    firewall_id: Mapped[str] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), primary_key=True)
    entity: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(300), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class ConfigSnapshot(Base):
    """Versionsstand der Konfiguration – neu angelegt, sobald sich der Inhalt ändert."""
    __tablename__ = "config_snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    firewall_id: Mapped[str] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    hash: Mapped[str] = mapped_column(String(64))
    # sync | deploy | initial
    reason: Mapped[str] = mapped_column(String(40), default="sync")
    change_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class ChangeRequest(Base):
    __tablename__ = "change_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    number: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    firewall_id: Mapped[str] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300), default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    ticket_ref: Mapped[str] = mapped_column(String(200), default="")
    # draft → pending → approved → deploying → deployed | failed | conflict ; rejected ; withdrawn
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)
    operations: Mapped[list] = mapped_column(JSON, default=list)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    # Frühester Zeitpunkt für das Ausrollen (Wartungsfenster), NULL = sofort nach Genehmigung
    deploy_after: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    deployed_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    deploy_log: Mapped[list] = mapped_column(JSON, default=list)
    # Rücknahme: verweist auf den ausgerollten Antrag, der umgekehrt wird
    reverts_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    error: Mapped[str] = mapped_column(Text, default="")

    firewall: Mapped[Firewall] = relationship()
    creator: Mapped[User] = relationship(foreign_keys=[created_by])
    events: Mapped[list["ChangeEvent"]] = relationship(order_by="ChangeEvent.ts", cascade="all, delete-orphan")


class ChangeEvent(Base):
    """Verlauf eines Antrags: eingereicht, Kommentar, genehmigt, abgelehnt, ausgerollt …"""
    __tablename__ = "change_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    change_id: Mapped[str] = mapped_column(ForeignKey("change_requests.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_name: Mapped[str] = mapped_column(String(200), default="system")
    kind: Mapped[str] = mapped_column(String(30))
    text: Mapped[str] = mapped_column(Text, default="")


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict | list | str | int | bool | None] = mapped_column(JSON)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(200), default="system")
    action: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[str] = mapped_column(String(100), default="", index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
