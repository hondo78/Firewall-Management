"""Zentrale Konfiguration – ausschließlich aus Umgebungsvariablen (siehe .env.example)."""
import os
import secrets


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


DATABASE_URL = _env("DATABASE_URL", "postgresql+psycopg2://fwm:fwm@db:5432/fwm")

# 32 Byte, base64-kodiert. Verschlüsselt API-Zugangsdaten (Central-Secrets, Firewall-Passwörter).
MASTER_KEY_B64 = _env("FWM_MASTER_KEY")

# Leer = zufällig pro Prozessstart (alle Logins verfallen dann beim Neustart).
JWT_SECRET = _env("JWT_SECRET") or secrets.token_urlsafe(48)
JWT_HOURS = int(_env("JWT_HOURS", "10"))

ADMIN_USERNAME = _env("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = _env("ADMIN_PASSWORD")

TIMEZONE = _env("TZ", "Europe/Berlin")

# Login-Sperre nach zu vielen Fehlversuchen
LOGIN_MAX_FAILURES = int(_env("LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCK_MINUTES = int(_env("LOGIN_LOCK_MINUTES", "5"))

# Hintergrund-Worker: Ausrollen genehmigter Änderungen + periodische Synchronisation
WORKER_INTERVAL_SECONDS = int(_env("WORKER_INTERVAL_SECONDS", "15"))
# Zeitlimits für Sophos-APIs
HTTP_TIMEOUT_SECONDS = float(_env("HTTP_TIMEOUT_SECONDS", "30"))
# Maximale Wartezeit auf asynchrone Central-Transaktionen (Export/Import)
CENTRAL_TRANSACTION_TIMEOUT = int(_env("CENTRAL_TRANSACTION_TIMEOUT", "600"))
CENTRAL_POLL_SECONDS = float(_env("CENTRAL_POLL_SECONDS", "3"))

# Standard-Endpunkte von Sophos Central (pro Central-Konto überschreibbar, z. B. für die Attrappe)
SOPHOS_ID_URL = _env("SOPHOS_ID_URL", "https://id.sophos.com").rstrip("/")
SOPHOS_API_URL = _env("SOPHOS_API_URL", "https://api.central.sophos.com").rstrip("/")

# Syslog-Export des Audit-Logs (leer = aus). z. B. host.docker.internal:5514 → Warroom
SYSLOG_HOST = _env("SYSLOG_HOST")
SYSLOG_PORT = int(_env("SYSLOG_PORT", "514"))
SYSLOG_PROTOCOL = _env("SYSLOG_PROTOCOL", "udp").lower()
SYSLOG_APP_NAME = _env("SYSLOG_APP_NAME", "fwm")

# Ablageort für Sicherungsdateien (optional, Einstellung „backup_to_directory“) – im Compose als Volume
BACKUP_DIR = _env("BACKUP_DIR", "/backups")

# Worker im Test abschalten
DISABLE_WORKER = _env("DISABLE_WORKER") == "1"
