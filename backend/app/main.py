import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select, text

from . import config, crypto, migrations, permissions, worker
from .audit import audit
from .db import Base, SessionLocal, engine
from .models import Role, User
from .routers import admin, audit_log, auth, central, changes, firewalls, notifications, templates
from .security import hash_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("fwm")


def _wait_for_db(retries: int = 30) -> None:
    for i in range(retries):
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            return
        except Exception:
            log.info("Warte auf Datenbank … (%s/%s)", i + 1, retries)
            time.sleep(2)
    raise RuntimeError("Datenbank nicht erreichbar")


def bootstrap() -> None:
    with SessionLocal() as db:
        existing = {r.name for r in db.execute(select(Role)).scalars()}
        for name, desc, perms in permissions.BUILTIN_ROLES:
            if name not in existing:
                db.add(Role(name=name, description=desc, permissions=perms, builtin=True))
        db.commit()
        if db.execute(select(User.id).limit(1)).first():
            return
        if not config.ADMIN_PASSWORD:
            raise RuntimeError("Keine Benutzer vorhanden und ADMIN_PASSWORD nicht gesetzt")
        admin_user = User(username=config.ADMIN_USERNAME.lower(), display_name="Administrator", is_superadmin=True,
                          password_hash=hash_password(config.ADMIN_PASSWORD))
        db.add(admin_user)
        db.flush()
        audit(db, "user.bootstrap", target_type="user", target_id=admin_user.id,
              details={"username": admin_user.username})
        log.info("Initialer Superadmin '%s' angelegt", admin_user.username)


@asynccontextmanager
async def lifespan(app: FastAPI):
    crypto._key()  # schlägt früh und deutlich fehl, wenn FWM_MASTER_KEY fehlt/ungültig ist
    await asyncio.to_thread(_wait_for_db)
    Base.metadata.create_all(engine)
    await asyncio.to_thread(migrations.run)
    await asyncio.to_thread(bootstrap)
    tasks = [] if config.DISABLE_WORKER else [asyncio.create_task(worker.run_forever())]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="Firewall-Management (Sophos)", lifespan=lifespan, docs_url="/api/docs",
              openapi_url="/api/openapi.json")

for r in (auth, admin, central, firewalls, changes, audit_log, notifications, templates):
    app.include_router(r.router)


@app.get("/api/health")
def health():
    return {"ok": True}
