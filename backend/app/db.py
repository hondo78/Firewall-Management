from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from . import config

_kwargs = {"pool_pre_ping": True}
if config.DATABASE_URL.startswith("postgresql"):
    _kwargs.update(pool_size=10, max_overflow=20)
elif config.DATABASE_URL.startswith("sqlite"):
    # Tests: eine gemeinsame In-Memory-DB für alle Threads
    from sqlalchemy.pool import StaticPool
    _kwargs.update(connect_args={"check_same_thread": False}, poolclass=StaticPool)

engine = create_engine(config.DATABASE_URL, **_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
