"""
Database connection and session factory for SQLite / SQLAlchemy.
"""

import os
from pathlib import Path
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.database.models import Base

DEFAULT_DB_PATH = Path("data/bugbounty.db")


def get_database_url() -> str:
    return os.getenv("BUGBOUNTY_DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")


def create_db_engine(db_url: str = None):
    url = db_url or get_database_url()
    if url.startswith("sqlite"):
        # Ensure parent directory exists for SQLite
        if "///" in url:
            file_part = url.split("///")[1]
            if file_part and not file_part.startswith(":memory:"):
                Path(file_part).parent.mkdir(parents=True, exist_ok=True)
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url)


# Global engine & SessionLocal
engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)


def init_db(custom_engine=None):
    """Create all tables in the database if they do not exist."""
    eng = custom_engine or engine
    Base.metadata.create_all(bind=eng)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for reliable session handling with auto-rollback on error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
