from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Any, Callable, Dict, Optional

from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, delete, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine


@dataclass(frozen=True)
class PacerTokenRecord:
    token: str
    obtained_at: datetime
    expires_at: Optional[datetime] = None
    environment: Optional[str] = None


def token_fingerprint(token: Optional[str], prefix_len: int = 12) -> Dict[str, Any]:
    if not token:
        return {"present": False, "length": 0, "sha256_prefix": ""}
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return {
        "present": True,
        "length": len(token),
        "sha256_prefix": digest[:prefix_len],
    }


def build_pacer_token_table(metadata: MetaData) -> Table:
    return Table(
        "pacer_tokens",
        metadata,
        Column("session_key", String(64), primary_key=True),
        Column("token", Text, nullable=False),
        Column("obtained_at", DateTime(timezone=True), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("environment", String(20), nullable=True),
    )


class InMemoryTokenBackend:
    def __init__(self) -> None:
        self._store: Dict[str, PacerTokenRecord] = {}

    def save_token(self, session_key: str, record: PacerTokenRecord) -> None:
        self._store[session_key] = record

    def get_token(self, session_key: str) -> Optional[PacerTokenRecord]:
        return self._store.get(session_key)

    def clear_token(self, session_key: str) -> None:
        self._store.pop(session_key, None)


class DatabaseTokenBackend:
    def __init__(self, engine: Engine, table: Table) -> None:
        self._engine = engine
        self._table = table

    def save_token(self, session_key: str, record: PacerTokenRecord) -> None:
        values = {
            "session_key": session_key,
            "token": record.token,
            "obtained_at": record.obtained_at,
            "expires_at": record.expires_at,
            "environment": record.environment,
        }

        with self._engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                stmt = pg_insert(self._table).values(**values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=[self._table.c.session_key],
                    set_={
                        "token": stmt.excluded.token,
                        "obtained_at": stmt.excluded.obtained_at,
                        "expires_at": stmt.excluded.expires_at,
                        "environment": stmt.excluded.environment,
                    },
                )
                conn.execute(stmt)
                return

            if conn.dialect.name == "sqlite":
                stmt = sqlite_insert(self._table).values(**values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=[self._table.c.session_key],
                    set_={
                        "token": stmt.excluded.token,
                        "obtained_at": stmt.excluded.obtained_at,
                        "expires_at": stmt.excluded.expires_at,
                        "environment": stmt.excluded.environment,
                    },
                )
                conn.execute(stmt)
                return

            # Fallback: delete + insert.
            conn.execute(delete(self._table).where(self._table.c.session_key == session_key))
            conn.execute(insert(self._table).values(**values))

    def get_token(self, session_key: str) -> Optional[PacerTokenRecord]:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(
                    self._table.c.token,
                    self._table.c.obtained_at,
                    self._table.c.expires_at,
                    self._table.c.environment,
                ).where(self._table.c.session_key == session_key)
            ).first()
        if not row:
            return None
        return PacerTokenRecord(
            token=row.token,
            obtained_at=row.obtained_at,
            expires_at=row.expires_at,
            environment=row.environment,
        )

    def clear_token(self, session_key: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(delete(self._table).where(self._table.c.session_key == session_key))


class PacerTokenStore:
    def __init__(
        self,
        backend: Any,
        session_accessor: Callable[[], Dict[str, Any]],
        session_key_name: str = "pacer_session_key",
    ) -> None:
        self._backend = backend
        self._session_accessor = session_accessor
        self._session_key_name = session_key_name

    def _session(self) -> Dict[str, Any]:
        return self._session_accessor()

    def _get_session_key(self) -> Optional[str]:
        return self._session().get(self._session_key_name)

    def _ensure_session_key(self) -> str:
        session = self._session()
        session_key = session.get(self._session_key_name)
        if not session_key:
            raise RuntimeError("PACER session key is not initialized.")
        return session_key

    def initialize_session(self, session_key: str) -> None:
        session = self._session()
        session[self._session_key_name] = session_key

    def save_token(
        self,
        token: str,
        obtained_at: datetime,
        expires_at: Optional[datetime] = None,
        environment: Optional[str] = None,
    ) -> PacerTokenRecord:
        session_key = self._ensure_session_key()
        if environment is None:
            existing = self._backend.get_token(session_key)
            environment = existing.environment if existing else None
        record = PacerTokenRecord(
            token=token,
            obtained_at=obtained_at,
            expires_at=expires_at,
            environment=environment,
        )
        self._backend.save_token(session_key, record)
        return record

    def get_token(self, expected_environment: Optional[str] = None) -> Optional[PacerTokenRecord]:
        session_key = self._get_session_key()
        if not session_key:
            return None
        record = self._backend.get_token(session_key)
        if not record:
            return None
        if expected_environment:
            if not record.environment:
                return None
            if record.environment != expected_environment:
                return None
        return record

    def get_token_for_key(
        self, session_key: str, expected_environment: Optional[str] = None
    ) -> Optional[PacerTokenRecord]:
        record = self._backend.get_token(session_key)
        if not record:
            return None
        if expected_environment:
            if not record.environment:
                return None
            if record.environment != expected_environment:
                return None
        return record

    def clear_token(self) -> None:
        session = self._session()
        session_key = session.pop(self._session_key_name, None)
        if session_key:
            self._backend.clear_token(session_key)
