from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, delete, insert, select
from sqlalchemy.engine import Engine


@dataclass(frozen=True)
class PacerTokenRecord:
    token: str
    obtained_at: datetime
    expires_at: Optional[datetime] = None


def build_pacer_token_table(metadata: MetaData) -> Table:
    return Table(
        "pacer_tokens",
        metadata,
        Column("session_key", String(64), primary_key=True),
        Column("token", Text, nullable=False),
        Column("obtained_at", DateTime(timezone=True), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=True),
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
        with self._engine.begin() as conn:
            conn.execute(delete(self._table).where(self._table.c.session_key == session_key))
            conn.execute(
                insert(self._table).values(
                    session_key=session_key,
                    token=record.token,
                    obtained_at=record.obtained_at,
                    expires_at=record.expires_at,
                )
            )

    def get_token(self, session_key: str) -> Optional[PacerTokenRecord]:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(
                    self._table.c.token,
                    self._table.c.obtained_at,
                    self._table.c.expires_at,
                ).where(self._table.c.session_key == session_key)
            ).first()
        if not row:
            return None
        return PacerTokenRecord(
            token=row.token,
            obtained_at=row.obtained_at,
            expires_at=row.expires_at,
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
    ) -> PacerTokenRecord:
        session_key = self._ensure_session_key()
        record = PacerTokenRecord(token=token, obtained_at=obtained_at, expires_at=expires_at)
        self._backend.save_token(session_key, record)
        return record

    def get_token(self) -> Optional[PacerTokenRecord]:
        session_key = self._get_session_key()
        if not session_key:
            return None
        return self._backend.get_token(session_key)

    def get_token_for_key(self, session_key: str) -> Optional[PacerTokenRecord]:
        return self._backend.get_token(session_key)

    def clear_token(self) -> None:
        session = self._session()
        session_key = session.pop(self._session_key_name, None)
        if session_key:
            self._backend.clear_token(session_key)
