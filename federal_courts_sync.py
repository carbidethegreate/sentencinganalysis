from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import requests
from sqlalchemy import Engine, Table, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

FEDERAL_COURTS_SOURCE_URL = (
    "https://pacer.uscourts.gov/file-case/court-cmecf-lookup/data.json"
)


class FederalCourtsSyncError(RuntimeError):
    """Raised when PACER court lookup data cannot be fetched or parsed."""


@dataclass(frozen=True)
class FederalCourtUpsertResult:
    inserted: int
    updated: int
    source_last_updated: Optional[str]
    total_records: int


def fetch_federal_courts_json(
    source_url: str = FEDERAL_COURTS_SOURCE_URL,
    *,
    timeout: int = 30,
) -> Tuple[Mapping[str, Any], List[Mapping[str, Any]]]:
    response = requests.get(source_url, timeout=timeout)
    response.raise_for_status()

    payload = response.json()
    if not isinstance(payload, Mapping):
        raise FederalCourtsSyncError("Expected top-level JSON object from PACER court lookup.")

    records = payload.get("data")
    if not isinstance(records, list):
        raise FederalCourtsSyncError("PACER court lookup JSON missing 'data' list.")

    meta = payload.get("meta")
    if not isinstance(meta, Mapping):
        meta = {}

    normalized_records: List[Mapping[str, Any]] = [
        record for record in records if isinstance(record, Mapping)
    ]

    return meta, normalized_records


def _derive_states(counties: Any) -> Tuple[Optional[List[str]], Optional[int]]:
    if not isinstance(counties, list):
        return None, None

    states = sorted(
        {
            str(county.get("state")).strip()
            for county in counties
            if isinstance(county, Mapping) and county.get("state")
        }
    )
    return (states or None), len(counties)


def _prepare_row(
    record: Mapping[str, Any],
    *,
    source_url: str,
    source_last_updated: Optional[str],
) -> Optional[Dict[str, Any]]:
    court_id = str(record.get("court_id", "")).strip()
    if not court_id:
        return None

    states, counties_count = _derive_states(record.get("counties"))

    return {
        "court_id": court_id,
        "title": record.get("title"),
        "court_name": record.get("court_name"),
        "court_type": record.get("type"),
        "circuit": record.get("circuit"),
        "login_url": record.get("login_url"),
        "web_url": record.get("web_url"),
        "rss_url": record.get("rss_url"),
        "software_version": record.get("software_version"),
        "go_live_date": record.get("go_live_date"),
        "pdf_size": record.get("pdf_size"),
        "merge_doc_size": record.get("merge_doc_size"),
        "vcis": record.get("vcis"),
        "states": states,
        "counties_count": counties_count,
        "source_url": source_url,
        "source_last_updated": source_last_updated,
        "raw_json": dict(record),
        "fetched_at": func.now(),
        "updated_at": func.now(),
    }


def upsert_federal_courts(
    engine: Engine,
    federal_courts: Table,
    records: Sequence[Mapping[str, Any]],
    meta: Mapping[str, Any],
    *,
    source_url: str = FEDERAL_COURTS_SOURCE_URL,
) -> FederalCourtUpsertResult:
    source_last_updated_value = meta.get("last_updated") if isinstance(meta, Mapping) else None
    source_last_updated = (
        str(source_last_updated_value).strip() if source_last_updated_value is not None else None
    )

    rows: List[Dict[str, Any]] = []
    for record in records:
        row = _prepare_row(
            record,
            source_url=source_url,
            source_last_updated=source_last_updated,
        )
        if row:
            rows.append(row)

    if not rows:
        return FederalCourtUpsertResult(
            inserted=0,
            updated=0,
            source_last_updated=source_last_updated,
            total_records=0,
        )

    court_ids = [row["court_id"] for row in rows]

    with engine.begin() as conn:
        existing_ids = {
            row["court_id"]
            for row in conn.execute(
                select(federal_courts.c.court_id).where(federal_courts.c.court_id.in_(court_ids))
            ).mappings()
        }

        inserted_count = sum(1 for court_id in court_ids if court_id not in existing_ids)
        updated_count = len(court_ids) - inserted_count

        if engine.dialect.name == "postgresql":
            insert_stmt = pg_insert(federal_courts).values(rows)
            update_columns = {
                column.name: getattr(insert_stmt.excluded, column.name)
                for column in federal_courts.columns
                if column.name
                not in {"id", "court_id", "fetched_at", "updated_at"}
            }
            update_columns["fetched_at"] = func.now()
            update_columns["updated_at"] = func.now()
            conn.execute(
                insert_stmt.on_conflict_do_update(
                    index_elements=[federal_courts.c.court_id],
                    set_=update_columns,
                )
            )
        else:
            for row in rows:
                if row["court_id"] in existing_ids:
                    conn.execute(
                        federal_courts.update()
                        .where(federal_courts.c.court_id == row["court_id"])
                        .values(**row)
                    )
                else:
                    conn.execute(federal_courts.insert().values(**row))

    return FederalCourtUpsertResult(
        inserted=inserted_count,
        updated=updated_count,
        source_last_updated=source_last_updated,
        total_records=len(rows),
    )
