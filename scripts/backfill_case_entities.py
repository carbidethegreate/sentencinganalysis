#!/usr/bin/env python3
"""
Backfill normalized case_entities from already-saved docket header fields.

Why:
- `pcl_case_fields.field_value_text` summaries (like docket_party_summary) may be
  truncated for index safety, which can cause searches to miss counsel/party
  names that appear later in a long summary.
- `case_entities` is a compact, future-proof, normalized table that stores
  Judges / Parties / Counsel / Charges as individual searchable rows.

Safe to run multiple times.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import MetaData, create_engine, inspect, select

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import build_database_url
from docket_enrichment import _build_case_entities_from_header_fields, _refresh_case_entities
from pcl_models import build_pcl_tables


def _coerce_header_fields(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--limit", type=int, default=0, help="Optional limit (0 = no limit).")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    batch_size = max(1, min(int(args.batch_size or 250), 2000))
    limit = int(args.limit or 0)

    engine = create_engine(build_database_url(), future=True, pool_pre_ping=True)
    metadata = MetaData()
    tables = build_pcl_tables(metadata)
    pcl_case_fields = tables.get("pcl_case_fields")
    case_entities = tables.get("case_entities")
    if pcl_case_fields is None or case_entities is None:
        raise RuntimeError("Missing required table definitions (pcl_case_fields / case_entities).")

    inspector = inspect(engine)
    if not inspector.has_table(case_entities.name):
        # Ensure the table exists even if migrations haven't been applied yet.
        metadata.create_all(engine, tables=[case_entities])

    scanned = 0
    refreshed = 0
    inserted_entities = 0

    last_case_id = 0
    while True:
        stmt = (
            select(pcl_case_fields.c.case_id, pcl_case_fields.c.field_value_json)
            .where(
                pcl_case_fields.c.field_name == "docket_header_fields",
                pcl_case_fields.c.case_id > last_case_id,
            )
            .order_by(pcl_case_fields.c.case_id.asc())
            .limit(batch_size)
        )

        with engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
            if not rows:
                break

            for row in rows:
                scanned += 1
                case_id = int(row["case_id"])
                header_fields = _coerce_header_fields(row.get("field_value_json"))
                last_case_id = case_id
                if not header_fields:
                    continue

                if args.dry_run:
                    would = len(_build_case_entities_from_header_fields(header_fields))
                    print(f"[DRY] case_id={case_id} entities={would}")
                    continue

                inserted = _refresh_case_entities(
                    conn,
                    case_entities,
                    case_id=case_id,
                    header_fields=header_fields,
                )
                if inserted > 0:
                    refreshed += 1
                    inserted_entities += inserted

                if limit > 0 and refreshed >= limit:
                    return _finish(scanned, refreshed, inserted_entities, dry_run=args.dry_run)

    return _finish(scanned, refreshed, inserted_entities, dry_run=args.dry_run)


def _finish(scanned: int, refreshed: int, inserted_entities: int, *, dry_run: bool) -> int:
    print(
        "Backfill complete."
        f" scanned={scanned}"
        f" refreshed_cases={refreshed}"
        f" inserted_entities={inserted_entities}"
        f" dry_run={dry_run}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
