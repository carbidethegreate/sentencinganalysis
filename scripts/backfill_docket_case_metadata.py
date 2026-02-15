#!/usr/bin/env python3
"""
Backfill case-list metadata derived from docket header fields.

Why:
- Some normalized fields (like `pcl_cases.judge_last_name`) are often missing in PCL
  search results, but become available once we pull a docket report (assigned judge,
  parties/counsel counts, etc.).
- Older enriched cases may already have `docket_header_fields` stored, but not the
  newer derived fields used by the attorney-friendly card view.

What it does:
- Reads `pcl_case_fields.docket_header_fields`.
- Writes derived case fields:
  - docket_judges (list)
  - docket_party_count (int)
  - docket_attorney_count (int)
- Backfills `pcl_cases.judge_last_name` when missing.

Safe to run multiple times.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import MetaData, create_engine, select, update

from app import build_database_url
from docket_enrichment import (
    _extract_judge_display_list,
    _guess_last_name_from_judge_label,
    _upsert_case_field,
)
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
    parser.add_argument("--limit", type=int, default=0, help="Optional limit (0 = no limit).")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing.")
    args = parser.parse_args()

    engine = create_engine(build_database_url(), future=True, pool_pre_ping=True)
    metadata = MetaData()
    tables = build_pcl_tables(metadata)
    pcl_cases = tables["pcl_cases"]
    pcl_case_fields = tables["pcl_case_fields"]

    stmt = (
        select(
            pcl_cases.c.id.label("case_id"),
            pcl_cases.c.judge_last_name,
            pcl_case_fields.c.field_value_json.label("header_fields"),
        )
        .select_from(
            pcl_case_fields.join(pcl_cases, pcl_case_fields.c.case_id == pcl_cases.c.id)
        )
        .where(pcl_case_fields.c.field_name == "docket_header_fields")
        .order_by(pcl_cases.c.id.asc())
    )
    if args.limit and args.limit > 0:
        stmt = stmt.limit(args.limit)

    now = datetime.utcnow()
    scanned = 0
    updated_cases = 0
    upserted_fields = 0

    with engine.begin() as conn:
        rows = conn.execute(stmt).mappings().all()
        for row in rows:
            scanned += 1
            case_id = int(row["case_id"])
            header_fields = _coerce_header_fields(row.get("header_fields"))
            if not header_fields:
                continue

            judges = _extract_judge_display_list(header_fields)
            party_count = header_fields.get("party_count")
            attorney_count = header_fields.get("attorney_count")

            judge_last_name_existing = (row.get("judge_last_name") or "").strip()
            judge_last_name_new = ""
            if judges and not judge_last_name_existing:
                judge_last_name_new = _guess_last_name_from_judge_label(judges[0])

            would_change = bool(judges) or isinstance(party_count, int) or isinstance(attorney_count, int) or bool(judge_last_name_new)
            if not would_change:
                continue

            if args.dry_run:
                print(
                    f"[DRY] case_id={case_id} judges={len(judges)} party_count={party_count!r} attorney_count={attorney_count!r} backfill_last={judge_last_name_new!r}"
                )
                continue

            if judges:
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_judges",
                    field_value_text=" | ".join(judges),
                    field_value_json=judges,
                    now=now,
                )
                upserted_fields += 1
            if isinstance(party_count, int):
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_party_count",
                    field_value_text=str(party_count),
                    field_value_json=party_count,
                    now=now,
                )
                upserted_fields += 1
            if isinstance(attorney_count, int):
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_attorney_count",
                    field_value_text=str(attorney_count),
                    field_value_json=attorney_count,
                    now=now,
                )
                upserted_fields += 1
            if judge_last_name_new:
                conn.execute(
                    update(pcl_cases)
                    .where(pcl_cases.c.id == case_id)
                    .values(judge_last_name=judge_last_name_new, updated_at=now)
                )
                updated_cases += 1

    print(
        f"Backfill complete. scanned={scanned} upserted_fields={upserted_fields} updated_cases={updated_cases} dry_run={args.dry_run}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

