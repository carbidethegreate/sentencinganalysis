#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Ensure repo root is importable when running via `python3 scripts/...`.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reuse the battle-tested parser/aggregator from the main importer.
from scripts.import_case_filed_report_txt import (  # type: ignore
    _aggregate_cases,
    _normalize_ws,
    _read_rows,
    _write_csv,
)


def _safe_stem(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "").strip("_") or "input"


def _as_iso_date(value: Any) -> str:
    if value is None:
        return ""
    # date / datetime -> ISO
    try:
        return value.isoformat()  # type: ignore[attr-defined]
    except Exception:
        return str(value)


def _as_iso_dt(value: Any) -> str:
    if value is None:
        return ""
    try:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.isoformat()
    except Exception:
        pass
    return str(value)


def _build_cases_upsert_sql(
    *,
    cases_csv: Path,
    mapping_tsv: Path,
) -> str:
    # NOTE: This file is meant to be executed via:
    #   render psql <postgres-id> -- -v ON_ERROR_STOP=1 -f <this.sql>
    cases_csv_abs = str(cases_csv.resolve())
    mapping_tsv_abs = str(mapping_tsv.resolve())

    # Temp tables keep the import isolated and avoid any schema changes.
    return f"""\\set ON_ERROR_STOP on

BEGIN;

CREATE TEMP TABLE tmp_case_import (
  court_id text NOT NULL,
  case_id text,
  case_number text NOT NULL,
  case_number_full text NOT NULL,
  case_type text,
  date_filed date,
  date_closed date,
  effective_date_closed date,
  short_title text,
  case_title text,
  case_link text,
  case_year text,
  case_office text,
  judge_last_name text,
  source_last_seen_at timestamptz,
  record_hash text,
  data_json text NOT NULL
) ON COMMIT DROP;

\\copy tmp_case_import (court_id, case_id, case_number, case_number_full, case_type, date_filed, date_closed, effective_date_closed, short_title, case_title, case_link, case_year, case_office, judge_last_name, source_last_seen_at, record_hash, data_json) FROM '{cases_csv_abs}' WITH (FORMAT csv, HEADER true);

SELECT count(*) AS staged_cases FROM tmp_case_import;
SELECT count(*) AS would_insert
FROM tmp_case_import t
LEFT JOIN pcl_cases c
  ON c.court_id = t.court_id
 AND c.case_number_full = t.case_number_full
WHERE c.id IS NULL;

INSERT INTO pcl_cases (
  court_id,
  case_id,
  case_number,
  case_number_full,
  case_type,
  date_filed,
  date_closed,
  effective_date_closed,
  short_title,
  case_title,
  case_link,
  case_year,
  case_office,
  judge_last_name,
  source_last_seen_at,
  record_hash,
  data_json,
  created_at,
  updated_at
)
SELECT
  court_id,
  NULLIF(case_id, ''),
  case_number,
  case_number_full,
  NULLIF(case_type, ''),
  date_filed,
  date_closed,
  effective_date_closed,
  NULLIF(short_title, ''),
  NULLIF(case_title, ''),
  NULLIF(case_link, ''),
  NULLIF(case_year, ''),
  NULLIF(case_office, ''),
  NULLIF(judge_last_name, ''),
  COALESCE(source_last_seen_at, now()),
  NULLIF(record_hash, ''),
  data_json,
  now(),
  now()
FROM tmp_case_import
ON CONFLICT (court_id, case_number_full) DO UPDATE SET
  updated_at = EXCLUDED.updated_at,
  case_id = EXCLUDED.case_id,
  case_number = EXCLUDED.case_number,
  case_type = EXCLUDED.case_type,
  date_filed = EXCLUDED.date_filed,
  date_closed = EXCLUDED.date_closed,
  effective_date_closed = EXCLUDED.effective_date_closed,
  short_title = EXCLUDED.short_title,
  case_title = EXCLUDED.case_title,
  case_link = EXCLUDED.case_link,
  case_year = EXCLUDED.case_year,
  case_office = EXCLUDED.case_office,
  judge_last_name = EXCLUDED.judge_last_name,
  source_last_seen_at = EXCLUDED.source_last_seen_at,
  record_hash = EXCLUDED.record_hash,
  data_json = EXCLUDED.data_json;

\\copy (SELECT c.id, c.case_number_full FROM pcl_cases c JOIN tmp_case_import t ON t.court_id = c.court_id AND t.case_number_full = c.case_number_full ORDER BY c.id ASC) TO '{mapping_tsv_abs}' WITH (FORMAT csv, DELIMITER E'\\t', HEADER true);

COMMIT;
"""


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare CaseFiledRPT pipe-delimited .txt for Render psql import (writes import CSVs + SQL scripts)."
    )
    parser.add_argument("--court-id", required=True, help="Court ID, e.g. paedc or vidc")
    parser.add_argument("--input", required=True, help="Path to CaseFiledRPT (*.txt)")
    parser.add_argument(
        "--out-dir",
        default="output/spreadsheet/case_filed_report",
        help="Output directory (will create a dated subfolder).",
    )
    parser.add_argument(
        "--source",
        default="case_filed_report_txt",
        help="Source label to store in pcl_cases.data_json",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    court_id = str(args.court_id).strip().lower()
    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    out_dir = Path(args.out_dir).expanduser().resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_dir = out_dir / f"{stamp}_{court_id}_{_safe_stem(input_path.stem)}"
    run_dir.mkdir(parents=True, exist_ok=True)

    headers, rows = _read_rows(input_path)
    normalized_rows = [{k: _normalize_ws(v) for k, v in row.items()} for row in rows]

    # 1) Row-level normalized CSV (audit).
    rows_csv = run_dir / f"{court_id}_rows_normalized.csv"
    _write_csv(rows_csv, normalized_rows, headers)

    # 2) Aggregate to case-level records + party list.
    case_records, party_records = _aggregate_cases(
        rows=normalized_rows, court_id=court_id, source_label=str(args.source)
    )

    # 3) User-friendly case review CSV.
    review_headers = [
        "court_id",
        "case_number_full",
        "case_id",
        "case_link",
        "case_type",
        "date_filed",
        "date_closed",
        "judge_full_name",
        "judge_last_name",
        "short_title",
        "party_count",
        "parties",
        "raw_case_key",
    ]
    review_rows: List[Dict[str, Any]] = []
    for c in case_records:
        payload = {}
        try:
            payload = json.loads(c.get("data_json") or "{}")
        except Exception:
            payload = {}
        parties = payload.get("parties") if isinstance(payload, dict) else []
        if not isinstance(parties, list):
            parties = []
        judge_full = payload.get("pre_judge_name") if isinstance(payload, dict) else None
        raw_case_key = payload.get("raw_case_key") if isinstance(payload, dict) else None
        review_rows.append(
            {
                "court_id": c.get("court_id"),
                "case_number_full": c.get("case_number_full"),
                "case_id": c.get("case_id") or "",
                "case_link": c.get("case_link") or "",
                "case_type": c.get("case_type") or "",
                "date_filed": _as_iso_date(c.get("date_filed")),
                "date_closed": _as_iso_date(c.get("date_closed")),
                "judge_full_name": judge_full or "",
                "judge_last_name": c.get("judge_last_name") or "",
                "short_title": c.get("short_title") or "",
                "party_count": len(parties),
                "parties": " | ".join(parties[:75]) + (" | …" if len(parties) > 75 else ""),
                "raw_case_key": raw_case_key or "",
            }
        )
    cases_review_csv = run_dir / f"{court_id}_cases_review.csv"
    _write_csv(cases_review_csv, review_rows, review_headers)

    # 4) DB import CSV (pcl_cases).
    cases_import_headers = [
        "court_id",
        "case_id",
        "case_number",
        "case_number_full",
        "case_type",
        "date_filed",
        "date_closed",
        "effective_date_closed",
        "short_title",
        "case_title",
        "case_link",
        "case_year",
        "case_office",
        "judge_last_name",
        "source_last_seen_at",
        "record_hash",
        "data_json",
    ]
    cases_import_rows: List[Dict[str, Any]] = []
    for c in case_records:
        cases_import_rows.append(
            {
                "court_id": c.get("court_id") or court_id,
                "case_id": c.get("case_id") or "",
                "case_number": c.get("case_number") or "",
                "case_number_full": c.get("case_number_full") or "",
                "case_type": c.get("case_type") or "",
                "date_filed": _as_iso_date(c.get("date_filed")),
                "date_closed": _as_iso_date(c.get("date_closed")),
                "effective_date_closed": _as_iso_date(c.get("effective_date_closed")),
                "short_title": c.get("short_title") or "",
                "case_title": c.get("case_title") or "",
                "case_link": c.get("case_link") or "",
                "case_year": c.get("case_year") or "",
                "case_office": c.get("case_office") or "",
                "judge_last_name": c.get("judge_last_name") or "",
                "source_last_seen_at": _as_iso_dt(c.get("source_last_seen_at")),
                "record_hash": c.get("record_hash") or "",
                "data_json": c.get("data_json") or "{}",
            }
        )
    cases_import_csv = run_dir / f"{court_id}_cases_import.csv"
    _write_csv(cases_import_csv, cases_import_rows, cases_import_headers)

    # 5) Parties basic CSV (resolved to case_id later via mapping).
    parties_headers = ["court_id", "case_number_full", "party_role", "party_name"]
    parties_rows: List[Dict[str, Any]] = []
    for p in party_records:
        parties_rows.append(
            {
                "court_id": court_id,
                "case_number_full": p.get("case_number_full") or "",
                "party_role": p.get("party_role") or "",
                "party_name": p.get("party_name") or "",
            }
        )
    parties_basic_csv = run_dir / f"{court_id}_parties_basic.csv"
    _write_csv(parties_basic_csv, parties_rows, parties_headers)

    # 6) SQL script to upsert cases + emit mapping TSV.
    mapping_tsv = run_dir / f"{court_id}_case_id_mapping.tsv"
    cases_sql = run_dir / f"{court_id}_cases_upsert.sql"
    cases_sql.write_text(
        _build_cases_upsert_sql(cases_csv=cases_import_csv, mapping_tsv=mapping_tsv),
        encoding="utf-8",
    )

    meta = {
        "input": str(input_path),
        "court_id": court_id,
        "rows_read": len(rows),
        "unique_cases_aggregated": len(case_records),
        "party_rows_aggregated": len(party_records),
        "outputs": {
            "rows_csv": str(rows_csv),
            "cases_review_csv": str(cases_review_csv),
            "cases_import_csv": str(cases_import_csv),
            "parties_basic_csv": str(parties_basic_csv),
            "cases_upsert_sql": str(cases_sql),
            "case_id_mapping_tsv": str(mapping_tsv),
        },
    }
    (run_dir / "prepare_summary.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
