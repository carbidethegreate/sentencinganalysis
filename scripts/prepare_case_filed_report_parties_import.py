#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.import_case_filed_report_txt import _hash_record  # type: ignore


def _build_parties_insert_sql(*, parties_csv: Path) -> str:
    parties_csv_abs = str(parties_csv.resolve())
    return f"""\\set ON_ERROR_STOP on

BEGIN;

CREATE TEMP TABLE tmp_party_import (
  case_id integer NOT NULL,
  party_role text,
  party_name text,
  record_hash text NOT NULL,
  data_json text NOT NULL,
  source_last_seen_at timestamptz,
  created_at timestamptz,
  updated_at timestamptz
) ON COMMIT DROP;

\\copy tmp_party_import (case_id, party_role, party_name, record_hash, data_json, source_last_seen_at, created_at, updated_at) FROM '{parties_csv_abs}' WITH (FORMAT csv, HEADER true);

SELECT count(*) AS staged_parties FROM tmp_party_import;
SELECT count(*) AS would_insert
FROM tmp_party_import t
LEFT JOIN pcl_parties p
  ON p.record_hash = t.record_hash
WHERE p.id IS NULL;

INSERT INTO pcl_parties (
  created_at,
  updated_at,
  case_id,
  last_name,
  first_name,
  middle_name,
  party_type,
  party_role,
  party_name,
  last_search_run_id,
  last_search_run_at,
  source_last_seen_at,
  record_hash,
  data_json
)
SELECT
  COALESCE(created_at, now()),
  COALESCE(updated_at, now()),
  case_id,
  NULL,
  NULL,
  NULL,
  NULL,
  NULLIF(party_role, ''),
  NULLIF(party_name, ''),
  NULL,
  NULL,
  COALESCE(source_last_seen_at, now()),
  record_hash,
  data_json
FROM tmp_party_import
ON CONFLICT (record_hash) DO NOTHING;

COMMIT;
"""


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare party import CSV (pcl_parties) by joining parties_basic.csv with case_id_mapping.tsv."
    )
    parser.add_argument("--mapping", required=True, help="Path to <court>_case_id_mapping.tsv (from the cases upsert step)")
    parser.add_argument("--parties-basic", required=True, help="Path to <court>_parties_basic.csv (from prepare step)")
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Output directory (will write <court>_parties_import.csv and <court>_parties_insert.sql).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    mapping_path = Path(args.mapping).expanduser().resolve()
    parties_basic_path = Path(args.parties_basic).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not mapping_path.exists():
        raise SystemExit(f"Mapping file not found: {mapping_path}")
    if not parties_basic_path.exists():
        raise SystemExit(f"Parties file not found: {parties_basic_path}")

    # Load mapping (case_number_full -> id).
    mapping: Dict[str, int] = {}
    with mapping_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            cn = (row.get("case_number_full") or "").strip()
            case_id_raw = (row.get("id") or "").strip()
            if not cn or not case_id_raw:
                continue
            try:
                mapping[cn] = int(case_id_raw)
            except ValueError:
                continue

    now = datetime.now(timezone.utc)

    out_rows = []
    skipped_missing_case = 0
    with parties_basic_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cn = (row.get("case_number_full") or "").strip()
            party_name = (row.get("party_name") or "").strip()
            party_role = (row.get("party_role") or "").strip()
            case_pk = mapping.get(cn)
            if not case_pk:
                skipped_missing_case += 1
                continue

            record_hash = _hash_record(
                [
                    case_pk,
                    None,  # last_name
                    None,  # first_name
                    None,  # middle_name
                    None,  # party_type
                    party_role or None,
                    party_name or None,
                ]
            )
            data_json = json.dumps(
                {
                    "case_number_full": cn,
                    "party_role": party_role or None,
                    "party_name": party_name or None,
                },
                sort_keys=True,
                default=str,
            )
            out_rows.append(
                {
                    "case_id": case_pk,
                    "party_role": party_role,
                    "party_name": party_name,
                    "record_hash": record_hash,
                    "data_json": data_json,
                    "source_last_seen_at": now.isoformat(),
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                }
            )

    parties_import_csv = out_dir / "parties_import.csv"
    fieldnames = [
        "case_id",
        "party_role",
        "party_name",
        "record_hash",
        "data_json",
        "source_last_seen_at",
        "created_at",
        "updated_at",
    ]
    with parties_import_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in out_rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    parties_sql = out_dir / "parties_insert.sql"
    parties_sql.write_text(_build_parties_insert_sql(parties_csv=parties_import_csv), encoding="utf-8")

    summary = {
        "mapping_path": str(mapping_path),
        "mapped_case_count": len(mapping),
        "parties_basic_path": str(parties_basic_path),
        "parties_prepared": len(out_rows),
        "parties_skipped_missing_case": skipped_missing_case,
        "outputs": {
            "parties_import_csv": str(parties_import_csv),
            "parties_insert_sql": str(parties_sql),
        },
    }
    (out_dir / "parties_prepare_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
