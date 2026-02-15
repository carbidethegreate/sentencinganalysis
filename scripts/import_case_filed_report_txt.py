#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import MetaData, create_engine, func, inspect, select, update
from sqlalchemy.exc import SQLAlchemyError

# Ensure repo root is importable when running via `python3 scripts/...`.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app import build_database_url  # noqa: E402
from pcl_models import build_pcl_tables  # noqa: E402


@dataclass(frozen=True)
class ParsedCaseNumber:
    office: str
    year: str
    case_type: str
    seq: str  # zero-padded numeric string (len>=1)

    @property
    def case_number_full(self) -> str:
        # Match PCL style used elsewhere in the app: 2:2026cr00063
        seq = self.seq.zfill(5)
        return f"{self.office}:{self.year}{self.case_type}{seq}"

    @property
    def case_number(self) -> str:
        try:
            return str(int(self.seq))
        except ValueError:
            return self.seq.lstrip("0") or self.seq


def _hash_record(parts: Sequence[Any]) -> str:
    hashed = hashlib.sha256()
    for part in parts:
        text = "" if part is None else str(part)
        hashed.update(text.encode("utf-8"))
        hashed.update(b"|")
    return hashed.hexdigest()


def _parse_mmddyyyy(value: str) -> Optional[date]:
    text = (value or "").strip()
    if not text:
        return None
    # Report exports appear as MM/DD/YYYY.
    try:
        return datetime.strptime(text, "%m/%d/%Y").date()
    except ValueError:
        return None


def _normalize_ws(value: Optional[str]) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\t", " ").split()).strip()


def _two_digit_year_to_four(year2: str) -> str:
    year2 = year2.strip()
    if len(year2) != 2 or not year2.isdigit():
        return year2
    y = int(year2)
    # Conservative pivot: 00-30 => 2000-2030, otherwise 1900s.
    return str(2000 + y if y <= 30 else 1900 + y)


_CASE_NUMBER_RE = re.compile(
    r"^(?P<office>[A-Za-z0-9]+):(?P<year>\d{2,4})-(?P<type>[A-Za-z]{1,6})-(?P<seq>\d+)"
)


def _parse_case_number(raw: str) -> Optional[ParsedCaseNumber]:
    text = _normalize_ws(raw)
    if not text:
        return None

    match = _CASE_NUMBER_RE.search(text)
    if not match:
        # Some inputs may omit dashes or include other separators; fall back to digit scan.
        # Expected canonical is already like 2:2026cr00063; handle that too.
        m2 = re.search(
            r"^(?P<office>[A-Za-z0-9]+):(?P<year>\d{4})(?P<type>[A-Za-z]{1,6})(?P<seq>\d+)$",
            text,
        )
        if not m2:
            return None
        office = m2.group("office")
        year = m2.group("year")
        case_type = m2.group("type").lower()
        seq = m2.group("seq")
        return ParsedCaseNumber(office=office, year=year, case_type=case_type, seq=seq)

    office = match.group("office")
    year = match.group("year")
    if len(year) == 2:
        year = _two_digit_year_to_four(year)
    case_type = match.group("type").lower()
    seq = match.group("seq")
    return ParsedCaseNumber(office=office, year=year, case_type=case_type, seq=seq)


def _judge_last_name(full_name: str) -> Optional[str]:
    text = _normalize_ws(full_name)
    if not text:
        return None
    # Strip suffixes like ", III" which would otherwise break last-name extraction.
    if "," in text:
        text = text.split(",", 1)[0].strip()
    parts = [p for p in text.split(" ") if p]
    return parts[-1] if parts else None


def _case_link_for(court_id: str, case_id: str) -> Optional[str]:
    court = (court_id or "").strip().lower()
    case_id = (case_id or "").strip()
    if not court or not case_id:
        return None
    # Expand as needed; current import covers PAEDC and VIDC.
    host_map = {
        "paedc": "ecf.paed.uscourts.gov",
        "vidc": "ecf.vid.uscourts.gov",
        # Optional (kept for compatibility with existing sample data):
        "vibk": "ecf.vib.uscourts.gov",
        "vibk1": "ecf.vib.uscourts.gov",
    }
    host = host_map.get(court)
    if not host:
        return None
    return f"https://{host}/cgi-bin/iqquerymenu.pl?{case_id}"


def _read_rows(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter="|")
        headers = list(reader.fieldnames or [])
        rows = [{k: (v or "") for k, v in row.items()} for row in reader]
    return headers, rows


def _write_csv(path: Path, rows: Iterable[Dict[str, Any]], headers: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(headers))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in headers})


def _aggregate_cases(
    *, rows: Sequence[Dict[str, str]], court_id: str, source_label: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        raw_key = (
            row.get("cs_sort_case_numb")
            or row.get("lead_case_number")
            or row.get("cs_case_number")
            or ""
        )
        key = _normalize_ws(raw_key)
        if not key:
            continue
        grouped[key].append(row)

    now = datetime.now(timezone.utc)
    case_records: List[Dict[str, Any]] = []
    party_records: List[Dict[str, Any]] = []

    for raw_case_key, bucket in grouped.items():
        parsed = _parse_case_number(raw_case_key) or _parse_case_number(
            _normalize_ws(bucket[0].get("cs_case_number") or "")
        )
        if not parsed:
            # Skip unparseable case numbers; keep a minimal record for audit.
            continue

        # Prefer lead case id when available; fall back to row case id.
        lead_caseid = _normalize_ws(bucket[0].get("lead_caseid") or "")
        cs_caseid = _normalize_ws(bucket[0].get("cs_caseid") or "")
        chosen_caseid = lead_caseid or cs_caseid
        case_link = _case_link_for(court_id, chosen_caseid)

        short_title = _normalize_ws(bucket[0].get("cs_short_title") or "")
        if not short_title:
            short_title = _normalize_ws(bucket[0].get("lead_short_title") or "")

        pre_judge = _normalize_ws(bucket[0].get("pre_judge_name") or "")
        judge_last = _judge_last_name(pre_judge) or None

        parties = sorted(
            {p for p in (_normalize_ws(row.get("party") or "") for row in bucket) if p}
        )

        payload = {
            "source": source_label,
            "court_id": court_id,
            "raw_case_key": raw_case_key,
            "cs_sort_case_numb": _normalize_ws(bucket[0].get("cs_sort_case_numb") or ""),
            "cs_case_number": _normalize_ws(bucket[0].get("cs_case_number") or ""),
            "lead_case_number": _normalize_ws(bucket[0].get("lead_case_number") or ""),
            "lead_caseid": lead_caseid or None,
            "cs_caseid": cs_caseid or None,
            "all_cs_caseids": sorted(
                {
                    _normalize_ws(row.get("cs_caseid") or "")
                    for row in bucket
                    if _normalize_ws(row.get("cs_caseid") or "")
                }
            ),
            "office_trans": _normalize_ws(bucket[0].get("office_trans") or "") or None,
            "pre_judge_name": pre_judge or None,
            "ref_judge_name": _normalize_ws(bucket[0].get("ref_judge_name") or "") or None,
            "parties": parties,
            "row_count": len(bucket),
        }
        data_json = json.dumps(payload, sort_keys=True, default=str)

        case_type_value = _normalize_ws(bucket[0].get("cs_type") or "") or parsed.case_type
        case_type_value = case_type_value.strip().lower()

        date_filed = _parse_mmddyyyy(bucket[0].get("cs_date_filed") or "") or _parse_mmddyyyy(
            bucket[0].get("lead_date_filed") or ""
        )
        date_term = _parse_mmddyyyy(bucket[0].get("cs_date_term") or "") or _parse_mmddyyyy(
            bucket[0].get("lead_date_term") or ""
        )

        case_records.append(
            {
                "court_id": court_id,
                "case_id": chosen_caseid or None,
                "case_number": parsed.case_number,
                "case_number_full": parsed.case_number_full,
                "case_type": case_type_value,
                "date_filed": date_filed,
                "date_closed": date_term,
                "effective_date_closed": date_term,
                "short_title": short_title or None,
                "case_title": short_title or None,
                "case_link": case_link,
                "case_year": parsed.year,
                "case_office": parsed.office,
                "judge_last_name": judge_last,
                "record_hash": _hash_record([court_id, parsed.case_number_full, data_json]),
                "data_json": data_json,
                "source_last_seen_at": now,
            }
        )

        # Build party records (insert later once case PKs are known).
        for party_name in parties:
            party_records.append(
                {
                    "case_number_full": parsed.case_number_full,
                    "party_name": party_name,
                    # Defendants in this report. Keep type empty; docket pulls will enrich further.
                    "party_role": "defendant",
                }
            )

    return case_records, party_records


def _upsert_cases_and_parties(
    *,
    engine: Any,
    tables: Dict[str, Any],
    cases: Sequence[Dict[str, Any]],
    parties: Sequence[Dict[str, Any]],
    court_id: str,
) -> Dict[str, Any]:
    pcl_cases = tables["pcl_cases"]
    pcl_parties = tables["pcl_parties"]

    now = datetime.now(timezone.utc)

    # Build a lookup of existing cases for this court.
    with engine.begin() as conn:
        existing = {
            str(row["case_number_full"]): int(row["id"])
            for row in conn.execute(
                select(pcl_cases.c.id, pcl_cases.c.case_number_full).where(
                    pcl_cases.c.court_id == court_id
                )
            ).mappings()
        }

    inserted = 0
    updated = 0
    case_pk_by_number: Dict[str, int] = {}

    with engine.begin() as conn:
        for record in cases:
            cn_full = str(record["case_number_full"])
            existing_id = existing.get(cn_full)
            payload = {**record, "updated_at": now}
            if existing_id:
                conn.execute(update(pcl_cases).where(pcl_cases.c.id == existing_id).values(**payload))
                case_pk_by_number[cn_full] = existing_id
                updated += 1
                continue

            payload = {**payload, "created_at": now}
            result = conn.execute(pcl_cases.insert().values(**payload))
            new_id = int(result.inserted_primary_key[0])
            existing[cn_full] = new_id
            case_pk_by_number[cn_full] = new_id
            inserted += 1

        # Insert parties. Deduplicate within the import run by hash.
        party_inserted = 0
        party_skipped = 0
        seen_hashes: set[str] = set()
        for party in parties:
            cn_full = str(party.get("case_number_full") or "")
            case_pk = case_pk_by_number.get(cn_full) or existing.get(cn_full)
            if not case_pk:
                party_skipped += 1
                continue
            party_name = party.get("party_name")
            party_role = party.get("party_role")
            record_hash = _hash_record(
                [
                    case_pk,
                    None,  # last_name
                    None,  # first_name
                    None,  # middle_name
                    None,  # party_type
                    party_role,
                    party_name,
                ]
            )
            if record_hash in seen_hashes:
                party_skipped += 1
                continue
            seen_hashes.add(record_hash)
            try:
                conn.execute(
                    pcl_parties.insert().values(
                        created_at=now,
                        updated_at=now,
                        case_id=case_pk,
                        last_name=None,
                        first_name=None,
                        middle_name=None,
                        party_type=None,
                        party_role=party_role,
                        party_name=party_name,
                        last_search_run_id=None,
                        last_search_run_at=None,
                        source_last_seen_at=now,
                        record_hash=record_hash,
                        data_json=json.dumps(party, sort_keys=True, default=str),
                    )
                )
                party_inserted += 1
            except SQLAlchemyError:
                # Likely uniqueness hit on record_hash; skip.
                party_skipped += 1

    return {
        "cases_inserted": inserted,
        "cases_updated": updated,
        "parties_inserted": party_inserted,
        "parties_skipped": party_skipped,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import PACER Case Filed Report .txt (pipe-delimited) into pcl_cases/pcl_parties and write a clean CSV summary."
    )
    parser.add_argument("--court-id", required=True, help="Court ID, e.g. paedc or vidc")
    parser.add_argument("--input", required=True, help="Path to CaseFiledRPT (*.txt)")
    parser.add_argument(
        "--out-dir",
        default="data/manual_import",
        help="Output directory (will create a subfolder).",
    )
    parser.add_argument("--source", default="case_filed_report_txt", help="Source label to store in data_json")
    args = parser.parse_args(list(argv) if argv is not None else None)

    court_id = str(args.court_id).strip().lower()
    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    out_dir = Path(args.out_dir).expanduser().resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", input_path.stem)
    run_dir = out_dir / f"{stamp}_{court_id}_{safe_name}"
    run_dir.mkdir(parents=True, exist_ok=True)

    headers, rows = _read_rows(input_path)
    normalized_rows = [{k: _normalize_ws(v) for k, v in row.items()} for row in rows]

    # Write a normalized row-level CSV for audit.
    rows_csv = run_dir / f"{court_id}_rows.csv"
    _write_csv(rows_csv, normalized_rows, headers)

    case_records, party_records = _aggregate_cases(
        rows=normalized_rows, court_id=court_id, source_label=args.source
    )

    # Write a case-level summary CSV for easy review.
    summary_headers = [
        "court_id",
        "case_number_full",
        "case_id",
        "case_link",
        "case_type",
        "date_filed",
        "date_closed",
        "judge_last_name",
        "short_title",
        "party_count",
        "parties",
    ]
    summary_rows = []
    for c in case_records:
        payload = json.loads(c.get("data_json") or "{}")
        parties = payload.get("parties") if isinstance(payload, dict) else []
        if not isinstance(parties, list):
            parties = []
        summary_rows.append(
            {
                "court_id": c.get("court_id"),
                "case_number_full": c.get("case_number_full"),
                "case_id": c.get("case_id"),
                "case_link": c.get("case_link"),
                "case_type": c.get("case_type"),
                "date_filed": c.get("date_filed"),
                "date_closed": c.get("date_closed"),
                "judge_last_name": c.get("judge_last_name"),
                "short_title": c.get("short_title"),
                "party_count": len(parties),
                "parties": " | ".join(parties[:50]) + (" | …" if len(parties) > 50 else ""),
            }
        )
    summary_csv = run_dir / f"{court_id}_cases.csv"
    _write_csv(summary_csv, summary_rows, summary_headers)

    # Import into the app DB.
    database_url = build_database_url()
    engine = create_engine(database_url, future=True, pool_pre_ping=True)
    metadata = MetaData()
    tables = build_pcl_tables(metadata)
    # Ensure PCL tables exist (safe if already created).
    metadata.create_all(engine, tables=list(tables.values()))

    stats = _upsert_cases_and_parties(
        engine=engine,
        tables=tables,
        cases=case_records,
        parties=party_records,
        court_id=court_id,
    )

    info = {
        "input": str(input_path),
        "court_id": court_id,
        "rows_read": len(rows),
        "cases_aggregated": len(case_records),
        "parties_aggregated": len(party_records),
        "rows_csv": str(rows_csv),
        "cases_csv": str(summary_csv),
        "database_url": database_url,
        "import_stats": stats,
    }
    (run_dir / "import_summary.json").write_text(
        json.dumps(info, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )

    print(json.dumps(info, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
