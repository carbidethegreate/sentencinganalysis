from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import Table, select, update

DEFAULT_PCL_COURTS_PATH = Path(__file__).resolve().parent / "data" / "pcl_courts.json"


def load_pcl_courts_catalog(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    source_path = path or DEFAULT_PCL_COURTS_PATH
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("PCL court catalog must be a list of court entries.")
    return [row for row in payload if isinstance(row, dict)]


def seed_pcl_courts(
    engine,
    table: Table,
    courts: Iterable[Dict[str, Any]],
) -> Dict[str, int]:
    normalized: List[Dict[str, Any]] = []
    for row in courts:
        pcl_court_id = str(row.get("pcl_court_id") or "").strip().lower()
        name = str(row.get("name") or "").strip()
        if not pcl_court_id or not name:
            continue
        normalized.append(
            {
                "pcl_court_id": pcl_court_id,
                "name": name,
                "active": bool(row.get("active", True)),
                "source": str(row.get("source") or "PCL Appendix A").strip(),
            }
        )
    if not normalized:
        return {"inserted": 0, "updated": 0, "skipped": 0}

    with engine.begin() as conn:
        existing_rows = (
            conn.execute(
                select(
                    table.c.pcl_court_id,
                    table.c.name,
                    table.c.active,
                    table.c.source,
                ).where(table.c.pcl_court_id.in_([row["pcl_court_id"] for row in normalized]))
            )
            .mappings()
            .all()
        )
        existing = {row["pcl_court_id"]: row for row in existing_rows}
        inserted = 0
        updated = 0
        skipped = 0
        for row in normalized:
            current = existing.get(row["pcl_court_id"])
            if not current:
                conn.execute(table.insert().values(**row))
                inserted += 1
                continue
            if (
                current["name"] == row["name"]
                and bool(current["active"]) == bool(row["active"])
                and (current["source"] or "") == row["source"]
            ):
                skipped += 1
                continue
            conn.execute(
                update(table)
                .where(table.c.pcl_court_id == row["pcl_court_id"])
                .values(name=row["name"], active=row["active"], source=row["source"])
            )
            updated += 1

    return {"inserted": inserted, "updated": updated, "skipped": skipped}
