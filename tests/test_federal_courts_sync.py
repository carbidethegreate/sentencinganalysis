import unittest
from unittest.mock import patch

from sqlalchemy import delete, select

from app import create_app
from federal_courts_sync import FEDERAL_COURTS_SOURCE_URL, fetch_federal_courts_json, upsert_federal_courts


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FederalCourtsSyncTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.engine = self.app.engine
        self.table = self.app.federal_courts_table
        with self.engine.begin() as conn:
            conn.execute(delete(self.table))

    def tearDown(self):
        self.ctx.pop()

    def test_fetch_federal_courts_json(self):
        payload = {
            "meta": {"last_updated": "2025-01-02"},
            "data": [{"court_id": "test1", "title": "Test Court"}],
        }
        with patch("federal_courts_sync.requests.get", return_value=DummyResponse(payload)):
            meta, records = fetch_federal_courts_json()
        self.assertEqual(meta["last_updated"], "2025-01-02")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["court_id"], "test1")

    def test_upsert_federal_courts_idempotent(self):
        meta = {"last_updated": "2025-02-03"}
        records = [
            {
                "court_id": "abc",
                "title": "Alpha Court",
                "court_name": "Alpha District",
                "type": "District",
                "login_url": "https://example.com/login",
            },
            {
                "court_id": "xyz",
                "title": "Zeta Court",
                "type": "Bankruptcy",
                "circuit": "9th",
                "counties": [
                    {"name": "Ada", "state": "ID"},
                    {"name": "Multnomah", "state": "OR"},
                ],
                "locations": [
                    {"name": "Portland", "address": "100 Main"},
                ],
                "help_desk": [
                    {"phone": "555-0100", "hours": "9-5"},
                ],
                "flags": {"requires_cso": True},
            },
        ]

        first = upsert_federal_courts(self.engine, self.table, records, meta)
        second = upsert_federal_courts(self.engine, self.table, records, meta)

        self.assertEqual(first.inserted, 2)
        self.assertEqual(first.updated, 0)
        self.assertEqual(second.inserted, 0)
        self.assertEqual(second.updated, 2)

        with self.engine.connect() as conn:
            rows = conn.execute(select(self.table.c.court_id, self.table.c.states, self.table.c.raw_json)).mappings().all()

        self.assertEqual({row["court_id"] for row in rows}, {"abc", "xyz"})
        xyz_row = next(row for row in rows if row["court_id"] == "xyz")
        self.assertEqual(sorted(xyz_row["states"]), ["ID", "OR"])
        self.assertIn("help_desk", xyz_row["raw_json"])
        self.assertEqual(FEDERAL_COURTS_SOURCE_URL, "https://pacer.uscourts.gov/file-case/court-cmecf-lookup/data.json")


if __name__ == "__main__":
    unittest.main()
