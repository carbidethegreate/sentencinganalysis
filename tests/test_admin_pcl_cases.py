import os
import tempfile
import unittest
from datetime import date, datetime

from sqlalchemy import insert, text as sa_text

from app import create_app
from pcl_queries import PclCaseFilters, list_cases


class AdminPclCasesTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {key: os.environ.get(key) for key in ("DB_PATH", "SECRET_KEY_PATH")}
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        self.app = create_app()
        self.client = self.app.test_client()
        self.engine = self.app.engine
        self.tables = self.app.pcl_tables
        self._seed_data()

    def tearDown(self):
        self._tmpdir.cleanup()
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _seed_data(self):
        requests = self.tables["pcl_batch_requests"]
        segments = self.tables["pcl_batch_segments"]
        cases = self.tables["pcl_cases"]
        raw = self.tables["pcl_case_result_raw"]
        receipts = self.tables["pcl_batch_receipts"]
        with self.engine.begin() as conn:
            request_result = conn.execute(
                insert(requests).values(
                    court_id="akd",
                    date_filed_from=date(2024, 1, 1),
                    date_filed_to=date(2024, 1, 31),
                    case_types='["cr"]',
                    status="completed",
                )
            )
            request_id = int(request_result.inserted_primary_key[0])

            segment_result = conn.execute(
                insert(segments).values(
                    batch_request_id=request_id,
                    court_id="akd",
                    date_filed_from=date(2024, 1, 1),
                    date_filed_to=date(2024, 1, 31),
                    case_types='["cr"]',
                    status="completed",
                    report_id="r-1",
                    completed_at=datetime(2024, 2, 1),
                )
            )
            segment_id = int(segment_result.inserted_primary_key[0])

            conn.execute(
                insert(cases),
                [
                    {
                        "court_id": "akd",
                        "case_number": "1:24-cr-00001",
                        "case_number_full": "1:24-cr-00001",
                        "case_type": "cr",
                        "date_filed": date(2024, 1, 2),
                        "date_closed": date(2024, 3, 4),
                        "short_title": "USA v. Doe",
                        "case_title": "United States v. Doe",
                        "judge_last_name": "Jackson",
                        "record_hash": "hash-1",
                        "last_segment_id": segment_id,
                        "data_json": "{}",
                    },
                    {
                        "court_id": "akd",
                        "case_number": "1:24-cr-00002",
                        "case_number_full": "1:24-cr-00002",
                        "case_type": "cr",
                        "date_filed": date(2024, 1, 20),
                        "date_closed": None,
                        "short_title": "USA v. Roe",
                        "case_title": None,
                        "judge_last_name": "Nguyen",
                        "record_hash": "hash-2",
                        "last_segment_id": segment_id,
                        "data_json": "{}",
                    },
                    {
                        "court_id": "cand",
                        "case_number": "3:24-cr-00077",
                        "case_number_full": "3:24-cr-00077",
                        "case_type": "cr",
                        "date_filed": date(2024, 2, 10),
                        "date_closed": None,
                        "short_title": "USA v. Smith",
                        "case_title": None,
                        "judge_last_name": "Smith",
                        "record_hash": "hash-3",
                        "last_segment_id": segment_id,
                        "data_json": "{}",
                    },
                ],
            )

            conn.execute(
                insert(raw).values(
                    segment_id=segment_id,
                    report_id="r-1",
                    court_id="akd",
                    case_number="1:24-cr-00001",
                    record_hash="hash-1",
                    payload_json='{"caseNumber": "1:24-cr-00001"}',
                )
            )
            conn.execute(
                insert(receipts).values(
                    segment_id=segment_id,
                    report_id="r-1",
                    receipt_json='{"itemCount": 2}',
                )
            )

    def _admin_session(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = "test-token"

    def test_query_filters_and_index_usage(self):
        filters = PclCaseFilters(
            court_id="akd",
            date_filed_from=date(2024, 1, 1),
            date_filed_to=date(2024, 1, 31),
        )
        result = list_cases(self.engine, self.tables, filters, page=1, page_size=10)
        self.assertEqual(result.pagination.total, 2)
        self.assertTrue(all(row["court_id"] == "akd" for row in result.rows))

        with self.engine.begin() as conn:
            plan_rows = conn.execute(
                sa_text(
                    "EXPLAIN QUERY PLAN SELECT id FROM pcl_cases WHERE court_id = :court_id AND date_filed >= :date_from AND date_filed <= :date_to"
                ),
                {
                    "court_id": "akd",
                    "date_from": "2024-01-01",
                    "date_to": "2024-01-31",
                },
            ).fetchall()
        plan_text = " ".join(str(row[-1]) for row in plan_rows)
        self.assertIn("ix_pcl_cases_court_date", plan_text)

    def test_admin_routes_render(self):
        self._admin_session()
        response = self.client.get(
            "/admin/pcl/cases?court_id=akd&date_filed_from=2024-01-01&date_filed_to=2024-01-31"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Indexed PCL cases", response.data)
        self.assertIn(b"USA v. Doe", response.data)

        with self.engine.begin() as conn:
            case_id = conn.execute(sa_text("SELECT id FROM pcl_cases WHERE case_number = :case_number"), {"case_number": "1:24-cr-00001"}).scalar_one()
        detail_response = self.client.get(f"/admin/pcl/cases/{case_id}")
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn(b"Batch segment provenance", detail_response.data)
        self.assertIn(b"Raw payloads", detail_response.data)


if __name__ == "__main__":
    unittest.main()
