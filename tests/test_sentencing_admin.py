import os
import tempfile
import unittest
from datetime import date

from sqlalchemy import insert, select

from app import create_app
from pcl_queries import PclCaseFilters, list_cases
from sentencing_queries import SentencingReportFilters, list_sentencing_events_by_judge


class SentencingAdminTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {key: os.environ.get(key) for key in ("DB_PATH", "SECRET_KEY_PATH")}
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        self.app = create_app()
        self.client = self.app.test_client()
        self.engine = self.app.engine
        self.tables = self.app.pcl_tables
        self.case_id, self.other_case_id = self._seed_cases()
        self._login_admin()

    def tearDown(self):
        self._tmpdir.cleanup()
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = "test-token"

    def _seed_cases(self):
        cases = self.tables["pcl_cases"]
        with self.engine.begin() as conn:
            first = conn.execute(
                insert(cases).values(
                    court_id="akd",
                    case_number="1:24-cr-00010",
                    case_number_full="1:24-cr-00010",
                    case_type="cr",
                    date_filed=date(2024, 1, 10),
                    short_title="USA v. Alpha",
                    data_json="{}",
                )
            )
            second = conn.execute(
                insert(cases).values(
                    court_id="cand",
                    case_number="3:24-cr-00011",
                    case_number_full="3:24-cr-00011",
                    case_type="cr",
                    date_filed=date(2024, 2, 10),
                    short_title="USA v. Beta",
                    data_json="{}",
                )
            )
        return int(first.inserted_primary_key[0]), int(second.inserted_primary_key[0])

    def test_admin_can_create_sentencing_event_with_evidence_and_judge(self):
        response = self.client.post(
            f"/admin/pcl/cases/{self.case_id}/sentencing-events",
            data={
                "csrf_token": "test-token",
                "sentencing_date": "2024-06-01",
                "sentence_months": "48",
                "guideline_range_low": "41",
                "guideline_range_high": "51",
                "variance_type": "within",
                "judge_name": "Jane Example",
                "judge_confidence": "0.95",
                "evidence_source_type": ["manual"],
                "evidence_source_id": [""],
                "evidence_reference": ["Sentencing transcript at 12:3-13:8."],
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sentencing event saved.", response.data)

        judges = self.tables["judges"]
        case_judges = self.tables["case_judges"]
        sentencing_events = self.tables["sentencing_events"]
        sentencing_evidence = self.tables["sentencing_evidence"]

        with self.engine.begin() as conn:
            judge_id = conn.execute(
                select(judges.c.id).where(judges.c.name_full == "Jane Example")
            ).scalar_one()
            link = conn.execute(
                select(case_judges.c.role, case_judges.c.confidence).where(
                    case_judges.c.case_id == self.case_id,
                    case_judges.c.judge_id == judge_id,
                )
            ).mappings().one()
            event = conn.execute(
                select(sentencing_events.c.id, sentencing_events.c.sentence_months).where(
                    sentencing_events.c.case_id == self.case_id
                )
            ).mappings().one()
            evidence_rows = conn.execute(
                select(sentencing_evidence.c.source_type, sentencing_evidence.c.reference_text).where(
                    sentencing_evidence.c.sentencing_event_id == event["id"]
                )
            ).mappings().all()

        self.assertEqual(link["role"], "sentencing")
        self.assertAlmostEqual(float(link["confidence"]), 0.95, places=2)
        self.assertEqual(event["sentence_months"], 48)
        self.assertEqual(len(evidence_rows), 1)
        self.assertEqual(evidence_rows[0]["source_type"], "manual")

        filters = PclCaseFilters(sentencing_only=True)
        result = list_cases(self.engine, self.tables, filters, page=1, page_size=25)
        result_case_ids = {row["id"] for row in result.rows}
        self.assertIn(self.case_id, result_case_ids)
        self.assertNotIn(self.other_case_id, result_case_ids)

    def test_sentencing_report_filters_by_judge_and_court(self):
        judges = self.tables["judges"]
        case_judges = self.tables["case_judges"]
        sentencing_events = self.tables["sentencing_events"]
        sentencing_evidence = self.tables["sentencing_evidence"]

        with self.engine.begin() as conn:
            judge_one = conn.execute(
                insert(judges).values(name_full="Judge One", name_last="One", court_id="akd")
            )
            judge_one_id = int(judge_one.inserted_primary_key[0])
            judge_two = conn.execute(
                insert(judges).values(name_full="Judge Two", name_last="Two", court_id="cand")
            )
            judge_two_id = int(judge_two.inserted_primary_key[0])

            conn.execute(
                insert(case_judges),
                [
                    {
                        "case_id": self.case_id,
                        "judge_id": judge_one_id,
                        "role": "sentencing",
                        "confidence": 1.0,
                        "source_system": "admin",
                    },
                    {
                        "case_id": self.other_case_id,
                        "judge_id": judge_two_id,
                        "role": "sentencing",
                        "confidence": 1.0,
                        "source_system": "admin",
                    },
                ],
            )

            first_event = conn.execute(
                insert(sentencing_events).values(
                    case_id=self.case_id,
                    sentencing_date=date(2024, 6, 1),
                    sentence_months=60,
                    variance_type="within",
                )
            )
            first_event_id = int(first_event.inserted_primary_key[0])
            second_event = conn.execute(
                insert(sentencing_events).values(
                    case_id=self.other_case_id,
                    sentencing_date=date(2024, 7, 1),
                    sentence_months=24,
                    variance_type="downward",
                )
            )
            second_event_id = int(second_event.inserted_primary_key[0])

            conn.execute(
                insert(sentencing_evidence),
                [
                    {
                        "sentencing_event_id": first_event_id,
                        "source_type": "manual",
                        "reference_text": "Judgment at page 3.",
                    },
                    {
                        "sentencing_event_id": second_event_id,
                        "source_type": "manual",
                        "reference_text": "Statement of reasons.",
                    },
                ],
            )

        filters = SentencingReportFilters(judge_id=judge_one_id, court_id="akd")
        rows, _, _ = list_sentencing_events_by_judge(self.engine, self.tables, filters)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["case_id"], self.case_id)
        self.assertEqual(rows[0]["judge_id"], judge_one_id)

        response = self.client.get(f"/admin/sentencing-events?judge_id={judge_one_id}&court_id=akd")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Judge One", response.data)
        self.assertIn(b"1:24-cr-00010", response.data)
        self.assertNotIn(b"3:24-cr-00011", response.data)


if __name__ == "__main__":
    unittest.main()
