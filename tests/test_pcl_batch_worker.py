import unittest
from datetime import date, datetime

from sqlalchemy import MetaData, create_engine, select

from pacer_http import TokenExpired
from pcl_batch import PclBatchPlanner, PclBatchWorker
from pcl_models import build_pcl_tables


class FakePclClient:
    def __init__(self):
        self.calls = []

    def start_case_download(self, payload):
        self.calls.append(("start", payload))
        return {"reportId": "r1"}

    def get_case_download_status(self, report_id):
        self.calls.append(("status", report_id))
        return {
            "status": "COMPLETED",
            "receipt": {"itemCount": 1, "totalCost": 0},
        }

    def download_case_report(self, report_id):
        self.calls.append(("download", report_id))
        return {
            "content": [
                {
                    "caseId": 5001,
                    "caseNumber": "1:24-cr-00001",
                    "caseNumberFull": "1:24-cr-00001",
                    "courtId": "akdc",
                    "caseType": "cr",
                    "dateFiled": "2024-01-02",
                    "shortTitle": "USA v. Doe",
                }
            ]
        }

    def delete_case_report(self, report_id):
        self.calls.append(("delete", report_id))
        return {"status": "deleted"}


class TokenExpiredClient(FakePclClient):
    def start_case_download(self, payload):
        raise TokenExpired("PACER token expired.")


class DuplicateCaseNumberClient(FakePclClient):
    def download_case_report(self, report_id):
        self.calls.append(("download", report_id))
        return {
            "content": [
                {
                    "caseId": 9001,
                    "caseNumber": "1:24-cr-00001",
                    "caseNumberFull": "1:24-cr-00001",
                    "courtId": "akdc",
                    "caseType": "cr",
                    "dateFiled": "2024-01-03",
                    "shortTitle": "USA v. Doe (updated)",
                }
            ]
        }


class PclBatchWorkerTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", future=True)
        metadata = MetaData()
        self.tables = build_pcl_tables(metadata)
        metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            conn.execute(
                self.tables["pcl_courts"].insert(),
                [
                    {
                        "pcl_court_id": "akdc",
                        "name": "Alaska District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    }
                ],
            )

    def test_end_to_end_happy_path(self):
        planner = PclBatchPlanner(self.engine, self.tables)
        planner.create_batch_request(
            court_id="akdc",
            date_filed_from=date(2024, 1, 1),
            date_filed_to=date(2024, 1, 31),
            case_types=["cr", "cv"],
        )
        client = FakePclClient()
        worker = PclBatchWorker(
            self.engine,
            self.tables,
            client,
            sleep_fn=lambda _: None,
            now_fn=lambda: datetime(2024, 1, 1),
        )
        processed = worker.run_once(max_segments=1)
        self.assertEqual(processed, 1)

        with self.engine.begin() as conn:
            cases = conn.execute(select(self.tables["pcl_cases"])).mappings().all()
            raw = conn.execute(
                select(self.tables["pcl_case_result_raw"])
            ).mappings().all()
            receipts = conn.execute(
                select(self.tables["pcl_batch_receipts"])
            ).mappings().all()
            segments = conn.execute(
                select(self.tables["pcl_batch_segments"])
            ).mappings().all()

        self.assertEqual(len(cases), 1)
        self.assertEqual(len(raw), 1)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(segments[0]["status"], "completed")
        self.assertIn(("delete", "r1"), client.calls)

        case = cases[0]
        raw_row = raw[0]
        self.assertEqual(case["case_number_full"], "1:24-cr-00001")
        self.assertEqual(case["last_segment_id"], segments[0]["id"])
        self.assertEqual(raw_row["court_id"], "akdc")
        self.assertEqual(raw_row["case_number"], "1:24-cr-00001")

    def test_token_expired_marks_failed(self):
        planner = PclBatchPlanner(self.engine, self.tables)
        planner.create_batch_request(
            court_id="akdc",
            date_filed_from=date(2024, 2, 1),
            date_filed_to=date(2024, 2, 28),
            case_types=["cr"],
        )
        worker = PclBatchWorker(
            self.engine,
            self.tables,
            TokenExpiredClient(),
            sleep_fn=lambda _: None,
            now_fn=lambda: datetime(2024, 2, 1),
        )
        worker.run_once(max_segments=1)

        with self.engine.begin() as conn:
            segment = conn.execute(
                select(self.tables["pcl_batch_segments"])
            ).mappings().one()

        self.assertEqual(segment["status"], "failed")
        self.assertEqual(segment["error_message"], "needs re authorization")

    def test_upsert_merges_on_case_number_full(self):
        # Simulate an older row that was stored without a stable case_id, then a later ingest
        # that provides a case_id for the same (court_id, case_number_full).
        with self.engine.begin() as conn:
            conn.execute(
                self.tables["pcl_cases"].insert(),
                [
                    {
                        "court_id": "akdc",
                        "case_id": None,
                        "case_number": "1:24-cr-00001",
                        "case_number_full": "1:24-cr-00001",
                        "case_type": "cr",
                        "date_filed": date(2024, 1, 2),
                        "data_json": "{}",
                    }
                ],
            )

        planner = PclBatchPlanner(self.engine, self.tables)
        planner.create_batch_request(
            court_id="akdc",
            date_filed_from=date(2024, 1, 1),
            date_filed_to=date(2024, 1, 31),
            case_types=["cr"],
        )
        client = DuplicateCaseNumberClient()
        worker = PclBatchWorker(
            self.engine,
            self.tables,
            client,
            sleep_fn=lambda _: None,
            now_fn=lambda: datetime(2024, 1, 1),
        )
        processed = worker.run_once(max_segments=1)
        self.assertEqual(processed, 1)

        with self.engine.begin() as conn:
            cases = conn.execute(select(self.tables["pcl_cases"])).mappings().all()
            segment = conn.execute(select(self.tables["pcl_batch_segments"])).mappings().one()

        self.assertEqual(segment["status"], "completed")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["case_id"], "9001")
        self.assertIn(("delete", "r1"), client.calls)


if __name__ == "__main__":
    unittest.main()
