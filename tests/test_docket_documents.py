import os
import tempfile
import unittest
from datetime import date, datetime

from sqlalchemy import insert, select

from app import create_app
from docket_documents import DocketDocumentWorker


class _FakeResponse:
    def __init__(self, body: bytes, content_type: str = "application/pdf") -> None:
        self.status_code = 200
        self.headers = {"Content-Type": content_type}
        self.body = body


class _FakeHttpClient:
    def request(self, method, url, headers=None, data=None, include_cookie=False):
        return _FakeResponse(b"%PDF-1.4 fake pdf bytes")


class DocketDocumentWorkerTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {key: os.environ.get(key) for key in ("DB_PATH", "SECRET_KEY_PATH")}
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        self.app = create_app()
        self.engine = self.app.engine
        self.tables = self.app.pcl_tables
        self.documents_dir = os.path.join(self._tmpdir.name, "docs")

    def tearDown(self):
        self._tmpdir.cleanup()
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _insert_case(self) -> int:
        cases = self.tables["pcl_cases"]
        with self.engine.begin() as conn:
            result = conn.execute(
                insert(cases).values(
                    court_id="paedc",
                    case_number="2:24-cr-00001",
                    case_number_full="2:24-cr-00001",
                    case_type="cr",
                    date_filed=date(2024, 1, 1),
                    short_title="USA v. Test",
                    case_title="United States v. Test",
                    judge_last_name="Kearney",
                    record_hash="hash-test-case",
                    data_json="{}",
                )
            )
        return int(result.inserted_primary_key[0])

    def _insert_job_with_items(self, item_count: int) -> int:
        jobs = self.tables["docket_document_jobs"]
        items = self.tables["docket_document_items"]
        case_id = self._insert_case()
        with self.engine.begin() as conn:
            job_result = conn.execute(
                insert(jobs).values(case_id=case_id, status="queued")
            )
            job_id = int(job_result.inserted_primary_key[0])
            conn.execute(
                insert(items),
                [
                    {
                        "job_id": job_id,
                        "document_number": str(index + 1),
                        "description": f"Document {index + 1}",
                        "source_url": f"https://example.test/doc/{index + 1}.pdf",
                        "request_method": "GET",
                        "status": "queued",
                    }
                    for index in range(item_count)
                ],
            )
        return job_id

    def _load_job(self, job_id: int):
        jobs = self.tables["docket_document_jobs"]
        with self.engine.begin() as conn:
            row = conn.execute(
                select(jobs).where(jobs.c.id == job_id)
            ).mappings().first()
        return dict(row)

    def test_run_job_batches_leaves_job_queued_when_items_remain(self):
        job_id = self._insert_job_with_items(5)
        worker = DocketDocumentWorker(
            self.engine,
            self.tables,
            http_client=_FakeHttpClient(),
            documents_dir=self.documents_dir,
        )

        result = worker.run_job_batches(job_id, max_docs=2, max_batches=2, max_seconds=5)
        job = self._load_job(job_id)

        self.assertEqual(result["processed"], 4)
        self.assertEqual(result["queued_remaining"], 1)
        self.assertEqual(job["status"], "queued")
        self.assertIsNone(job["finished_at"])
        self.assertEqual(job["documents_downloaded"], 4)

    def test_run_job_batches_completes_after_last_item(self):
        job_id = self._insert_job_with_items(3)
        worker = DocketDocumentWorker(
            self.engine,
            self.tables,
            http_client=_FakeHttpClient(),
            documents_dir=self.documents_dir,
        )

        result = worker.run_job_batches(job_id, max_docs=2, max_batches=5, max_seconds=5)
        job = self._load_job(job_id)

        self.assertEqual(result["processed"], 3)
        self.assertEqual(result["queued_remaining"], 0)
        self.assertEqual(job["status"], "completed")
        self.assertIsNotNone(job["finished_at"])
        self.assertEqual(job["documents_downloaded"], 3)

    def test_run_job_resumes_completed_job_when_queued_items_remain(self):
        job_id = self._insert_job_with_items(2)
        jobs = self.tables["docket_document_jobs"]
        with self.engine.begin() as conn:
            conn.execute(
                jobs.update().where(jobs.c.id == job_id).values(
                    status="completed",
                    finished_at=datetime(2024, 1, 1, 0, 0, 0),
                )
            )
        worker = DocketDocumentWorker(
            self.engine,
            self.tables,
            http_client=_FakeHttpClient(),
            documents_dir=self.documents_dir,
        )

        processed = worker.run_job(job_id, max_docs=5)
        job = self._load_job(job_id)

        self.assertEqual(processed, 2)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["documents_downloaded"], 2)
        self.assertIsNotNone(job["finished_at"])


if __name__ == "__main__":
    unittest.main()
