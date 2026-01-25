import os
import tempfile
import unittest

from sqlalchemy import insert

from app import create_app


class AdminPclBatchSearchTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in (
                "DB_PATH",
                "SECRET_KEY_PATH",
                "PACER_AUTH_BASE_URL",
                "PCL_BASE_URL",
            )
        }
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        os.environ["PACER_AUTH_BASE_URL"] = "https://qa-login.uscourts.gov"
        os.environ["PCL_BASE_URL"] = "https://qa-pcl.uscourts.gov/pcl-public-api/rest"
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.engine = self.app.engine
        self.courts_table = self.app.pcl_courts_table
        self._seed_courts()
        self._login_admin()

    def tearDown(self):
        self._tmpdir.cleanup()
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _seed_courts(self):
        with self.engine.begin() as conn:
            conn.execute(
                insert(self.courts_table),
                [
                    {
                        "pcl_court_id": "akdc",
                        "name": "Alaska District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                    {
                        "pcl_court_id": "vi",
                        "name": "Virgin Islands District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                ],
            )

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = "csrf-token"

    def test_batch_search_lists_pcl_courts(self):
        response = self.client.get("/admin/federal-data-dashboard/pcl-batch-search")
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("PCL Batch Search", html)
        self.assertIn("akdc, Alaska District Court", html)

    def test_batch_search_rejects_invalid_court_id(self):
        response = self.client.post(
            "/admin/federal-data-dashboard/pcl-batch-search/create",
            data={
                "csrf_token": "csrf-token",
                "court_id": "vidc",
                "date_filed_from": "2024-01-01",
                "date_filed_to": "2024-01-31",
                "case_types": "cr",
            },
            follow_redirects=True,
        )
        html = response.data.decode("utf-8")
        self.assertIn("Court ID is not recognized. Please select a valid court.", html)

    def test_batch_search_accepts_valid_court_id(self):
        response = self.client.post(
            "/admin/federal-data-dashboard/pcl-batch-search/create",
            data={
                "csrf_token": "csrf-token",
                "court_id": "VI",
                "date_filed_from": "2024-01-01",
                "date_filed_to": "2024-01-31",
                "case_types": "cr",
            },
            follow_redirects=True,
        )
        html = response.data.decode("utf-8")
        self.assertIn("PCL batch request", html)
