import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from sqlalchemy import insert

from app import create_app
from pacer_http import TokenExpired
from pacer_tokens import PacerTokenRecord
from pcl_client import PclApiError, PclJsonResponse


class AdminPacerExploreTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {key: os.environ.get(key) for key in ("DB_PATH", "SECRET_KEY_PATH")}
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.engine = self.app.engine
        self.courts_table = self.app.federal_courts_table
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
                        "court_id": "akd",
                        "court_name": "District of Alaska",
                        "title": "U.S. District Court for the District of Alaska",
                        "raw_json": {},
                    },
                    {
                        "court_id": "cand",
                        "court_name": "Northern District of California",
                        "title": "U.S. District Court for the Northern District of California",
                        "raw_json": {},
                    },
                ],
            )

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = "csrf-token"

    def _authorize_pacer(self):
        with self.client.session_transaction() as sess:
            session_key = sess.get("pacer_session_key") or "session-key"
            sess["pacer_session_key"] = session_key
        record = PacerTokenRecord(token="server-side-token", obtained_at=datetime.utcnow())
        self.app.pacer_token_store._backend.save_token(session_key, record)

    def _post_run(self, **overrides):
        payload = {
            "csrf_token": "csrf-token",
            "court_id": "akd",
            "date_filed_from": "2024-01-01",
            "date_filed_to": "2024-01-31",
            "max_records": "54",
        }
        payload.update(overrides)
        return self.client.post("/admin/pacer/explore/run", data=payload)

    def test_get_explore_page_lists_courts(self):
        response = self.client.get("/admin/pacer/explore")
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Explore PACER", html)
        self.assertIn("akd, District of Alaska", html)
        self.assertIn("cand, Northern District of California", html)

    def test_post_run_requires_authorization(self):
        with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
            response = self._post_run()
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("PACER authorization is required", html)
        self.assertIn("Next step: click Authorize", html)
        self.assertIn("Copy debug bundle", html)
        self.assertNotIn("server-side-token", html)
        mock_search.assert_not_called()

    def test_post_run_success_shows_results_and_observed_fields(self):
        self._authorize_pacer()
        payload = {
            "cases": [
                {
                    "caseNumber": "1:24-cr-00001",
                    "caseType": "cr",
                    "dateFiled": "2024-01-02",
                    "shortTitle": "USA v. Doe",
                    "judgeLastName": "Jackson",
                },
                {
                    "caseNumber": "1:24-cr-00002",
                    "caseType": "cr",
                    "dateFiled": "2024-01-10",
                    "shortTitle": "USA v. Roe",
                    "judgeLastName": "",
                    "natureOfSuit": "510",
                },
            ],
            "receipt": {"billablePages": 1, "searchFee": 0.1},
            "pageInfo": {"page": 1, "totalPages": 1, "totalRecords": 2},
        }
        fake_response = PclJsonResponse(status_code=200, payload=payload, raw_body=b"{}")

        with patch.object(self.app.pcl_client, "immediate_case_search", return_value=fake_response):
            response = self._post_run()

        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Run complete", html)
        self.assertIn("1:24-cr-00001", html)
        self.assertIn("caseNumber", html)
        self.assertIn("judgeLastName", html)
        self.assertIn("natureOfSuit", html)
        self.assertIn("Billable pages total: <strong>1</strong>", html)
        self.assertIn("status_codes", html)
        self.assertNotIn("server-side-token", html)

    def test_post_run_handles_401_and_406_errors(self):
        self._authorize_pacer()

        with self.subTest("401 token expired"):
            with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=TokenExpired()):
                response = self._post_run()
            html = response.data.decode("utf-8")
            self.assertIn("Token expired or invalid", html)
            self.assertIn("re-authorize", html)
            self.assertIn("Copy debug bundle", html)
            self.assertNotIn("server-side-token", html)

        with self.subTest("406 invalid parameter"):
            error = PclApiError(406, "Invalid search", details={"message": "bad filter"})
            with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=error):
                response = self._post_run(case_types=["cr"])
            html = response.data.decode("utf-8")
            self.assertIn("Invalid search parameter", html)
            self.assertIn("open a fix request", html)
            self.assertIn("Copy debug bundle", html)
            self.assertIn("bad filter", html)
            self.assertNotIn("server-side-token", html)


if __name__ == "__main__":
    unittest.main()
