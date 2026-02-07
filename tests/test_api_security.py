import os
import tempfile
import unittest

from app import create_app


class ApiSecurityTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key) for key in ("DB_PATH", "SECRET_KEY_PATH")
        }
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        self._tmpdir.cleanup()
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _admin_session(self, csrf_token: str = "test-token"):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = csrf_token

    def test_api_tables_requires_admin(self):
        response = self.client.get("/api/tables")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login", response.headers.get("Location", ""))

    def test_api_tables_allows_admin(self):
        self._admin_session()
        response = self.client.get("/api/tables")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_api_post_requires_csrf(self):
        self._admin_session(csrf_token="expected")
        payload = {"court_id": "akd", "case_number": "1:24-cr-00001", "data_json": "{}"}
        response = self.client.post("/api/pcl_cases", json=payload)
        self.assertEqual(response.status_code, 400)

    def test_api_post_allows_csrf(self):
        self._admin_session(csrf_token="expected")
        payload = {
            "csrf_token": "expected",
            "court_id": "akd",
            "case_number": "1:24-cr-00001",
            "case_number_full": "1:24-cr-00001",
            "data_json": "{}",
        }
        response = self.client.post("/api/pcl_cases", json=payload)
        self.assertEqual(response.status_code, 201)


if __name__ == "__main__":
    unittest.main()
