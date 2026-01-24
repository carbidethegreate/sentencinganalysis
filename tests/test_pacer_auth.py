import json
import unittest
from unittest.mock import patch

from app import (
    PacerAuthClient,
    PacerAuthResult,
    build_pacer_auth_payload,
    create_app,
    interpret_pacer_auth_response,
)


class DummyResponse:
    def __init__(self, payload: bytes, status: int = 200):
        self._payload = payload
        self._status = status

    def read(self) -> bytes:
        return self._payload

    def getcode(self) -> int:
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class PacerAuthTests(unittest.TestCase):
    def test_build_payload_includes_optional_fields(self):
        payload = build_pacer_auth_payload(
            "user",
            "pass",
            otp_code="123456",
            client_code="CLIENT1",
            redact_flag=True,
        )
        self.assertEqual(
            payload,
            {
                "loginId": "user",
                "password": "pass",
                "otpCode": "123456",
                "clientCode": "CLIENT1",
                "redactFlag": "1",
            },
        )

    def test_build_payload_excludes_blank_optional_fields(self):
        payload = build_pacer_auth_payload("user", "pass")
        self.assertEqual(payload, {"loginId": "user", "password": "pass"})

    def test_client_builds_correct_request_body(self):
        captured = {}

        def fake_urlopen(request, timeout=30):
            captured["data"] = request.data
            response_payload = json.dumps(
                {
                    "loginResult": "0",
                    "nextGenCSO": "token",
                    "errorDescription": "",
                }
            ).encode("utf-8")
            return DummyResponse(response_payload)

        with patch("app.urllib.request.urlopen", side_effect=fake_urlopen):
            client = PacerAuthClient("https://qa-login.uscourts.gov")
            result = client.authenticate("user", "pass")

        request_payload = json.loads(captured["data"].decode("utf-8"))
        self.assertEqual(request_payload, {"loginId": "user", "password": "pass"})
        self.assertTrue(result.can_proceed)

    def test_interpret_success_response(self):
        response = interpret_pacer_auth_response(
            {"loginResult": "0", "nextGenCSO": "token", "errorDescription": ""},
            None,
        )
        self.assertTrue(response.can_proceed)
        self.assertEqual(response.token, "token")

    def test_interpret_invalid_credentials(self):
        response = interpret_pacer_auth_response(
            {
                "loginResult": "13",
                "nextGenCSO": "",
                "errorDescription": "Invalid username, password, or one-time passcode.",
            },
            None,
        )
        self.assertFalse(response.can_proceed)
        self.assertEqual(response.error_description, "Invalid username, password, or one-time passcode.")
        self.assertTrue(response.needs_otp)

    def test_interpret_required_client_code(self):
        response = interpret_pacer_auth_response(
            {
                "loginResult": "0",
                "nextGenCSO": "token",
                "errorDescription": "Required client code not entered.",
            },
            None,
        )
        self.assertFalse(response.can_proceed)
        self.assertTrue(response.needs_client_code)

    def test_interpret_needs_otp_when_one_time_passcode_missing(self):
        response = interpret_pacer_auth_response(
            {
                "loginResult": "13",
                "nextGenCSO": "",
                "errorDescription": "A one-time passcode is needed to continue.",
            },
            None,
        )
        self.assertTrue(response.needs_otp)


class FederalDataDashboardTests(unittest.TestCase):
    def test_get_pacer_data_hides_manual_creds_when_server_creds_present(self):
        def fake_first_env_or_secret_file(*names):
            if names == ("puser",):
                return "pacer-user"
            if names == ("ppass",):
                return "pacer-pass"
            if names == ("SECRET_KEY", "Secrets", "SECRETS"):
                return "test-secret"
            return None

        with patch("app._first_env_or_secret_file", side_effect=fake_first_env_or_secret_file):
            app = create_app()
            app.testing = True

            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["is_admin"] = True

                response = client.get("/admin/federal-data-dashboard/get-pacer-data")
                html = response.data.decode("utf-8")
                self.assertIn("name=\"pacer_otp_code\"", html)
                self.assertNotIn("name=\"pacer_login_id\"", html)
                self.assertNotIn("name=\"pacer_login_secret\"", html)

                manual_response = client.get(
                    "/admin/federal-data-dashboard/get-pacer-data?manual=1"
                )
                manual_html = manual_response.data.decode("utf-8")
                self.assertIn("name=\"pacer_login_id\"", manual_html)
                self.assertIn("name=\"pacer_login_secret\"", manual_html)

    def test_pacer_auth_json_stores_token(self):
        app = create_app()
        app.testing = True

        result = PacerAuthResult(
            token="next-gen-token",
            error_description="",
            login_result="0",
            needs_otp=False,
            needs_client_code=False,
            can_proceed=True,
        )

        with patch("app.PacerAuthClient.authenticate", return_value=result):
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["is_admin"] = True
                    sess["csrf_token"] = "csrf-token"

                response = client.post(
                    "/admin/federal-data-dashboard/pacer-auth",
                    json={
                        "csrf_token": "csrf-token",
                        "username": "user",
                        "password": "pass",
                    },
                )

                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertTrue(payload["authorized"])
                self.assertEqual(payload["status"], "authorized")
                self.assertNotIn("nextGenCSO", response.data.decode("utf-8"))

                with client.session_transaction() as sess:
                    session_key = sess.get("pacer_session_key")

                record = app.pacer_token_store.get_token_for_key(session_key)
                self.assertIsNotNone(record)
                self.assertEqual(record.token, "next-gen-token")

    def test_pacer_auth_json_needs_otp(self):
        app = create_app()
        app.testing = True

        result = PacerAuthResult(
            token="",
            error_description="One-time passcode required.",
            login_result="13",
            needs_otp=True,
            needs_client_code=False,
            can_proceed=False,
        )

        with patch("app.PacerAuthClient.authenticate", return_value=result):
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["is_admin"] = True
                    sess["csrf_token"] = "csrf-token"

                response = client.post(
                    "/admin/federal-data-dashboard/pacer-auth",
                    json={
                        "csrf_token": "csrf-token",
                        "username": "user",
                        "password": "pass",
                    },
                )

                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertFalse(payload["authorized"])
                self.assertEqual(payload["status"], "needs_otp")

    def test_pacer_auth_json_needs_client_code(self):
        app = create_app()
        app.testing = True

        result = PacerAuthResult(
            token="",
            error_description="Required client code not entered.",
            login_result="0",
            needs_otp=False,
            needs_client_code=True,
            can_proceed=False,
        )

        with patch("app.PacerAuthClient.authenticate", return_value=result):
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["is_admin"] = True
                    sess["csrf_token"] = "csrf-token"

                response = client.post(
                    "/admin/federal-data-dashboard/pacer-auth",
                    json={
                        "csrf_token": "csrf-token",
                        "username": "user",
                        "password": "pass",
                    },
                )

                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertFalse(payload["authorized"])
                self.assertEqual(payload["status"], "needs_client_code")


if __name__ == "__main__":
    unittest.main()
