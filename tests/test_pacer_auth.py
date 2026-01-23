import json
import unittest
from unittest.mock import patch

from app import (
    PacerAuthClient,
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
        self.assertFalse(response.needs_otp)

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


class FederalDataDashboardTemplateTests(unittest.TestCase):
    def test_get_pacer_data_form_has_autofill_mitigations(self):
        app = create_app()
        app.testing = True
        client = app.test_client()

        with client.session_transaction() as session:
            session["is_admin"] = True

        response = client.get("/admin/federal-data-dashboard/get-pacer-data")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        self.assertIn('name="username"', html)
        self.assertIn('name="password"', html)
        self.assertIn('name="pacer_login_id"', html)
        self.assertIn('name="pacer_login_secret"', html)
        self.assertIn('name="pacer_otp_code"', html)
        self.assertNotIn("2FA code (only if prompted)", html)


if __name__ == "__main__":
    unittest.main()
