import io
import json
import urllib.error
import unittest
from unittest.mock import patch

from app import (
    PacerAuthClient,
    PacerAuthResult,
    _build_pacer_auth_url,
    _normalize_pacer_base_url,
    _parse_pacer_auth_response_payload,
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

    def test_build_payload_normalizes_otp_with_separators(self):
        payload = build_pacer_auth_payload(
            "user",
            "pass",
            otp_code="123 456",
            client_code="CLIENT1",
            redact_flag=True,
        )
        self.assertEqual(payload["otpCode"], "123456")

    def test_client_builds_correct_request_body(self):
        captured = {}

        def fake_urlopen(request, timeout=30):
            captured["data"] = request.data
            captured["url"] = request.full_url
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
        self.assertEqual(captured["url"], "https://qa-login.uscourts.gov/services/cso-auth")
        self.assertTrue(result.can_proceed)

    def test_client_redaction_error_sets_redaction_requirement(self):
        def fake_urlopen(request, timeout=30):
            response_payload = json.dumps(
                {
                    "loginResult": "1",
                    "nextGenCSO": "",
                    "errorDescription": "All filers must redact: Social Security or taxpayer identification numbers.",
                }
            ).encode("utf-8")
            return DummyResponse(response_payload)

        with patch("app.urllib.request.urlopen", side_effect=fake_urlopen):
            client = PacerAuthClient("https://qa-login.uscourts.gov")
            result = client.authenticate("user", "pass", redact_flag=False)

        self.assertFalse(result.can_proceed)
        self.assertTrue(result.needs_redaction_ack)

    def test_client_parses_xml_response(self):
        def fake_urlopen(request, timeout=30):
            response_payload = (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b"<CsoAuth>"
                b"<nextGenCSO>token-from-xml</nextGenCSO>"
                b"<loginResult>0</loginResult>"
                b"<errorDescription></errorDescription>"
                b"</CsoAuth>"
            )
            return DummyResponse(response_payload)

        with patch("app.urllib.request.urlopen", side_effect=fake_urlopen):
            client = PacerAuthClient("https://qa-login.uscourts.gov")
            result = client.authenticate("user", "pass")

        self.assertTrue(result.can_proceed)
        self.assertEqual(result.token, "token-from-xml")

    def test_parse_pacer_auth_payload_from_xml(self):
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<CsoAuth>"
            "<nextGenCSO>xml-token</nextGenCSO>"
            "<loginResult>13</loginResult>"
            "<errorDescription>Invalid username, password, or one-time passcode.</errorDescription>"
            "</CsoAuth>"
        )
        parsed = _parse_pacer_auth_response_payload(payload)
        self.assertEqual(parsed["loginResult"], "13")
        self.assertEqual(parsed["nextGenCSO"], "xml-token")
        self.assertIn("one-time passcode", parsed["errorDescription"])

    def test_normalize_pacer_base_url_strips_auth_suffixes(self):
        self.assertEqual(
            _normalize_pacer_base_url("https://pacer.login.uscourts.gov/services/cso-auth"),
            "https://pacer.login.uscourts.gov",
        )
        self.assertEqual(
            _normalize_pacer_base_url("https://qa-login.uscourts.gov/cso-auth"),
            "https://qa-login.uscourts.gov",
        )
        self.assertEqual(
            _normalize_pacer_base_url("https://qa-login.uscourts.gov/services"),
            "https://qa-login.uscourts.gov",
        )
        self.assertEqual(
            _normalize_pacer_base_url(
                " 'https://qa-login.uscourts.gov/services/cso-auth?from=manual' "
            ),
            "https://qa-login.uscourts.gov",
        )
        self.assertEqual(
            _normalize_pacer_base_url("qa-login.uscourts.gov/services/cso-auth"),
            "https://qa-login.uscourts.gov",
        )

    def test_build_pacer_auth_url_always_targets_services_path(self):
        self.assertEqual(
            _build_pacer_auth_url("https://pacer.login.uscourts.gov/cso-auth"),
            "https://pacer.login.uscourts.gov/services/cso-auth",
        )
        self.assertEqual(
            _build_pacer_auth_url("https://qa-login.uscourts.gov/services/cso-auth?x=1"),
            "https://qa-login.uscourts.gov/services/cso-auth",
        )

    def test_client_404_error_mentions_exact_endpoint(self):
        http_error = urllib.error.HTTPError(
            url="https://pacer.login.uscourts.gov/cso-auth",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=io.BytesIO(b"<html><body>Object not found!</body></html>"),
        )

        with patch("app.urllib.request.urlopen", side_effect=http_error):
            client = PacerAuthClient("https://pacer.login.uscourts.gov/cso-auth")
            with self.assertRaises(ValueError) as ctx:
                client.authenticate("user", "pass")

        self.assertIn(
            "https://pacer.login.uscourts.gov/services/cso-auth",
            str(ctx.exception),
        )

    def test_interpret_success_response(self):
        response = interpret_pacer_auth_response(
            {"loginResult": "0", "nextGenCSO": "token", "errorDescription": ""},
            None,
        )
        self.assertTrue(response.can_proceed)
        self.assertEqual(response.token, "token")
        self.assertFalse(response.search_disabled)

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
        self.assertEqual(
            response.error_description, "Invalid username, password, or one-time passcode."
        )
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
        self.assertTrue(response.can_proceed)
        self.assertTrue(response.needs_client_code)
        self.assertTrue(response.search_disabled)

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
    @staticmethod
    def _fake_env_with_pacer_creds(*names):
        if "puser" in names:
            return "pacer-user"
        if "ppass" in names:
            return "pacer-pass"
        if names == ("SECRET_KEY", "Secrets", "SECRETS"):
            return "test-secret"
        return None

    def test_get_pacer_data_hides_manual_creds_when_server_creds_present(self):
        with patch(
            "app._first_env_or_secret_file", side_effect=self._fake_env_with_pacer_creds
        ):
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
                self.assertIn("name=\"pacer_redaction_ack\"", html)

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
            needs_redaction_ack=False,
            search_disabled=False,
            search_disabled_reason=None,
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
                        "pacer_redaction_ack": True,
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
            needs_redaction_ack=False,
            search_disabled=False,
            search_disabled_reason=None,
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
                        "pacer_redaction_ack": True,
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
            needs_redaction_ack=False,
            search_disabled=False,
            search_disabled_reason=None,
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
                        "pacer_redaction_ack": True,
                    },
                )

                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertFalse(payload["authorized"])
                self.assertEqual(payload["status"], "needs_client_code")

    def test_pacer_auth_json_search_disabled_requires_client_code(self):
        app = create_app()
        app.testing = True

        result = PacerAuthResult(
            token="next-gen-token",
            error_description="Required client code not entered.",
            login_result="0",
            needs_otp=False,
            needs_client_code=True,
            needs_redaction_ack=False,
            search_disabled=True,
            search_disabled_reason="PACER authenticated, but searching is disabled.",
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
                        "pacer_redaction_ack": True,
                    },
                )

                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertTrue(payload["authorized"])
                self.assertFalse(payload["search_enabled"])

                with client.session_transaction() as sess:
                    self.assertTrue(sess.get("pacer_search_disabled"))

    def test_pacer_auth_requires_redaction_acknowledgement(self):
        with patch(
            "app._first_env_or_secret_file", side_effect=self._fake_env_with_pacer_creds
        ):
            app = create_app()
            app.testing = True

            with patch("app.PacerAuthClient.authenticate") as auth_mock:
                with app.test_client() as client:
                    with client.session_transaction() as sess:
                        sess["is_admin"] = True
                        sess["csrf_token"] = "csrf-token"

                    response = client.post(
                        "/admin/federal-data-dashboard/pacer-auth",
                        data={"csrf_token": "csrf-token"},
                        headers={"Accept": "text/html"},
                        follow_redirects=True,
                    )

                    html = response.data.decode("utf-8")
                    self.assertIn("acknowledge the PACER redaction rules", html)
                    self.assertIn("require this acknowledgement", html)
                    auth_mock.assert_not_called()

    def test_pacer_auth_redaction_failure_shows_guidance(self):
        app = create_app()
        app.testing = True

        result = PacerAuthResult(
            token="",
            error_description="All filers must redact: Social Security or taxpayer identification numbers.",
            login_result="1",
            needs_otp=False,
            needs_client_code=False,
            needs_redaction_ack=True,
            search_disabled=False,
            search_disabled_reason=None,
            can_proceed=False,
        )

        with patch("app.PacerAuthClient.authenticate", return_value=result):
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["is_admin"] = True
                    sess["csrf_token"] = "csrf-token"

                response = client.post(
                    "/admin/federal-data-dashboard/pacer-auth",
                    data={
                        "csrf_token": "csrf-token",
                        "pacer_login_id": "user",
                        "pacer_login_secret": "pass",
                        "pacer_redaction_ack": "1",
                    },
                    headers={"Accept": "text/html"},
                    follow_redirects=True,
                )

                html = response.data.decode("utf-8")
                self.assertIn("All filers must redact", html)
                self.assertIn("acknowledge the redaction rules", html)

    def test_pacer_auth_with_acknowledgement_sets_redact_flag_and_stores_token(self):
        app = create_app()
        app.testing = True

        captured = {}

        def fake_authenticate(
            login_id, password, otp_code=None, client_code=None, redact_flag=None
        ):
            captured["redact_flag"] = redact_flag
            return PacerAuthResult(
                token="next-gen-token",
                error_description="",
                login_result="0",
                needs_otp=False,
                needs_client_code=False,
                needs_redaction_ack=False,
                search_disabled=False,
                search_disabled_reason=None,
                can_proceed=True,
            )

        with patch("app.PacerAuthClient.authenticate", side_effect=fake_authenticate):
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
                        "pacer_redaction_ack": True,
                    },
                )

                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertTrue(payload["authorized"])
                self.assertEqual(captured["redact_flag"], True)
                self.assertNotIn("nextGenCSO", response.data.decode("utf-8"))

                with client.session_transaction() as sess:
                    session_key = sess.get("pacer_session_key")

                record = app.pacer_token_store.get_token_for_key(session_key)
                self.assertIsNotNone(record)
                self.assertEqual(record.token, "next-gen-token")

    def test_pacer_auth_form_normalizes_user_entered_otp(self):
        with patch(
            "app._first_env_or_secret_file", side_effect=self._fake_env_with_pacer_creds
        ):
            app = create_app()
            app.testing = True

            captured = {}

            def fake_authenticate(
                login_id, password, otp_code=None, client_code=None, redact_flag=None
            ):
                captured["login_id"] = login_id
                captured["password"] = password
                captured["otp_code"] = otp_code
                return PacerAuthResult(
                    token="next-gen-token",
                    error_description="",
                    login_result="0",
                    needs_otp=False,
                    needs_client_code=False,
                    needs_redaction_ack=False,
                    search_disabled=False,
                    search_disabled_reason=None,
                    can_proceed=True,
                )

            with patch("app.PacerAuthClient.authenticate", side_effect=fake_authenticate):
                with app.test_client() as client:
                    with client.session_transaction() as sess:
                        sess["is_admin"] = True
                        sess["csrf_token"] = "csrf-token"

                    response = client.post(
                        "/admin/federal-data-dashboard/pacer-auth",
                        data={
                            "csrf_token": "csrf-token",
                            "pacer_otp_code": "123 456",
                            "pacer_redaction_ack": "1",
                        },
                        headers={"Accept": "text/html"},
                        follow_redirects=False,
                    )

                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(captured["login_id"], "pacer-user")
                    self.assertEqual(captured["password"], "pacer-pass")
                    self.assertEqual(captured["otp_code"], "123456")

    def test_pacer_auth_logging_never_includes_next_gen_cso_value(self):
        messages = []

        class CaptureLogger:
            def info(self, message, *args):
                messages.append(message % args if args else message)

        client = PacerAuthClient("https://qa-login.uscourts.gov", logger=CaptureLogger())
        client._log_response(200, {"loginResult": "0", "nextGenCSO": "secret-token"})
        combined = " ".join(messages)
        self.assertNotIn("secret-token", combined)


if __name__ == "__main__":
    unittest.main()
