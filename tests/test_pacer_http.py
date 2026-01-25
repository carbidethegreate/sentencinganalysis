import io
import unittest
from datetime import datetime
from unittest.mock import patch
import urllib.error

from pacer_http import PacerEnvironmentMismatch, PacerHttpClient, TokenExpired
from pacer_tokens import InMemoryTokenBackend, PacerTokenStore


class DummyResponse:
    def __init__(self, payload: bytes, status: int = 200, headers=None):
        self._payload = payload
        self._status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._payload

    def getcode(self) -> int:
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class PacerHttpClientTests(unittest.TestCase):
    def test_token_refresh_updates_store(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        store.save_token("initial-token", obtained_at=datetime.utcnow())

        client = PacerHttpClient(store)

        def fake_urlopen(request, timeout=30):
            return DummyResponse(
                b"ok",
                headers={"X-NEXT-GEN-CSO": "refreshed-token"},
            )

        with patch("pacer_http.urllib.request.urlopen", side_effect=fake_urlopen):
            response = client.request("GET", "https://example.test/pcl")

        self.assertEqual(response.status_code, 200)
        refreshed = store.get_token()
        self.assertIsNotNone(refreshed)
        self.assertEqual(refreshed.token, "refreshed-token")

    def test_401_reauth_retries_once(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        store.save_token("initial-token", obtained_at=datetime.utcnow())
        refresh_calls = []

        def refresher():
            refresh_calls.append("refresh")
            return store.save_token("new-token", obtained_at=datetime.utcnow())

        client = PacerHttpClient(store, token_refresher=refresher)
        calls = {"count": 0}

        def fake_urlopen(request, timeout=30):
            calls["count"] += 1
            if calls["count"] == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    401,
                    "Unauthorized",
                    {},
                    io.BytesIO(b"unauthorized"),
                )
            return DummyResponse(b"ok")

        with patch("pacer_http.urllib.request.urlopen", side_effect=fake_urlopen):
            response = client.request("GET", "https://example.test/pcl")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls["count"], 2)
        self.assertEqual(len(refresh_calls), 1)

    def test_401_reauth_stops_after_second_failure(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        store.save_token("initial-token", obtained_at=datetime.utcnow())
        refresh_calls = []

        def refresher():
            refresh_calls.append("refresh")
            return store.save_token("new-token", obtained_at=datetime.utcnow())

        client = PacerHttpClient(store, token_refresher=refresher)

        def fake_urlopen(request, timeout=30):
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {},
                io.BytesIO(b"unauthorized"),
            )

        with patch("pacer_http.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(TokenExpired):
                client.request("GET", "https://example.test/pcl")

        self.assertEqual(len(refresh_calls), 1)

    def test_401_raises_token_expired(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        store.save_token("initial-token", obtained_at=datetime.utcnow())

        client = PacerHttpClient(store)

        def fake_urlopen(request, timeout=30):
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {},
                io.BytesIO(b"unauthorized"),
            )

        with patch("pacer_http.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(TokenExpired):
                client.request("GET", "https://example.test/pcl")

    def test_missing_token_blocks_without_http(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        client = PacerHttpClient(store)

        with patch("pacer_http.urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(TokenExpired):
                client.request("GET", "https://example.test/pcl")
        mock_urlopen.assert_not_called()

    def test_env_mismatch_blocks_without_http(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        store.save_token("initial-token", obtained_at=datetime.utcnow())
        client = PacerHttpClient(store, env_mismatch_reason="Mismatch")

        with patch("pacer_http.urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(PacerEnvironmentMismatch):
                client.request("GET", "https://example.test/pcl")
        mock_urlopen.assert_not_called()

    def test_request_includes_next_gen_header(self):
        session = {"pacer_session_key": "session-1"}
        store = PacerTokenStore(InMemoryTokenBackend(), session_accessor=lambda: session)
        store.save_token("initial-token", obtained_at=datetime.utcnow())
        client = PacerHttpClient(store)

        captured = {}

        def fake_urlopen(request, timeout=30):
            captured["headers"] = dict(request.header_items())
            return DummyResponse(b"ok")

        with patch("pacer_http.urllib.request.urlopen", side_effect=fake_urlopen):
            client.request("GET", "https://example.test/pcl")

        headers = {key.lower(): value for key, value in captured["headers"].items()}
        self.assertEqual(headers.get("x-next-gen-cso"), "initial-token")


if __name__ == "__main__":
    unittest.main()
