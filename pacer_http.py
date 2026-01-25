from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
import urllib.error
import urllib.request

from pacer_logging import scrub_log_message
from pacer_tokens import PacerTokenStore


class TokenExpired(Exception):
    """Raised when the PACER token is missing or expired."""


class PacerEnvironmentMismatch(Exception):
    """Raised when PACER auth and PCL environments do not align."""


@dataclass(frozen=True)
class PacerHttpResponse:
    status_code: int
    headers: Dict[str, Any]
    body: bytes


class PacerHttpClient:
    def __init__(
        self,
        token_store: PacerTokenStore,
        logger: Optional[Any] = None,
        token_cookie_name: str = "NextGenCSO",
        expected_environment: Optional[str] = None,
        env_mismatch_reason: Optional[str] = None,
    ) -> None:
        self._token_store = token_store
        self._logger = logger
        self._token_cookie_name = token_cookie_name
        self._expected_environment = expected_environment
        self._env_mismatch_reason = env_mismatch_reason

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: int = 30,
        include_cookie: bool = False,
    ) -> PacerHttpResponse:
        if self._env_mismatch_reason:
            raise PacerEnvironmentMismatch(self._env_mismatch_reason)

        token_record = self._token_store.get_token(
            expected_environment=self._expected_environment
        )
        if not token_record or not token_record.token:
            raise TokenExpired("PACER token missing or expired.")

        request_headers: Dict[str, str] = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)
        request_headers["X-NEXT-GEN-CSO"] = token_record.token

        if include_cookie:
            cookie_value = f"{self._token_cookie_name}={token_record.token}"
            existing_cookie = request_headers.get("Cookie")
            if existing_cookie:
                request_headers["Cookie"] = f"{existing_cookie}; {cookie_value}"
            else:
                request_headers["Cookie"] = cookie_value

        if self._logger:
            self._logger.debug("PCL request %s %s", method, scrub_log_message(url))

        request_obj = urllib.request.Request(
            url, data=data, headers=request_headers, method=method
        )

        try:
            with urllib.request.urlopen(request_obj, timeout=timeout) as response:
                body = response.read()
                status_code = response.getcode()
                headers = dict(response.headers)
        except urllib.error.HTTPError as exc:
            if exc.headers:
                self._capture_refreshed_token(dict(exc.headers))
            if exc.code == 401:
                raise TokenExpired("PACER token expired.") from exc
            raise

        self._capture_refreshed_token(headers)
        return PacerHttpResponse(status_code=status_code, headers=headers, body=body)

    def _capture_refreshed_token(self, headers: Dict[str, Any]) -> None:
        refreshed = None
        for key, value in headers.items():
            if key.lower() == "x-next-gen-cso":
                refreshed = value
                break
        if refreshed:
            self._token_store.save_token(
                refreshed,
                obtained_at=datetime.utcnow(),
                environment=self._expected_environment,
            )
