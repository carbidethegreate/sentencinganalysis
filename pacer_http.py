from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from http.cookies import SimpleCookie
from typing import Any, Dict, Optional
import urllib.error
import urllib.request

from pacer_logging import scrub_log_message
from pacer_tokens import PacerTokenRecord, PacerTokenStore


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
        token_refresher: Optional[Any] = None,
    ) -> None:
        self._token_store = token_store
        self._logger = logger
        self._token_cookie_name = token_cookie_name
        self._expected_environment = expected_environment
        self._env_mismatch_reason = env_mismatch_reason
        self._token_refresher = token_refresher
        self._cookie_jar: Dict[str, str] = {}

    def set_cookie(self, name: str, value: str) -> None:
        if not name or value is None:
            return
        self._cookie_jar[name] = str(value)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: int = 30,
        include_cookie: bool = False,
        _retried: bool = False,
    ) -> PacerHttpResponse:
        if self._env_mismatch_reason:
            raise PacerEnvironmentMismatch(self._env_mismatch_reason)

        token_record = self._token_store.get_token(
            expected_environment=self._expected_environment
        )
        if not token_record or not token_record.token:
            token_record = self._refresh_token()
        if not token_record or not token_record.token:
            raise TokenExpired("PACER token missing or expired.")

        request_headers: Dict[str, str] = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)
        request_headers["X-NEXT-GEN-CSO"] = token_record.token

        if include_cookie:
            cookie_parts = [f"{self._token_cookie_name}={token_record.token}"]
            for key, value in self._cookie_jar.items():
                cookie_parts.append(f"{key}={value}")
            existing_cookie = request_headers.get("Cookie")
            if existing_cookie:
                request_headers["Cookie"] = f"{existing_cookie}; {'; '.join(cookie_parts)}"
            else:
                request_headers["Cookie"] = "; ".join(cookie_parts)

        if self._logger:
            self._logger.debug("PCL request %s %s", method, scrub_log_message(url))

        request_obj = urllib.request.Request(
            url, data=data, headers=request_headers, method=method
        )

        try:
            with urllib.request.urlopen(request_obj, timeout=timeout) as response:
                body = response.read()
                status_code = response.getcode()
                headers_obj = response.headers
                headers = dict(headers_obj)
        except urllib.error.HTTPError as exc:
            if exc.headers:
                self._capture_refreshed_token(exc.headers)
                self._capture_cookies(exc.headers)
            if exc.code == 401:
                if not _retried and self._token_refresher:
                    refreshed = self._refresh_token()
                    if refreshed and refreshed.token:
                        return self.request(
                            method,
                            url,
                            headers=headers,
                            data=data,
                            timeout=timeout,
                            include_cookie=include_cookie,
                            _retried=True,
                        )
                raise TokenExpired("PACER token expired.") from exc
            raise

        self._capture_refreshed_token(headers_obj)
        self._capture_cookies(headers_obj)
        return PacerHttpResponse(status_code=status_code, headers=headers, body=body)

    def refresh_token(self) -> Optional[PacerTokenRecord]:
        """Force a token refresh if a refresher is configured."""
        return self._refresh_token()

    def _capture_refreshed_token(self, headers: Any) -> None:
        refreshed = None
        for value in _iter_header_values(headers, "X-NEXT-GEN-CSO"):
            refreshed = value
            break
        if refreshed:
            self._token_store.save_token(
                refreshed,
                obtained_at=datetime.utcnow(),
                environment=self._expected_environment,
            )

    def _capture_cookies(self, headers: Any) -> None:
        if not headers:
            return
        for header in _iter_header_values(headers, "Set-Cookie"):
            try:
                cookie = SimpleCookie()
                cookie.load(header)
                for name, morsel in cookie.items():
                    if morsel.value:
                        self._cookie_jar[name] = morsel.value
            except Exception:
                continue

    def _refresh_token(self) -> Optional[PacerTokenRecord]:
        if not self._token_refresher:
            return None
        try:
            refreshed = self._token_refresher()
        except Exception:
            if self._logger:
                self._logger.warning("PACER token refresh failed.")
            return None
        if isinstance(refreshed, PacerTokenRecord):
            return refreshed
        if isinstance(refreshed, str) and refreshed:
            return self._token_store.save_token(
                refreshed,
                obtained_at=datetime.utcnow(),
                environment=self._expected_environment,
            )
        return None


def _iter_header_values(headers: Any, name: str) -> list[str]:
    if headers is None:
        return []
    if hasattr(headers, "get_all"):
        values = headers.get_all(name)  # type: ignore[attr-defined]
        if values:
            return [value for value in values if value]
    if isinstance(headers, dict):
        for key in (name, name.lower(), name.upper()):
            value = headers.get(key)
            if value:
                return [value]
    return []
