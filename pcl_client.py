from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
import urllib.error
from urllib.parse import urlencode

from pacer_http import PacerEnvironmentMismatch, PacerHttpClient, TokenExpired


@dataclass(frozen=True)
class PclApiError(Exception):
    status_code: int
    message: str
    details: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        return f"PCL API error {self.status_code}: {self.message}"


@dataclass(frozen=True)
class PclJsonResponse:
    status_code: int
    payload: Dict[str, Any]
    raw_body: bytes


class PclClient:
    def __init__(
        self,
        http_client: PacerHttpClient,
        base_url: str,
        *,
        logger: Optional[Any] = None,
    ) -> None:
        self._http_client = http_client
        self._base_url = base_url.rstrip("/")
        self._logger = logger

    def start_case_download(
        self,
        payload: Dict[str, Any],
        *,
        sort_params: Optional[list[tuple[str, str]]] = None,
    ) -> Dict[str, Any]:
        path = _build_path_with_params("/cases/download", sort_params)
        return self._request_json("POST", path, payload)

    def get_case_download_status(self, report_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/cases/download/status/{report_id}")

    def list_case_reports(self) -> Dict[str, Any]:
        return self._request_json("GET", "/cases/reports")

    def download_case_report(self, report_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/cases/download/{report_id}")

    def delete_case_report(self, report_id: str) -> Dict[str, Any]:
        return self._request_json("DELETE", f"/cases/reports/{report_id}")

    def start_party_download(
        self,
        payload: Dict[str, Any],
        *,
        sort_params: Optional[list[tuple[str, str]]] = None,
    ) -> Dict[str, Any]:
        path = _build_path_with_params("/parties/download", sort_params)
        return self._request_json("POST", path, payload)

    def get_party_download_status(self, report_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/parties/download/status/{report_id}")

    def list_party_reports(self) -> Dict[str, Any]:
        return self._request_json("GET", "/parties/reports")

    def download_party_report(self, report_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"/parties/download/{report_id}")

    def delete_party_report(self, report_id: str) -> Dict[str, Any]:
        return self._request_json("DELETE", f"/parties/reports/{report_id}")

    def immediate_case_search(
        self,
        page: int,
        payload: Dict[str, Any],
        *,
        sort_params: Optional[list[tuple[str, str]]] = None,
    ) -> PclJsonResponse:
        page_num = max(0, int(page))
        sanitized = _sanitize_case_search_payload(payload)
        params = [("page", page_num)]
        if sort_params:
            params.extend(sort_params)
        return self._request_json_with_meta(
            "POST",
            _build_path_with_params("/cases/find", params),
            sanitized,
        )

    def immediate_party_search(
        self,
        page: int,
        payload: Dict[str, Any],
        *,
        sort_params: Optional[list[tuple[str, str]]] = None,
    ) -> PclJsonResponse:
        page_num = max(0, int(page))
        params = [("page", page_num)]
        if sort_params:
            params.extend(sort_params)
        return self._request_json_with_meta(
            "POST",
            _build_path_with_params("/parties/find", params),
            payload,
        )

    def _request_json(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        response = self._request_json_with_meta(method, path, payload)
        return response.payload

    def _request_json_with_meta(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> PclJsonResponse:
        url = f"{self._base_url}{path}"
        body = None
        headers = {"Content-Type": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        try:
            response = self._http_client.request(
                method,
                url,
                headers=headers,
                data=body,
            )
        except (PacerEnvironmentMismatch, TokenExpired):
            raise
        except urllib.error.HTTPError as exc:
            return self._handle_http_error(exc)

        payload_dict = _safe_json_loads(response.body) if response.body else {}
        return PclJsonResponse(
            status_code=response.status_code,
            payload=payload_dict,
            raw_body=response.body,
        )

    def _handle_http_error(self, exc: urllib.error.HTTPError) -> PclJsonResponse:
        body = exc.read()
        details = _safe_json_loads(body) if body else {}
        message = _first_non_empty_string(
            details.get("message"),
            details.get("error"),
            details.get("detail"),
            getattr(exc, "reason", None),
        )
        if not message:
            message = f"HTTP {exc.code}"
        if self._logger:
            self._logger.warning("PCL API error %s: %s", exc.code, message)
        raise PclApiError(exc.code, message, details=details)


def _safe_json_loads(payload: bytes) -> Dict[str, Any]:
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return {}


def _sanitize_case_search_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = dict(payload or {})
    for key in ("pageSize", "page_size", "page", "pageNumber", "page_number"):
        cleaned.pop(key, None)
    return cleaned


def _build_path_with_params(
    path: str, params: Optional[list[tuple[str, str]]]
) -> str:
    if not params:
        return path
    query = urlencode(params, doseq=True)
    return f"{path}?{query}"


def _first_non_empty_string(*values: Any) -> str:
    """Return the first value that can be rendered as a non-empty string.

    Guards against the common `str(None) == "None"` pitfall when parsing API errors.
    """

    for value in values:
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            try:
                rendered = json.dumps(value, sort_keys=True, default=str)
            except Exception:
                rendered = str(value)
        else:
            rendered = str(value)
        rendered = rendered.strip()
        if not rendered:
            continue
        if rendered.lower() == "none":
            continue
        return rendered
    return ""
