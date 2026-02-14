#!/usr/bin/env python3
"""
Minimal smoke checks for the unified admin "Cases" surface.

This does not require pytest. It uses Flask's test_client and a temporary sqlite DB.
"""

from __future__ import annotations

import os
import tempfile
import sys
from pathlib import Path
from typing import Iterable, Tuple


def _make_app():
    # Isolate the DB so we don't touch a developer's real sqlite file.
    fd, db_path = tempfile.mkstemp(prefix="smoke_cases_", suffix=".sqlite")
    os.close(fd)
    os.environ["DB_PATH"] = db_path
    # Ensure bootstrap is enabled so required tables exist.
    os.environ.pop("DB_BOOTSTRAP", None)

    repo_root = str(Path(__file__).resolve().parents[1])
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    from app import create_app

    app = create_app()
    app.config.update(TESTING=True)
    return app, db_path


def _admin_client(app):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["is_admin"] = True
    return client


def _assert_status(path: str, status_code: int, actual: int) -> None:
    if actual != status_code:
        raise SystemExit(f"[FAIL] {path}: expected {status_code}, got {actual}")
    print(f"[OK]   {path}: {actual}")


def _assert_redirect(path: str, location: str, expected_prefix: str) -> None:
    if not location:
        raise SystemExit(f"[FAIL] {path}: missing Location header")
    if not location.startswith(expected_prefix):
        raise SystemExit(
            f"[FAIL] {path}: expected redirect to {expected_prefix}, got {location}"
        )
    print(f"[OK]   {path}: 302 -> {location}")


def main() -> None:
    app, db_path = _make_app()
    client = _admin_client(app)

    try:
        ok_gets: Iterable[Tuple[str, str]] = [
            ("Cases (default)", "/admin/federal-data-dashboard/cases"),
            ("Cases (pacer cards)", "/admin/federal-data-dashboard/cases?source=pacer&view=cards"),
            ("Cases (pacer ops)", "/admin/federal-data-dashboard/cases?source=pacer&view=ops"),
            ("Cases (imported)", "/admin/federal-data-dashboard/cases?source=imported"),
        ]
        for _, path in ok_gets:
            resp = client.get(path)
            _assert_status(path, 200, resp.status_code)

        redirect_checks: Iterable[Tuple[str, str]] = [
            ("Old Case Cards", "/admin/federal-data-dashboard/case-cards"),
            ("Old Indexed Cases", "/admin/pcl/cases"),
            ("Old Case Data One", "/admin/case-data-one"),
        ]
        expected_prefix = "/admin/federal-data-dashboard/cases"
        for _, path in redirect_checks:
            resp = client.get(path, follow_redirects=False)
            _assert_status(path, 302, resp.status_code)
            _assert_redirect(path, resp.headers.get("Location", ""), expected_prefix)

        print("\nAll smoke checks passed.")
    finally:
        try:
            os.remove(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
