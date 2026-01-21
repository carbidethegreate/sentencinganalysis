import io
import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import CASE_STAGE1_DISPLAY_COLUMNS, create_app


def get_csrf(client):
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf_token"]


def wait_for_import(client, timeout_s=5):
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        status_response = client.get("/admin/case-stage1/import-status")
        status_payload = status_response.get_json()
        if status_payload.get("status") in {"completed", "failed"}:
            return status_payload
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for case stage 1 import to finish.")


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "case_stage1.sqlite")
        os.environ["DB_PATH"] = db_path
        os.environ["SECRET_KEY"] = "test-secret-key"
        for key in (
            "DATABASE_URL",
            "InternalDatabaseURL",
            "Internal_Database_URL",
            "ExternalDatabaseURL",
            "External_Database_URL",
            "Hostname",
            "HOSTNAME",
            "Port",
            "PORT",
            "Database",
            "DB_NAME",
            "Username",
            "DB_USER",
            "Password",
            "DB_PASSWORD",
        ):
            os.environ.pop(key, None)

        app = create_app()
        client = app.test_client()

        with client.session_transaction() as session:
            session["is_admin"] = True

        sample = "".join(
            [
                "cs_caseid|cs_case_number|cs_case_type|cs_file_date|cs_short_title|cs_party_last_name|cs_court_location\n",
                "1|2024-001|Civil|01/02/2024|Alpha|Smith|USVI\n",
                "2|2024-002|Criminal|02/03/2024|Beta|Jones|USVI\n",
            ]
        )

        data = {
            "csrf_token": get_csrf(client),
            "case_stage1_file": (
                io.BytesIO(sample.encode("utf-8")),
                "CaseFiledRPT_USVI.txt",
            ),
        }
        response = client.post(
            "/admin/case-stage1/upload", data=data, content_type="multipart/form-data"
        )
        assert response.status_code == 302, "Expected upload to redirect on success."

        status_payload = wait_for_import(client)
        assert (
            status_payload.get("status") == "completed"
        ), f"Expected upload to complete, got {status_payload.get('status')}."

        query = urlencode({"draw": 1, "start": 0, "length": 1})
        start_time = time.monotonic()
        response = client.get(f"/admin/case-stage1/data?{query}")
        elapsed = time.monotonic() - start_time
        payload = response.get_json()
        assert elapsed < 2.0, f"Expected data endpoint to respond quickly, took {elapsed:.2f}s."
        assert payload["recordsTotal"] > 0, "Expected recordsTotal > 0."
        assert payload["recordsFiltered"] == payload["recordsTotal"], (
            "Expected recordsFiltered to match recordsTotal for empty search."
        )
        if payload["data"]:
            row_keys = set(payload["data"][0].keys())
            assert row_keys <= set(CASE_STAGE1_DISPLAY_COLUMNS), (
                "Expected response to only include display columns."
            )

        search_query = urlencode(
            {"draw": 2, "start": 0, "length": 10, "search[value]": "Alpha"}
        )
        response = client.get(f"/admin/case-stage1/data?{search_query}")
        payload = response.get_json()
        assert payload["recordsFiltered"] <= payload["recordsTotal"], (
            "Expected filtered count to be <= total count."
        )

    print("Admin case stage 1 performance verification complete.")


if __name__ == "__main__":
    main()
