import io
import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode

from sqlalchemy import MetaData, Table, create_engine, func, select

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import build_database_url, create_app


def get_csrf(client):
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf_token"]


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
                "cs_caseid|cs_case_number|cs_short_title|cs_short_title|cs_date_filed\n",
                "1|2024-001|Alpha|Lead Alpha|01/02/2024\n",
                "2|2024-002|Beta|Lead Beta|02/03/2024\n",
            ]
        )
        def build_payload():
            return {
                "csrf_token": get_csrf(client),
                "case_stage1_file": (
                    io.BytesIO(sample.encode("utf-8")),
                    "CaseFiledRPT_USVI.txt",
                ),
            }

        data = build_payload()
        response = client.post(
            "/admin/case-stage1/upload", data=data, content_type="multipart/form-data"
        )
        assert response.status_code == 302, "Expected upload to redirect on success."
        for _ in range(50):
            status_response = client.get("/admin/case-stage1/import-status")
            status_payload = status_response.get_json()
            if status_payload.get("status") in {"completed", "failed"}:
                break
            time.sleep(0.1)
        assert (
            status_payload.get("status") == "completed"
        ), f"Expected upload to complete, got {status_payload.get('status')}."

        query = urlencode({"draw": 1, "start": 0, "length": 1})
        response = client.get(f"/admin/case-stage1/data?{query}")
        payload = response.get_json()
        assert payload["recordsTotal"] > 0, "Expected recordsTotal > 0."
        assert len(payload["data"]) <= 1, "Expected data length to respect length."

        # Upload again to verify upsert (no duplicate cs_caseid).
        data = build_payload()
        client.post("/admin/case-stage1/upload", data=data, content_type="multipart/form-data")
        for _ in range(50):
            status_response = client.get("/admin/case-stage1/import-status")
            status_payload = status_response.get_json()
            if status_payload.get("status") in {"completed", "failed"}:
                break
            time.sleep(0.1)
        assert (
            status_payload.get("status") == "completed"
        ), f"Expected upload to complete, got {status_payload.get('status')}."

        engine = create_engine(build_database_url(), future=True)
        metadata = MetaData()
        case_stage1 = Table("case_stage1", metadata, autoload_with=engine)
        with engine.connect() as conn:
            total = conn.execute(select(func.count()).select_from(case_stage1)).scalar_one()
            distinct_ids = conn.execute(
                select(func.count(func.distinct(case_stage1.c.cs_caseid)))
            ).scalar_one()
        assert total == distinct_ids, "Expected no duplicate cs_caseid rows."

        search_query = urlencode({"draw": 2, "start": 0, "length": 10, "search[value]": "Alpha"})
        response = client.get(f"/admin/case-stage1/data?{search_query}")
        payload = response.get_json()
        assert payload["recordsFiltered"] <= payload["recordsTotal"], "Expected filtered count."
        assert payload["recordsFiltered"] >= 1, "Expected search to return results."

    print("Case stage 1 DataTables verification complete.")


if __name__ == "__main__":
    main()
