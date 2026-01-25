import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from sqlalchemy import insert, select

from app import create_app
from pacer_http import TokenExpired
from pacer_tokens import PacerTokenRecord
from pacer_explore_schemas import build_party_search_payload, validate_pcl_payload
from pcl_client import PclApiError, PclJsonResponse


class AdminPacerExploreTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            key: os.environ.get(key)
            for key in (
                "DB_PATH",
                "SECRET_KEY_PATH",
                "PACER_AUTH_BASE_URL",
                "PCL_BASE_URL",
            )
        }
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(self._tmpdir.name, "test.sqlite")
        os.environ["SECRET_KEY_PATH"] = os.path.join(self._tmpdir.name, ".secret_key")
        os.environ["PACER_AUTH_BASE_URL"] = "https://qa-login.uscourts.gov"
        os.environ["PCL_BASE_URL"] = "https://qa-pcl.uscourts.gov/pcl-public-api/rest"
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.engine = self.app.engine
        self.courts_table = self.app.pcl_courts_table
        self.explore_runs_table = self.app.pcl_tables["pacer_explore_runs"]
        self.search_requests_table = self.app.pcl_tables["pacer_search_requests"]
        self.search_runs_table = self.app.pcl_tables["pacer_search_runs"]
        self.cases_table = self.app.pcl_tables["pcl_cases"]
        self.parties_table = self.app.pcl_tables["pcl_parties"]
        self._seed_courts()
        self._login_admin()

    def tearDown(self):
        self._tmpdir.cleanup()
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _seed_courts(self):
        with self.engine.begin() as conn:
            conn.execute(
                insert(self.courts_table),
                [
                    {
                        "pcl_court_id": "akdc",
                        "name": "Alaska District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                    {
                        "pcl_court_id": "candc",
                        "name": "California Northern District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                    {
                        "pcl_court_id": "vi",
                        "name": "Virgin Islands District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                ],
            )

    def _seed_courts_for_app(self, app):
        with app.engine.begin() as conn:
            conn.execute(
                insert(app.pcl_courts_table),
                [
                    {
                        "pcl_court_id": "akdc",
                        "name": "Alaska District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                    {
                        "pcl_court_id": "candc",
                        "name": "California Northern District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                    {
                        "pcl_court_id": "vi",
                        "name": "Virgin Islands District Court",
                        "active": True,
                        "source": "PCL Appendix A",
                    },
                ],
            )

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = "csrf-token"

    def _login_admin_for_client(self, client):
        with client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["csrf_token"] = "csrf-token"

    def _authorize_pacer(self):
        with self.client.session_transaction() as sess:
            session_key = sess.get("pacer_session_key") or "session-key"
            sess["pacer_session_key"] = session_key
        record = PacerTokenRecord(
            token="server-side-token",
            obtained_at=datetime.utcnow(),
            environment="qa",
        )
        self.app.pacer_token_store._backend.save_token(session_key, record)

    def _post_run(self, **overrides):
        payload = {
            "csrf_token": "csrf-token",
            "mode": "cases",
            "court_id": "akdc",
            "date_filed_from": "2024-01-01",
            "date_filed_to": "2024-01-31",
            "max_records": "54",
            "page": "1",
        }
        if "search_mode" in overrides:
            payload["search_mode"] = overrides.pop("search_mode")
        payload.update(overrides)
        return self.client.post("/admin/pacer/explore/run", data=payload)

    def test_get_explore_page_lists_courts(self):
        response = self.client.get("/admin/pacer/explore")
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Explore PACER", html)
        self.assertIn("akdc, Alaska District Court", html)
        self.assertIn("candc, California Northern District Court", html)

    def test_post_run_requires_authorization(self):
        with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
            response = self._post_run()
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("PACER authorization is required", html)
        self.assertIn("Next step: click Authorize", html)
        self.assertIn("Copy debug bundle", html)
        self.assertNotIn("server-side-token", html)
        mock_search.assert_not_called()

    def test_post_run_blocks_on_env_mismatch(self):
        env_backup = {key: os.environ.get(key) for key in os.environ.keys()}
        tmpdir = tempfile.TemporaryDirectory()
        try:
            os.environ["DB_PATH"] = os.path.join(tmpdir.name, "mismatch.sqlite")
            os.environ["SECRET_KEY_PATH"] = os.path.join(tmpdir.name, ".secret_key")
            os.environ["PACER_AUTH_BASE_URL"] = "https://pacer.login.uscourts.gov"
            os.environ["PCL_BASE_URL"] = "https://qa-pcl.uscourts.gov/pcl-public-api/rest"
            with self.assertRaises(ValueError) as ctx:
                create_app()
            self.assertIn("PACER_AUTH_BASE_URL=https://qa-login.uscourts.gov", str(ctx.exception))
        finally:
            tmpdir.cleanup()
            os.environ.clear()
            os.environ.update(env_backup)

    def test_post_run_blocks_on_token_environment_mismatch(self):
        with self.client.session_transaction() as sess:
            sess["pacer_session_key"] = "session-key"
        self.app.pacer_token_store._backend.save_token(
            "session-key",
            PacerTokenRecord(
                token="server-side-token",
                obtained_at=datetime.utcnow(),
                environment="prod",
            ),
        )
        with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
            response = self._post_run()
        html = response.data.decode("utf-8")
        self.assertIn("Re-authorize in the correct environment", html)
        mock_search.assert_not_called()

    def test_post_run_blocks_when_search_disabled(self):
        self._authorize_pacer()
        with self.client.session_transaction() as sess:
            sess["pacer_search_disabled"] = True
            sess["pacer_search_disabled_reason"] = (
                "PACER authenticated, but searching is disabled."
            )
        with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
            response = self._post_run()
        html = response.data.decode("utf-8")
        self.assertIn("searching is disabled", html)
        self.assertIn("client code", html)
        mock_search.assert_not_called()

    def test_post_run_allows_matching_environment(self):
        self._authorize_pacer()
        payload = {
            "content": [],
            "receipt": {"billablePages": 0},
            "pageInfo": {"page": 1, "totalPages": 1, "totalRecords": 0},
        }
        fake_response = PclJsonResponse(status_code=200, payload=payload, raw_body=b"{}")
        with patch.object(self.app.pcl_client, "immediate_case_search", return_value=fake_response) as mock_search:
            response = self._post_run()
        self.assertEqual(response.status_code, 200)
        mock_search.assert_called()

    def test_post_run_blocks_invalid_court_id(self):
        self._authorize_pacer()
        with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
            response = self._post_run(court_id="vidc")
        html = response.data.decode("utf-8")
        self.assertIn("Select a valid court from the list.", html)
        mock_search.assert_not_called()

    def test_post_run_accepts_known_court_id(self):
        self._authorize_pacer()
        payload = {
            "content": [],
            "receipt": {"billablePages": 0},
            "pageInfo": {"page": 1, "totalPages": 1, "totalRecords": 0},
        }
        fake_response = PclJsonResponse(status_code=200, payload=payload, raw_body=b"{}")
        with patch.object(self.app.pcl_client, "immediate_case_search", return_value=fake_response) as mock_search:
            response = self._post_run(court_id="VI")
        html = response.data.decode("utf-8")
        self.assertIn("Run complete", html)
        mock_search.assert_called()

    def test_post_run_success_shows_results_and_observed_fields(self):
        self._authorize_pacer()
        payload = {
            "content": [
                {
                    "caseNumber": "1:24-cr-00001",
                    "caseType": "cr",
                    "dateFiled": "2024-01-02",
                    "shortTitle": "USA v. Doe",
                    "judgeLastName": "Jackson",
                },
                {
                    "caseNumber": "1:24-cr-00002",
                    "caseType": "cr",
                    "dateFiled": "2024-01-10",
                    "shortTitle": "USA v. Roe",
                    "judgeLastName": "",
                    "natureOfSuit": "510",
                },
            ],
            "receipt": {"billablePages": 1, "searchFee": 0.1},
            "pageInfo": {"page": 1, "totalPages": 1, "totalRecords": 2},
        }
        fake_response = PclJsonResponse(status_code=200, payload=payload, raw_body=b"{}")

        with patch.object(self.app.pcl_client, "immediate_case_search", return_value=fake_response):
            response = self._post_run()

        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Run complete", html)
        self.assertIn("1:24-cr-00001", html)
        self.assertIn("Top-level field coverage", html)
        self.assertIn("caseNumber", html)
        self.assertIn("judgeLastName", html)
        self.assertIn("natureOfSuit", html)
        self.assertIn("Billable pages total: <strong>1</strong>", html)
        self.assertIn("status_codes", html)
        self.assertNotIn("server-side-token", html)

        with self.engine.begin() as conn:
            runs = conn.execute(select(self.explore_runs_table)).mappings().all()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["mode"], "cases")
        self.assertIsNone(runs[0]["error_summary"])

    def test_case_search_payload_excludes_page_size(self):
        self._authorize_pacer()
        captured: dict = {}

        def _fake_search(page, payload):
            captured["payload"] = payload
            return PclJsonResponse(
                status_code=200,
                payload={"content": [], "pageInfo": {"page": 0}},
                raw_body=b"{}",
            )

        with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=_fake_search):
            response = self._post_run()

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("pageSize", captured["payload"])

    def test_case_search_uses_zero_based_page_param(self):
        self._authorize_pacer()
        pages = []

        def _fake_search(page, payload):
            pages.append(page)
            return PclJsonResponse(
                status_code=200,
                payload={"content": [], "pageInfo": {"page": page}},
                raw_body=b"{}",
            )

        with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=_fake_search):
            response = self._post_run()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(pages)
        self.assertEqual(pages[0], 0)

    def test_post_run_handles_401_and_406_errors(self):
        self._authorize_pacer()

        with self.subTest("401 token expired"):
            with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=TokenExpired()):
                response = self._post_run()
            html = response.data.decode("utf-8")
            self.assertIn("Token expired or invalid", html)
            self.assertIn("re-authorize", html)
            self.assertIn("Copy debug bundle", html)
            self.assertNotIn("server-side-token", html)

        with self.subTest("406 invalid parameter"):
            error = PclApiError(406, "Invalid search", details={"message": "bad filter"})
            with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=error):
                response = self._post_run(case_types=["cr"])
            html = response.data.decode("utf-8")
            self.assertIn("PCL rejected the request parameters", html)
            self.assertIn("Status 406", html)
            self.assertIn("Copy debug bundle", html)
            self.assertIn("bad filter", html)
            self.assertNotIn("server-side-token", html)

        with self.engine.begin() as conn:
            runs = conn.execute(select(self.explore_runs_table)).mappings().all()
        self.assertEqual(len(runs), 2)
        self.assertTrue(any(run["error_summary"] for run in runs))

    def test_post_run_creates_history_on_failed_run(self):
        self._authorize_pacer()
        error = PclApiError(406, "Invalid search", details={"message": "bad filter"})
        with patch.object(self.app.pcl_client, "immediate_case_search", side_effect=error):
            response = self._post_run(case_types=["cr"])
        self.assertEqual(response.status_code, 200)

        with self.engine.begin() as conn:
            run = conn.execute(
                select(self.explore_runs_table).order_by(self.explore_runs_table.c.id.desc())
            ).mappings().first()
        self.assertIsNotNone(run)
        self.assertIn("PCL rejected the request parameters", run["error_summary"])

    def test_payload_validation_blocks_invalid_keys_before_http(self):
        self._authorize_pacer()
        invalid_payload = {
            "courtId": ["akdc"],
            "dateFiledFrom": "2024-01-01",
            "dateFiledTo": "2024-01-31",
            "pageSize": 54,
        }
        with patch("app.build_case_search_payload", return_value=invalid_payload):
            with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
                response = self._post_run()
        html = response.data.decode("utf-8")
        self.assertIn("Internal payload validation failed before contacting PCL", html)
        self.assertIn("Invalid payload keys: pageSize.", html)
        mock_search.assert_not_called()

    def test_unexpected_ui_keys_are_recorded_in_debug_bundle(self):
        self._authorize_pacer()
        fake_response = PclJsonResponse(
            status_code=200,
            payload={"content": [], "pageInfo": {"page": 0}},
            raw_body=b"{}",
        )
        with patch.object(self.app.pcl_client, "immediate_case_search", return_value=fake_response):
            response = self._post_run(page_size="54", someNewField="extra")
        html = response.data.decode("utf-8")
        self.assertIn("Run complete", html)
        self.assertIn("unexpected_input_keys", html)
        self.assertIn("page_size", html)
        self.assertIn("someNewField", html)

    def test_party_builder_and_validation_enforce_allowlist(self):
        payload = build_party_search_payload(
            {
                "last_name": "doe",
                "exact_name_match": "true",
                "first_name": "jane",
                "ssn": "123-45-6789",
                "court_id": "akdc",
                "date_filed_from": "2024-01-01",
                "date_filed_to": "2024-01-31",
                "pageSize": "ignored",
            },
            include_date_range=True,
        )
        valid, invalid_keys, missing_keys = validate_pcl_payload("parties", payload)
        self.assertTrue(valid)
        self.assertEqual(invalid_keys, [])
        self.assertEqual(missing_keys, [])
        self.assertNotIn("pageSize", payload)
        self.assertIn("ssn", payload)

        invalid_payload = build_party_search_payload(
            {"first_name": "jane"},
            include_date_range=False,
        )
        valid, invalid_keys, missing_keys = validate_pcl_payload("parties", invalid_payload)
        self.assertFalse(valid)
        self.assertEqual(invalid_keys, [])
        self.assertIn("lastName", missing_keys)

    def test_party_mode_renders_results_and_nested_fields(self):
        self._authorize_pacer()
        payload = {
            "content": [
                {
                    "lastName": "Doe",
                    "firstName": "Jane",
                    "partyType": "defendant",
                        "courtCase": {
                            "caseNumber": "1:24-cr-00003",
                            "courtId": "akdc",
                            "judgeLastName": "Smith",
                        },
                    }
            ],
            "receipt": {"billablePages": 1, "searchFee": 0.1},
            "pageInfo": {"page": 1, "totalPages": 1, "totalRecords": 1},
        }
        fake_response = PclJsonResponse(status_code=200, payload=payload, raw_body=b"{}")

        with patch.object(self.app.pcl_client, "immediate_party_search", return_value=fake_response):
            response = self._post_run(
                mode="parties",
                last_name="doe",
                first_name="jane",
                court_id="akdc",
            )

        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Returned parties", html)
        self.assertIn("Doe", html)
        self.assertIn("courtCase", html)
        self.assertIn("judgeLastName", html)

    def test_batch_mode_submits_report_and_stores_request(self):
        self._authorize_pacer()
        report_payload = {"reportId": "123", "status": "SUBMITTED", "recordCount": 10}
        with patch.object(self.app.pcl_client, "start_case_download", return_value=report_payload) as mock_start:
            response = self._post_run(search_mode="batch", max_records="108")
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Report submitted", html)
        mock_start.assert_called_once()
        with self.engine.begin() as conn:
            row = conn.execute(
                select(self.search_requests_table).order_by(self.search_requests_table.c.id.desc())
            ).mappings().first()
        self.assertIsNotNone(row)
        self.assertEqual(row["search_mode"], "batch")
        self.assertEqual(row["report_id"], "123")

    def test_batch_status_updates_request(self):
        self._authorize_pacer()
        criteria = {
            "ui_inputs": {
                "court_id": "akdc",
                "date_filed_from": "2024-01-01",
                "date_filed_to": "2024-01-31",
                "max_records": "54",
            },
            "request_body": {
                "courtId": ["akdc"],
                "dateFiledFrom": "2024-01-01",
                "dateFiledTo": "2024-01-31",
            },
        }
        with self.engine.begin() as conn:
            request_id = conn.execute(
                insert(self.search_requests_table).values(
                    search_type="case",
                    search_mode="batch",
                    criteria_json=json.dumps(criteria),
                    report_id="101",
                    report_status="SUBMITTED",
                )
            ).inserted_primary_key[0]

        status_payload = {"reportId": "101", "status": "COMPLETED", "recordCount": 5}
        with patch.object(self.app.pcl_client, "get_case_download_status", return_value=status_payload):
            response = self.client.post(
                "/admin/pacer/explore/batch/status",
                data={"csrf_token": "csrf-token", "request_id": request_id},
            )
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("COMPLETED", html)
        with self.engine.begin() as conn:
            row = conn.execute(
                select(self.search_requests_table).where(self.search_requests_table.c.id == request_id)
            ).mappings().first()
        self.assertEqual(row["report_status"], "COMPLETED")

    def test_batch_load_results_after_completion(self):
        self._authorize_pacer()
        criteria = {
            "ui_inputs": {
                "court_id": "akdc",
                "date_filed_from": "2024-01-01",
                "date_filed_to": "2024-01-31",
                "max_records": "54",
            },
            "request_body": {
                "courtId": ["akdc"],
                "dateFiledFrom": "2024-01-01",
                "dateFiledTo": "2024-01-31",
            },
        }
        with self.engine.begin() as conn:
            request_id = conn.execute(
                insert(self.search_requests_table).values(
                    search_type="case",
                    search_mode="batch",
                    criteria_json=json.dumps(criteria),
                    report_id="202",
                    report_status="SUBMITTED",
                )
            ).inserted_primary_key[0]

        status_payload = {"reportId": "202", "status": "COMPLETED", "recordCount": 1}
        report_payload = {
            "content": [
                {
                    "caseNumber": "1:24-cr-00004",
                    "caseType": "cr",
                    "dateFiled": "2024-01-20",
                    "shortTitle": "USA v. Batch",
                }
            ]
        }
        with patch.object(self.app.pcl_client, "get_case_download_status", return_value=status_payload):
            with patch.object(self.app.pcl_client, "download_case_report", return_value=report_payload):
                response = self.client.post(
                    "/admin/pacer/explore/batch/load",
                    data={"csrf_token": "csrf-token", "request_id": request_id},
                )
        html = response.data.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("1:24-cr-00004", html)

    def test_invalid_search_mode_is_rejected(self):
        self._authorize_pacer()
        with patch.object(self.app.pcl_client, "immediate_case_search") as mock_search:
            response = self._post_run(search_mode="unsupported")
        html = response.data.decode("utf-8")
        self.assertIn("Search mode must be Immediate or Batch", html)
        mock_search.assert_not_called()

    def test_run_delete_is_admin_only(self):
        with self.engine.begin() as conn:
            run_id = conn.execute(
                insert(self.explore_runs_table).values(
                    mode="cases",
                    court_id="akdc",
                    request_params={},
                    pages_fetched=1,
                )
            ).inserted_primary_key[0]

        anon_client = self.app.test_client()
        response = anon_client.post(f"/admin/pacer/explore/runs/{run_id}/delete")
        self.assertEqual(response.status_code, 302)

        response = self.client.post(
            f"/admin/pacer/explore/runs/{run_id}/delete",
            data={"csrf_token": "csrf-token", "mode": "cases"},
        )
        self.assertEqual(response.status_code, 302)
        with self.engine.begin() as conn:
            remaining = conn.execute(
                select(self.explore_runs_table).where(self.explore_runs_table.c.id == run_id)
            ).mappings().all()
        self.assertEqual(remaining, [])

    def test_immediate_pagination_controls_respect_page_number(self):
        self._authorize_pacer()
        payload = {
            "content": [],
            "receipt": {"billablePages": 0},
            "pageInfo": {
                "number": 1,
                "size": 54,
                "totalPages": 3,
                "totalElements": 120,
                "numberOfElements": 54,
                "first": False,
                "last": False,
            },
        }
        fake_response = PclJsonResponse(status_code=200, payload=payload, raw_body=b"{}")
        with patch.object(self.app.pcl_client, "immediate_case_search", return_value=fake_response) as mock_search:
            response = self._post_run(page="2")
        self.assertEqual(response.status_code, 200)
        mock_search.assert_called_once()
        self.assertIn("Page 2", response.data.decode("utf-8"))

    def test_store_or_update_upserts_cases(self):
        payload = {
            "mode": "cases",
            "search_mode": "immediate",
            "criteria": {
                "ui_inputs": {
                    "court_id": "akdc",
                    "date_filed_from": "2024-01-01",
                    "date_filed_to": "2024-01-31",
                },
                "request_body": {
                    "courtId": ["akdc"],
                    "dateFiledFrom": "2024-01-01",
                    "dateFiledTo": "2024-01-31",
                },
            },
            "results": [
                {
                    "caseNumber": "1:24-cr-00001",
                    "caseNumberFull": "1:24-cr-00001",
                    "caseType": "cr",
                    "caseTitle": "USA v. Doe",
                    "dateFiled": "2024-01-02",
                    "courtId": "akdc",
                }
            ],
            "receipts": [
                {
                    "page": 1,
                    "receipt": {
                        "transactionDate": "2024-01-02",
                        "billablePages": 1,
                        "loginId": "acct",
                        "search": "case search",
                        "description": "PCL search",
                        "csoId": "abc",
                        "reportId": "r1",
                        "searchFee": 0.1,
                    },
                }
            ],
            "page_info": {"number": 0, "size": 54, "totalPages": 1, "totalElements": 1},
            "raw_response": {"content": []},
        }
        response = self.client.post(
            "/admin/pacer/explore/store",
            data={"csrf_token": "csrf-token", "store_payload": json.dumps(payload)},
        )
        self.assertEqual(response.status_code, 200)
        with self.engine.begin() as conn:
            cases = conn.execute(select(self.cases_table)).mappings().all()
            runs = conn.execute(select(self.search_runs_table)).mappings().all()
        self.assertEqual(len(cases), 1)
        self.assertEqual(len(runs), 1)

        payload["results"][0]["caseTitle"] = "USA v. Doe Updated"
        response = self.client.post(
            "/admin/pacer/explore/store",
            data={"csrf_token": "csrf-token", "store_payload": json.dumps(payload)},
        )
        self.assertEqual(response.status_code, 200)
        with self.engine.begin() as conn:
            cases = conn.execute(select(self.cases_table)).mappings().all()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["case_title"], "USA v. Doe Updated")

    def test_store_or_update_links_parties_to_cases(self):
        payload = {
            "mode": "parties",
            "search_mode": "immediate",
            "criteria": {
                "ui_inputs": {"last_name": "doe"},
                "request_body": {"lastName": "doe"},
            },
            "results": [
                {
                    "lastName": "Doe",
                    "firstName": "Jane",
                    "partyType": "defendant",
                    "courtCase": {
                        "caseNumber": "2:24-cr-00002",
                        "caseNumberFull": "2:24-cr-00002",
                        "courtId": "akdc",
                        "caseType": "cr",
                    },
                }
            ],
            "receipts": [],
            "page_info": None,
            "raw_response": {"content": []},
        }
        response = self.client.post(
            "/admin/pacer/explore/store",
            data={"csrf_token": "csrf-token", "store_payload": json.dumps(payload)},
        )
        self.assertEqual(response.status_code, 200)
        with self.engine.begin() as conn:
            cases = conn.execute(select(self.cases_table)).mappings().all()
            parties = conn.execute(select(self.parties_table)).mappings().all()
        self.assertEqual(len(cases), 1)
        self.assertEqual(len(parties), 1)
        self.assertEqual(parties[0]["case_id"], cases[0]["id"])

    def test_store_or_update_records_batch_report_metadata(self):
        payload = {
            "mode": "cases",
            "search_mode": "batch",
            "criteria": {
                "ui_inputs": {
                    "court_id": "akdc",
                    "date_filed_from": "2024-01-01",
                    "date_filed_to": "2024-01-31",
                },
                "request_body": {
                    "courtId": ["akdc"],
                    "dateFiledFrom": "2024-01-01",
                    "dateFiledTo": "2024-01-31",
                },
            },
            "results": [
                {
                    "caseNumber": "3:24-cr-00003",
                    "caseNumberFull": "3:24-cr-00003",
                    "caseType": "cr",
                    "caseTitle": "USA v. Batch",
                    "dateFiled": "2024-01-20",
                    "courtId": "akdc",
                }
            ],
            "receipts": [],
            "page_info": None,
            "raw_response": {"content": []},
            "report_request": {
                "request_id": 1,
                "report_id": "batch-55",
                "status": "COMPLETED",
                "info": {"reportId": "batch-55", "status": "COMPLETED"},
            },
        }
        response = self.client.post(
            "/admin/pacer/explore/store",
            data={"csrf_token": "csrf-token", "store_payload": json.dumps(payload)},
        )
        self.assertEqual(response.status_code, 200)
        with self.engine.begin() as conn:
            runs = conn.execute(select(self.search_runs_table)).mappings().all()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["report_id"], "batch-55")
        self.assertEqual(runs[0]["report_status"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()
