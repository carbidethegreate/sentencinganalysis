import csv
import json
import hmac
import os
import re
import secrets
import time
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote_plus

import requests
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import (
    Boolean,
    BigInteger,
    Date,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Text,
    bindparam,
    create_engine,
    delete,
    desc,
    func,
    inspect,
    insert,
    literal_column,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, insert as pg_insert
from sqlalchemy import text as sa_text
from sqlalchemy.exc import IntegrityError, NoSuchTableError, OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

from pacer_http import PacerHttpClient
from pacer_tokens import (
    DatabaseTokenBackend,
    InMemoryTokenBackend,
    PacerTokenStore,
    build_pacer_token_table,
)
from docket_enrichment import DocketEnrichmentWorker
from pcl_batch import PclBatchPlanner, PclBatchWorker
from pcl_client import PclClient
from pcl_models import build_pcl_tables
from sentencing_models import (
    VALID_EVIDENCE_SOURCE_TYPES,
    VALID_VARIANCE_TYPES,
    build_sentencing_tables,
)
from pcl_queries import get_case_detail, list_cases, parse_filters
from sentencing_queries import list_sentencing_events_by_judge, parse_sentencing_filters
from federal_courts_sync import (
    FEDERAL_COURTS_SOURCE_URL,
    FederalCourtsSyncError,
    fetch_federal_courts_json,
    upsert_federal_courts,
)

DEFAULT_DB_FILENAME = "case_filed_rpt.sqlite"
CASE_STAGE1_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
CASE_STAGE1_CHUNK_SIZE = 1000
CASE_STAGE1_DISPLAY_COLUMNS = [
    "cs_caseid",
    "cs_case_number",
    "cs_case_type",
    "cs_file_date",
    "cs_short_title",
    "cs_party_last_name",
    "cs_court_location",
    "updated_at",
]
CASE_STAGE1_IMPORT_COLUMNS = [
    "cs_caseid",
    "cs_case_number",
    "cs_case_type",
    "cs_file_date",
    "cs_short_title",
    "lead_short_title",
    "cs_party_last_name",
    "cs_court_location",
]
CASE_STAGE1_DATE_COLUMNS = {"cs_file_date"}
CASE_STAGE1_HEADER_ALIASES = {"cs_date_filed": "cs_file_date"}
CASE_DATA_ONE_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
CASE_DATA_ONE_CHUNK_SIZE = 1000
CASE_DATA_ONE_PROGRESS_INTERVAL_ROWS = 50
CASE_DATA_ONE_PROGRESS_INTERVAL_SECONDS = 1.0
SQLITE_MAX_VARIABLE_NUMBER = 999
CASE_DATA_ONE_DISPLAY_COLUMNS = [
    "cs_caseid",
    "cs_case_number",
    "cs_short_title",
    "cs_date_filed",
    "cs_date_term",
    "cs_type",
    "lead_case_number",
    "lead_short_title",
    "pre_judge_name",
    "ref_judge_name",
    "party",
]
CASE_DATA_ONE_IMPORT_COLUMNS = [
    "cs_caseid",
    "cs_case_number",
    "cs_short_title",
    "cs_date_filed",
    "cs_date_term",
    "cs_date_reopen",
    "cs_type",
    "cs_type_normalized",
    "cs_case_restriction",
    "lead_caseid",
    "lead_case_number",
    "lead_short_title",
    "lead_date_filed",
    "lead_date_term",
    "lead_date_reopen",
    "office_trans",
    "pre_judge_name",
    "ref_judge_name",
    "cs_case_office",
    "cs_case_year",
    "cs_case_type_code",
    "cs_case_number_seq",
    "cs_sort_case_numb",
    "cs_def_num",
    "cs_term_digit",
    "party",
    "party_normalized",
    "party_type",
    "party_type_normalized",
    "party_role",
    "party_role_normalized",
    "party_start_date",
    "party_end_date",
    "party_def_num",
    "party_def_num_normalized",
    "loc_date_start",
    "loc_date_end",
]
CASE_DATA_ONE_DATE_COLUMNS = {
    "cs_date_filed",
    "cs_date_term",
    "cs_date_reopen",
    "lead_date_filed",
    "lead_date_term",
    "lead_date_reopen",
    "party_start_date",
    "party_end_date",
    "loc_date_start",
    "loc_date_end",
}
CASE_DATA_ONE_HEADER_ALIASES: Dict[str, str] = {}
CASE_DATA_ONE_ERROR_DETAIL_LIMIT = 200
CASE_DATA_ONE_SEARCH_COLUMNS = [
    "cs_case_number",
    "cs_short_title",
    "cs_type",
    "cs_type_normalized",
    "party",
    "party_type",
    "party_role",
    "pre_judge_name",
    "ref_judge_name",
]
CASE_DATA_ONE_CARD_FIELDS = [
    "cs_caseid",
    "cs_case_number",
    "cs_short_title",
    "cs_date_filed",
    "cs_date_term",
    "cs_type",
    "cs_type_normalized",
    "cs_case_year",
    "cs_case_type_code",
    "cs_case_number_seq",
    "cs_case_office",
    "cs_term_digit",
    "party",
    "party_type",
    "party_role",
    "party_def_num",
    "pre_judge_name",
    "ref_judge_name",
]

USER_TYPES = [
    "Attorney, Solo Practitioner",
    "Attorney, Law Firm",
    "Paralegal, Legal Assistant",
    "Litigation Support, E-Discovery Professional",
    "Court Reporter, Deposition Services",
    "Legal Operations, In-House Counsel",
    "Compliance, Risk Management",
    "Claims, Insurance Professional",
    "Investigator, Private or Corporate",
    "Expert Witness, Consultant",
    "Data Analyst, Legal Analytics",
    "Researcher, Academic",
    "Student, Law or Graduate",
    "Journalist, News Media",
    "Policy Analyst, Government or Nonprofit",
    "Government Attorney, Prosecutor",
    "Government Attorney, Public Defender",
    "Judge, Judicial Staff",
    "Court Administration, Clerk’s Office",
    "Law Enforcement, Intelligence Analyst",
    "Real Estate, Title or Land Use Professional",
    "Finance, Banking or Lending Professional",
    "HR, Employment Relations",
    "Business Development, Legal Services",
    "Software Vendor, Integration Partner",
    "Other",
]

VALID_JURISDICTION_TYPES = {"ap", "bk", "cr", "cv", "mdl", "mj", "po"}


def _first_env(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _read_secret_file(path: Path) -> Optional[str]:
    try:
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
    except OSError:
        return None
    return None


def _first_env_or_secret_file(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value

        file_override = os.environ.get(f"{name}_FILE")
        if file_override:
            value = _read_secret_file(Path(file_override))
            if value:
                return value

        value = _read_secret_file(Path("/etc/secrets") / name)
        if value:
            return value
    return None


def _normalize_database_url(url: str) -> str:
    # Normalize older scheme and explicitly select the psycopg driver.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://") and "+" not in url.split("://", 1)[0]:
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def build_database_url() -> str:
    # Prefer a full URL when available.
    url = _first_env_or_secret_file(
        "DATABASE_URL",
        "InternalDatabaseURL",
        "Internal_Database_URL",
        "ExternalDatabaseURL",
        "External_Database_URL",
    )
    if url:
        return _normalize_database_url(url)

    # Fall back to discrete parts if present.
    host = _first_env_or_secret_file("Hostname", "HOSTNAME")
    port = _first_env_or_secret_file("Port", "PORT")
    dbname = _first_env_or_secret_file("Database", "DB_NAME")
    user = _first_env_or_secret_file("Username", "DB_USER")
    password = _first_env_or_secret_file("Password", "DB_PASSWORD")
    if host and port and dbname and user and password:
        return (
            "postgresql+psycopg://"
            f"{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{quote_plus(dbname)}"
        )

    # Local/dev fallback: sqlite file next to this module.
    db_path = os.environ.get("DB_PATH")
    if not db_path:
        db_path = str(Path(__file__).with_name(DEFAULT_DB_FILENAME))
    return f"sqlite:///{db_path}"


def _load_or_create_secret_key() -> Tuple[str, str]:
    secret_key = _first_env_or_secret_file("SECRET_KEY", "Secrets", "SECRETS")
    if secret_key:
        return secret_key, "env"

    key_path = os.environ.get("SECRET_KEY_PATH")
    if not key_path:
        key_path = str(Path(__file__).with_name(".secret_key"))
    key_file = Path(key_path)
    if key_file.exists():
        existing = key_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing, "file"

    generated = secrets.token_hex(32)
    try:
        key_file.write_text(generated, encoding="utf-8")
        os.chmod(key_file, 0o600)
        return generated, "generated"
    except OSError:
        return generated, "ephemeral"


@dataclass
class PacerAuthResult:
    token: str
    error_description: str
    login_result: str
    needs_otp: bool
    needs_client_code: bool
    needs_redaction_ack: bool
    can_proceed: bool


def _normalize_pacer_base_url(base_url: str) -> str:
    normalized = (base_url or "").strip()
    return normalized[:-1] if normalized.endswith("/") else normalized


def get_configured_pacer_credentials() -> Tuple[Optional[str], Optional[str]]:
    login_id = _first_env_or_secret_file("puser")
    password = _first_env_or_secret_file("ppass")
    return login_id, password


def pacer_environment_label(base_url: str) -> str:
    if "qa-login.uscourts.gov" in base_url:
        return "QA"
    if "pacer.login.uscourts.gov" in base_url:
        return "Production"
    return "Custom"


def pacer_environment_notice(base_url: str) -> Optional[str]:
    if "qa-login.uscourts.gov" in base_url:
        return "QA environment selected, requires a QA PACER account."
    if "pacer.login.uscourts.gov" in base_url:
        return "Production environment selected, billable searches may apply."
    return None


def _pacer_mentions_otp(error_description: str) -> bool:
    if not error_description:
        return False
    message = error_description.lower()
    if "one-time passcode" in message or "one time passcode" in message:
        return True
    return re.search(r"\botp\b", message) is not None


def _pacer_mentions_redaction(error_description: str) -> bool:
    if not error_description:
        return False
    return "all filers must redact" in error_description.lower()


def _safe_json_loads(payload: str) -> Dict[str, Any]:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


def build_pacer_auth_payload(
    login_id: str,
    password: str,
    otp_code: Optional[str] = None,
    client_code: Optional[str] = None,
    redact_flag: bool = False,
) -> Dict[str, str]:
    payload: Dict[str, str] = {"loginId": login_id, "password": password}
    if otp_code:
        payload["otpCode"] = otp_code
    if client_code:
        payload["clientCode"] = client_code
    if redact_flag:
        payload["redactFlag"] = "1"
    return payload


def _pacer_requires_otp(error_description: str, otp_code: Optional[str]) -> bool:
    if otp_code:
        return False
    if not error_description:
        return False
    if _pacer_mentions_otp(error_description):
        return True
    message = error_description.lower()
    otp_terms = ("one-time", "passcode", "two-factor", "2fa")
    required_terms = ("required", "enter", "missing", "needed", "not entered", "provide")
    return any(term in message for term in otp_terms) and any(
        term in message for term in required_terms
    )


def _pacer_requires_client_code(error_description: str) -> bool:
    if not error_description:
        return False
    message = error_description.lower()
    return "client code" in message and any(
        term in message for term in ("required", "not entered", "enter", "provide", "missing")
    )


def interpret_pacer_auth_response(
    response_payload: Dict[str, Any], otp_code: Optional[str]
) -> PacerAuthResult:
    login_result = str(response_payload.get("loginResult", "")).strip()
    token = response_payload.get("nextGenCSO") or ""
    error_description = (response_payload.get("errorDescription") or "").strip()
    needs_otp = _pacer_requires_otp(error_description, otp_code)
    needs_client_code = _pacer_requires_client_code(error_description)
    needs_redaction_ack = bool(
        login_result == "1" and _pacer_mentions_redaction(error_description)
    )
    can_proceed = bool(login_result == "0" and token and not error_description)
    return PacerAuthResult(
        token=token if can_proceed else "",
        error_description=error_description,
        login_result=login_result,
        needs_otp=needs_otp,
        needs_client_code=needs_client_code,
        needs_redaction_ack=needs_redaction_ack,
        can_proceed=can_proceed,
    )


class PacerAuthClient:
    def __init__(self, base_url: str, logger: Optional[Any] = None, redact_flag: bool = False):
        self.base_url = _normalize_pacer_base_url(base_url)
        self.logger = logger
        self.redact_flag = redact_flag

    def authenticate(
        self,
        login_id: str,
        password: str,
        otp_code: Optional[str] = None,
        client_code: Optional[str] = None,
        redact_flag: Optional[bool] = None,
    ) -> PacerAuthResult:
        use_redact_flag = self.redact_flag if redact_flag is None else bool(redact_flag)
        payload = build_pacer_auth_payload(
            login_id,
            password,
            otp_code=otp_code,
            client_code=client_code,
            redact_flag=use_redact_flag,
        )
        request_data = json.dumps(payload).encode("utf-8")
        request_obj = urllib.request.Request(
            f"{self.base_url}/services/cso-auth",
            data=request_data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )

        if self.logger:
            self.logger.info(
                "PACER auth environment: %s", pacer_environment_label(self.base_url)
            )

        try:
            with urllib.request.urlopen(request_obj, timeout=30) as response:
                status_code = response.getcode()
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            error_body = exc.read().decode("utf-8", errors="ignore")
            error_payload = _safe_json_loads(error_body)
            self._log_response(status_code, error_payload)
            result = interpret_pacer_auth_response(error_payload, otp_code)
            if result.error_description:
                return result
            raise ValueError("PACER authentication failed.") from exc
        except urllib.error.URLError as exc:
            raise ValueError("PACER authentication failed. Please try again.") from exc

        response_payload = _safe_json_loads(response_body)
        if not response_payload:
            raise ValueError("PACER authentication failed.")
        self._log_response(status_code, response_payload)
        return interpret_pacer_auth_response(response_payload, otp_code)

    def _log_response(self, status_code: int, response_payload: Dict[str, Any]) -> None:
        if not self.logger:
            return
        login_result = str(response_payload.get("loginResult", "")).strip() or "unknown"
        token_present = bool(response_payload.get("nextGenCSO"))
        self.logger.info(
            "PACER auth response status=%s loginResult=%s tokenPresent=%s",
            status_code,
            login_result,
            token_present,
        )


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Session signing key
    secret_key, secret_source = _load_or_create_secret_key()
    if secret_source in {"generated", "ephemeral"}:
        app.logger.warning(
            "SECRET_KEY not set; using %s key (sessions reset on restart).",
            "a persisted" if secret_source == "generated" else "an ephemeral",
        )
    app.secret_key = secret_key

    database_url = build_database_url()
    engine = create_engine(database_url, future=True, pool_pre_ping=True)

    metadata = MetaData()

    users = Table(
        "users",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("first_name", String(100), nullable=False),
        Column("last_name", String(100), nullable=False),
        Column("user_type", String(120), nullable=False),
        Column("firm_name", String(255), nullable=True),
        Column("title", String(255), nullable=True),
        Column("email", String(255), nullable=False, unique=True),
        Column("password_hash", String(255), nullable=False),
        Column("phone", String(50), nullable=True),
        Column("address", String(255), nullable=True),
        Column("city", String(100), nullable=True),
        Column("state", String(100), nullable=True),
        Column("zip", String(20), nullable=True),
        Column("county", String(100), nullable=True),
        Column("country", String(100), nullable=True),
        Column(
            "has_pacer_account",
            Boolean,
            nullable=False,
            server_default=sa_text("false"),
        ),
        Column("heard_about_us", Text, nullable=True),
        Column("referral_code", String(100), nullable=True),
    )

    newsletter_subscriptions = Table(
        "newsletter_subscriptions",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("email", String(255), nullable=False, unique=True, index=True),
        Column("user_id", Integer, ForeignKey("users.id"), nullable=True),
        Column("opt_in", Boolean, nullable=False, server_default=sa_text("true")),
        Column("subscribed_at", DateTime(timezone=True), nullable=True),
        Column("unsubscribed_at", DateTime(timezone=True), nullable=True),
    )

    case_stage1 = Table(
        "case_stage1",
        metadata,
        Column("cs_caseid", Integer, primary_key=True),
        Column("cs_case_number", Text, nullable=True),
        Column("cs_case_type", Text, nullable=True),
        Column("cs_file_date", Date, nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("cs_short_title", Text, nullable=True),
        Column("lead_short_title", Text, nullable=True),
        Column("cs_party_last_name", Text, nullable=True),
        Column("cs_court_location", Text, nullable=True),
        Column("search_text", Text, nullable=True),
    )

    case_data_one = Table(
        "case_data_one",
        metadata,
        Column("cs_caseid", Integer, primary_key=True),
        Column("cs_case_number", Text, nullable=True),
        Column("cs_short_title", Text, nullable=True),
        Column("cs_date_filed", Date, nullable=True),
        Column("cs_date_term", Date, nullable=True),
        Column("cs_date_reopen", Date, nullable=True),
        Column("cs_type", Text, nullable=True),
        Column("cs_type_normalized", Text, nullable=True),
        Column("cs_case_restriction", Text, nullable=True),
        Column("lead_caseid", Text, nullable=True),
        Column("lead_case_number", Text, nullable=True),
        Column("lead_short_title", Text, nullable=True),
        Column("lead_date_filed", Date, nullable=True),
        Column("lead_date_term", Date, nullable=True),
        Column("lead_date_reopen", Date, nullable=True),
        Column("office_trans", Text, nullable=True),
        Column("pre_judge_name", Text, nullable=True),
        Column("ref_judge_name", Text, nullable=True),
        Column("cs_case_office", Text, nullable=True),
        Column("cs_case_year", Text, nullable=True),
        Column("cs_case_type_code", Text, nullable=True),
        Column("cs_case_number_seq", Text, nullable=True),
        Column("cs_sort_case_numb", Text, nullable=True),
        Column("cs_def_num", Text, nullable=True),
        Column("cs_term_digit", Text, nullable=True),
        Column("party", Text, nullable=True),
        Column("party_normalized", Text, nullable=True),
        Column("party_type", Text, nullable=True),
        Column("party_type_normalized", Text, nullable=True),
        Column("party_role", Text, nullable=True),
        Column("party_role_normalized", Text, nullable=True),
        Column("party_start_date", Date, nullable=True),
        Column("party_end_date", Date, nullable=True),
        Column("party_def_num", Text, nullable=True),
        Column("party_def_num_normalized", Text, nullable=True),
        Column("loc_date_start", Date, nullable=True),
        Column("loc_date_end", Date, nullable=True),
    )

    if engine.dialect.name == "postgresql":
        federal_id_type = BigInteger
        federal_states_type = ARRAY(String)
        federal_raw_json_type = JSONB
    else:
        federal_id_type = Integer
        federal_states_type = JSON
        federal_raw_json_type = JSON

    federal_courts = Table(
        "federal_courts",
        metadata,
        Column("id", federal_id_type, primary_key=True, autoincrement=True),
        Column("court_id", Text, nullable=False, unique=True),
        Column("title", Text, nullable=True),
        Column("court_name", Text, nullable=True),
        Column("court_type", Text, nullable=True),
        Column("circuit", Text, nullable=True),
        Column("login_url", Text, nullable=True),
        Column("web_url", Text, nullable=True),
        Column("rss_url", Text, nullable=True),
        Column("software_version", Text, nullable=True),
        Column("go_live_date", Text, nullable=True),
        Column("pdf_size", Text, nullable=True),
        Column("merge_doc_size", Text, nullable=True),
        Column("vcis", Text, nullable=True),
        Column("states", federal_states_type, nullable=True),
        Column("counties_count", Integer, nullable=True),
        Column(
            "source_url",
            Text,
            nullable=False,
            server_default=sa_text(f"'{FEDERAL_COURTS_SOURCE_URL}'"),
        ),
        Column("source_last_updated", Text, nullable=True),
        Column("fetched_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("raw_json", federal_raw_json_type, nullable=False),
    )

    pacer_tokens = build_pacer_token_table(metadata)
    pcl_tables = build_pcl_tables(metadata)
    sentencing_tables = build_sentencing_tables(metadata)
    pcl_tables.update(sentencing_tables)

    # Create the users/newsletter/case_stage1/case_data_one tables if they don't exist.
    try:
        metadata.create_all(
            engine,
            tables=[
                users,
                newsletter_subscriptions,
                case_stage1,
                case_data_one,
                pacer_tokens,
                federal_courts,
                *pcl_tables.values(),
            ],
        )
    except OperationalError as exc:
        if "already exists" in str(exc).lower():
            app.logger.warning("Database tables already exist; skipping create_all.")
        else:
            raise

    def _ensure_table_columns(
        table_name: str, column_specs: Dict[str, str], *, label: str
    ) -> None:
        try:
            inspector = inspect(engine)
            existing_columns = {
                column["name"] for column in inspector.get_columns(table_name)
            }
        except Exception:
            app.logger.exception("Unable to inspect %s columns.", label)
            return

        missing = [name for name in column_specs if name not in existing_columns]
        if not missing:
            return

        try:
            with engine.begin() as conn:
                for name in missing:
                    conn.execute(
                        sa_text(
                            f"ALTER TABLE {table_name} ADD COLUMN {name} {column_specs[name]}"
                        )
                    )
        except Exception:
            app.logger.exception("Unable to add missing %s columns.", label)

    _ensure_table_columns(
        "case_stage1",
        {"search_text": "TEXT"},
        label="case_stage1",
    )
    _ensure_table_columns(
        "case_data_one",
        {
            "cs_type_normalized": "TEXT",
            "cs_case_office": "TEXT",
            "cs_case_year": "TEXT",
            "cs_case_type_code": "TEXT",
            "cs_case_number_seq": "TEXT",
            "party_normalized": "TEXT",
            "party_type": "TEXT",
            "party_type_normalized": "TEXT",
            "party_role": "TEXT",
            "party_role_normalized": "TEXT",
            "party_def_num_normalized": "TEXT",
        },
        label="case_data_one",
    )
    _ensure_table_columns(
        "pcl_cases",
        {
            "case_number_full": "TEXT",
            "date_closed": "DATE",
            "case_title": "TEXT",
            "judge_last_name": "VARCHAR(80)",
            "record_hash": "VARCHAR(128)",
            "last_segment_id": "INTEGER",
        },
        label="pcl_cases",
    )
    _ensure_table_columns(
        "pcl_case_result_raw",
        {
            "court_id": "VARCHAR(50)",
            "case_number": "TEXT",
        },
        label="pcl_case_result_raw",
    )

    def _ensure_indexes(statements: Dict[str, str], *, label: str) -> None:
        try:
            with engine.begin() as conn:
                for statement in statements.values():
                    conn.execute(sa_text(statement))
        except Exception:
            app.logger.exception("Unable to ensure %s indexes.", label)

    if engine.dialect.name == "sqlite":
        _ensure_indexes(
            {
                "ix_pcl_cases_court_date": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_court_date ON pcl_cases (court_id, date_filed)",
                "ix_pcl_cases_case_type": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_case_type ON pcl_cases (case_type)",
                "ix_pcl_cases_judge_last_name": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_judge_last_name ON pcl_cases (judge_last_name)",
                "ix_pcl_case_result_raw_court_case": "CREATE INDEX IF NOT EXISTS ix_pcl_case_result_raw_court_case ON pcl_case_result_raw (court_id, case_number)",
            },
            label="pcl",
        )
        _ensure_indexes(
            {
                "ix_judges_name_last": "CREATE INDEX IF NOT EXISTS ix_judges_name_last ON judges (name_last)",
                "ix_judges_court_id": "CREATE INDEX IF NOT EXISTS ix_judges_court_id ON judges (court_id)",
                "ix_case_judges_case_id": "CREATE INDEX IF NOT EXISTS ix_case_judges_case_id ON case_judges (case_id)",
                "ix_case_judges_judge_id": "CREATE INDEX IF NOT EXISTS ix_case_judges_judge_id ON case_judges (judge_id)",
                "ix_sentencing_events_case_date": "CREATE INDEX IF NOT EXISTS ix_sentencing_events_case_date ON sentencing_events (case_id, sentencing_date)",
                "ix_sentencing_evidence_event_source": "CREATE INDEX IF NOT EXISTS ix_sentencing_evidence_event_source ON sentencing_evidence (sentencing_event_id, source_type)",
            },
            label="sentencing",
        )

    _ensure_indexes(
        {
            "ix_federal_courts_court_type": "CREATE INDEX IF NOT EXISTS ix_federal_courts_court_type ON federal_courts (court_type)",
            "ix_federal_courts_circuit": "CREATE INDEX IF NOT EXISTS ix_federal_courts_circuit ON federal_courts (circuit)",
        },
        label="federal courts",
    )
    if engine.dialect.name == "postgresql":
        _ensure_indexes(
            {
                "ix_federal_courts_states_gin": "CREATE INDEX IF NOT EXISTS ix_federal_courts_states_gin ON federal_courts USING GIN (states)"
            },
            label="federal courts states",
        )

    case_stage1_imports: Dict[str, Dict[str, Any]] = {}
    case_data_one_imports: Dict[str, Dict[str, Any]] = {}
    pacer_auth_base_url = _normalize_pacer_base_url(
        os.environ.get("PACER_AUTH_BASE_URL", "https://pacer.login.uscourts.gov")
    )
    pacer_auth_client = PacerAuthClient(
        pacer_auth_base_url, logger=app.logger, redact_flag=False
    )
    pacer_token_store_mode = os.environ.get("PACER_TOKEN_STORE", "").strip().lower()
    use_db_tokens = pacer_token_store_mode in {
        "db",
        "database",
        "postgres",
    } or engine.dialect.name == "postgresql"
    if use_db_tokens:
        pacer_token_backend = DatabaseTokenBackend(engine, pacer_tokens)
    else:
        pacer_token_backend = InMemoryTokenBackend()
    pacer_token_store = PacerTokenStore(pacer_token_backend, session_accessor=lambda: session)
    app.pacer_token_store = pacer_token_store
    app.pcl_tables = pcl_tables
    app.engine = engine
    app.federal_courts_table = federal_courts

    pcl_base_url = _normalize_pacer_base_url(
        os.environ.get("PCL_BASE_URL", "https://qa-pcl.uscourts.gov/pcl-public-api/rest")
    )
    pcl_http_client = PacerHttpClient(pacer_token_store, logger=app.logger)
    pcl_client = PclClient(pcl_http_client, pcl_base_url, logger=app.logger)
    app.pcl_client = pcl_client

    # -----------------
    # Helpers
    # -----------------

    def load_table(table_name: str) -> Table:
        try:
            return Table(table_name, metadata, autoload_with=engine)
        except NoSuchTableError as exc:
            raise KeyError(f"Table '{table_name}' not found") from exc

    def get_csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def require_csrf() -> None:
        form_token = request.form.get("csrf_token")
        header_token = request.headers.get("X-CSRF-Token")
        json_token = None
        if not form_token and not header_token:
            json_payload = request.get_json(silent=True) or {}
            json_token = json_payload.get("csrf_token")
        request_token = form_token or header_token or json_token
        session_token = session.get("csrf_token")
        if (
            not request_token
            or not session_token
            or not hmac.compare_digest(str(request_token), session_token)
        ):
            abort(400)

    def _is_postgres() -> bool:
        return engine.dialect.name == "postgresql"

    def run_federal_courts_sync() -> Dict[str, Any]:
        meta, records = fetch_federal_courts_json()
        result = upsert_federal_courts(engine, federal_courts, records, meta)
        return {
            "inserted": result.inserted,
            "updated": result.updated,
            "total": result.total_records,
            "source_last_updated": result.source_last_updated,
        }

    def _parse_stage1_date(value: Optional[str]) -> Optional[Any]:
        if not value:
            return None
        try:
            return datetime.strptime(value.strip(), "%m/%d/%Y").date()
        except ValueError:
            return None

    def _parse_case_data_one_date(value: Optional[str]) -> Optional[Any]:
        if not value:
            return None
        try:
            return datetime.strptime(value.strip(), "%m/%d/%Y").date()
        except ValueError:
            return None

    def _parse_iso_date(value: Optional[str]) -> Optional[Any]:
        if not value:
            return None
        try:
            return datetime.strptime(value.strip(), "%Y-%m-%d").date()
        except ValueError:
            return None

    def _parse_optional_int(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return int(cleaned)
        except ValueError:
            return None

    def _parse_optional_float(value: Optional[str]) -> Optional[float]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return float(cleaned)
        except ValueError:
            return None

    def _normalize_variance_type(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        cleaned = value.strip().lower()
        return cleaned if cleaned in VALID_VARIANCE_TYPES else None

    def _collect_evidence_rows(form_data) -> List[Dict[str, Optional[str]]]:
        source_types = form_data.getlist("evidence_source_type")
        source_ids = form_data.getlist("evidence_source_id")
        references = form_data.getlist("evidence_reference")

        rows: List[Dict[str, Optional[str]]] = []
        total = max(len(source_types), len(source_ids), len(references))
        for idx in range(total):
            source_type = (source_types[idx] if idx < len(source_types) else "").strip()
            source_id = (source_ids[idx] if idx < len(source_ids) else "").strip()
            reference_text = (references[idx] if idx < len(references) else "").strip()
            if not source_type and not source_id and not reference_text:
                continue
            rows.append(
                {
                    "source_type": source_type.lower() if source_type else "",
                    "source_id": source_id or None,
                    "reference_text": reference_text,
                }
            )
        return rows

    def _validate_evidence_rows(rows: List[Dict[str, Optional[str]]]) -> Optional[str]:
        if not rows:
            return "At least one evidence reference is required."
        for row in rows:
            source_type = row.get("source_type") or ""
            reference_text = (row.get("reference_text") or "").strip()
            if source_type not in VALID_EVIDENCE_SOURCE_TYPES:
                return "Evidence source type must be docket entry, document, or manual."
            if not reference_text:
                return "Each evidence reference needs an excerpt or description."
            if source_type in {"docket_entry", "document"} and not (row.get("source_id") or "").strip():
                return "Docket entry and document evidence must include a source id."
        return None

    def _ensure_case_sentencing_judge(case_id: int, judge_id: int, confidence: Optional[float]) -> None:
        case_judges = pcl_tables["case_judges"]
        confidence_value = confidence if confidence is not None else 1.0
        with engine.begin() as conn:
            existing_id = conn.execute(
                select(case_judges.c.id).where(
                    case_judges.c.case_id == case_id,
                    case_judges.c.judge_id == judge_id,
                    case_judges.c.role == "sentencing",
                )
            ).scalar_one_or_none()
            if existing_id:
                conn.execute(
                    update(case_judges)
                    .where(case_judges.c.id == existing_id)
                    .values(confidence=confidence_value)
                )
            else:
                conn.execute(
                    insert(case_judges).values(
                        case_id=case_id,
                        judge_id=judge_id,
                        role="sentencing",
                        confidence=confidence_value,
                        source_system="admin",
                    )
                )

    def _get_or_create_judge_id(judge_id_value: Optional[str], judge_name: Optional[str], court_id: Optional[str]) -> Optional[int]:
        judges = pcl_tables["judges"]
        parsed_id = _parse_optional_int(judge_id_value)
        if parsed_id:
            return parsed_id
        if not judge_name:
            return None
        name_full = judge_name.strip()
        if not name_full:
            return None
        name_parts = [part for part in name_full.replace(",", " ").split() if part]
        name_first = name_parts[0] if len(name_parts) > 1 else None
        name_last = name_parts[-1] if name_parts else None
        normalized_court = (court_id or "").strip().lower() or None
        with engine.begin() as conn:
            existing_id = conn.execute(
                select(judges.c.id).where(
                    func.lower(judges.c.name_full) == name_full.lower(),
                    judges.c.court_id == normalized_court,
                )
            ).scalar_one_or_none()
            if existing_id:
                return int(existing_id)
            result = conn.execute(
                insert(judges).values(
                    name_full=name_full,
                    name_first=name_first,
                    name_last=name_last,
                    court_id=normalized_court,
                    source_system="admin",
                )
            )
            return int(result.inserted_primary_key[0])

    def _load_sentencing_judge_choices() -> List[Dict[str, Any]]:
        judges = pcl_tables["judges"]
        stmt = select(judges.c.id, judges.c.name_full, judges.c.court_id).order_by(
            judges.c.name_last.asc(), judges.c.name_full.asc()
        )
        with engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [dict(row) for row in rows]

    def _normalize_text(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned.lower() if cleaned else None

    def _get_pacer_session() -> Optional[Dict[str, Any]]:
        record = pacer_token_store.get_token()
        if not record:
            return None
        return {
            "token": record.token,
            "authorized_at": record.obtained_at.isoformat(),
        }

    def _set_pacer_session(token: str) -> None:
        session_key = session.get("pacer_session_key")
        if not session_key:
            session_key = secrets.token_urlsafe(16)
            session["pacer_session_key"] = session_key
        pacer_token_store.initialize_session(session_key)
        pacer_token_store.save_token(token, obtained_at=datetime.utcnow())

    def _clear_pacer_session() -> None:
        pacer_token_store.clear_token()

    def _normalize_party_def_num(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = re.sub(r"[^0-9]", "", value)
        if not cleaned:
            return None
        try:
            return str(int(cleaned))
        except ValueError:
            return None

    def _is_sealed_or_unavailable_case_type(value: Optional[str]) -> bool:
        normalized = _normalize_text(value)
        if not normalized:
            return False
        return "sealed" in normalized or "unavailable" in normalized

    def _normalize_case_type(value: Optional[str]) -> Optional[str]:
        normalized = _normalize_text(value)
        if not normalized:
            return None
        if _is_sealed_or_unavailable_case_type(normalized):
            return None
        normalized = normalized.replace(".", "")
        if normalized in VALID_JURISDICTION_TYPES:
            return normalized
        aliases = {
            "appeal": "ap",
            "appellate": "ap",
            "bankruptcy": "bk",
            "bankrupt": "bk",
            "civil": "cv",
            "civ": "cv",
            "criminal": "cr",
            "crim": "cr",
            "mdl": "mdl",
            "mag": "mj",
            "magistrate": "mj",
            "petty offense": "po",
            "pettyoffense": "po",
        }
        return aliases.get(normalized)

    def _parse_case_number_components(value: Optional[str]) -> Dict[str, Optional[str]]:
        if not value:
            return {}
        raw = value.strip().lower()
        if not raw:
            return {}
        office = None
        office_match = re.match(r"^(?P<office>\d)\s*:\s*(?P<rest>.+)$", raw)
        if office_match:
            office = office_match.group("office")
            raw = office_match.group("rest")
        compact = re.sub(r"[\s\-]", "", raw)
        match = re.match(
            r"^(?P<year>\d{2,4})(?P<case_type>[a-z]{1,4})?(?P<number>\d{1,6})$",
            compact,
        )
        if not match:
            match = re.match(
                r"^(?P<year>\d{2,4})\s*[-/\\]?\s*(?P<case_type>[a-z]{1,4})?\s*[-/\\]?\s*(?P<number>\d{1,6})(?:\D.*)?$",
                raw,
            )
        if not match:
            return {}
        year = match.group("year")
        case_type = match.group("case_type") or None
        number = match.group("number")
        normalized_year = year
        if len(year) == 2:
            normalized_year = f"20{year}"
        term_digit = normalized_year[-1] if normalized_year else None
        sort_key = f"{office or '0'}:{normalized_year}-{case_type or ''}-{number.zfill(5)}"
        return {
            "cs_case_office": office,
            "cs_case_year": normalized_year,
            "cs_case_type_code": case_type,
            "cs_case_number_seq": number,
            "cs_term_digit": term_digit,
            "cs_sort_case_numb": sort_key,
        }

    def _normalize_case_stage1_headers(raw_headers: Sequence[str]) -> List[str]:
        normalized: List[str] = []
        counts: Dict[str, int] = {}
        for header in raw_headers:
            name = re.sub(r"[^a-zA-Z0-9_]", "_", header.strip())
            if not name:
                continue
            counts[name] = counts.get(name, 0) + 1
            if name == "cs_short_title" and counts[name] == 2:
                name = "lead_short_title"
            elif counts[name] > 1:
                name = f"{name}_{counts[name]}"
            name = CASE_STAGE1_HEADER_ALIASES.get(name, name)
            normalized.append(name)
        return normalized

    def _normalize_case_data_one_headers(raw_headers: Sequence[str]) -> List[str]:
        normalized: List[str] = []
        counts: Dict[str, int] = {}
        for header in raw_headers:
            name = re.sub(r"[^a-zA-Z0-9_]", "_", header.strip())
            if not name:
                continue
            counts[name] = counts.get(name, 0) + 1
            if name == "cs_short_title" and counts[name] == 2:
                name = "lead_short_title"
            elif counts[name] > 1:
                name = f"{name}_{counts[name]}"
            name = CASE_DATA_ONE_HEADER_ALIASES.get(name, name)
            normalized.append(name)
        return normalized

    def _ensure_case_stage1_search_index() -> None:
        if not _is_postgres():
            return
        try:
            inspector = inspect(engine)
            existing_columns = {
                column["name"] for column in inspector.get_columns("case_stage1")
            }
            if "search_text" not in existing_columns:
                app.logger.warning(
                    "case_stage1.search_text missing; skipping search index creation."
                )
                return
            with engine.begin() as conn:
                conn.execute(
                    sa_text(
                        "CREATE INDEX IF NOT EXISTS case_stage1_search_idx "
                        "ON case_stage1 USING GIN "
                        "(to_tsvector('english', coalesce(search_text, '')))"
                    )
                )
        except Exception:
            app.logger.exception("Unable to create case_stage1 search index.")

    def _build_case_stage1_search_text(row_data: Dict[str, Any]) -> Optional[str]:
        parts: List[str] = []
        for column in CASE_STAGE1_IMPORT_COLUMNS:
            value = row_data.get(column)
            if value is None:
                continue
            text_value = str(value).strip()
            if not text_value:
                continue
            parts.append(text_value.lower())
        return " ".join(parts) if parts else None

    def _case_data_one_search_text_expression(table: Table) -> Any:
        expr = func.coalesce(table.c.cs_case_number, "")
        for column_name in CASE_DATA_ONE_SEARCH_COLUMNS[1:]:
            expr = expr + literal_column("' '") + func.coalesce(table.c[column_name], "")
        return expr

    def _ensure_case_data_one_search_index() -> None:
        if not _is_postgres():
            return
        try:
            search_expression = (
                "coalesce(cs_case_number, '') || ' ' || "
                "coalesce(cs_short_title, '') || ' ' || "
                "coalesce(cs_type, '') || ' ' || "
                "coalesce(cs_type_normalized, '') || ' ' || "
                "coalesce(party, '') || ' ' || "
                "coalesce(party_type, '') || ' ' || "
                "coalesce(party_role, '') || ' ' || "
                "coalesce(pre_judge_name, '') || ' ' || "
                "coalesce(ref_judge_name, '')"
            )
            with engine.begin() as conn:
                conn.execute(
                    sa_text(
                        "CREATE INDEX IF NOT EXISTS case_data_one_search_idx "
                        "ON case_data_one USING GIN "
                        f"(to_tsvector('english', {search_expression}))"
                    )
                )
        except Exception:
            app.logger.exception("Unable to create case data one search index.")

    def _upsert_case_stage1_batch(
        conn: Any,
        table: Table,
        rows: List[Dict[str, Any]],
        *,
        track_counts: bool = True,
    ) -> Tuple[int, int]:
        if not rows:
            return 0, 0
        if _is_postgres():
            stmt = pg_insert(table).values(rows)
            update_values = {
                col.name: stmt.excluded[col.name]
                for col in table.c
                if col.name
                not in {"cs_caseid", "created_at", "updated_at"}
            }
            update_values["updated_at"] = func.now()
            stmt = stmt.on_conflict_do_update(
                index_elements=[table.c.cs_caseid], set_=update_values
            )
            if track_counts:
                stmt = stmt.returning(literal_column("xmax = 0").label("inserted"))
                inserted_flags = conn.execute(stmt).scalars().all()
                inserted_count = sum(1 for flag in inserted_flags if flag)
                updated_count = len(inserted_flags) - inserted_count
                return inserted_count, updated_count
            conn.execute(stmt)
            return 0, 0

        ids = [row["cs_caseid"] for row in rows]
        existing_ids = set(
            conn.execute(select(table.c.cs_caseid).where(table.c.cs_caseid.in_(ids))).scalars()
        )
        inserted_count = len(rows) - len(existing_ids)
        updated_count = len(existing_ids)
        insert_rows = [row for row in rows if row["cs_caseid"] not in existing_ids]
        update_rows = [
            {**row, "b_cs_caseid": row["cs_caseid"]}
            for row in rows
            if row["cs_caseid"] in existing_ids
        ]
        if insert_rows:
            conn.execute(insert(table), insert_rows)
        if update_rows:
            update_columns = {
                col.name: bindparam(col.name)
                for col in table.c
                if col.name
                not in {"cs_caseid", "created_at", "updated_at"}
            }
            update_stmt = (
                update(table)
                .where(table.c.cs_caseid == bindparam("b_cs_caseid"))
                .values(**update_columns)
                .values(updated_at=func.now())
            )
            conn.execute(update_stmt, update_rows)
        return inserted_count, updated_count

    def _upsert_case_data_one_batch(
        conn: Any,
        table: Table,
        rows: List[Dict[str, Any]],
        *,
        track_counts: bool = True,
    ) -> Tuple[int, int]:
        if not rows:
            return 0, 0
        if _is_postgres():
            stmt = pg_insert(table).values(rows)
            update_values = {
                col.name: stmt.excluded[col.name]
                for col in table.c
                if col.name not in {"cs_caseid"}
            }
            stmt = stmt.on_conflict_do_update(
                index_elements=[table.c.cs_caseid], set_=update_values
            )
            if track_counts:
                stmt = stmt.returning(literal_column("xmax = 0").label("inserted"))
                inserted_flags = conn.execute(stmt).scalars().all()
                inserted_count = sum(1 for flag in inserted_flags if flag)
                updated_count = len(inserted_flags) - inserted_count
                return inserted_count, updated_count
            conn.execute(stmt)
            return 0, 0

        ids = [row["cs_caseid"] for row in rows]
        existing_ids = set(
            conn.execute(select(table.c.cs_caseid).where(table.c.cs_caseid.in_(ids))).scalars()
        )
        inserted_count = len(rows) - len(existing_ids)
        updated_count = len(existing_ids)
        insert_rows = [row for row in rows if row["cs_caseid"] not in existing_ids]
        update_rows = [
            {**row, "b_cs_caseid": row["cs_caseid"]}
            for row in rows
            if row["cs_caseid"] in existing_ids
        ]
        if insert_rows:
            conn.execute(insert(table), insert_rows)
        if update_rows:
            update_columns = {
                col.name: bindparam(col.name)
                for col in table.c
                if col.name not in {"cs_caseid"}
            }
            update_stmt = (
                update(table)
                .where(table.c.cs_caseid == bindparam("b_cs_caseid"))
                .values(**update_columns)
            )
            conn.execute(update_stmt, update_rows)
        return inserted_count, updated_count

    def _set_case_stage1_import(job_id: str, **fields: Any) -> None:
        case_stage1_imports.setdefault(job_id, {}).update(fields)

    def _latest_case_stage1_import() -> Optional[Dict[str, Any]]:
        latest_id = case_stage1_imports.get("latest")
        if not latest_id:
            return None
        return case_stage1_imports.get(latest_id)

    def _set_case_data_one_import(job_id: str, **fields: Any) -> None:
        case_data_one_imports.setdefault(job_id, {}).update(fields)

    def _latest_case_data_one_import() -> Optional[Dict[str, Any]]:
        latest_id = case_data_one_imports.get("latest")
        if not latest_id:
            return None
        return case_data_one_imports.get(latest_id)

    _ensure_case_stage1_search_index()
    _ensure_case_data_one_search_index()

    def _record_case_data_one_error(
        error_details: List[Dict[str, Any]],
        *,
        row_number: Optional[int],
        message: str,
        record: Optional[Any] = None,
    ) -> None:
        if len(error_details) >= CASE_DATA_ONE_ERROR_DETAIL_LIMIT:
            return
        serialized_record = None
        if record is not None:
            try:
                serialized_record = json.dumps(record, default=str, ensure_ascii=False)
            except (TypeError, ValueError):
                serialized_record = str(record)
        error_details.append(
            {
                "row_number": row_number,
                "message": message,
                "record": serialized_record,
            }
        )

    def _stringify_case_data_one_error_record(record: Any) -> str:
        if record is None:
            return "(none)"
        if isinstance(record, str):
            return record
        if isinstance(record, list):
            return "|".join(str(item) for item in record)
        try:
            return json.dumps(record, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(record)

    def _build_case_data_one_error_prompt(error_report: Dict[str, Any]) -> str:
        error_details = error_report.get("error_details") or []
        total_rows = error_report.get("total_rows")
        processed_rows = error_report.get("processed_rows")
        inserted_rows = error_report.get("inserted_rows")
        updated_rows = error_report.get("updated_rows")
        skipped_rows = error_report.get("skipped_rows")
        error_rows = error_report.get("error_rows")
        message = error_report.get("message")

        summary_lines = [
            "You are a chatgpt.com/codex senior engineer with a specialty in prompting Codex to fix upload errors based on error reports.",
            "The data was uploaded by an admin user at the url https://courtdatapro.com/admin/case-data-one/upload.",
            "The following show the error and with the record that resulted in the error below it.",
            "Write a prompt to have Codex fix the error [insert the report and records] and then send it to openai using the API key and when a reponse is returned display it in code view for the admin user to click a button to copy to their clipboard. of course provide a great user experience with lots of feedback and guidance as long the way so the user is new left guessing.",
            "",
            "Import summary:",
            f"- Total rows: {total_rows if total_rows is not None else 'unknown'}",
            f"- Processed rows: {processed_rows if processed_rows is not None else 'unknown'}",
            f"- Inserted rows: {inserted_rows if inserted_rows is not None else 'unknown'}",
            f"- Updated rows: {updated_rows if updated_rows is not None else 'unknown'}",
            f"- Skipped rows: {skipped_rows if skipped_rows is not None else 'unknown'}",
            f"- Error rows: {error_rows if error_rows is not None else 'unknown'}",
        ]
        if message:
            summary_lines.append(f"- Status message: {message}")

        error_lines = ["", "Error details:"]
        for index, item in enumerate(error_details, start=1):
            row_number = item.get("row_number")
            row_label = f"Row {row_number}" if row_number else "Row (unknown)"
            detail_message = item.get("message", "(no message)")
            record_text = _stringify_case_data_one_error_record(item.get("record"))
            error_lines.append(
                f"{index}. {row_label}\n   Message: {detail_message}\n   Record: {record_text}"
            )

        if not error_details:
            error_lines.append("No error detail rows were provided.")

        return "\n".join(summary_lines + error_lines).strip()

    def _build_case_data_one_error_report_text(error_report: Dict[str, Any]) -> str:
        error_details = error_report.get("error_details") or []
        total_rows = error_report.get("total_rows")
        processed_rows = error_report.get("processed_rows")
        inserted_rows = error_report.get("inserted_rows")
        updated_rows = error_report.get("updated_rows")
        skipped_rows = error_report.get("skipped_rows")
        error_rows = error_report.get("error_rows")
        message = error_report.get("message")
        status = error_report.get("status")

        summary_lines = [
            "Case Data One Import Error Report",
            f"Status: {status or 'unknown'}",
            f"Message: {message or 'N/A'}",
            f"Total rows: {total_rows if total_rows is not None else 'unknown'}",
            f"Processed rows: {processed_rows if processed_rows is not None else 'unknown'}",
            f"Inserted rows: {inserted_rows if inserted_rows is not None else 'unknown'}",
            f"Updated rows: {updated_rows if updated_rows is not None else 'unknown'}",
            f"Skipped rows: {skipped_rows if skipped_rows is not None else 'unknown'}",
            f"Error rows: {error_rows if error_rows is not None else 'unknown'}",
            "",
        ]

        detail_lines = ["Itemized errors:"]
        for index, item in enumerate(error_details, start=1):
            row_number = item.get("row_number")
            row_label = f"Row {row_number}" if row_number else "Row (unknown)"
            detail_message = item.get("message", "(no message)")
            record_text = _stringify_case_data_one_error_record(item.get("record"))
            detail_lines.append(
                f"{index}. {row_label}\n   Message: {detail_message}\n   Record: {record_text}"
            )
        if not error_details:
            detail_lines.append("No itemized error records were captured.")

        return "\n".join(summary_lines + detail_lines).strip()

    def _call_openai_chat_completion(prompt: str) -> str:
        api_key = _first_env_or_secret_file("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key is not configured.")

        model = os.environ.get("OPENAI_MODEL", "gpt-5.2")
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a data ingestion assistant helping diagnose CSV/pipe "
                        "delimited import errors. Focus on root causes and fixes."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        request_data = json.dumps(payload).encode("utf-8")
        request_obj = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=request_data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request_obj, timeout=30) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="ignore")
            app.logger.warning("OpenAI API error: %s", error_body)
            raise ValueError("OpenAI API request failed.") from exc
        except urllib.error.URLError as exc:
            app.logger.warning("OpenAI API connection error: %s", exc)
            raise ValueError("OpenAI API request failed.") from exc

        response_payload = json.loads(response_body)
        choices = response_payload.get("choices") or []
        content = ""
        if choices:
            content = choices[0].get("message", {}).get("content", "")
        if not content:
            raise ValueError("OpenAI response was empty.")
        return content.strip()

    def _apply_case_data_one_classifications(
        row_data: Dict[str, Any],
        *,
        row_number: int,
        error_details: List[Dict[str, Any]],
    ) -> int:
        error_count = 0
        parsed_case = _parse_case_number_components(row_data.get("cs_case_number"))
        if parsed_case:
            row_data.update(parsed_case)
        elif row_data.get("cs_case_number"):
            _record_case_data_one_error(
                error_details,
                row_number=row_number,
                message="Unable to parse cs_case_number components.",
                record=row_data,
            )
            error_count += 1

        normalized_case_type = _normalize_case_type(row_data.get("cs_type"))
        row_data["cs_type_normalized"] = normalized_case_type
        if (
            row_data.get("cs_type")
            and normalized_case_type is None
            and not _is_sealed_or_unavailable_case_type(row_data.get("cs_type"))
        ):
            _record_case_data_one_error(
                error_details,
                row_number=row_number,
                message=(
                    "Invalid cs_type value; expected ap, bk, cr, cv, mdl, mj, or po "
                    "(values containing sealed/unavailable are treated as unavailable)."
                ),
                record=row_data,
            )
            error_count += 1

        row_data["party_normalized"] = _normalize_text(row_data.get("party"))
        row_data["party_type_normalized"] = _normalize_text(row_data.get("party_type"))
        row_data["party_role_normalized"] = _normalize_text(row_data.get("party_role"))
        row_data["party_def_num_normalized"] = _normalize_party_def_num(
            row_data.get("party_def_num")
        )
        return error_count

    def _process_case_stage1_upload(job_id: str, file_path: str) -> None:
        total_rows = 0
        inserted_rows = 0
        updated_rows = 0
        skipped_rows = 0
        error_rows = 0
        processed_rows = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                reader = csv.reader(handle, delimiter="|")
                raw_headers = next(reader, None)
                if not raw_headers:
                    raise ValueError("Uploaded file is missing a header row.")

                headers = _normalize_case_stage1_headers(raw_headers)
                if "cs_caseid" not in headers:
                    raise ValueError("Uploaded file must include cs_caseid header.")
                if _is_postgres():
                    with engine.connect() as conn:
                        records_total_before = conn.execute(
                            select(func.count()).select_from(case_stage1)
                        ).scalar_one()
                else:
                    records_total_before = 0

                header_columns = [
                    header if header in CASE_STAGE1_IMPORT_COLUMNS else None
                    for header in headers
                ]

                with engine.begin() as conn:
                    case_stage1_table = case_stage1
                    date_columns = CASE_STAGE1_DATE_COLUMNS
                    data_columns = CASE_STAGE1_IMPORT_COLUMNS

                    batch: List[Dict[str, Any]] = []
                    for row in reader:
                        total_rows += 1
                        row_data: Dict[str, Any] = {column: None for column in data_columns}
                        for header, value in zip(header_columns, row):
                            if not header:
                                continue
                            clean_value = value.strip()
                            row_data[header] = clean_value if clean_value else None
                        for column in data_columns:
                            row_data.setdefault(column, None)

                        case_id_raw = row_data.get("cs_caseid")
                        try:
                            row_data["cs_caseid"] = (
                                int(case_id_raw) if case_id_raw is not None else None
                            )
                        except (TypeError, ValueError):
                            skipped_rows += 1
                            continue
                        if row_data["cs_caseid"] is None:
                            skipped_rows += 1
                            continue

                        for header in date_columns:
                            row_data[header] = _parse_stage1_date(row_data.get(header))
                        row_data["search_text"] = _build_case_stage1_search_text(row_data)

                        processed_rows += 1
                        batch.append(row_data)
                        if len(batch) >= CASE_STAGE1_CHUNK_SIZE:
                            inserted, updated = _upsert_case_stage1_batch(
                                conn,
                                case_stage1_table,
                                batch,
                                track_counts=not _is_postgres(),
                            )
                            inserted_rows += inserted
                            updated_rows += updated
                            batch = []

                    if batch:
                        inserted, updated = _upsert_case_stage1_batch(
                            conn,
                            case_stage1_table,
                            batch,
                            track_counts=not _is_postgres(),
                        )
                        inserted_rows += inserted
                        updated_rows += updated

                if _is_postgres():
                    with engine.connect() as conn:
                        records_total_after = conn.execute(
                            select(func.count()).select_from(case_stage1)
                        ).scalar_one()
                    inserted_rows = max(0, records_total_after - records_total_before)
                    updated_rows = max(0, processed_rows - inserted_rows)

            _set_case_stage1_import(
                job_id,
                status="completed",
                completed_at=datetime.utcnow().isoformat(),
                total_rows=total_rows,
                inserted_rows=inserted_rows,
                updated_rows=updated_rows,
                skipped_rows=skipped_rows,
                error_rows=error_rows,
                message=(
                    "Upload complete. "
                    f"Total rows: {total_rows}. "
                    f"Inserted: {inserted_rows}. "
                    f"Updated: {updated_rows}. "
                    f"Skipped: {skipped_rows}. "
                    f"Errors: {error_rows}."
                ),
            )
        except Exception:
            app.logger.exception("Case stage 1 upload failed.")
            error_rows += 1
            _set_case_stage1_import(
                job_id,
                status="failed",
                completed_at=datetime.utcnow().isoformat(),
                total_rows=total_rows,
                inserted_rows=inserted_rows,
                updated_rows=updated_rows,
                skipped_rows=skipped_rows,
                error_rows=error_rows,
                message="Upload failed. Please check the server logs for details.",
            )
        finally:
            try:
                os.remove(file_path)
            except OSError:
                app.logger.warning("Unable to remove uploaded file %s", file_path)

    def _process_case_data_one_upload(job_id: str, file_path: str) -> None:
        total_rows = 0
        inserted_rows = 0
        updated_rows = 0
        skipped_rows = 0
        error_rows = 0
        processed_rows = 0
        error_details: List[Dict[str, Any]] = []
        validation_failed = False
        valid_rows: Optional[List[Dict[str, Any]]] = []

        try:
            batch_size = CASE_DATA_ONE_CHUNK_SIZE
            if not _is_postgres():
                column_count = max(1, len(CASE_DATA_ONE_IMPORT_COLUMNS))
                sqlite_insert_limit = max(
                    1, (SQLITE_MAX_VARIABLE_NUMBER // column_count) - 1
                )
                sqlite_in_limit = max(1, SQLITE_MAX_VARIABLE_NUMBER - 1)
                batch_size = min(batch_size, sqlite_insert_limit, sqlite_in_limit)

            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                total_rows = max(0, sum(1 for _ in handle) - 1)
                handle.seek(0)
                reader = csv.reader(handle, delimiter="|")
                raw_headers = next(reader, None)
                if not raw_headers:
                    _record_case_data_one_error(
                        error_details,
                        row_number=1,
                        message="Missing header row.",
                        record=raw_headers,
                    )
                    raise ValueError("Uploaded file is missing a header row.")

                headers = _normalize_case_data_one_headers(raw_headers)
                if "cs_caseid" not in headers:
                    _record_case_data_one_error(
                        error_details,
                        row_number=1,
                        message="Missing cs_caseid header.",
                        record=raw_headers,
                    )
                    raise ValueError("Uploaded file must include cs_caseid header.")
                _set_case_data_one_import(job_id, total_rows=total_rows)
                if _is_postgres():
                    with engine.connect() as conn:
                        records_total_before = conn.execute(
                            select(func.count()).select_from(case_data_one)
                        ).scalar_one()
                else:
                    records_total_before = 0

                header_columns = [
                    header if header in CASE_DATA_ONE_IMPORT_COLUMNS else None
                    for header in headers
                ]
                last_progress_update = time.monotonic()
                rows_since_update = 0

                def _update_case_data_one_progress(
                    force: bool = False, *, status: str = "processing", message: str = ""
                ) -> None:
                    nonlocal last_progress_update, rows_since_update
                    now = time.monotonic()
                    if not force:
                        if (
                            rows_since_update < CASE_DATA_ONE_PROGRESS_INTERVAL_ROWS
                            and (now - last_progress_update)
                            < CASE_DATA_ONE_PROGRESS_INTERVAL_SECONDS
                        ):
                            return
                    _set_case_data_one_import(
                        job_id,
                        status=status,
                        total_rows=total_rows,
                        processed_rows=processed_rows,
                        inserted_rows=inserted_rows,
                        updated_rows=updated_rows,
                        skipped_rows=skipped_rows,
                        error_rows=error_rows,
                        error_details=error_details,
                        message=message
                        or (
                            "Validating rows. "
                            f"Processed {processed_rows} of {total_rows}."
                        ),
                    )
                    last_progress_update = now
                    rows_since_update = 0

                case_data_one_table = case_data_one
                date_columns = CASE_DATA_ONE_DATE_COLUMNS
                data_columns = CASE_DATA_ONE_IMPORT_COLUMNS

                for row_index, row in enumerate(reader, start=2):
                    processed_rows += 1
                    try:
                        row_data: Dict[str, Any] = {
                            column: None for column in data_columns
                        }
                        for header, value in zip(header_columns, row):
                            if not header:
                                continue
                            clean_value = value.strip()
                            row_data[header] = clean_value if clean_value else None
                        for column in data_columns:
                            row_data.setdefault(column, None)

                        case_id_raw = row_data.get("cs_caseid")
                        row_valid = True
                        if all(value is None for value in row_data.values()):
                            skipped_rows += 1
                            continue
                        try:
                            row_data["cs_caseid"] = (
                                int(case_id_raw) if case_id_raw is not None else None
                            )
                        except (TypeError, ValueError):
                            skipped_rows += 1
                            error_rows += 1
                            _record_case_data_one_error(
                                error_details,
                                row_number=row_index,
                                message="Invalid cs_caseid value.",
                                record=row_data,
                            )
                            row_valid = False
                        if row_valid and row_data["cs_caseid"] is None:
                            skipped_rows += 1
                            error_rows += 1
                            _record_case_data_one_error(
                                error_details,
                                row_number=row_index,
                                message="Missing cs_caseid value.",
                                record=row_data,
                            )
                            row_valid = False

                        if row_valid:
                            for header in date_columns:
                                row_data[header] = _parse_case_data_one_date(
                                    row_data.get(header)
                                )
                            validation_errors = _apply_case_data_one_classifications(
                                row_data,
                                row_number=row_index,
                                error_details=error_details,
                            )
                            if validation_errors:
                                error_rows += validation_errors
                                row_valid = False

                        if row_valid and valid_rows is not None:
                            valid_rows.append(row_data)
                        if not row_valid:
                            validation_failed = True
                            valid_rows = None
                    except Exception as exc:
                        error_rows += 1
                        validation_failed = True
                        valid_rows = None
                        _record_case_data_one_error(
                            error_details,
                            row_number=row_index,
                            message=f"Row parsing failed: {exc}",
                            record=row_data,
                        )
                    rows_since_update += 1
                    _update_case_data_one_progress(status="validating")

                _update_case_data_one_progress(
                    force=True, status="validating", message="Validation complete."
                )

                if error_rows:
                    validation_failed = True

                if not validation_failed:
                    valid_rows = valid_rows or []
                    with engine.begin() as conn:
                        batch: List[Dict[str, Any]] = []
                        for row_data in valid_rows:
                            batch.append(row_data)
                            if len(batch) >= batch_size:
                                inserted, updated = _upsert_case_data_one_batch(
                                    conn,
                                    case_data_one_table,
                                    batch,
                                    track_counts=not _is_postgres(),
                                )
                                inserted_rows += inserted
                                updated_rows += updated
                                batch = []
                                _update_case_data_one_progress(
                                    force=True,
                                    status="processing",
                                    message="Applying validated rows.",
                                )

                        if batch:
                            inserted, updated = _upsert_case_data_one_batch(
                                conn,
                                case_data_one_table,
                                batch,
                                track_counts=not _is_postgres(),
                            )
                            inserted_rows += inserted
                            updated_rows += updated
                            _update_case_data_one_progress(
                                force=True,
                                status="processing",
                                message="Applying validated rows.",
                            )
                else:
                    inserted_rows = 0
                    updated_rows = 0

                if _is_postgres() and not validation_failed:
                    with engine.connect() as conn:
                        records_total_after = conn.execute(
                            select(func.count()).select_from(case_data_one)
                        ).scalar_one()
                    inserted_rows = max(0, records_total_after - records_total_before)
                    updated_rows = max(0, processed_rows - inserted_rows)

            completion_message = (
                "Upload complete. "
                f"Total rows: {total_rows}. "
                f"Inserted: {inserted_rows}. "
                f"Updated: {updated_rows}. "
                f"Skipped: {skipped_rows}. "
                f"Errors: {error_rows}."
            )
            if error_rows:
                completion_suffix = (
                    "One or more errors occurred; no files were added to the database."
                )
                completion_message = (
                    f"{completion_message} {completion_suffix} Download the error "
                    "report or check the server logs for details."
                )
            else:
                completion_suffix = "All files have been added to the database."
                completion_message = f"{completion_message} {completion_suffix}"

            _set_case_data_one_import(
                job_id,
                status="completed",
                completed_at=datetime.utcnow().isoformat(),
                total_rows=total_rows,
                processed_rows=processed_rows,
                inserted_rows=inserted_rows,
                updated_rows=updated_rows,
                skipped_rows=skipped_rows,
                error_rows=error_rows,
                error_details=error_details,
                message=completion_message,
            )
        except Exception:
            app.logger.exception("Case data one upload failed.")
            error_rows += 1
            if not error_details:
                _record_case_data_one_error(
                    error_details,
                    row_number=None,
                    message="Upload failed unexpectedly. Check server logs for details.",
                    record=None,
                )
            _set_case_data_one_import(
                job_id,
                status="failed",
                completed_at=datetime.utcnow().isoformat(),
                total_rows=total_rows,
                processed_rows=processed_rows,
                inserted_rows=inserted_rows,
                updated_rows=updated_rows,
                skipped_rows=skipped_rows,
                error_rows=error_rows,
                error_details=error_details,
                message=(
                    "Upload failed. Please check the server logs for details or "
                    "download the error report."
                ),
            )
        finally:
            try:
                os.remove(file_path)
            except OSError:
                app.logger.warning("Unable to remove uploaded file %s", file_path)

    def normalize_email(email: str) -> str:
        return email.strip().lower()

    def valid_email(email: str) -> bool:
        # Simple sanity check.
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

    def _earliest_date(*values: Optional[Any]) -> Optional[Any]:
        candidates = [value for value in values if value is not None]
        return min(candidates) if candidates else None

    def _latest_date(*values: Optional[Any]) -> Optional[Any]:
        candidates = [value for value in values if value is not None]
        return max(candidates) if candidates else None

    def upsert_subscribe(
        email: str, user_id: Optional[int] = None, conn: Optional[Any] = None
    ) -> None:
        normalized_email = normalize_email(email)

        def _execute(connection: Any) -> None:
            row = (
                connection.execute(
                    select(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.email == normalized_email)
                    .limit(1)
                )
                .mappings()
                .first()
            )
            if row:
                update_values: Dict[str, Any] = {
                    "opt_in": True,
                    "unsubscribed_at": None,
                    "updated_at": func.now(),
                }
                if row.get("subscribed_at") is None:
                    update_values["subscribed_at"] = func.now()
                if user_id is not None and (row.get("user_id") in {None, user_id}):
                    update_values["user_id"] = user_id
                connection.execute(
                    update(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.id == row["id"])
                    .values(**update_values)
                )
                return

            connection.execute(
                insert(newsletter_subscriptions).values(
                    email=normalized_email,
                    user_id=user_id,
                    opt_in=True,
                    subscribed_at=func.now(),
                )
            )

        if conn is None:
            with engine.begin() as connection:
                _execute(connection)
            return
        _execute(conn)

    def set_subscription(
        email: str, opt_in: bool, user_id: Optional[int] = None, conn: Optional[Any] = None
    ) -> None:
        normalized_email = normalize_email(email)

        def _execute(connection: Any) -> None:
            row = (
                connection.execute(
                    select(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.email == normalized_email)
                    .limit(1)
                )
                .mappings()
                .first()
            )
            if opt_in:
                upsert_subscribe(normalized_email, user_id=user_id, conn=connection)
                return

            update_values: Dict[str, Any] = {
                "opt_in": False,
                "unsubscribed_at": func.now(),
                "updated_at": func.now(),
            }
            if row:
                if user_id is not None and (row.get("user_id") in {None, user_id}):
                    update_values["user_id"] = user_id
                connection.execute(
                    update(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.id == row["id"])
                    .values(**update_values)
                )
                return

            connection.execute(
                insert(newsletter_subscriptions).values(
                    email=normalized_email,
                    user_id=user_id,
                    opt_in=False,
                    unsubscribed_at=func.now(),
                )
            )

        if conn is None:
            with engine.begin() as connection:
                _execute(connection)
            return
        _execute(conn)

    def merge_newsletter_subscriptions(
        conn: Any, old_email: str, new_email: str, user_id: int
    ) -> None:
        normalized_old = normalize_email(old_email)
        normalized_new = normalize_email(new_email)
        if normalized_old == normalized_new:
            row = (
                conn.execute(
                    select(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.email == normalized_new)
                    .limit(1)
                )
                .mappings()
                .first()
            )
            if row and row.get("user_id") in {None, user_id}:
                conn.execute(
                    update(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.id == row["id"])
                    .values(user_id=user_id, updated_at=func.now())
                )
            return

        old_row = (
            conn.execute(
                select(newsletter_subscriptions)
                .where(newsletter_subscriptions.c.email == normalized_old)
                .limit(1)
            )
            .mappings()
            .first()
        )
        new_row = (
            conn.execute(
                select(newsletter_subscriptions)
                .where(newsletter_subscriptions.c.email == normalized_new)
                .limit(1)
            )
            .mappings()
            .first()
        )

        if not old_row and not new_row:
            return

        if not new_row and old_row:
            conn.execute(
                update(newsletter_subscriptions)
                .where(newsletter_subscriptions.c.id == old_row["id"])
                .values(email=normalized_new, user_id=user_id, updated_at=func.now())
            )
            return

        if not new_row:
            return

        opt_in = bool(new_row.get("opt_in")) or bool(old_row.get("opt_in") if old_row else False)
        subscribed_at = _earliest_date(
            new_row.get("subscribed_at"),
            old_row.get("subscribed_at") if old_row else None,
        )
        if opt_in:
            unsubscribed_at = None
        else:
            unsubscribed_at = _latest_date(
                new_row.get("unsubscribed_at"),
                old_row.get("unsubscribed_at") if old_row else None,
            )

        conn.execute(
            update(newsletter_subscriptions)
            .where(newsletter_subscriptions.c.id == new_row["id"])
            .values(
                user_id=user_id,
                opt_in=opt_in,
                subscribed_at=subscribed_at,
                unsubscribed_at=unsubscribed_at,
                updated_at=func.now(),
            )
        )

        if old_row:
            conn.execute(
                delete(newsletter_subscriptions).where(newsletter_subscriptions.c.id == old_row["id"])
            )

    def current_user() -> Optional[Dict[str, Any]]:
        user_id = session.get("user_id")
        if not user_id:
            return None
        with engine.connect() as conn:
            row = conn.execute(select(users).where(users.c.id == user_id)).mappings().first()
        if not row:
            session.pop("user_id", None)
            return None
        return dict(row)

    def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if not g.current_user:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def admin_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if not session.get("is_admin"):
                return redirect(url_for("admin_login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    @app.before_request
    def _load_user() -> None:
        g.current_user = current_user()

    @app.context_processor
    def _inject_globals() -> Dict[str, Any]:
        return {
            "current_user": g.get("current_user"),
            "is_admin": bool(session.get("is_admin")),
            "csrf_token": get_csrf_token(),
        }

    # -----------------
    # Public pages
    # -----------------

    @app.route("/")
    def home():
        return render_template(
            "home.html",
            active_page="home",
            newsletter_success=request.args.get("newsletter") == "success",
            newsletter_error=request.args.get("newsletter_error"),
            newsletter_email=request.args.get("newsletter_email", ""),
        )

    @app.route("/pricing")
    def pricing():
        return render_template("pricing.html", active_page="pricing")

    @app.route("/news")
    def news():
        return render_template("news.html", active_page="news")

    @app.route("/about")
    def about():
        return render_template("about.html", active_page="about")

    @app.route("/contact")
    def contact():
        return render_template("contact.html", active_page="contact")

    @app.route("/health")
    def health_root():
        return jsonify({"status": "ok"})

    # -----------------
    # Auth
    # -----------------

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            require_csrf()

            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            user_type = request.form.get("user_type", "").strip()
            firm_name = request.form.get("firm_name", "").strip() or None
            title = request.form.get("title", "").strip() or None
            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")

            phone = request.form.get("phone", "").strip() or None
            address = request.form.get("address", "").strip() or None
            city = request.form.get("city", "").strip() or None
            state = request.form.get("state", "").strip() or None
            zip_code = request.form.get("zip", "").strip() or None
            county = request.form.get("county", "").strip() or None
            country = request.form.get("country", "").strip() or None

            has_pacer_account = bool(request.form.get("has_pacer_account"))
            heard_about_us = request.form.get("heard_about_us", "").strip() or None
            referral_code = request.form.get("referral_code", "").strip() or None

            errors = []
            if not first_name:
                errors.append("First name is required.")
            if not last_name:
                errors.append("Last name is required.")
            if user_type not in USER_TYPES:
                errors.append("User type is required.")
            if not email or not valid_email(email):
                errors.append("A valid email is required.")
            if not password or len(password) < 8:
                errors.append("Password must be at least 8 characters.")
            if user_type == "Attorney, Law Firm":
                if not firm_name:
                    errors.append("Firm name is required for law firm accounts.")
                if not title:
                    errors.append("Title is required for law firm accounts.")

            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template(
                    "signup.html",
                    active_page="login",
                    user_types=USER_TYPES,
                    form=request.form,
                )

            password_hash = generate_password_hash(password)

            payload = {
                "first_name": first_name,
                "last_name": last_name,
                "user_type": user_type,
                "firm_name": firm_name,
                "title": title,
                "email": email,
                "password_hash": password_hash,
                "phone": phone,
                "address": address,
                "city": city,
                "state": state,
                "zip": zip_code,
                "county": county,
                "country": country,
                "has_pacer_account": has_pacer_account,
                "heard_about_us": heard_about_us,
                "referral_code": referral_code,
            }

            try:
                with engine.begin() as conn:
                    result = conn.execute(insert(users).values(**payload))
                    user_id = result.inserted_primary_key[0]
                    newsletter_row = (
                        conn.execute(
                            select(newsletter_subscriptions)
                            .where(newsletter_subscriptions.c.email == email)
                            .limit(1)
                        )
                        .mappings()
                        .first()
                    )
                    if newsletter_row and newsletter_row.get("user_id") in {None, user_id}:
                        conn.execute(
                            update(newsletter_subscriptions)
                            .where(newsletter_subscriptions.c.id == newsletter_row["id"])
                            .values(user_id=user_id, updated_at=func.now())
                        )
            except IntegrityError:
                flash("An account with that email already exists.", "error")
                return render_template(
                    "signup.html",
                    active_page="login",
                    user_types=USER_TYPES,
                    form=request.form,
                )

            session["user_id"] = user_id
            flash("Account created. Welcome!", "success")
            return redirect(url_for("dashboard"))

        return render_template(
            "signup.html",
            active_page="login",
            user_types=USER_TYPES,
            form={},
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            require_csrf()

            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")

            if not email or not password:
                flash("Email and password are required.", "error")
                return render_template("login.html", active_page="login")

            with engine.connect() as conn:
                row = conn.execute(select(users).where(users.c.email == email)).mappings().first()

            # Avoid user enumeration by using one generic message.
            if not row or not check_password_hash(row["password_hash"], password):
                flash("Invalid email or password.", "error")
                return render_template("login.html", active_page="login")

            session["user_id"] = row["id"]
            flash("Logged in.", "success")
            next_url = request.args.get("next")
            if next_url:
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        return render_template("login.html", active_page="login")

    @app.post("/logout")
    def logout():
        require_csrf()
        session.pop("user_id", None)
        session.pop("is_admin", None)
        flash("Logged out.", "success")
        return redirect(url_for("home"))

    # -----------------
    # User pages
    # -----------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", active_page="dashboard")

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = g.current_user
        assert user is not None

        if request.method == "POST":
            require_csrf()

            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            user_type = request.form.get("user_type", "").strip()
            firm_name = request.form.get("firm_name", "").strip() or None
            title = request.form.get("title", "").strip() or None
            email = normalize_email(request.form.get("email", ""))
            old_email = normalize_email(user.get("email", ""))
            newsletter_opt_in = bool(request.form.get("newsletter_opt_in"))

            phone = request.form.get("phone", "").strip() or None
            address = request.form.get("address", "").strip() or None
            city = request.form.get("city", "").strip() or None
            state = request.form.get("state", "").strip() or None
            zip_code = request.form.get("zip", "").strip() or None
            county = request.form.get("county", "").strip() or None
            country = request.form.get("country", "").strip() or None

            has_pacer_account = bool(request.form.get("has_pacer_account"))
            heard_about_us = request.form.get("heard_about_us", "").strip() or None
            referral_code = request.form.get("referral_code", "").strip() or None

            errors = []
            if not first_name:
                errors.append("First name is required.")
            if not last_name:
                errors.append("Last name is required.")
            if user_type not in USER_TYPES:
                errors.append("User type is required.")
            if not email or not valid_email(email):
                errors.append("A valid email is required.")
            if user_type == "Attorney, Law Firm":
                if not firm_name:
                    errors.append("Firm name is required for law firm accounts.")
                if not title:
                    errors.append("Title is required for law firm accounts.")

            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template(
                    "profile.html",
                    active_page="profile",
                    user_types=USER_TYPES,
                    user=request.form,
                    newsletter_opt_in=newsletter_opt_in,
                )

            payload = {
                "first_name": first_name,
                "last_name": last_name,
                "user_type": user_type,
                "firm_name": firm_name,
                "title": title,
                "email": email,
                "phone": phone,
                "address": address,
                "city": city,
                "state": state,
                "zip": zip_code,
                "county": county,
                "country": country,
                "has_pacer_account": has_pacer_account,
                "heard_about_us": heard_about_us,
                "referral_code": referral_code,
            }

            try:
                with engine.begin() as conn:
                    conn.execute(update(users).where(users.c.id == user["id"]).values(**payload))
                    merge_newsletter_subscriptions(conn, old_email, email, user["id"])
                    set_subscription(
                        email, newsletter_opt_in, user_id=user["id"], conn=conn
                    )
            except IntegrityError:
                flash("That email is already in use.", "error")
                return render_template(
                    "profile.html",
                    active_page="profile",
                    user_types=USER_TYPES,
                    user=request.form,
                    newsletter_opt_in=newsletter_opt_in,
                )

            flash("Profile updated.", "success")
            return redirect(url_for("profile"))

        # GET
        newsletter_row = None
        with engine.connect() as conn:
            newsletter_row = (
                conn.execute(
                    select(newsletter_subscriptions)
                    .where(newsletter_subscriptions.c.email == normalize_email(user["email"]))
                    .limit(1)
                )
                .mappings()
                .first()
            )
        newsletter_opt_in = bool(newsletter_row.get("opt_in")) if newsletter_row else False

        return render_template(
            "profile.html",
            active_page="profile",
            user_types=USER_TYPES,
            user=user,
            newsletter_opt_in=newsletter_opt_in,
        )

    @app.post("/profile/newsletter")
    @login_required
    def profile_newsletter():
        require_csrf()
        user = g.current_user
        assert user is not None

        payload = request.get_json(silent=True) or {}
        raw_opt_in = payload.get("opt_in")
        if raw_opt_in is None:
            raw_opt_in = request.form.get("opt_in")

        if isinstance(raw_opt_in, bool):
            opt_in = raw_opt_in
        elif raw_opt_in is None:
            opt_in = False
        elif isinstance(raw_opt_in, (int, float)):
            opt_in = bool(raw_opt_in)
        else:
            opt_in = str(raw_opt_in).strip().lower() in {"1", "true", "yes", "on"}

        with engine.begin() as conn:
            set_subscription(user["email"], opt_in, user_id=user["id"], conn=conn)

        return jsonify({"ok": True})

    @app.post("/newsletter/subscribe")
    def newsletter_subscribe():
        require_csrf()
        raw_email = request.form.get("email", "").strip()
        normalized_email = normalize_email(raw_email)
        wants_json = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.accept_mimetypes.best == "application/json"
        )

        if not normalized_email or not valid_email(normalized_email):
            error_message = "Please enter a valid email address."
            if wants_json:
                return jsonify({"ok": False, "error": error_message}), 400
            return redirect(
                url_for(
                    "home",
                    newsletter="error",
                    newsletter_error=error_message,
                    newsletter_email=raw_email,
                )
            )

        upsert_subscribe(normalized_email)

        if wants_json:
            return jsonify({"ok": True})
        return redirect(url_for("home", newsletter="success"))

    # -----------------
    # Admin
    # -----------------

    @app.cli.command("federal-courts-sync")
    def federal_courts_sync_command() -> None:
        """Sync PACER CM/ECF court lookup data into the database."""
        try:
            stats = run_federal_courts_sync()
        except (FederalCourtsSyncError, requests.RequestException) as exc:
            app.logger.exception("Federal courts sync failed.")
            raise SystemExit(f"Federal courts sync failed: {exc}") from exc

        message = (
            "Federal courts sync complete: "
            f"{stats['inserted']} inserted, {stats['updated']} updated "
            f"(meta.last_updated={stats['source_last_updated'] or 'unknown'})."
        )
        app.logger.info(message)
        print(message)

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        expected_pass = os.environ.get("CPD_ADMIN_KEY")
        admin_key_file = os.environ.get("CPD_ADMIN_KEY_FILE", "/etc/secrets/CPD_ADMIN_KEY")
        if not expected_pass and admin_key_file:
            try:
                expected_pass = Path(admin_key_file).read_text(encoding="utf-8").strip()
            except (FileNotFoundError, OSError):
                expected_pass = None
        if not expected_pass:
            flash(
                "Admin login is not configured. Set CPD_ADMIN_KEY or provide a secret file "
                "to enable admin access.",
                "error",
            )
            return render_template("admin_login.html", admin_configured=False)

        if request.method == "POST":
            require_csrf()

            admin_user = request.form.get("username", "").strip()
            admin_pass = request.form.get("password", "")

            expected_user = "CPDADMIN"

            if hmac.compare_digest(admin_user, expected_user) and hmac.compare_digest(
                admin_pass, expected_pass
            ):
                session["is_admin"] = True
                flash("Admin access granted.", "success")
                next_url = request.args.get("next")
                if next_url:
                    return redirect(next_url)
                return redirect(url_for("admin_home"))

            flash("Invalid admin credentials.", "error")

        return render_template("admin_login.html", admin_configured=True)

    @app.get("/admin")
    @admin_required
    def admin_home():
        return render_template("admin_home.html")

    @app.get("/admin/federal-data-dashboard")
    @admin_required
    def admin_federal_data_dashboard():
        return redirect(url_for("admin_federal_data_dashboard_get_pacer_data"))

    @app.get("/admin/federal-data-dashboard/get-pacer-data")
    @admin_required
    def admin_federal_data_dashboard_get_pacer_data():
        pacer_session = _get_pacer_session()
        pacer_server_creds_available = bool(
            _first_env_or_secret_file("puser") and _first_env_or_secret_file("ppass")
        )
        manual_mode = request.args.get("manual") == "1"
        return render_template(
            "admin_federal_data_get_pacer_data.html",
            active_page="federal_data_dashboard",
            active_subnav="get_pacer_data",
            pacer_authorized=bool(pacer_session),
            pacer_authorized_at=(pacer_session or {}).get("authorized_at"),
            pacer_needs_otp=bool(session.get("pacer_needs_otp")),
            pacer_client_code_required=bool(session.get("pacer_client_code_required")),
            pacer_redaction_required=bool(session.get("pacer_redaction_required")),
            pacer_redaction_acknowledged=bool(session.get("pacer_redaction_acknowledged")),
            pacer_base_url=pacer_auth_base_url,
            pacer_env_notice=pacer_environment_notice(pacer_auth_base_url),
            pacer_server_creds_available=pacer_server_creds_available,
            manual_mode=manual_mode,
        )

    @app.get("/admin/federal-data-dashboard/federal-courts")
    @admin_required
    def admin_federal_data_dashboard_federal_courts():
        q = request.args.get("q", "").strip()
        summary_columns = [
            federal_courts.c.court_id,
            federal_courts.c.title,
            federal_courts.c.court_name,
            federal_courts.c.court_type,
            federal_courts.c.circuit,
            federal_courts.c.login_url,
            federal_courts.c.web_url,
            federal_courts.c.rss_url,
            federal_courts.c.software_version,
            federal_courts.c.go_live_date,
            federal_courts.c.pdf_size,
            federal_courts.c.merge_doc_size,
            federal_courts.c.vcis,
            federal_courts.c.states,
            federal_courts.c.counties_count,
            federal_courts.c.source_last_updated,
            federal_courts.c.fetched_at,
            federal_courts.c.updated_at,
        ]
        stmt = select(*summary_columns)
        if q:
            pattern = f"%{q}%"
            stmt = stmt.where(
                or_(
                    federal_courts.c.court_id.ilike(pattern),
                    federal_courts.c.title.ilike(pattern),
                    federal_courts.c.court_name.ilike(pattern),
                    federal_courts.c.court_type.ilike(pattern),
                    federal_courts.c.circuit.ilike(pattern),
                    federal_courts.c.states.cast(Text).ilike(pattern),
                )
            )
        stmt = stmt.order_by(federal_courts.c.court_type.asc(), federal_courts.c.title.asc())

        with engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
            total_courts = conn.execute(
                select(func.count()).select_from(federal_courts)
            ).scalar_one()
            last_fetched_at = conn.execute(select(func.max(federal_courts.c.fetched_at))).scalar_one()
            last_source_updated = conn.execute(
                select(func.max(federal_courts.c.source_last_updated))
            ).scalar_one()

        def _format_dt(value: Any) -> Optional[str]:
            if value is None:
                return None
            if hasattr(value, "isoformat"):
                try:
                    return value.isoformat(sep=" ", timespec="seconds")
                except TypeError:
                    return value.isoformat()
            return str(value)

        courts: List[Dict[str, Any]] = []
        for row in rows:
            states_value = row.get("states")
            if isinstance(states_value, str):
                try:
                    parsed_states = json.loads(states_value)
                    states_value = parsed_states if isinstance(parsed_states, list) else None
                except json.JSONDecodeError:
                    states_value = [states_value]
            courts.append(
                {
                    **row,
                    "states": states_value,
                    "fetched_at_display": _format_dt(row.get("fetched_at")),
                    "updated_at_display": _format_dt(row.get("updated_at")),
                }
            )

        return render_template(
            "admin_federal_courts.html",
            active_page="federal_data_dashboard",
            active_subnav="federal_courts",
            courts=courts,
            total_courts=total_courts,
            query=q,
            last_fetched_at_display=_format_dt(last_fetched_at),
            last_source_updated=last_source_updated,
        )

    @app.post("/admin/federal-data-dashboard/federal-courts/sync")
    @admin_required
    def admin_federal_data_dashboard_federal_courts_sync():
        require_csrf()
        try:
            stats = run_federal_courts_sync()
        except (FederalCourtsSyncError, requests.RequestException):
            app.logger.exception("Federal courts sync failed from admin UI.")
            flash("Federal courts sync failed. Check logs for details.", "error")
            return redirect(url_for("admin_federal_data_dashboard_federal_courts"))

        flash(
            "Federal courts sync complete: "
            f"{stats['inserted']} inserted, {stats['updated']} updated.",
            "success",
        )
        return redirect(url_for("admin_federal_data_dashboard_federal_courts"))

    @app.get("/admin/federal-data-dashboard/federal-courts/<court_id>/json")
    @admin_required
    def admin_federal_data_dashboard_federal_court_json(court_id: str):
        stmt = (
            select(
                federal_courts.c.court_id,
                federal_courts.c.source_last_updated,
                federal_courts.c.raw_json,
            )
            .where(federal_courts.c.court_id == court_id)
            .limit(1)
        )
        with engine.connect() as conn:
            row = conn.execute(stmt).mappings().first()
        if not row:
            abort(404)
        return jsonify(
            {
                "court_id": row["court_id"],
                "source_last_updated": row.get("source_last_updated"),
                "raw_json": row.get("raw_json"),
            }
        )

    @app.post("/admin/federal-data-dashboard/pacer-auth")
    @admin_required
    def admin_federal_data_dashboard_pacer_auth():
        require_csrf()

        json_payload = request.get_json(silent=True) or {}
        wants_json = request.is_json or request.accept_mimetypes["application/json"] >= request.accept_mimetypes[
            "text/html"
        ]

        manual_mode = request.form.get("manual_mode") == "1" or str(
            json_payload.get("manual_mode", "")
        ).lower() in {"1", "true", "yes"}
        login_id = (
            json_payload.get("username")
            or json_payload.get("loginId")
            or json_payload.get("pacer_login_id")
            or request.form.get("pacer_login_id", "")
        ).strip()
        password = (
            json_payload.get("password")
            or json_payload.get("pacer_login_secret")
            or request.form.get("pacer_login_secret", "")
        )
        otp_code = (
            json_payload.get("otpCode")
            or json_payload.get("pacer_otp_code")
            or request.form.get("pacer_otp_code", "")
        ).strip()
        client_code = (
            json_payload.get("clientCode")
            or json_payload.get("pacer_client_code")
            or request.form.get("pacer_client_code", "")
        ).strip()
        redaction_ack = request.form.get("pacer_redaction_ack") == "1" or str(
            json_payload.get("pacer_redaction_ack", "")
        ).lower() in {"1", "true", "yes", "on"}

        redirect_target = (
            url_for("admin_federal_data_dashboard_get_pacer_data", manual="1")
            if manual_mode
            else url_for("admin_federal_data_dashboard_get_pacer_data")
        )

        if not login_id or not password:
            fallback_user, fallback_pass = get_configured_pacer_credentials()
            if fallback_user and fallback_pass:
                login_id = fallback_user
                password = fallback_pass
            else:
                session["pacer_needs_otp"] = False
                session["pacer_client_code_required"] = False
                session["pacer_redaction_required"] = False
                message = (
                    "PACER credentials are not configured. Set Render env var puser and "
                    "secret file ppass, or use manual mode."
                )
                if wants_json:
                    return (
                        jsonify(
                            {
                                "authorized": False,
                                "timestamp": datetime.utcnow().isoformat(),
                                "status": "error",
                            }
                        ),
                        400,
                    )
                flash(message, "error")
                return redirect(redirect_target)

        if login_id.strip().upper() == "CPDADMIN":
            session["pacer_needs_otp"] = False
            session["pacer_client_code_required"] = False
            session["pacer_redaction_required"] = False
            message = (
                "Those look like CourtDataPro admin creds. Enter PACER credentials instead."
            )
            if wants_json:
                return (
                    jsonify(
                        {
                            "authorized": False,
                            "timestamp": datetime.utcnow().isoformat(),
                            "status": "error",
                        }
                    ),
                    400,
                )
            flash(message, "error")
            return redirect(redirect_target)

        otp_code = otp_code or None
        client_code = client_code or None
        session["pacer_redaction_acknowledged"] = bool(redaction_ack)

        if not redaction_ack:
            session["pacer_needs_otp"] = False
            session["pacer_client_code_required"] = False
            session["pacer_redaction_required"] = True
            message = (
                "You must acknowledge the PACER redaction rules before authorizing a filer account."
            )
            if wants_json:
                return (
                    jsonify(
                        {
                            "authorized": False,
                            "timestamp": datetime.utcnow().isoformat(),
                            "status": "redaction_required",
                        }
                    ),
                    400,
                )
            flash(message, "error")
            return redirect(redirect_target)

        try:
            result = pacer_auth_client.authenticate(
                login_id,
                password,
                otp_code=otp_code,
                client_code=client_code,
                redact_flag=redaction_ack,
            )
        except ValueError as exc:
            session["pacer_needs_otp"] = False
            session["pacer_client_code_required"] = False
            session["pacer_redaction_required"] = False
            if wants_json:
                return (
                    jsonify(
                        {
                            "authorized": False,
                            "timestamp": datetime.utcnow().isoformat(),
                            "status": "error",
                        }
                    ),
                    401,
                )
            flash(str(exc), "error")
            return redirect(redirect_target)

        if result.can_proceed:
            _set_pacer_session(result.token)
            session["pacer_needs_otp"] = False
            session["pacer_client_code_required"] = False
            session["pacer_redaction_required"] = False
            if wants_json:
                return jsonify(
                    {
                        "authorized": True,
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": "authorized",
                    }
                )
            flash("PACER authentication successful.", "success")
        else:
            session["pacer_needs_otp"] = bool(result.needs_otp)
            session["pacer_client_code_required"] = bool(result.needs_client_code)
            session["pacer_redaction_required"] = bool(result.needs_redaction_ack)
            status = "error"
            if result.needs_otp:
                status = "needs_otp"
            elif result.needs_client_code:
                status = "needs_client_code"
            elif result.needs_redaction_ack:
                status = "redaction_required"
            if wants_json:
                return jsonify(
                    {
                        "authorized": False,
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": status,
                    }
                )
            error_description = result.error_description or "PACER authentication failed."
            login_result = result.login_result or "unknown"
            flash(f"{error_description} (loginResult: {login_result})", "error")
            if login_result == "13" and not otp_code:
                flash(
                    "If your PACER account is enrolled in MFA, a one time passcode (2FA code) is required.",
                    "error",
                )
            if result.needs_redaction_ack:
                flash(
                    "PACER requires filer accounts to acknowledge the redaction rules. Confirm the acknowledgement and try again.",
                    "error",
                )

        return redirect(redirect_target)

    @app.post("/admin/federal-data-dashboard/pacer-logout")
    @admin_required
    def admin_federal_data_dashboard_pacer_logout():
        require_csrf()
        _clear_pacer_session()
        session["pacer_needs_otp"] = False
        session["pacer_client_code_required"] = False
        session["pacer_redaction_required"] = False
        session["pacer_redaction_acknowledged"] = False
        flash("PACER session cleared.", "success")
        return redirect(url_for("admin_federal_data_dashboard_get_pacer_data"))

    def _render_federal_data_placeholder(
        page_title: str, active_subnav: Optional[str] = None
    ):
        return render_template(
            "admin_federal_data_placeholder.html",
            active_page="federal_data_dashboard",
            active_subnav=active_subnav,
            page_title=page_title,
        )

    @app.get("/admin/federal-data-dashboard/case-cards")
    @admin_required
    def admin_federal_data_dashboard_case_cards():
        return _render_federal_data_placeholder("Case Cards", "case_cards")

    @app.get("/admin/federal-data-dashboard/logs")
    @admin_required
    def admin_federal_data_dashboard_logs():
        return _render_federal_data_placeholder("Logs", "logs")

    @app.get("/admin/federal-data-dashboard/health-checks")
    @admin_required
    def admin_federal_data_dashboard_health_checks():
        return _render_federal_data_placeholder("Health Checks", "health_checks")

    @app.get("/admin/federal-data-dashboard/configure-ask-loulou")
    @admin_required
    def admin_federal_data_dashboard_configure_ask_loulou():
        return _render_federal_data_placeholder("Configure Ask LouLou", "configure_ask_loulou")

    @app.get("/admin/federal-data-dashboard/pcl-batch-search")
    @admin_required
    def admin_federal_data_dashboard_pcl_batch_search():
        pcl_batch_requests = pcl_tables["pcl_batch_requests"]
        pcl_batch_segments = pcl_tables["pcl_batch_segments"]
        with engine.connect() as conn:
            batch_rows = (
                conn.execute(select(pcl_batch_requests).order_by(pcl_batch_requests.c.id.desc()))
                .mappings()
                .all()
            )
            segment_rows = (
                conn.execute(select(pcl_batch_segments).order_by(pcl_batch_segments.c.id.asc()))
                .mappings()
                .all()
            )
        segments_by_batch: Dict[int, List[Dict[str, Any]]] = {}
        for row in segment_rows:
            segments_by_batch.setdefault(row["batch_request_id"], []).append(row)
        return render_template(
            "admin_pcl_batch_search.html",
            active_page="federal_data_dashboard",
            active_subnav="get_pacer_data",
            batch_requests=batch_rows,
            segments_by_batch=segments_by_batch,
            csrf_token=get_csrf_token(),
            pcl_base_url=pcl_base_url,
        )

    @app.post("/admin/federal-data-dashboard/pcl-batch-search/create")
    @admin_required
    def admin_federal_data_dashboard_pcl_batch_search_create():
        require_csrf()
        court_id = (request.form.get("court_id") or "").strip()
        date_from = (request.form.get("date_filed_from") or "").strip()
        date_to = (request.form.get("date_filed_to") or "").strip()
        case_types = request.form.getlist("case_types")
        if not court_id or not date_from or not date_to:
            flash("Court ID and date range are required.", "error")
            return redirect(url_for("admin_federal_data_dashboard_pcl_batch_search"))
        try:
            date_filed_from = datetime.fromisoformat(date_from).date()
            date_filed_to = datetime.fromisoformat(date_to).date()
        except ValueError:
            flash("Invalid date format. Use YYYY-MM-DD.", "error")
            return redirect(url_for("admin_federal_data_dashboard_pcl_batch_search"))
        planner = PclBatchPlanner(engine, pcl_tables)
        batch_id = planner.create_batch_request(
            court_id=court_id,
            date_filed_from=date_filed_from,
            date_filed_to=date_filed_to,
            case_types=case_types or ["cr"],
        )
        flash(f"PCL batch request {batch_id} created.", "success")
        return redirect(url_for("admin_federal_data_dashboard_pcl_batch_search"))

    @app.post("/admin/federal-data-dashboard/pcl-batch-search/run")
    @admin_required
    def admin_federal_data_dashboard_pcl_batch_search_run():
        require_csrf()
        max_segments = request.form.get("max_segments", "1").strip()
        try:
            max_segments_int = max(1, int(max_segments))
        except ValueError:
            max_segments_int = 1

        def _run_worker() -> None:
            worker = PclBatchWorker(
                engine,
                pcl_tables,
                pcl_client,
                logger=app.logger,
                sleep_fn=time.sleep,
            )
            worker.run_once(max_segments=max_segments_int)

        threading.Thread(target=_run_worker, daemon=True).start()
        flash("PCL batch worker started.", "success")
        return redirect(url_for("admin_federal_data_dashboard_pcl_batch_search"))

    def _parse_include_docket_text(value: Optional[str]) -> bool:
        if value is None:
            return False
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def _enqueue_docket_enrichment(case_id: int, include_docket_text: bool) -> int:
        job_table = pcl_tables["docket_enrichment_jobs"]
        with engine.begin() as conn:
            result = conn.execute(
                insert(job_table).values(
                    case_id=case_id,
                    include_docket_text=include_docket_text,
                    status="queued",
                    attempts=0,
                    last_error=None,
                )
            )
        return int(result.inserted_primary_key[0])

    def _load_docket_dashboard_rows(limit: int = 200) -> List[Dict[str, Any]]:
        job_table = pcl_tables["docket_enrichment_jobs"]
        receipt_table = pcl_tables["docket_enrichment_receipts"]
        pcl_cases = pcl_tables["pcl_cases"]

        stmt = (
            select(
                job_table.c.id,
                job_table.c.case_id,
                job_table.c.include_docket_text,
                job_table.c.status,
                job_table.c.attempts,
                job_table.c.last_error,
                job_table.c.created_at,
                job_table.c.updated_at,
                job_table.c.started_at,
                job_table.c.finished_at,
                pcl_cases.c.court_id,
                pcl_cases.c.case_number,
                pcl_cases.c.case_number_full,
                pcl_cases.c.short_title,
                pcl_cases.c.case_title,
                pcl_cases.c.case_type,
                func.count(receipt_table.c.id).label("receipt_count"),
                func.sum(receipt_table.c.fee).label("total_fee"),
                func.sum(receipt_table.c.billable_pages).label("total_billable_pages"),
                func.max(receipt_table.c.created_at).label("last_receipt_at"),
            )
            .select_from(
                job_table.join(pcl_cases, pcl_cases.c.id == job_table.c.case_id).outerjoin(
                    receipt_table, receipt_table.c.job_id == job_table.c.id
                )
            )
            .group_by(job_table.c.id, pcl_cases.c.id)
            .order_by(desc(job_table.c.created_at), desc(job_table.c.id))
            .limit(limit)
        )

        with engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [dict(row) for row in rows]

    def _load_docket_status_counts() -> Dict[str, int]:
        job_table = pcl_tables["docket_enrichment_jobs"]
        stmt = select(job_table.c.status, func.count().label("count")).group_by(job_table.c.status)
        counts: Dict[str, int] = {}
        with engine.begin() as conn:
            for row in conn.execute(stmt):
                counts[str(row.status)] = int(row.count)
        return counts

    @app.get("/admin/pcl/cases")
    @admin_required
    def admin_pcl_cases():
        filters, page, page_size = parse_filters(request.args.to_dict(flat=True))
        result = list_cases(engine, pcl_tables, filters, page=page, page_size=page_size)

        params = request.args.to_dict(flat=True)

        def page_url(target_page: int) -> str:
            next_params = dict(params)
            next_params["page"] = target_page
            return url_for("admin_pcl_cases", **next_params)

        return render_template(
            "admin_pcl_cases.html",
            active_page="federal_data_dashboard",
            active_subnav="pcl_cases",
            cases=result.rows,
            pagination=result.pagination,
            filters=filters,
            page_url=page_url,
            available_courts=result.available_courts,
            available_case_types=result.available_case_types,
        )

    @app.post("/admin/pcl/cases/<int:case_id>/docket-enrichment/queue")
    @admin_required
    def admin_pcl_case_queue_docket_enrichment(case_id: int):
        require_csrf()
        detail = get_case_detail(engine, pcl_tables, case_id)
        if not detail:
            abort(404)

        include_docket_text = _parse_include_docket_text(request.form.get("include_docket_text"))
        job_id = _enqueue_docket_enrichment(case_id, include_docket_text)

        estimate = detail.get("docket_estimate", {}).get("by_include_docket_text", {}).get(
            include_docket_text
        )
        if estimate and estimate.get("receipt_count"):
            fee_value = estimate.get("avg_fee")
            fee_display = (
                f"${fee_value:.2f}" if isinstance(fee_value, (int, float)) else "unknown"
            )
            flash(
                f"Queued docket enrichment job {job_id}. Estimated cost: {fee_display} based on {estimate['receipt_count']} receipts.",
                "success",
            )
        else:
            flash(
                f"Queued docket enrichment job {job_id}. Estimated cost is unknown (no historical receipts yet).",
                "success",
            )

        return redirect(url_for("admin_pcl_case_detail", case_id=case_id))

    @app.get("/admin/pcl/cases/<int:case_id>")
    @admin_required
    def admin_pcl_case_detail(case_id: int):
        detail = get_case_detail(engine, pcl_tables, case_id)
        if not detail:
            abort(404)
        return render_template(
            "admin_pcl_case_detail.html",
            active_page="federal_data_dashboard",
            active_subnav="pcl_cases",
            case_detail=detail,
        )

    @app.get("/admin/pcl/cases/<int:case_id>/sentencing-events/new")
    @admin_required
    def admin_sentencing_event_new(case_id: int):
        detail = get_case_detail(engine, pcl_tables, case_id)
        if not detail:
            abort(404)
        judge_choices = _load_sentencing_judge_choices()
        return render_template(
            "admin_sentencing_event_form.html",
            active_page="federal_data_dashboard",
            active_subnav="sentencing_events",
            case_detail=detail,
            judge_choices=judge_choices,
            variance_types=VALID_VARIANCE_TYPES,
            evidence_source_types=VALID_EVIDENCE_SOURCE_TYPES,
            form_values={},
        )

    @app.post("/admin/pcl/cases/<int:case_id>/sentencing-events")
    @admin_required
    def admin_sentencing_event_create(case_id: int):
        require_csrf()
        detail = get_case_detail(engine, pcl_tables, case_id)
        if not detail:
            abort(404)

        sentencing_events = pcl_tables["sentencing_events"]
        sentencing_evidence = pcl_tables["sentencing_evidence"]

        sentencing_date = _parse_iso_date(request.form.get("sentencing_date"))
        sentence_months = _parse_optional_int(request.form.get("sentence_months"))
        guideline_low = _parse_optional_int(request.form.get("guideline_range_low"))
        guideline_high = _parse_optional_int(request.form.get("guideline_range_high"))
        offense_level = _parse_optional_int(request.form.get("offense_level"))
        criminal_history_category = (request.form.get("criminal_history_category") or "").strip() or None
        variance_type = _normalize_variance_type(request.form.get("variance_type"))
        notes = (request.form.get("notes") or "").strip() or None
        defendant_identifier = (request.form.get("defendant_identifier") or "").strip() or None
        judge_confidence = _parse_optional_float(request.form.get("judge_confidence"))

        evidence_rows = _collect_evidence_rows(request.form)

        errors: List[str] = []
        if not sentencing_date:
            errors.append("Sentencing date is required.")
        if sentence_months is None:
            errors.append("Sentence (months) is required.")
        if guideline_low is not None and guideline_high is not None and guideline_low > guideline_high:
            errors.append("Guideline range low must be less than or equal to guideline range high.")
        if request.form.get("variance_type") and not variance_type:
            errors.append("Variance type must be one of the provided options.")
        evidence_error = _validate_evidence_rows(evidence_rows)
        if evidence_error:
            errors.append(evidence_error)

        judge_id = _get_or_create_judge_id(
            request.form.get("judge_id"),
            request.form.get("judge_name"),
            detail.get("court_id"),
        )
        if not judge_id:
            errors.append("A sentencing judge is required. Select an existing judge or enter a name.")
        if judge_confidence is not None and not (0 <= judge_confidence <= 1.0):
            errors.append("Judge confidence must be between 0 and 1.")

        if errors:
            for message in errors:
                flash(message, "error")
            judge_choices = _load_sentencing_judge_choices()
            form_values = {key: request.form.getlist(key) if key.startswith("evidence_") else request.form.get(key) for key in request.form.keys()}
            return render_template(
                "admin_sentencing_event_form.html",
                active_page="federal_data_dashboard",
                active_subnav="sentencing_events",
                case_detail=detail,
                judge_choices=judge_choices,
                variance_types=VALID_VARIANCE_TYPES,
                evidence_source_types=VALID_EVIDENCE_SOURCE_TYPES,
                form_values=form_values,
            )

        with engine.begin() as conn:
            result = conn.execute(
                insert(sentencing_events).values(
                    case_id=case_id,
                    defendant_identifier=defendant_identifier,
                    sentencing_date=sentencing_date,
                    guideline_range_low=guideline_low,
                    guideline_range_high=guideline_high,
                    offense_level=offense_level,
                    criminal_history_category=criminal_history_category,
                    sentence_months=sentence_months,
                    variance_type=variance_type,
                    notes=notes,
                )
            )
            sentencing_event_id = int(result.inserted_primary_key[0])
            conn.execute(
                insert(sentencing_evidence),
                [
                    {
                        "sentencing_event_id": sentencing_event_id,
                        "source_type": row["source_type"],
                        "source_id": row["source_id"],
                        "reference_text": row["reference_text"],
                    }
                    for row in evidence_rows
                ],
            )

        _ensure_case_sentencing_judge(case_id, judge_id, judge_confidence)
        flash("Sentencing event saved.", "success")
        return redirect(url_for("admin_pcl_case_detail", case_id=case_id))

    @app.get("/admin/sentencing-events")
    @admin_required
    def admin_sentencing_events_report():
        filters = parse_sentencing_filters(request.args)
        rows, available_courts, available_case_types = list_sentencing_events_by_judge(
            engine, pcl_tables, filters
        )
        judge_choices = _load_sentencing_judge_choices()
        return render_template(
            "admin_sentencing_events_report.html",
            active_page="federal_data_dashboard",
            active_subnav="sentencing_events",
            rows=rows,
            filters=filters,
            judge_choices=judge_choices,
            available_courts=available_courts,
            available_case_types=available_case_types,
        )

    @app.get("/admin/docket-enrichment")
    @admin_required
    def admin_docket_enrichment_dashboard():
        rows = _load_docket_dashboard_rows()
        counts = _load_docket_status_counts()
        return render_template(
            "admin_docket_enrichment.html",
            active_page="federal_data_dashboard",
            active_subnav="docket_enrichment",
            jobs=rows,
            status_counts=counts,
        )

    @app.post("/admin/docket-enrichment/run")
    @admin_required
    def admin_docket_enrichment_run():
        require_csrf()
        max_jobs = request.form.get("max_jobs", "5").strip()
        try:
            max_jobs_int = max(1, min(50, int(max_jobs)))
        except ValueError:
            flash("Enter a valid max jobs value between 1 and 50.", "error")
            return redirect(url_for("admin_docket_enrichment_dashboard"))

        def _run_worker() -> None:
            worker = DocketEnrichmentWorker(engine, pcl_tables, logger=app.logger)
            worker.run_once(max_jobs=max_jobs_int)

        threading.Thread(target=_run_worker, daemon=True).start()
        flash(
            "Docket enrichment worker started. Jobs will fail with a placeholder error until endpoints are wired.",
            "success",
        )
        return redirect(url_for("admin_docket_enrichment_dashboard"))

    @app.get("/admin/federal-data-dashboard/expand-existing")
    @admin_required
    def admin_federal_data_dashboard_expand_existing():
        return _render_federal_data_placeholder("Expand Existing PCL Data")

    @app.get("/admin/federal-data-dashboard/advanced")
    @admin_required
    def admin_federal_data_dashboard_advanced():
        return _render_federal_data_placeholder("Advanced")

    @app.get("/admin/users")
    @admin_required
    def admin_users():
        with engine.connect() as conn:
            rows = (
                conn.execute(
                    select(
                        users.c.id,
                        users.c.created_at,
                        users.c.first_name,
                        users.c.last_name,
                        users.c.email,
                        users.c.user_type,
                    ).order_by(users.c.created_at.desc())
                )
                .mappings()
                .all()
            )
        return render_template("admin_users.html", users=rows)

    @app.get("/admin/newsletter")
    @admin_required
    def admin_newsletter():
        with engine.connect() as conn:
            rows = (
                conn.execute(
                    select(newsletter_subscriptions)
                    .order_by(newsletter_subscriptions.c.created_at.desc())
                    .limit(200)
                )
                .mappings()
                .all()
            )
        return render_template("admin_newsletter.html", subscriptions=rows)

    @app.get("/admin/case-stage1/upload")
    @admin_required
    def admin_case_stage1_upload():
        return render_template("admin_case_stage1_upload.html")

    @app.post("/admin/case-stage1/upload")
    @admin_required
    def admin_case_stage1_upload_post():
        require_csrf()

        if request.content_length and request.content_length > CASE_STAGE1_MAX_UPLOAD_BYTES:
            flash("File too large. Maximum size is 25MB.", "error")
            return redirect(url_for("admin_case_stage1_upload"))

        uploaded = request.files.get("case_stage1_file")
        if not uploaded or not uploaded.filename:
            flash("Please select a file to upload.", "error")
            return redirect(url_for("admin_case_stage1_upload"))
        if not uploaded.filename.lower().endswith((".txt", ".csv")):
            flash("Only .txt or .csv files are supported.", "error")
            return redirect(url_for("admin_case_stage1_upload"))

        suffix = Path(uploaded.filename).suffix or ".txt"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            uploaded.save(temp_file.name)
            temp_path = temp_file.name

        job_id = secrets.token_urlsafe(8)
        case_stage1_imports["latest"] = job_id
        _set_case_stage1_import(
            job_id,
            status="processing",
            started_at=datetime.utcnow().isoformat(),
            original_filename=uploaded.filename,
            message="Upload started. Processing in the background.",
        )

        thread = threading.Thread(
            target=_process_case_stage1_upload, args=(job_id, temp_path), daemon=True
        )
        thread.start()

        flash("Upload started. Processing in the background.", "success")
        return redirect(url_for("admin_case_stage1_list"))

    @app.get("/admin/case-stage1")
    @admin_required
    def admin_case_stage1_list():
        return render_template(
            "admin_case_stage1_list.html", columns=CASE_STAGE1_DISPLAY_COLUMNS
        )

    @app.get("/admin/case-stage1/data")
    @admin_required
    def admin_case_stage1_data():
        case_stage1_table = case_stage1
        columns = CASE_STAGE1_DISPLAY_COLUMNS
        draw = int(request.args.get("draw", 1))
        start = max(int(request.args.get("start", 0)), 0)
        length = min(int(request.args.get("length", 25)), 200)
        search_value = request.args.get("search[value]", "").strip()

        order_col_index = request.args.get("order[0][column]", "0")
        order_dir = request.args.get("order[0][dir]", "asc")
        try:
            order_index = int(order_col_index)
        except ValueError:
            order_index = 0
        order_column_name = columns[order_index] if order_index < len(columns) else "cs_caseid"
        order_column = case_stage1_table.c.get(order_column_name, case_stage1_table.c.cs_caseid)

        selected_columns = [case_stage1_table.c[name] for name in columns]
        base_query = select(*selected_columns)

        if search_value:
            if _is_postgres():
                search_filter = func.to_tsvector(
                    "english", func.coalesce(case_stage1_table.c.search_text, "")
                ).op("@@")(func.plainto_tsquery("english", search_value))
            else:
                like_term = f"%{search_value.lower()}%"
                search_filter = func.lower(
                    func.coalesce(case_stage1_table.c.search_text, "")
                ).like(like_term)
            base_query = base_query.where(search_filter)
            count_query = select(func.count()).select_from(case_stage1_table).where(search_filter)
        else:
            count_query = select(func.count()).select_from(case_stage1_table)

        if search_value:
            if order_dir == "desc":
                base_query = base_query.order_by(order_column.desc())
            else:
                base_query = base_query.order_by(order_column.asc())
        else:
            base_query = base_query.order_by(case_stage1_table.c.cs_caseid.desc())

        base_query = base_query.limit(length).offset(start)

        with engine.connect() as conn:
            records_total = conn.execute(
                select(func.count()).select_from(case_stage1_table)
            ).scalar_one()
            if search_value:
                records_filtered = conn.execute(count_query).scalar_one()
            else:
                records_filtered = records_total
            rows = conn.execute(base_query).mappings().all()

        return jsonify(
            {
                "draw": draw,
                "recordsTotal": records_total,
                "recordsFiltered": records_filtered,
                "data": [dict(row) for row in rows],
            }
        )

    @app.get("/admin/case-data-one/upload")
    @admin_required
    def admin_case_data_one_upload():
        return render_template("admin_case_data_one_upload.html")

    @app.post("/admin/case-data-one/upload")
    @admin_required
    def admin_case_data_one_upload_post():
        require_csrf()

        if request.content_length and request.content_length > CASE_DATA_ONE_MAX_UPLOAD_BYTES:
            flash("File too large. Maximum size is 25MB.", "error")
            return redirect(url_for("admin_case_data_one_upload"))

        uploaded = request.files.get("case_data_one_file")
        if not uploaded or not uploaded.filename:
            flash("Please select a file to upload.", "error")
            return redirect(url_for("admin_case_data_one_upload"))
        if not uploaded.filename.lower().endswith((".txt", ".csv")):
            flash("Only .txt or .csv files are supported.", "error")
            return redirect(url_for("admin_case_data_one_upload"))

        suffix = Path(uploaded.filename).suffix or ".txt"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            uploaded.save(temp_file.name)
            temp_path = temp_file.name

        job_id = secrets.token_urlsafe(8)
        case_data_one_imports["latest"] = job_id
        _set_case_data_one_import(
            job_id,
            status="processing",
            started_at=datetime.utcnow().isoformat(),
            original_filename=uploaded.filename,
            message="Upload started. Processing in the background.",
            total_rows=0,
            processed_rows=0,
            inserted_rows=0,
            updated_rows=0,
            skipped_rows=0,
            error_rows=0,
            error_details=[],
        )

        thread = threading.Thread(
            target=_process_case_data_one_upload, args=(job_id, temp_path), daemon=True
        )
        thread.start()

        flash("Upload started. Processing in the background.", "success")
        return redirect(url_for("admin_case_data_one_upload"))

    @app.get("/admin/case-data-one")
    @admin_required
    def admin_case_data_one_list():
        return render_template(
            "admin_case_data_one_list.html", columns=CASE_DATA_ONE_CARD_FIELDS
        )

    @app.get("/admin/case-data-one/data")
    @admin_required
    def admin_case_data_one_data():
        case_data_one_table = case_data_one
        columns = CASE_DATA_ONE_CARD_FIELDS
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 12)), 1), 100)
        search_value = request.args.get("search", "").strip()
        case_type = request.args.get("case_type", "").strip().lower()
        party_role = request.args.get("party_role", "").strip().lower()
        party_type = request.args.get("party_type", "").strip().lower()
        case_year = request.args.get("case_year", "").strip()
        offset = (page - 1) * per_page

        selected_columns = [case_data_one_table.c[name] for name in columns]
        base_query = select(*selected_columns)
        search_expression = _case_data_one_search_text_expression(case_data_one_table)
        filters = []

        if case_type:
            filters.append(case_data_one_table.c.cs_type_normalized == case_type)
        if party_role:
            filters.append(case_data_one_table.c.party_role_normalized == party_role)
        if party_type:
            filters.append(case_data_one_table.c.party_type_normalized == party_type)
        if case_year:
            filters.append(case_data_one_table.c.cs_case_year == case_year)

        if search_value:
            if _is_postgres():
                search_filter = func.to_tsvector("english", search_expression).op("@@")(
                    func.plainto_tsquery("english", search_value)
                )
            else:
                like_term = f"%{search_value.lower()}%"
                search_filter = func.lower(search_expression).like(like_term)
            filters.append(search_filter)

        if filters:
            base_query = base_query.where(*filters)
            count_query = (
                select(func.count()).select_from(case_data_one_table).where(*filters)
            )
        else:
            count_query = select(func.count()).select_from(case_data_one_table)

        base_query = base_query.order_by(case_data_one_table.c.cs_caseid.desc())
        base_query = base_query.limit(per_page).offset(offset)

        with engine.connect() as conn:
            records_total = conn.execute(
                select(func.count()).select_from(case_data_one_table)
            ).scalar_one()
            if search_value:
                records_filtered = conn.execute(count_query).scalar_one()
            else:
                records_filtered = records_total
            rows = conn.execute(base_query).mappings().all()

        total_pages = max(1, (records_filtered + per_page - 1) // per_page)
        return jsonify(
            {
                "page": page,
                "per_page": per_page,
                "recordsTotal": records_total,
                "recordsFiltered": records_filtered,
                "totalPages": total_pages,
                "data": [dict(row) for row in rows],
            }
        )

    @app.get("/admin/case-data-one/import-status")
    @admin_required
    def admin_case_data_one_import_status():
        latest = _latest_case_data_one_import()
        if not latest:
            return jsonify({"status": "idle"})
        return jsonify(latest)

    @app.post("/admin/case-data-one/error-prompt")
    @admin_required
    def admin_case_data_one_error_prompt():
        require_csrf()
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON payload required."}), 400

        prompt = _build_case_data_one_error_prompt(payload)
        try:
            response_text = _call_openai_chat_completion(prompt)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 502

        model = os.environ.get("OPENAI_MODEL", "gpt-5.2")
        return jsonify({"response": response_text, "model": model})

    @app.get("/admin/case-data-one/error-report")
    @admin_required
    def admin_case_data_one_error_report():
        latest = _latest_case_data_one_import()
        if not latest:
            return jsonify({"error": "No import found."}), 404
        if not latest.get("error_rows"):
            return jsonify({"error": "No errors were recorded."}), 404

        report_text = _build_case_data_one_error_report_text(latest)
        return (
            report_text,
            200,
            {
                "Content-Type": "text/plain; charset=utf-8",
                "Content-Disposition": (
                    "attachment; filename=case-data-one-import-errors.txt"
                ),
            },
        )

    @app.get("/admin/case-stage1/import-status")
    @admin_required
    def admin_case_stage1_import_status():
        latest = _latest_case_stage1_import()
        if not latest:
            return jsonify({"status": "idle"})
        return jsonify(latest)

    @app.post("/admin/logout")
    def admin_logout():
        require_csrf()
        session.pop("is_admin", None)
        flash("Admin logged out.", "success")
        return redirect(url_for("home"))

    # -----------------
    # Existing API (kept), with a safety blocklist
    # -----------------

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok"})

    @app.route("/api/tables")
    def list_tables():
        metadata.reflect(bind=engine)
        # Do not reveal protected tables.
        tables = [
            t
            for t in metadata.tables.keys()
            if t.lower()
            not in {"users", "newsletter_subscriptions", "case_stage1", "case_data_one"}
        ]
        return jsonify(sorted(tables))

    @app.route("/api/<table_name>", methods=["GET", "POST"])
    def table_records(table_name: str):
        if table_name.lower() in {"users", "newsletter_subscriptions", "case_stage1", "case_data_one"}:
            return jsonify({"error": "Forbidden"}), 403

        try:
            table = load_table(table_name)
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 404

        if request.method == "POST":
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify({"error": "JSON object payload required"}), 400
            with engine.begin() as conn:
                result = conn.execute(insert(table).values(**payload))
                inserted_pk = result.inserted_primary_key
            return jsonify({"inserted_primary_key": inserted_pk}), 201

        limit = min(int(request.args.get("limit", 100)), 1000)
        offset = max(int(request.args.get("offset", 0)), 0)
        stmt = select(table).limit(limit).offset(offset)
        with engine.connect() as conn:
            rows = [dict(row._mapping) for row in conn.execute(stmt)]
        return jsonify({"rows": rows, "limit": limit, "offset": offset})

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
