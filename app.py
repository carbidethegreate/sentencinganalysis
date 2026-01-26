import csv
import io
import json
import hmac
import math
import os
import re
import secrets
import time
import tempfile
import threading
import traceback
import urllib.error
import urllib.request
import hashlib
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import quote_plus

import requests
from flask import (
    Flask,
    abort,
    flash,
    g,
    has_request_context,
    jsonify,
    make_response,
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
    tuple_,
    update,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, insert as pg_insert
from sqlalchemy import text as sa_text
from sqlalchemy.exc import (
    IntegrityError,
    NoSuchTableError,
    OperationalError,
    ProgrammingError,
    SQLAlchemyError,
)
from werkzeug.security import check_password_hash, generate_password_hash

from pacer_http import PacerHttpClient, TokenExpired
from pacer_logging import redact_tokens
from pacer_tokens import (
    DatabaseTokenBackend,
    InMemoryTokenBackend,
    PacerTokenRecord,
    PacerTokenStore,
    build_pacer_token_table,
    token_fingerprint,
)
from pacer_env import (
    DEFAULT_PACER_AUTH_BASE_URL,
    DEFAULT_PACER_AUTH_BASE_URL_PROD,
    DEFAULT_PCL_BASE_URL,
    DEFAULT_PCL_BASE_URL_PROD,
    ENV_PROD,
    ENV_QA,
    infer_pacer_env,
    pacer_env_billable,
    pacer_env_host,
    pacer_env_label,
    build_pacer_environment_config,
    validate_pacer_environment_config,
)
from docket_enrichment import DocketEnrichmentWorker
from pcl_batch import CRIMINAL_CASE_TYPES, PclBatchPlanner, PclBatchWorker
from pcl_client import PclApiError, PclClient, PclJsonResponse
from pcl_models import build_pcl_tables
from sentencing_models import (
    VALID_EVIDENCE_SOURCE_TYPES,
    VALID_VARIANCE_TYPES,
    build_sentencing_tables,
)
from pacer_explore_schemas import (
    build_case_search_payload,
    build_party_search_payload,
    collect_ui_inputs,
    validate_pcl_payload,
    validate_ui_inputs,
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
PCL_CRIMINAL_CASE_TYPES = [
    case_type
    for case_type in ("cr", "crim", "ncrim", "dcrim")
    if case_type in CRIMINAL_CASE_TYPES
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
    host = _first_env_or_secret_file("Hostname", "DB_HOST")
    port = _first_env_or_secret_file("Port", "DB_PORT")
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
    search_disabled: bool
    search_disabled_reason: Optional[str]
    can_proceed: bool


def _normalize_pacer_base_url(base_url: str) -> str:
    normalized = (base_url or "").strip()
    return normalized[:-1] if normalized.endswith("/") else normalized


def get_configured_pacer_credentials() -> Tuple[Optional[str], Optional[str]]:
    login_id = _first_env_or_secret_file("puser")
    password = _first_env_or_secret_file("ppass")
    return login_id, password


def pacer_environment_label(base_url: str) -> str:
    return pacer_env_label(infer_pacer_env(base_url))


def pacer_environment_notice(base_url: str) -> Optional[str]:
    env = infer_pacer_env(base_url)
    if env == "qa":
        return "QA environment selected, requires a QA PACER account."
    if env == "prod":
        return "Production environment selected, billable searches may apply."
    return "Custom PACER environment configured; verify credentials and billing details."


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
    token_present = bool(login_result == "0" and token)
    search_disabled = False
    search_disabled_reason = None
    can_proceed = bool(token_present and (search_disabled or not error_description))
    return PacerAuthResult(
        token=token if can_proceed else "",
        error_description=error_description,
        login_result=login_result,
        needs_otp=needs_otp,
        needs_client_code=needs_client_code,
        needs_redaction_ack=needs_redaction_ack,
        search_disabled=search_disabled,
        search_disabled_reason=search_disabled_reason,
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
    pcl_courts = pcl_tables["pcl_courts"]

    # Create the users/newsletter/case_stage1/case_data_one tables if they don't exist.
    bootstrap_setting = os.environ.get("DB_BOOTSTRAP", "true").strip().lower()
    if bootstrap_setting not in {"0", "false", "no"}:
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
        except (OperationalError, ProgrammingError) as exc:
            message = str(exc).lower()
            if "already exists" in message or "duplicate" in message:
                app.logger.warning("Database tables already exist; skipping create_all.")
            else:
                raise
    else:
        app.logger.info("DB_BOOTSTRAP disabled; skipping create_all.")

    def _ensure_table_columns(
        table_name: str, column_specs: Dict[str, str], *, label: str
    ) -> None:
        try:
            inspector = inspect(engine)
            if not inspector.has_table(table_name):
                app.logger.info("Skipping %s column check; table is missing.", label)
                return
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
        "pacer_search_runs",
        {
            "cases_inserted": "INTEGER",
            "cases_updated": "INTEGER",
            "parties_inserted": "INTEGER",
            "parties_updated": "INTEGER",
        },
        label="pacer_search_runs",
    )
    _ensure_table_columns(
        "pacer_tokens",
        {"environment": "VARCHAR(20)"},
        label="pacer_tokens",
    )
    _ensure_table_columns(
        "pcl_cases",
        {
            "case_id": "VARCHAR(120)",
            "case_number_full": "TEXT",
            "date_closed": "DATE",
            "effective_date_closed": "DATE",
            "case_title": "TEXT",
            "case_link": "TEXT",
            "case_year": "VARCHAR(10)",
            "case_office": "VARCHAR(20)",
            "judge_last_name": "VARCHAR(80)",
            "record_hash": "VARCHAR(128)",
            "last_segment_id": "INTEGER",
            "source_last_seen_at": "TIMESTAMP",
        },
        label="pcl_cases",
    )
    _ensure_table_columns(
        "pcl_case_result_raw",
        {
            "court_id": "VARCHAR(50)",
            "case_number": "TEXT",
            "ingested_at": "TIMESTAMP",
        },
        label="pcl_case_result_raw",
    )
    _ensure_table_columns(
        "pcl_batch_segments",
        {
            "batch_search_id": "INTEGER",
            "segment_from": "DATE",
            "segment_to": "DATE",
            "attempts": "INTEGER",
            "last_error": "TEXT",
        },
        label="pcl_batch_segments",
    )

    def _ensure_indexes(
        statements: Dict[str, str], *, label: str, required_tables: Optional[Set[str]] = None
    ) -> None:
        try:
            if required_tables:
                inspector = inspect(engine)
                existing_tables = set(inspector.get_table_names())
                missing_tables = required_tables - existing_tables
                if missing_tables:
                    app.logger.warning(
                        "Skipping %s indexes; missing tables: %s",
                        label,
                        ", ".join(sorted(missing_tables)),
                    )
                    return
            with engine.begin() as conn:
                for statement in statements.values():
                    conn.execute(sa_text(statement))
        except Exception:
            app.logger.exception("Unable to ensure %s indexes.", label)

    _ensure_indexes(
        {
            "ix_pcl_cases_court_date": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_court_date ON pcl_cases (court_id, date_filed)",
            "ix_pcl_cases_case_type": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_case_type ON pcl_cases (case_type)",
            "ix_pcl_cases_judge_last_name": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_judge_last_name ON pcl_cases (judge_last_name)",
            "ix_pcl_cases_court_case_number_full": "CREATE INDEX IF NOT EXISTS ix_pcl_cases_court_case_number_full ON pcl_cases (court_id, case_number_full)",
            "ix_pcl_case_result_raw_court_case": "CREATE INDEX IF NOT EXISTS ix_pcl_case_result_raw_court_case ON pcl_case_result_raw (court_id, case_number)",
        },
        label="pcl",
    )
    if engine.dialect.name == "sqlite":
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
            required_tables={
                "judges",
                "case_judges",
                "sentencing_events",
                "sentencing_evidence",
            },
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
        try:
            with engine.begin() as conn:
                constraint_exists = conn.execute(
                    sa_text(
                        "SELECT 1 FROM pg_constraint WHERE conname = 'ck_pcl_cases_case_type'"
                    )
                ).scalar()
                if not constraint_exists:
                    conn.execute(
                        sa_text(
                            "ALTER TABLE pcl_cases ADD CONSTRAINT ck_pcl_cases_case_type CHECK (case_type in ('cr','crim','ncrim','dcrim'))"
                        )
                    )
        except Exception:
            app.logger.exception("Unable to ensure pcl case type constraint.")

    case_stage1_imports: Dict[str, Dict[str, Any]] = {}
    case_data_one_imports: Dict[str, Dict[str, Any]] = {}
    pacer_auth_base_url_env = os.environ.get("PACER_AUTH_BASE_URL")
    pcl_base_url_env = os.environ.get("PCL_BASE_URL")
    pacer_auth_base_url = _normalize_pacer_base_url(
        pacer_auth_base_url_env or DEFAULT_PACER_AUTH_BASE_URL
    )
    pcl_base_url_candidate = _normalize_pacer_base_url(
        pcl_base_url_env or DEFAULT_PCL_BASE_URL
    )
    if not pacer_auth_base_url_env and pcl_base_url_candidate:
        inferred_env = infer_pacer_env(pcl_base_url_candidate)
        if inferred_env == ENV_PROD:
            pacer_auth_base_url = DEFAULT_PACER_AUTH_BASE_URL_PROD
        elif inferred_env == ENV_QA:
            pacer_auth_base_url = DEFAULT_PACER_AUTH_BASE_URL
    if not pcl_base_url_env and pacer_auth_base_url:
        inferred_env = infer_pacer_env(pacer_auth_base_url)
        if inferred_env == ENV_PROD:
            pcl_base_url_candidate = DEFAULT_PCL_BASE_URL_PROD
        elif inferred_env == ENV_QA:
            pcl_base_url_candidate = DEFAULT_PCL_BASE_URL
    try:
        pacer_env_config = validate_pacer_environment_config(
            pacer_auth_base_url,
            pcl_base_url_candidate,
        )
    except ValueError as exc:
        app.logger.error("PACER environment mismatch: %s", exc)
        pacer_env_config = build_pacer_environment_config(
            pacer_auth_base_url,
            pcl_base_url_candidate,
        )
    pacer_auth_env = pacer_env_config.auth_env
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
    app.pcl_courts_table = pcl_courts

    pcl_base_url = pacer_env_config.pcl_base_url
    app.config["PACER_ENV_CONFIG"] = pacer_env_config.as_dict()
    app.config["PACER_ENV_MISMATCH"] = pacer_env_config.mismatch
    app.config["PACER_ENV_MISMATCH_REASON"] = pacer_env_config.mismatch_reason
    def _refresh_pacer_token() -> Optional[str]:
        if not has_request_context():
            return None
        login_id, password = get_configured_pacer_credentials()
        if not login_id or not password:
            return None
        session_key = session.get("pacer_session_key")
        if not session_key:
            session_key = secrets.token_urlsafe(16)
            session["pacer_session_key"] = session_key
        pacer_token_store.initialize_session(session_key)
        try:
            result = pacer_auth_client.authenticate(
                login_id,
                password,
                redact_flag=True,
            )
        except ValueError:
            return None
        if not result.can_proceed or not result.token:
            return None
        pacer_token_store.save_token(
            result.token,
            obtained_at=datetime.utcnow(),
            environment=pacer_auth_env,
        )
        session["pacer_needs_otp"] = bool(result.needs_otp)
        session["pacer_client_code_required"] = bool(result.needs_client_code)
        session["pacer_redaction_required"] = bool(result.needs_redaction_ack)
        session["pacer_search_disabled"] = bool(result.search_disabled)
        session["pacer_search_disabled_reason"] = result.search_disabled_reason
        return result.token

    pcl_http_client = PacerHttpClient(
        pacer_token_store,
        logger=app.logger,
        expected_environment=pacer_env_config.pcl_env,
        env_mismatch_reason=pacer_env_config.mismatch_reason if pacer_env_config.mismatch else None,
        token_refresher=_refresh_pacer_token,
    )
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
            "authorized_at": record.obtained_at.isoformat(),
            "environment": record.environment,
        }

    def _token_diagnostics(record: Optional[PacerTokenRecord]) -> Dict[str, Any]:
        fingerprint = token_fingerprint(record.token if record else None)
        environment = record.environment if record else None
        return {
            **fingerprint,
            "environment": environment,
            "environment_label": pacer_env_label(environment or "unknown"),
        }

    def _set_pacer_session(token: str) -> None:
        session_key = session.get("pacer_session_key")
        if not session_key:
            session_key = secrets.token_urlsafe(16)
            session["pacer_session_key"] = session_key
        pacer_token_store.initialize_session(session_key)
        pacer_token_store.save_token(
            token, obtained_at=datetime.utcnow(), environment=pacer_auth_env
        )

    def _clear_pacer_session() -> None:
        pacer_token_store.clear_token()

    def _pacer_token_matches_pcl() -> bool:
        record = pacer_token_store.get_token()
        if not record:
            return False
        expected_env = pacer_env_config.pcl_env
        if expected_env:
            return record.environment == expected_env
        return True

    def _pacer_token_mismatch_message(record_env: Optional[str]) -> str:
        expected_env = pacer_env_config.pcl_env
        expected_label = pacer_env_label(expected_env)
        record_label = pacer_env_label(record_env or "unknown")
        if record_env:
            return (
                f"PACER token is scoped to {record_label} but PCL is configured for "
                f"{expected_label}. Re-authorize in the correct environment."
            )
        return (
            f"PACER token environment is unknown while PCL is configured for {expected_label}. "
            "Re-authorize in the correct environment."
        )

    def _pacer_search_disabled() -> bool:
        return bool(session.get("pacer_search_disabled"))

    def _pacer_search_enabled() -> bool:
        if app.config.get("PACER_ENV_MISMATCH"):
            return False
        return _pacer_token_matches_pcl() and not _pacer_search_disabled()

    # Immediate PCL searches always return 54 records per page; pageSize is not valid in /cases/find.
    PCL_PAGE_SIZE = 54
    PCL_EXPLORE_DEFAULT_MAX_RECORDS = 54
    PCL_IMMEDIATE_MAX_PAGES = 100
    PCL_BATCH_MAX_PAGES = 2000
    PCL_BATCH_MAX_RECORDS = PCL_PAGE_SIZE * PCL_BATCH_MAX_PAGES
    PCL_EXPLORE_RUN_RETENTION = 200
    PCL_CASE_TYPES = [
        ("cv", "Civil (cv)"),
        ("cr", "Criminal (cr)"),
        ("bk", "Bankruptcy (bk)"),
        ("ap", "Appellate (ap)"),
    ]

    def _build_pacer_explore_defaults() -> Tuple[Dict[str, Any], Dict[str, Any]]:
        case_defaults = {
            "search_mode": "immediate",
            "date_filed_from": "",
            "date_filed_to": "",
            "court_id": "",
            "page": 1,
            "max_records": PCL_EXPLORE_DEFAULT_MAX_RECORDS,
            "case_types": [],
        }
        party_defaults = {
            "search_mode": "immediate",
            "last_name": "",
            "exact_name_match": False,
            "first_name": "",
            "ssn": "",
            "date_filed_from": "",
            "date_filed_to": "",
            "court_id": "",
            "page": 1,
            "max_records": PCL_EXPLORE_DEFAULT_MAX_RECORDS,
        }
        return case_defaults, party_defaults

    def _render_pacer_explore_with_result(
        *,
        mode: str,
        case_values: Optional[Dict[str, Any]],
        party_values: Optional[Dict[str, Any]],
        run_result: Optional[Dict[str, Any]],
        pacer_authorized: bool,
    ) -> str:
        pacer_session = _get_pacer_session()
        pacer_authenticated = bool(pacer_session)
        pacer_search_disabled = bool(session.get("pacer_search_disabled"))
        env_config = app.config.get("PACER_ENV_CONFIG") or {}
        auth_env = env_config.get("auth_env", "unknown")
        pcl_env = env_config.get("pcl_env", "unknown")
        billable_flag = pacer_env_billable(str(pcl_env))
        billable_label = (
            "Yes" if billable_flag is True else "No" if billable_flag is False else "Unknown"
        )
        case_defaults, party_defaults = _build_pacer_explore_defaults()
        return render_template(
            "admin_pacer_explore.html",
            active_page="federal_data_dashboard",
            active_subnav="explore_pacer",
            csrf_token=get_csrf_token(),
            pacer_authenticated=pacer_authenticated,
            pacer_search_enabled=bool(pacer_authorized and not _pacer_search_disabled()),
            pacer_search_disabled=pacer_search_disabled,
            pacer_search_disabled_reason=session.get("pacer_search_disabled_reason"),
            pacer_authorized_at=(pacer_session or {}).get("authorized_at"),
            pacer_authorize_url=url_for("admin_federal_data_dashboard_get_pacer_data"),
            pacer_auth_env_label=pacer_env_label(str(auth_env)),
            pcl_env_label=pacer_env_label(str(pcl_env)),
            pacer_auth_host=pacer_env_host(pacer_auth_base_url),
            pcl_host=pacer_env_host(pcl_base_url),
            pacer_env_billable_label=billable_label,
            pacer_env_mismatch=bool(app.config.get("PACER_ENV_MISMATCH")),
            pacer_env_mismatch_reason=app.config.get("PACER_ENV_MISMATCH_REASON"),
            courts=_load_court_choices(),
            case_type_choices=_load_case_type_choices(),
            mode=mode,
            case_defaults=case_defaults,
            party_defaults=party_defaults,
            immediate_max_pages=PCL_IMMEDIATE_MAX_PAGES,
            batch_max_pages=PCL_BATCH_MAX_PAGES,
            explore_page_size=PCL_PAGE_SIZE,
            explore_max_records=PCL_BATCH_MAX_RECORDS,
            run_result=run_result,
            case_values=case_values,
            party_values=party_values,
            run_history=_load_pacer_explore_runs(),
            search_run_history=_load_pacer_search_runs(),
        )

    def _load_court_choices() -> List[Dict[str, Any]]:
        pacer_courts = pcl_tables["pacer_courts"]
        pcl_courts_table = pcl_tables["pcl_courts"]
        choices: List[Dict[str, Any]] = []
        try:
            with engine.begin() as conn:
                pacer_rows = (
                    conn.execute(
                        select(pacer_courts.c.court_id, pacer_courts.c.court_name).order_by(
                            pacer_courts.c.court_id.asc()
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as exc:
            app.logger.warning("PACER courts unavailable: %s", exc)
            pacer_rows = []

        if pacer_rows:
            for row in pacer_rows:
                name = row.get("court_name") or ""
                court_id = row.get("court_id") or ""
                label = f"{court_id}, {name}".strip().rstrip(",")
                choices.append({"court_id": court_id, "name": name, "label": label})
            return choices

        stmt = (
            select(
                pcl_courts_table.c.pcl_court_id,
                pcl_courts_table.c.name,
            )
            .where(pcl_courts_table.c.active.is_(True))
            .order_by(pcl_courts_table.c.pcl_court_id.asc())
        )
        with engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        for row in rows:
            name = row.get("name") or ""
            court_id = row["pcl_court_id"]
            label = f"{court_id}, {name}".strip().rstrip(",")
            choices.append({"court_id": court_id, "name": name, "label": label})
        return choices

    def _parse_iso_date(value: str) -> Optional[datetime.date]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).date()
        except ValueError:
            return None

    def _clamp_max_records(value: str) -> Tuple[int, Optional[str]]:
        warning = None
        try:
            parsed = int(str(value).strip() or PCL_EXPLORE_DEFAULT_MAX_RECORDS)
        except ValueError:
            parsed = PCL_EXPLORE_DEFAULT_MAX_RECORDS
            warning = "Max records must be an integer. Using the safe default of 54."
        if parsed < 1:
            parsed = PCL_EXPLORE_DEFAULT_MAX_RECORDS
            warning = "Max records must be at least 1. Using the safe default of 54."
        if parsed > PCL_BATCH_MAX_RECORDS:
            warning = (
                f"Max records capped at {PCL_BATCH_MAX_RECORDS} "
                f"({PCL_BATCH_MAX_PAGES} pages)."
            )
            parsed = PCL_BATCH_MAX_RECORDS
        return parsed, warning

    def _normalize_receipt_payloads(
        receipts: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        fields = [
            "transactionDate",
            "billablePages",
            "loginId",
            "search",
            "description",
            "csoId",
            "reportId",
            "searchFee",
        ]
        normalized: List[Dict[str, Any]] = []
        for row in receipts:
            payload = row.get("receipt") if isinstance(row, dict) else None
            if not isinstance(payload, dict):
                payload = row if isinstance(row, dict) else {}
            receipt = {key: payload.get(key) for key in fields if key in payload}
            if receipt:
                normalized.append(receipt)
        return normalized

    def _normalize_page_info(page_info: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(page_info, dict):
            return None
        keys = [
            "number",
            "size",
            "totalPages",
            "totalElements",
            "numberOfElements",
            "first",
            "last",
        ]
        normalized = {key: page_info.get(key) for key in keys if key in page_info}
        return normalized or None

    def _hash_record(parts: Sequence[Any]) -> str:
        hashed = hashlib.sha256()
        for part in parts:
            text = "" if part is None else str(part)
            hashed.update(text.encode("utf-8"))
            hashed.update(b"|")
        return hashed.hexdigest()

    def _normalize_case_record(
        record: Dict[str, Any],
        *,
        default_court_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        court_id = record.get("courtId") or record.get("court_id") or default_court_id
        case_number = (
            record.get("caseNumber")
            or record.get("case_number")
            or record.get("caseNumberFull")
            or record.get("case_number_full")
        )
        if not court_id or not case_number:
            return None
        case_number_full = (
            record.get("caseNumberFull")
            or record.get("case_number_full")
            or case_number
        )
        data_json = json.dumps(record, default=str)
        case_type_value = record.get("caseType") or record.get("case_type")
        if isinstance(case_type_value, str):
            case_type_value = case_type_value.strip().lower()
        if case_type_value and case_type_value not in CRIMINAL_CASE_TYPES:
            case_type_value = None
        return {
            "court_id": court_id,
            "case_id": record.get("caseId") or record.get("case_id"),
            "case_number": case_number,
            "case_number_full": case_number_full,
            "case_type": case_type_value,
            "date_filed": _parse_iso_date(
                str(record.get("dateFiled") or record.get("date_filed") or "")
            ),
            "date_closed": _parse_iso_date(
                str(record.get("dateClosed") or record.get("date_closed") or "")
            ),
            "effective_date_closed": _parse_iso_date(
                str(record.get("effectiveDateClosed") or record.get("effective_date_closed") or "")
            ),
            "short_title": record.get("shortTitle") or record.get("short_title"),
            "case_title": record.get("caseTitle") or record.get("case_title"),
            "case_link": record.get("caseLink") or record.get("case_link"),
            "case_year": record.get("caseYear") or record.get("case_year"),
            "case_office": record.get("caseOffice") or record.get("case_office"),
            "judge_last_name": record.get("judgeLastName") or record.get("judge_last_name"),
            "record_hash": _hash_record([court_id, case_number_full, data_json]),
            "data_json": data_json,
            "source_last_seen_at": datetime.utcnow(),
        }

    def _normalize_party_record(
        record: Dict[str, Any],
        *,
        case_id: int,
    ) -> Dict[str, Any]:
        data_json = json.dumps(record, default=str)
        last_name = record.get("lastName") or record.get("last_name")
        first_name = record.get("firstName") or record.get("first_name")
        middle_name = record.get("middleName") or record.get("middle_name")
        party_type = record.get("partyType") or record.get("party_type")
        party_role = record.get("partyRole") or record.get("party_role")
        party_name = record.get("partyName") or record.get("party_name")
        record_hash = _hash_record(
            [
                case_id,
                last_name,
                first_name,
                middle_name,
                party_type,
                party_role,
                party_name,
            ]
        )
        return {
            "case_id": case_id,
            "last_name": last_name,
            "first_name": first_name,
            "middle_name": middle_name,
            "party_type": party_type,
            "party_role": party_role,
            "party_name": party_name,
            "record_hash": record_hash,
            "data_json": data_json,
            "source_last_seen_at": datetime.utcnow(),
        }

    def _parse_page_number(value: Any) -> Tuple[int, Optional[str]]:
        warning = None
        try:
            parsed = int(str(value).strip() or "1")
        except ValueError:
            parsed = 1
            warning = "Page must be an integer. Defaulting to page 1."
        if parsed < 1:
            parsed = 1
            warning = "Page must be at least 1. Defaulting to page 1."
        return parsed, warning

    def _extract_case_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "content" in payload:
            value = payload.get("content")
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            return []
        for key in ("cases", "caseList", "caseResults", "results", "data"):
            if key in payload and isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return []

    def _extract_party_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "content" in payload:
            value = payload.get("content")
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            return []
        for key in ("parties", "partyList", "partyResults", "results", "data"):
            if key in payload and isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return []

    def _is_non_empty(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, dict, tuple, set)):
            return len(value) > 0
        return True

    def _observed_fields(records: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        for record in records:
            for key, value in record.items():
                counts.setdefault(str(key), 0)
                if _is_non_empty(value):
                    counts[str(key)] += 1
        total = len(records)
        observed = [
            {
                "field": field,
                "non_empty_count": count,
                "coverage": (count / total) if total else 0.0,
            }
            for field, count in counts.items()
        ]
        observed.sort(key=lambda item: (-item["non_empty_count"], item["field"]))
        return observed

    def _observed_party_fields(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        party_fields = _observed_fields(records)
        court_cases = [
            record.get("courtCase")
            for record in records
            if isinstance(record.get("courtCase"), dict)
        ]
        court_case_fields = _observed_fields(court_cases)
        return {"party": party_fields, "court_case": court_case_fields}

    def _truncate_value(value: Any, max_len: int = 240) -> Any:
        if isinstance(value, str):
            cleaned = redact_tokens(value)
            return cleaned if len(cleaned) <= max_len else f"{cleaned[:max_len]}…"
        if isinstance(value, list):
            return [_truncate_value(item, max_len=max_len) for item in value[:5]]
        if isinstance(value, dict):
            truncated: Dict[str, Any] = {}
            for idx, (key, item) in enumerate(value.items()):
                if idx >= 30:
                    truncated["…"] = "truncated"
                    break
                truncated[str(key)] = _truncate_value(item, max_len=max_len)
            return truncated
        return value

    def _build_debug_bundle(
        *,
        mode: str,
        search_mode: str,
        court_id: str,
        date_filed_from: str,
        date_filed_to: str,
        last_name: Optional[str],
        exact_name_match: Optional[bool],
        first_name: Optional[str],
        max_records: int,
        requested_page: Optional[int],
        unexpected_input_keys: Sequence[str],
        pages_requested: int,
        pages_fetched: int,
        request_body: Dict[str, Any],
        request_urls: Sequence[str],
        status_codes: Sequence[int],
        records: Sequence[Dict[str, Any]],
        page_infos: Sequence[Dict[str, Any]],
        truncated_notice: Optional[str],
        error_message: Optional[str],
        response_snippets: Sequence[Dict[str, Any]],
        environment: Optional[Dict[str, Any]] = None,
        token_diagnostics: Optional[Dict[str, Any]] = None,
    ) -> str:
        preamble_lines = [
            "courtdatapro admin debug bundle",
            "page: /admin/pacer/explore/run",
            f"mode: {mode}",
        ]
        if court_id:
            preamble_lines.append(f"court_id: {court_id}")
        bundle = {
            "inputs": {
                "mode": mode,
                "search_mode": search_mode,
                "court_id": court_id,
                "date_filed_from": date_filed_from,
                "date_filed_to": date_filed_to,
                "last_name": last_name,
                "exact_name_match": exact_name_match,
                "first_name": first_name,
                "max_records": max_records,
                "requested_page": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "pages_requested": pages_requested,
                "pages_fetched": pages_fetched,
                "unexpected_input_keys": list(unexpected_input_keys),
            },
            "request_body": request_body,
            "request_urls": list(request_urls),
            "status_codes": list(status_codes),
            "page_info": list(page_infos),
            "truncated_notice": truncated_notice,
            "error_message": error_message,
            "response_snippets": list(response_snippets),
            "record_samples": [_truncate_value(record) for record in list(records)[:3]],
            "environment": environment,
            "token_diagnostics": token_diagnostics,
        }
        preamble = "\n".join(preamble_lines)
        return f"{preamble}\n\n{json.dumps(bundle, indent=2, sort_keys=True, default=str)}"

    def _apply_pacer_explore_run_retention(conn) -> None:
        pacer_explore_runs = pcl_tables["pacer_explore_runs"]
        stale_ids = (
            select(pacer_explore_runs.c.id)
            .order_by(
                pacer_explore_runs.c.created_at.desc(),
                pacer_explore_runs.c.id.desc(),
            )
            .offset(PCL_EXPLORE_RUN_RETENTION)
        )
        conn.execute(
            delete(pacer_explore_runs).where(pacer_explore_runs.c.id.in_(stale_ids))
        )

    def _store_pacer_explore_run(
        *,
        mode: str,
        court_id: Optional[str],
        date_from: Optional[datetime.date],
        date_to: Optional[datetime.date],
        request_params: Dict[str, Any],
        pages_fetched: int,
        receipts: Sequence[Dict[str, Any]],
        observed_fields: Optional[Any],
        error_summary: Optional[str],
    ) -> None:
        pacer_explore_runs = pcl_tables["pacer_explore_runs"]
        sanitized_request_params = _truncate_value(request_params)
        sanitized_receipts = _truncate_value(list(receipts)) if receipts else []
        payload = {
            "created_by": None,
            "mode": mode,
            "court_id": court_id,
            "date_from": date_from,
            "date_to": date_to,
            "request_params": sanitized_request_params,
            "pages_fetched": pages_fetched,
            "receipts": sanitized_receipts,
            "observed_fields": observed_fields,
            "error_summary": error_summary,
        }
        with engine.begin() as conn:
            conn.execute(insert(pacer_explore_runs).values(payload))
            _apply_pacer_explore_run_retention(conn)

    def _load_pacer_explore_runs(limit: int = 12) -> List[Dict[str, Any]]:
        pacer_explore_runs = pcl_tables["pacer_explore_runs"]
        stmt = (
            select(pacer_explore_runs)
            .order_by(
                pacer_explore_runs.c.created_at.desc(),
                pacer_explore_runs.c.id.desc(),
            )
            .limit(limit)
        )
        with engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        runs = []
        for row in rows:
            created_at = row.get("created_at")
            runs.append(
                {
                    **row,
                    "created_at_display": (
                        created_at.isoformat().replace("T", " ")
                        if isinstance(created_at, datetime)
                        else str(created_at or "")
                    ),
                }
            )
        return runs

    def _store_pacer_search_request(
        *,
        search_type: str,
        search_mode: str,
        criteria: Dict[str, Any],
        report_id: Optional[str] = None,
        report_status: Optional[str] = None,
        report_meta: Optional[Dict[str, Any]] = None,
    ) -> int:
        pacer_search_requests = pcl_tables["pacer_search_requests"]
        payload = {
            "search_type": search_type,
            "search_mode": search_mode,
            "criteria_json": json.dumps(criteria, default=str),
            "report_id": report_id,
            "report_status": report_status,
            "report_meta_json": json.dumps(report_meta, default=str)
            if report_meta is not None
            else None,
        }
        with engine.begin() as conn:
            result = conn.execute(insert(pacer_search_requests).values(payload))
            return int(result.inserted_primary_key[0])

    def _update_pacer_search_request(
        request_id: int,
        *,
        report_id: Optional[str] = None,
        report_status: Optional[str] = None,
        report_meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        pacer_search_requests = pcl_tables["pacer_search_requests"]
        updates: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if report_id is not None:
            updates["report_id"] = report_id
        if report_status is not None:
            updates["report_status"] = report_status
        if report_meta is not None:
            updates["report_meta_json"] = json.dumps(report_meta, default=str)
        with engine.begin() as conn:
            conn.execute(
                update(pacer_search_requests)
                .where(pacer_search_requests.c.id == request_id)
                .values(**updates)
            )

    def _load_pacer_search_request(request_id: int) -> Optional[Dict[str, Any]]:
        pacer_search_requests = pcl_tables["pacer_search_requests"]
        with engine.begin() as conn:
            row = (
                conn.execute(
                    select(pacer_search_requests).where(
                        pacer_search_requests.c.id == request_id
                    )
                )
                .mappings()
                .first()
            )
        return dict(row) if row else None

    def _parse_search_request_criteria(payload: Optional[str]) -> Dict[str, Any]:
        if not payload:
            return {}
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _upsert_pcl_case(
        conn: Any,
        case_record: Dict[str, Any],
    ) -> Tuple[int, bool]:
        pcl_cases = pcl_tables["pcl_cases"]
        court_id = case_record["court_id"]
        case_number_full = case_record["case_number_full"]
        existing = (
            conn.execute(
                select(pcl_cases.c.id).where(
                    (pcl_cases.c.court_id == court_id)
                    & (pcl_cases.c.case_number_full == case_number_full)
                )
            )
            .mappings()
            .first()
        )
        now = datetime.utcnow()
        if existing:
            conn.execute(
                update(pcl_cases)
                .where(pcl_cases.c.id == existing["id"])
                .values(
                    **{
                        **case_record,
                        "updated_at": now,
                    }
                )
            )
            return int(existing["id"]), False
        result = conn.execute(
            insert(pcl_cases).values(
                **{
                    **case_record,
                    "created_at": now,
                    "updated_at": now,
                }
            )
        )
        return int(result.inserted_primary_key[0]), True

    def _upsert_pcl_party(
        conn: Any,
        party_record: Dict[str, Any],
    ) -> Tuple[int, bool]:
        pcl_parties = pcl_tables["pcl_parties"]
        record_hash = party_record["record_hash"]
        existing = (
            conn.execute(
                select(pcl_parties.c.id).where(pcl_parties.c.record_hash == record_hash)
            )
            .mappings()
            .first()
        )
        now = datetime.utcnow()
        if existing:
            conn.execute(
                update(pcl_parties)
                .where(pcl_parties.c.id == existing["id"])
                .values(
                    **{
                        **party_record,
                        "updated_at": now,
                    }
                )
            )
            return int(existing["id"]), False
        result = conn.execute(
            insert(pcl_parties).values(
                **{
                    **party_record,
                    "created_at": now,
                    "updated_at": now,
                }
            )
        )
        return int(result.inserted_primary_key[0]), True

    def _store_pacer_search_run(
        *,
        search_type: str,
        search_mode: str,
        criteria: Dict[str, Any],
        receipts: Sequence[Dict[str, Any]],
        page_info: Optional[Dict[str, Any]],
        raw_response: Optional[Dict[str, Any]],
        results: Sequence[Dict[str, Any]],
        report_id: Optional[str] = None,
        report_status: Optional[str] = None,
    ) -> Dict[str, int]:
        pacer_search_runs = pcl_tables["pacer_search_runs"]
        counts = {
            "cases_inserted": 0,
            "cases_updated": 0,
            "parties_inserted": 0,
            "parties_updated": 0,
        }
        normalized_receipts = _normalize_receipt_payloads(receipts)
        normalized_page_info = _normalize_page_info(page_info)
        criteria_json = json.dumps(criteria, default=str)
        receipt_json = json.dumps(normalized_receipts, default=str)
        page_info_json = json.dumps(normalized_page_info, default=str) if normalized_page_info else None
        raw_response_json = (
            json.dumps(raw_response, default=str) if isinstance(raw_response, dict) else None
        )
        default_court_id = (criteria.get("ui_inputs") or {}).get("court_id")
        with engine.begin() as conn:
            if search_type == "case":
                for record in results:
                    if not isinstance(record, dict):
                        continue
                    normalized = _normalize_case_record(
                        record, default_court_id=default_court_id
                    )
                    if not normalized:
                        continue
                    _, inserted = _upsert_pcl_case(conn, normalized)
                    if inserted:
                        counts["cases_inserted"] += 1
                    else:
                        counts["cases_updated"] += 1
            else:
                for record in results:
                    if not isinstance(record, dict):
                        continue
                    court_case = record.get("courtCase")
                    if not isinstance(court_case, dict):
                        continue
                    normalized_case = _normalize_case_record(
                        court_case, default_court_id=default_court_id
                    )
                    if not normalized_case:
                        continue
                    case_id, case_inserted = _upsert_pcl_case(conn, normalized_case)
                    if case_inserted:
                        counts["cases_inserted"] += 1
                    else:
                        counts["cases_updated"] += 1
                    party_record = _normalize_party_record(record, case_id=case_id)
                    _, party_inserted = _upsert_pcl_party(conn, party_record)
                    if party_inserted:
                        counts["parties_inserted"] += 1
                    else:
                        counts["parties_updated"] += 1

            conn.execute(
                insert(pacer_search_runs).values(
                    search_type=search_type,
                    search_mode=search_mode,
                    criteria_json=criteria_json,
                    report_id=report_id,
                    report_status=report_status,
                    receipt_json=receipt_json,
                    page_info_json=page_info_json,
                    raw_response_json=raw_response_json,
                    cases_inserted=counts["cases_inserted"],
                    cases_updated=counts["cases_updated"],
                    parties_inserted=counts["parties_inserted"],
                    parties_updated=counts["parties_updated"],
                )
            )
        return counts

    def _build_case_key(
        record: Dict[str, Any], *, default_court_id: Optional[str]
    ) -> Optional[Tuple[str, str]]:
        court_id = record.get("courtId") or record.get("court_id") or default_court_id
        case_number = (
            record.get("caseNumberFull")
            or record.get("case_number_full")
            or record.get("caseNumber")
            or record.get("case_number")
        )
        if not court_id or not case_number:
            return None
        return (str(court_id), str(case_number))

    def _load_existing_case_keys(
        records: Sequence[Dict[str, Any]], *, default_court_id: Optional[str]
    ) -> Set[Tuple[str, str]]:
        keys: List[Tuple[str, str]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            key = _build_case_key(record, default_court_id=default_court_id)
            if key:
                keys.append(key)
        if not keys:
            return set()
        pcl_cases = pcl_tables["pcl_cases"]
        with engine.begin() as conn:
            rows = (
                conn.execute(
                    select(pcl_cases.c.court_id, pcl_cases.c.case_number_full).where(
                        tuple_(pcl_cases.c.court_id, pcl_cases.c.case_number_full).in_(
                            keys
                        )
                    )
                )
                .mappings()
                .all()
            )
        return {(row["court_id"], row["case_number_full"]) for row in rows}

    def _build_case_view_rows(
        records: Sequence[Dict[str, Any]], *, default_court_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        existing_keys = _load_existing_case_keys(
            records, default_court_id=default_court_id
        )
        rows: List[Dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            key = _build_case_key(record, default_court_id=default_court_id)
            rows.append(
                {
                    "case_number": record.get("caseNumber")
                    or record.get("case_number")
                    or record.get("caseNumberFull")
                    or record.get("case_number_full")
                    or "—",
                    "case_type": record.get("caseType")
                    or record.get("case_type")
                    or "—",
                    "date_filed": record.get("dateFiled") or record.get("date_filed") or "—",
                    "short_title": record.get("shortTitle")
                    or record.get("short_title")
                    or "—",
                    "court_id": record.get("courtId")
                    or record.get("court_id")
                    or default_court_id
                    or "—",
                    "already_indexed": key in existing_keys if key else False,
                }
            )
        return rows

    def _load_pacer_response_code(status_code: Optional[int]) -> Optional[Dict[str, Any]]:
        if not status_code:
            return None
        pacer_response_codes = pcl_tables["pacer_response_codes"]
        stmt = select(pacer_response_codes).where(
            pacer_response_codes.c.http_status_code == status_code
        )
        try:
            with engine.begin() as conn:
                row = conn.execute(stmt).mappings().first()
        except SQLAlchemyError as exc:
            app.logger.warning("PACER response code lookup failed: %s", exc)
            return None
        return dict(row) if row else None

    def _format_pacer_response_code(status_code: Optional[int]) -> Optional[str]:
        record = _load_pacer_response_code(status_code)
        if not record:
            return None
        reason = record.get("reason_phrase") or ""
        usage = record.get("application_usage") or ""
        description = record.get("description") or ""
        details = f"{reason}."
        if usage:
            details = f"{details} {usage}."
        if description:
            details = f"{details} {description}"
        return details.strip()

    def _append_pcl_api_error(
        errors: List[str],
        exc: PclApiError,
        *,
        prefix: str,
    ) -> None:
        errors.append(f"{prefix} status {exc.status_code}.")
        errors.append(exc.message)
        details = _format_pacer_response_code(exc.status_code)
        if details:
            errors.append(details)

    def _format_run_timestamp(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat().replace("T", " ")
        return str(value or "")

    def _summarize_saved_search(criteria: Dict[str, Any]) -> Dict[str, Any]:
        ui_inputs = criteria.get("ui_inputs") if isinstance(criteria, dict) else {}
        if not isinstance(ui_inputs, dict):
            ui_inputs = {}
        case_types = ui_inputs.get("case_types") or []
        if isinstance(case_types, str):
            case_types = [case_types]
        return {
            "court_id": ui_inputs.get("court_id") or "",
            "date_from": ui_inputs.get("date_filed_from") or "",
            "date_to": ui_inputs.get("date_filed_to") or "",
            "case_types": [str(value) for value in case_types if value],
            "last_name": ui_inputs.get("last_name") or "",
            "first_name": ui_inputs.get("first_name") or "",
        }

    def _normalize_saved_search_schedule(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        schedule = str(value).strip().lower()
        if schedule in {"manual", "daily", "weekly", "monthly"}:
            return schedule
        return None

    def _default_saved_search_label(
        *, search_type: str, search_mode: str, criteria: Dict[str, Any]
    ) -> str:
        summary = _summarize_saved_search(criteria)
        court = summary.get("court_id") or "all courts"
        date_from = summary.get("date_from") or ""
        date_to = summary.get("date_to") or ""
        label_parts = [search_type.capitalize(), search_mode.capitalize(), court]
        if date_from or date_to:
            label_parts.append(f"{date_from or 'start'} to {date_to or 'end'}")
        return " · ".join(label_parts)

    def _build_saved_search_run_fields(
        *, search_type: str, search_mode: str, criteria: Dict[str, Any], saved_search_id: int
    ) -> List[Dict[str, str]]:
        ui_inputs = criteria.get("ui_inputs") if isinstance(criteria, dict) else {}
        if not isinstance(ui_inputs, dict):
            ui_inputs = {}
        fields: List[Dict[str, str]] = [
            {"name": "mode", "value": "cases" if search_type == "case" else "parties"},
            {"name": "search_mode", "value": search_mode},
            {"name": "saved_search_id", "value": str(saved_search_id)},
        ]

        def add_field(name: str, value: Any) -> None:
            if value is None:
                return
            text = str(value)
            if not text:
                return
            fields.append({"name": name, "value": text})

        for key in (
            "court_id",
            "date_filed_from",
            "date_filed_to",
            "page",
            "max_records",
            "last_name",
            "first_name",
            "ssn",
        ):
            add_field(key, ui_inputs.get(key))

        if ui_inputs.get("exact_name_match"):
            fields.append({"name": "exact_name_match", "value": "1"})

        case_types = ui_inputs.get("case_types") or []
        if isinstance(case_types, str):
            case_types = [case_types]
        for case_type in case_types:
            add_field("case_types", case_type)

        return fields

    def _load_pacer_saved_searches(limit: int = 12) -> List[Dict[str, Any]]:
        pacer_saved_searches = pcl_tables["pacer_saved_searches"]
        stmt = (
            select(pacer_saved_searches)
            .where(pacer_saved_searches.c.active.is_(True))
            .order_by(
                pacer_saved_searches.c.created_at.desc(),
                pacer_saved_searches.c.id.desc(),
            )
            .limit(limit)
        )
        try:
            with engine.begin() as conn:
                rows = conn.execute(stmt).mappings().all()
        except SQLAlchemyError as exc:
            app.logger.warning("PACER saved searches unavailable: %s", exc)
            return []
        saved: List[Dict[str, Any]] = []
        for row in rows:
            criteria = _parse_search_request_criteria(row.get("criteria_json"))
            summary = _summarize_saved_search(criteria)
            saved.append(
                {
                    **row,
                    "created_at_display": _format_run_timestamp(row.get("created_at")),
                    "last_run_display": _format_run_timestamp(row.get("last_run_at")),
                    "schedule_label": row.get("schedule") or "Manual",
                    "summary": summary,
                    "run_fields": _build_saved_search_run_fields(
                        search_type=row.get("search_type") or "case",
                        search_mode=row.get("search_mode") or "immediate",
                        criteria=criteria,
                        saved_search_id=row.get("id"),
                    ),
                }
            )
        return saved

    def _load_case_type_choices() -> List[Tuple[str, str]]:
        pacer_case_types = pcl_tables["pacer_case_types"]
        stmt = select(pacer_case_types.c.case_type_code).order_by(
            pacer_case_types.c.case_type_code.asc()
        )
        try:
            with engine.begin() as conn:
                rows = conn.execute(stmt).fetchall()
        except SQLAlchemyError as exc:
            app.logger.warning("PACER case types unavailable: %s", exc)
            rows = []
        if rows:
            codes = [row[0] for row in rows if row and row[0]]
            return [(code, code) for code in codes]
        return list(PCL_CASE_TYPES)

    def _load_pacer_search_run(run_id: int) -> Optional[Dict[str, Any]]:
        pacer_search_runs = pcl_tables["pacer_search_runs"]
        with engine.begin() as conn:
            row = (
                conn.execute(select(pacer_search_runs).where(pacer_search_runs.c.id == run_id))
                .mappings()
                .first()
            )
        return dict(row) if row else None

    def _touch_pacer_saved_search(search_id: int) -> None:
        pacer_saved_searches = pcl_tables["pacer_saved_searches"]
        now = datetime.utcnow()
        with engine.begin() as conn:
            conn.execute(
                update(pacer_saved_searches)
                .where(pacer_saved_searches.c.id == search_id)
                .values(
                    last_run_at=now,
                    run_count=pacer_saved_searches.c.run_count + 1,
                    updated_at=now,
                )
            )

    def _load_pacer_search_runs(limit: int = 12) -> List[Dict[str, Any]]:
        pacer_search_runs = pcl_tables["pacer_search_runs"]
        stmt = (
            select(pacer_search_runs)
            .order_by(
                pacer_search_runs.c.created_at.desc(),
                pacer_search_runs.c.id.desc(),
            )
            .limit(limit)
        )
        with engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        runs: List[Dict[str, Any]] = []
        for row in rows:
            created_at = row.get("created_at")
            criteria = _parse_search_request_criteria(row.get("criteria_json"))
            ui_inputs = criteria.get("ui_inputs") if isinstance(criteria, dict) else {}
            runs.append(
                {
                    **row,
                    "created_at_display": _format_run_timestamp(created_at),
                    "court_id": ui_inputs.get("court_id"),
                    "date_from": ui_inputs.get("date_filed_from"),
                    "date_to": ui_inputs.get("date_filed_to"),
                }
            )
        return runs

    def _hydrate_explore_values(
        mode: str, ui_inputs: Mapping[str, Any], search_mode: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        if mode == "cases":
            case_values = {
                "search_mode": search_mode,
                "court_id": ui_inputs.get("court_id", ""),
                "date_filed_from": ui_inputs.get("date_filed_from", ""),
                "date_filed_to": ui_inputs.get("date_filed_to", ""),
                "page": ui_inputs.get("page", 1),
                "max_records": ui_inputs.get("max_records", ""),
                "case_types": ui_inputs.get("case_types") or [],
            }
            return case_values, None
        party_values = {
            "search_mode": search_mode,
            "last_name": ui_inputs.get("last_name", ""),
            "exact_name_match": bool(ui_inputs.get("exact_name_match")),
            "first_name": ui_inputs.get("first_name", ""),
            "ssn": ui_inputs.get("ssn", ""),
            "date_filed_from": ui_inputs.get("date_filed_from", ""),
            "date_filed_to": ui_inputs.get("date_filed_to", ""),
            "court_id": ui_inputs.get("court_id", ""),
            "page": ui_inputs.get("page", 1),
            "max_records": ui_inputs.get("max_records", ""),
        }
        return None, party_values

    def _normalize_report_status(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip().upper()

    def _extract_report_info(payload: Dict[str, Any]) -> Dict[str, Any]:
        source = payload.get("reportInfo") if isinstance(payload.get("reportInfo"), dict) else payload
        def _get(key: str, alt_key: str) -> Any:
            return source.get(key) if key in source else source.get(alt_key)

        return {
            "reportId": _get("reportId", "report_id"),
            "status": _get("status", "reportStatus") or _get("report_status", "reportStatus"),
            "startTime": _get("startTime", "start_time"),
            "endTime": _get("endTime", "end_time"),
            "recordCount": _get("recordCount", "record_count"),
            "unbilledPageCount": _get("unbilledPageCount", "unbilled_page_count"),
            "downloadFee": _get("downloadFee", "download_fee"),
            "pages": _get("pages", "page_count"),
        }

    def _build_store_payload(
        *,
        mode: str,
        search_mode: str,
        criteria: Dict[str, Any],
        results: Sequence[Dict[str, Any]],
        receipts: Sequence[Dict[str, Any]],
        page_info: Optional[Dict[str, Any]],
        raw_response: Optional[Dict[str, Any]],
        report_request: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return {
            "mode": mode,
            "search_mode": search_mode,
            "criteria": criteria,
            "results": list(results),
            "receipts": list(receipts),
            "page_info": page_info,
            "raw_response": raw_response,
            "report_request": report_request,
        }

    def _base_run_result(mode: str, search_mode: str) -> Dict[str, Any]:
        return {
            "status": "error",
            "mode": mode,
            "search_mode": search_mode,
            "errors": [],
            "warnings": [],
            "logs": [],
            "receipts": [],
            "page_infos": [],
            "cases": [],
            "parties": [],
            "observed_fields": [],
            "party_observed_fields": [],
            "court_case_observed_fields": [],
            "cost_summary": {"billable_pages": 0, "fee_totals": {}},
            "debug_bundle": "",
            "response_snippets": [],
            "pages_requested": 0,
            "pages_fetched": 0,
            "truncated_notice": None,
            "endpoint": "",
            "report_request": None,
            "page_info": None,
            "page_number": None,
            "next_steps": [],
        }

    def _build_next_steps(
        *,
        status_codes: Sequence[int],
        observed_fields: Sequence[Dict[str, Any]],
        nested_observed_fields: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        def coverage_for(field: str, fields: Sequence[Dict[str, Any]]) -> float:
            for row in fields:
                if row.get("field") == field:
                    return float(row.get("coverage") or 0.0)
            return 0.0

        combined_fields = list(observed_fields)
        if nested_observed_fields:
            combined_fields.extend(nested_observed_fields)

        judge_coverage = max(
            coverage_for("judgeLastName", combined_fields),
            coverage_for("judge_last_name", combined_fields),
        )
        sparse_fields = False
        if combined_fields:
            low_coverage = sum(1 for row in combined_fields if (row.get("coverage") or 0) < 0.2)
            sparse_fields = (low_coverage / len(combined_fields)) >= 0.4

        return [
            {
                "label": "If judgeLastName is present and non-empty in many records, plan a judge normalization strategy.",
                "active": judge_coverage >= 0.5,
            },
            {
                "label": "If fields are frequently empty, consider court system enrichment for docket-level data.",
                "active": sparse_fields,
            },
            {
                "label": "If 401 occurs, re-authorize before retrying.",
                "active": 401 in status_codes,
            },
            {
                "label": "If 406 occurs, copy the debug bundle and open a fix request.",
                "active": 406 in status_codes,
            },
        ]
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

    @app.cli.command("pcl-courts-seed")
    def pcl_courts_seed_command() -> None:
        """Seed the PCL courts catalog from the static Appendix A list."""
        from pcl_courts_seed import load_pcl_courts_catalog, seed_pcl_courts

        courts = load_pcl_courts_catalog()
        stats = seed_pcl_courts(engine, pcl_courts, courts)
        message = (
            "PCL courts seed complete: "
            f"{stats['inserted']} inserted, {stats['updated']} updated, "
            f"{stats['skipped']} skipped."
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

    def _is_system_schema(schema_name: str) -> bool:
        if engine.dialect.name == "postgresql":
            return schema_name in {"information_schema", "pg_catalog"}
        if engine.dialect.name == "sqlite":
            return schema_name.startswith("sqlite")
        return False

    def _db_check_reference_tables() -> List[Dict[str, Any]]:
        preparer = engine.dialect.identifier_preparer
        inspector = inspect(engine)
        tables = [
            "pacer_response_codes",
            "search_regions",
            "pacer_case_types",
            "pacer_courts",
            "pacer_sortable_case_fields",
            "pacer_sortable_party_fields",
            "pacer_saved_searches",
            "pacer_search_runs",
            "pcl_cases",
        ]
        results: List[Dict[str, Any]] = []
        for table_name in tables:
            try:
                if not inspector.has_table(table_name):
                    results.append({"table": table_name, "exists": False, "count": None})
                    continue
            except SQLAlchemyError as exc:
                results.append(
                    {
                        "table": table_name,
                        "exists": False,
                        "count": None,
                        "error": str(exc),
                    }
                )
                continue
            qualified = preparer.quote(table_name)
            try:
                with engine.connect() as connection:
                    count = connection.execute(
                        sa_text(f"SELECT count(*) AS count FROM {qualified}")
                    ).scalar()
                results.append(
                    {
                        "table": table_name,
                        "exists": True,
                        "count": int(count) if count is not None else 0,
                    }
                )
            except SQLAlchemyError as exc:
                results.append(
                    {
                        "table": table_name,
                        "exists": True,
                        "count": None,
                        "error": str(exc),
                    }
                )
        return results

    @app.get("/admin/database-dashboard")
    @admin_required
    def admin_database_dashboard():
        inspector = inspect(engine)
        schema_names = sorted(inspector.get_schema_names())

        schemas: List[Dict[str, Any]] = []
        schema_table_map: Dict[str, List[str]] = {}
        total_tables = 0
        total_columns = 0
        total_views = 0

        for schema_name in schema_names:
            if _is_system_schema(schema_name):
                continue
            table_entries: List[Dict[str, Any]] = []
            schema_error: Optional[str] = None
            try:
                table_names = sorted(inspector.get_table_names(schema=schema_name))
                view_names = sorted(inspector.get_view_names(schema=schema_name))
            except SQLAlchemyError as exc:
                table_names = []
                view_names = []
                schema_error = str(exc)
            except Exception as exc:  # noqa: BLE001
                table_names = []
                view_names = []
                schema_error = f"{exc.__class__.__name__}: {exc}"

            schema_table_map[schema_name] = table_names
            for table_name in table_names:
                column_entries: List[Dict[str, Any]] = []
                column_error: Optional[str] = None
                try:
                    columns = inspector.get_columns(table_name, schema=schema_name)
                    column_entries = [
                        {
                            "name": column["name"],
                            "type": str(column["type"]),
                            "nullable": column.get("nullable", True),
                            "default": column.get("default"),
                        }
                        for column in columns
                    ]
                except SQLAlchemyError as exc:
                    column_error = str(exc)
                except Exception as exc:  # noqa: BLE001
                    column_error = f"{exc.__class__.__name__}: {exc}"

                table_entries.append(
                    {
                        "name": table_name,
                        "columns": column_entries,
                        "column_count": len(column_entries),
                        "column_error": column_error,
                    }
                )
                if column_error is None:
                    total_columns += len(column_entries)
            total_tables += len(table_entries)
            total_views += len(view_names)
            schemas.append(
                {
                    "name": schema_name,
                    "tables": table_entries,
                    "views": view_names,
                    "schema_error": schema_error,
                }
            )

        selected_schema = request.args.get("schema")
        selected_table = request.args.get("table")
        selected_column = request.args.get("column")
        preview_limit = request.args.get("limit", "25")
        try:
            preview_limit_value = int(preview_limit)
        except ValueError:
            preview_limit_value = 25
        preview_limit_value = max(5, min(preview_limit_value, 100))

        table_preview: Optional[Dict[str, Any]] = None
        column_preview: Optional[Dict[str, Any]] = None
        selected_table_columns: List[Dict[str, Any]] = []
        table_preview_error: Optional[str] = None
        column_preview_error: Optional[str] = None

        if selected_schema and selected_table:
            available_tables = schema_table_map.get(selected_schema, [])
            if selected_table in available_tables:
                try:
                    selected_table_columns = [
                        {
                            "name": column["name"],
                            "type": str(column["type"]),
                            "nullable": column.get("nullable", True),
                            "default": column.get("default"),
                        }
                        for column in inspector.get_columns(
                            selected_table, schema=selected_schema
                        )
                    ]
                except SQLAlchemyError as exc:
                    table_preview_error = str(exc)
                except Exception as exc:  # noqa: BLE001
                    table_preview_error = f"{exc.__class__.__name__}: {exc}"

                preparer = engine.dialect.identifier_preparer
                schema_identifier = preparer.quote(selected_schema)
                table_identifier = preparer.quote(selected_table)
                full_table_identifier = f"{schema_identifier}.{table_identifier}"
                if table_preview_error is None:
                    try:
                        with engine.connect() as connection:
                            result = connection.execute(
                                sa_text(f"SELECT * FROM {full_table_identifier} LIMIT :limit"),
                                {"limit": preview_limit_value},
                            )
                            rows = [dict(row._mapping) for row in result]
                            table_preview = {"columns": list(result.keys()), "rows": rows}
                    except SQLAlchemyError as exc:
                        table_preview_error = str(exc)
                    except Exception as exc:  # noqa: BLE001
                        table_preview_error = f"{exc.__class__.__name__}: {exc}"

                if selected_column:
                    column_names = {column["name"] for column in selected_table_columns}
                    if selected_column in column_names and table_preview_error is None:
                        column_identifier = preparer.quote(selected_column)
                        try:
                            with engine.connect() as connection:
                                result = connection.execute(
                                    sa_text(
                                        "SELECT {column} FROM {table} "
                                        "WHERE {column} IS NOT NULL LIMIT :limit".format(
                                            column=column_identifier,
                                            table=full_table_identifier,
                                        )
                                    ),
                                    {"limit": preview_limit_value},
                                )
                                values = [row[0] for row in result]
                                column_preview = {
                                    "name": selected_column,
                                    "values": values,
                                }
                        except SQLAlchemyError as exc:
                            column_preview_error = str(exc)
                        except Exception as exc:  # noqa: BLE001
                            column_preview_error = f"{exc.__class__.__name__}: {exc}"
                    elif selected_column:
                        column_preview_error = "Selected column is not available in this table."
            else:
                table_preview_error = "Selected table was not found in this schema."

        database_url = engine.url.render_as_string(hide_password=True)
        return render_template(
            "admin_database_dashboard.html",
            active_page="database_dashboard",
            database_url=database_url,
            database_dialect=engine.dialect.name,
            database_driver=engine.url.drivername,
            schemas=schemas,
            total_schemas=len(schemas),
            total_tables=total_tables,
            total_columns=total_columns,
            total_views=total_views,
            selected_schema=selected_schema,
            selected_table=selected_table,
            selected_column=selected_column,
            preview_limit=preview_limit_value,
            table_preview=table_preview,
            column_preview=column_preview,
            table_preview_error=table_preview_error,
            column_preview_error=column_preview_error,
            selected_table_columns=selected_table_columns,
        )

    @app.get("/admin/database-dashboard/db-check")
    @admin_required
    def admin_database_dashboard_db_check():
        return jsonify(
            {
                "ok": True,
                "checked_at": datetime.utcnow().isoformat(),
                "tables": _db_check_reference_tables(),
            }
        )

    @app.post("/admin/database-dashboard/refresh")
    @admin_required
    def admin_database_dashboard_refresh():
        require_csrf()
        engine.dispose()
        flash("Database metadata refreshed.", "success")
        return redirect(url_for("admin_database_dashboard"))

    @app.get("/admin/database-dashboard/export")
    @admin_required
    def admin_database_dashboard_export():
        inspector = inspect(engine)
        schema = request.args.get("schema")
        table = request.args.get("table")
        if not schema or not table:
            abort(400)
        if _is_system_schema(schema):
            abort(404)
        table_names = inspector.get_table_names(schema=schema)
        if table not in table_names:
            abort(404)
        available_columns = [column["name"] for column in inspector.get_columns(table, schema=schema)]
        requested_columns = request.args.getlist("columns")
        if not requested_columns:
            columns_param = request.args.get("columns")
            if columns_param:
                requested_columns = [
                    name.strip() for name in columns_param.split(",") if name.strip()
                ]
        selected_columns = (
            [column for column in requested_columns if column in available_columns]
            if requested_columns
            else available_columns
        )
        if not selected_columns:
            abort(400)
        export_limit = request.args.get("limit", "1000")
        try:
            export_limit_value = int(export_limit)
        except ValueError:
            export_limit_value = 1000
        export_limit_value = max(1, min(export_limit_value, 5000))

        preparer = engine.dialect.identifier_preparer
        schema_identifier = preparer.quote(schema)
        table_identifier = preparer.quote(table)
        column_identifiers = ", ".join(preparer.quote(column) for column in selected_columns)
        full_table_identifier = f"{schema_identifier}.{table_identifier}"
        try:
            with engine.connect() as connection:
                result = connection.execute(
                    sa_text(
                        f"SELECT {column_identifiers} FROM {full_table_identifier} LIMIT :limit"
                    ),
                    {"limit": export_limit_value},
                )
                rows = [row._mapping for row in result]
        except SQLAlchemyError as exc:
            abort(500, description=str(exc))

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(selected_columns)
        for row in rows:
            writer.writerow([row.get(column) for column in selected_columns])

        filename = f"{schema}.{table}.csv"
        response = make_response(output.getvalue())
        response.headers["Content-Type"] = "text/csv"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

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
        pacer_authenticated = bool(pacer_session)
        pacer_search_disabled = bool(session.get("pacer_search_disabled"))
        pacer_search_enabled = bool(pacer_authenticated and _pacer_search_enabled())
        env_config = app.config.get("PACER_ENV_CONFIG") or {}
        auth_env = env_config.get("auth_env", "unknown")
        pcl_env = env_config.get("pcl_env", "unknown")
        billable_flag = pacer_env_billable(str(pcl_env))
        billable_label = (
            "Yes" if billable_flag is True else "No" if billable_flag is False else "Unknown"
        )
        manual_mode = request.args.get("manual") == "1"
        search_mode = (request.args.get("search_mode") or "immediate").strip().lower()
        if search_mode not in {"immediate", "batch"}:
            search_mode = "immediate"
        return render_template(
            "admin_federal_data_get_pacer_data.html",
            active_page="federal_data_dashboard",
            active_subnav="get_pacer_data",
            pacer_authenticated=pacer_authenticated,
            pacer_search_enabled=pacer_search_enabled,
            pacer_search_disabled=pacer_search_disabled,
            pacer_search_disabled_reason=session.get("pacer_search_disabled_reason"),
            pacer_authorized_at=(pacer_session or {}).get("authorized_at"),
            pacer_needs_otp=bool(session.get("pacer_needs_otp")),
            pacer_client_code_required=bool(session.get("pacer_client_code_required")),
            pacer_redaction_required=bool(session.get("pacer_redaction_required")),
            pacer_redaction_acknowledged=bool(session.get("pacer_redaction_acknowledged")),
            pacer_base_url=pacer_auth_base_url,
            pacer_env_notice=pacer_environment_notice(pacer_auth_base_url),
            pacer_server_creds_available=pacer_server_creds_available,
            pacer_auth_env_label=pacer_env_label(str(auth_env)),
            pcl_env_label=pacer_env_label(str(pcl_env)),
            pacer_auth_host=pacer_env_host(pacer_auth_base_url),
            pcl_host=pacer_env_host(pcl_base_url),
            pacer_env_billable_label=billable_label,
            pacer_env_mismatch=bool(app.config.get("PACER_ENV_MISMATCH")),
            pacer_env_mismatch_reason=app.config.get("PACER_ENV_MISMATCH_REASON"),
            manual_mode=manual_mode,
            search_mode=search_mode,
            saved_searches=_load_pacer_saved_searches(),
            search_run_history=_load_pacer_search_runs(),
        )

    @app.post("/admin/pacer/saved-searches")
    @admin_required
    def admin_pacer_saved_search_create():
        require_csrf()
        run_id = _parse_optional_int(request.form.get("run_id"))
        label = (request.form.get("label") or "").strip()
        schedule = _normalize_saved_search_schedule(request.form.get("schedule"))
        next_url = request.form.get("next") or url_for("admin_federal_data_dashboard_get_pacer_data")
        if not next_url.startswith("/"):
            next_url = url_for("admin_federal_data_dashboard_get_pacer_data")

        if not run_id:
            flash("Select a run to save.", "error")
            return redirect(next_url)

        run = _load_pacer_search_run(run_id)
        if not run:
            flash("Run not found. Refresh and try again.", "error")
            return redirect(next_url)

        search_type = str(run.get("search_type") or "case")
        search_mode = str(run.get("search_mode") or "immediate")
        criteria_json = run.get("criteria_json")
        if not criteria_json:
            flash("Run criteria missing; cannot save this search.", "error")
            return redirect(next_url)

        criteria = _parse_search_request_criteria(criteria_json)
        if not label:
            label = _default_saved_search_label(
                search_type=search_type,
                search_mode=search_mode,
                criteria=criteria,
            )

        created_by = "Admin"
        if g.current_user:
            created_by = (
                g.current_user.get("email")
                or g.current_user.get("name")
                or str(g.current_user.get("id") or "Admin")
            )

        pacer_saved_searches = pcl_tables["pacer_saved_searches"]
        with engine.begin() as conn:
            conn.execute(
                insert(pacer_saved_searches).values(
                    label=label,
                    search_type=search_type,
                    search_mode=search_mode,
                    criteria_json=criteria_json,
                    schedule=schedule,
                    created_by=created_by,
                )
            )

        flash("Saved search created.", "success")
        return redirect(next_url)

    @app.post("/admin/pacer/saved-searches/<int:search_id>/delete")
    @admin_required
    def admin_pacer_saved_search_delete(search_id: int):
        require_csrf()
        next_url = request.form.get("next") or url_for("admin_federal_data_dashboard_get_pacer_data")
        if not next_url.startswith("/"):
            next_url = url_for("admin_federal_data_dashboard_get_pacer_data")
        pacer_saved_searches = pcl_tables["pacer_saved_searches"]
        now = datetime.utcnow()
        with engine.begin() as conn:
            conn.execute(
                update(pacer_saved_searches)
                .where(pacer_saved_searches.c.id == search_id)
                .values(active=False, updated_at=now)
            )
        flash("Saved search removed.", "success")
        return redirect(next_url)

    @app.get("/admin/pacer/explore")
    @admin_required
    def admin_pacer_explore():
        pacer_session = _get_pacer_session()
        pacer_authenticated = bool(pacer_session)
        pacer_search_disabled = bool(session.get("pacer_search_disabled"))
        pacer_search_enabled = bool(pacer_authenticated and _pacer_search_enabled())
        env_config = app.config.get("PACER_ENV_CONFIG") or {}
        auth_env = env_config.get("auth_env", "unknown")
        pcl_env = env_config.get("pcl_env", "unknown")
        billable_flag = pacer_env_billable(str(pcl_env))
        billable_label = (
            "Yes" if billable_flag is True else "No" if billable_flag is False else "Unknown"
        )
        mode = (request.args.get("mode") or "cases").strip().lower()
        if mode not in {"cases", "parties"}:
            mode = "cases"
        return _render_pacer_explore_with_result(
            mode=mode,
            case_values=None,
            party_values=None,
            run_result=None,
            pacer_authorized=pacer_search_enabled,
        )

    @app.post("/admin/pacer/explore/run")
    @admin_required
    def admin_pacer_explore_run():
        require_csrf()
        pacer_session = _get_pacer_session()
        env_config = app.config.get("PACER_ENV_CONFIG") or {}
        auth_env = env_config.get("auth_env", "unknown")
        pcl_env = env_config.get("pcl_env", "unknown")
        billable_flag = pacer_env_billable(str(pcl_env))
        billable_label = (
            "Yes" if billable_flag is True else "No" if billable_flag is False else "Unknown"
        )
        courts = _load_court_choices()
        court_ids = {row["court_id"] for row in courts}
        mode = (request.form.get("mode") or "cases").strip().lower()
        if mode not in {"cases", "parties"}:
            mode = "cases"
        ui_inputs = collect_ui_inputs(
            request.form.to_dict(flat=False),
            multi_keys={"case_types"},
        )
        ui_inputs["court_id"] = (ui_inputs.get("court_id") or "").strip().lower()
        unexpected_input_keys = validate_ui_inputs(mode, ui_inputs)
        if unexpected_input_keys:
            app.logger.info(
                "PACER explore unexpected input keys: %s", ", ".join(unexpected_input_keys)
            )
        search_mode_raw = str(ui_inputs.get("search_mode") or "").strip().lower()
        search_mode = search_mode_raw or "immediate"
        if search_mode_raw and search_mode_raw not in {"immediate", "batch"}:
            search_mode = "immediate"
        saved_search_id = _parse_optional_int(request.form.get("saved_search_id"))

        case_values = None
        party_values = None
        if mode == "cases":
            case_values = {
                "search_mode": search_mode,
                "court_id": ui_inputs.get("court_id", ""),
                "date_filed_from": ui_inputs.get("date_filed_from", ""),
                "date_filed_to": ui_inputs.get("date_filed_to", ""),
                "page": ui_inputs.get("page", "") or 1,
                "max_records": ui_inputs.get("max_records", ""),
                "case_types": ui_inputs.get("case_types") or [],
            }
            if search_mode == "batch":
                max_records, max_records_warning = _clamp_max_records(
                    case_values["max_records"]
                )
            else:
                max_records = PCL_PAGE_SIZE
                max_records_warning = None
        else:
            raw_exact_name_match = ui_inputs.get("exact_name_match")
            exact_name_match = False
            if isinstance(raw_exact_name_match, bool):
                exact_name_match = raw_exact_name_match
            elif raw_exact_name_match is not None:
                exact_name_match = str(raw_exact_name_match).strip().lower() in {
                    "1",
                    "true",
                    "yes",
                    "on",
                }
            party_values = {
                "search_mode": search_mode,
                "last_name": ui_inputs.get("last_name", ""),
                "exact_name_match": exact_name_match,
                "first_name": ui_inputs.get("first_name", ""),
                "date_filed_from": ui_inputs.get("date_filed_from", ""),
                "date_filed_to": ui_inputs.get("date_filed_to", ""),
                "court_id": ui_inputs.get("court_id", ""),
                "page": ui_inputs.get("page", "") or 1,
                "max_records": ui_inputs.get("max_records", ""),
            }
            if search_mode == "batch":
                max_records, max_records_warning = _clamp_max_records(
                    party_values["max_records"]
                )
            else:
                max_records = PCL_PAGE_SIZE
                max_records_warning = None

        requested_page: Optional[int] = None
        page_warning: Optional[str] = None

        run_result: Dict[str, Any] = {
            "status": "error",
            "mode": mode,
            "search_mode": search_mode,
            "errors": [],
            "warnings": [],
            "logs": [],
            "receipts": [],
            "page_infos": [],
            "cases": [],
            "parties": [],
            "observed_fields": [],
            "party_observed_fields": [],
            "court_case_observed_fields": [],
            "cost_summary": {"billable_pages": 0, "fee_totals": {}},
            "debug_bundle": "",
            "response_snippets": [],
            "pages_requested": 0,
            "pages_fetched": 0,
            "truncated_notice": None,
            "endpoint": "",
            "report_request": None,
            "page_info": None,
            "page_number": None,
            "next_steps": [],
        }

        if search_mode_raw and search_mode_raw not in {"immediate", "batch"}:
            run_result["errors"].append(
                "Search mode must be Immediate or Batch."
            )

        if search_mode == "immediate":
            page_source = (case_values or party_values or {}).get("page", "")
            requested_page, page_warning = _parse_page_number(page_source)
            run_result["page_number"] = requested_page
            if page_warning:
                run_result["warnings"].append(page_warning)

        token_record = pacer_token_store.get_token()
        token_diagnostics = _token_diagnostics(token_record)
        app.logger.info("PACER explore token diagnostics: %s", token_diagnostics)
        request_body: Dict[str, Any] = {}
        pages_requested = 0
        pages_to_fetch = 0
        truncated_notice = None
        request_urls: List[str] = []
        date_from: Optional[datetime.date] = None
        date_to: Optional[datetime.date] = None

        def render_response(pacer_authorized: bool) -> str:
            return _render_pacer_explore_with_result(
                mode=mode,
                case_values=case_values,
                party_values=party_values,
                run_result=run_result,
                pacer_authorized=pacer_authorized,
            )

        if not pacer_session:
            run_result["errors"].append(
                "PACER authorization is required. Next step: click Authorize on the Get PACER Data page."
            )
            run_result["debug_bundle"] = _build_debug_bundle(
                mode=mode,
                search_mode=search_mode,
                court_id=(case_values or party_values or {}).get("court_id", ""),
                date_filed_from=(case_values or party_values or {}).get(
                    "date_filed_from", ""
                ),
                date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
                last_name=party_values.get("last_name") if party_values else None,
                exact_name_match=party_values.get("exact_name_match") if party_values else None,
                first_name=party_values.get("first_name") if party_values else None,
                max_records=max_records,
                requested_page=requested_page,
                unexpected_input_keys=unexpected_input_keys,
                pages_requested=0,
                pages_fetched=0,
                request_body={},
                request_urls=request_urls,
                status_codes=[],
                records=[],
                page_infos=[],
                truncated_notice=None,
                error_message=run_result["errors"][0],
                response_snippets=[],
                environment=app.config.get("PACER_ENV_CONFIG"),
                token_diagnostics=token_diagnostics,
            )
            request_params = {
                "mode": mode,
                "search_mode": search_mode,
                "max_records": max_records,
                "page_number": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "request_body": {},
                "response_samples": [],
            }
            if mode == "cases" and case_values:
                request_params.update(
                    {
                        "court_id": case_values["court_id"],
                        "date_filed_from": case_values["date_filed_from"],
                        "date_filed_to": case_values["date_filed_to"],
                        "case_types": case_values["case_types"],
                    }
                )
            elif party_values:
                request_params.update(
                    {
                        "court_id": party_values["court_id"],
                        "last_name": party_values["last_name"],
                        "exact_name_match": party_values["exact_name_match"],
                        "first_name": party_values["first_name"],
                        "ssn": party_values.get("ssn"),
                        "date_filed_from": party_values["date_filed_from"],
                        "date_filed_to": party_values["date_filed_to"],
                    }
                )
            _store_pacer_explore_run(
                mode=mode,
                court_id=(case_values or party_values or {}).get("court_id"),
                date_from=None,
                date_to=None,
                request_params=request_params,
                pages_fetched=0,
                receipts=[],
                observed_fields=None,
                error_summary=run_result["errors"][0],
            )
            return render_response(False)

        if _pacer_search_disabled():
            run_result["errors"].append(
                "PACER authenticated, but searching is disabled. "
                "Next step: add a client code and re-authorize."
            )
            run_result["debug_bundle"] = _build_debug_bundle(
                mode=mode,
                search_mode=search_mode,
                court_id=(case_values or party_values or {}).get("court_id", ""),
                date_filed_from=(case_values or party_values or {}).get(
                    "date_filed_from", ""
                ),
                date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
                last_name=party_values.get("last_name") if party_values else None,
                exact_name_match=party_values.get("exact_name_match") if party_values else None,
                first_name=party_values.get("first_name") if party_values else None,
                max_records=max_records,
                requested_page=requested_page,
                unexpected_input_keys=unexpected_input_keys,
                pages_requested=0,
                pages_fetched=0,
                request_body={},
                request_urls=[],
                status_codes=[],
                records=[],
                page_infos=[],
                truncated_notice=None,
                error_message=run_result["errors"][0],
                response_snippets=[],
                environment=app.config.get("PACER_ENV_CONFIG"),
                token_diagnostics=token_diagnostics,
            )
            request_params = {
                "mode": mode,
                "search_mode": search_mode,
                "max_records": max_records,
                "page_number": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "request_body": {},
                "response_samples": [],
            }
            _store_pacer_explore_run(
                mode=mode,
                court_id=(case_values or party_values or {}).get("court_id"),
                date_from=None,
                date_to=None,
                request_params=request_params,
                pages_fetched=0,
                receipts=[],
                observed_fields=None,
                error_summary=run_result["errors"][0],
            )
            return render_response(False)

        if app.config.get("PACER_ENV_MISMATCH"):
            mismatch_reason = app.config.get("PACER_ENV_MISMATCH_REASON") or (
                "PACER auth and PCL environments do not match."
            )
            run_result["errors"].append(
                f"PACER environments mismatch. {mismatch_reason}"
            )
            run_result["debug_bundle"] = _build_debug_bundle(
                mode=mode,
                search_mode=search_mode,
                court_id=(case_values or party_values or {}).get("court_id", ""),
                date_filed_from=(case_values or party_values or {}).get(
                    "date_filed_from", ""
                ),
                date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
                last_name=party_values.get("last_name") if party_values else None,
                exact_name_match=party_values.get("exact_name_match") if party_values else None,
                first_name=party_values.get("first_name") if party_values else None,
                max_records=max_records,
                requested_page=requested_page,
                unexpected_input_keys=unexpected_input_keys,
                pages_requested=0,
                pages_fetched=0,
                request_body={},
                request_urls=[],
                status_codes=[],
                records=[],
                page_infos=[],
                truncated_notice=None,
                error_message=run_result["errors"][0],
                response_snippets=[],
                environment=app.config.get("PACER_ENV_CONFIG"),
                token_diagnostics=token_diagnostics,
            )
            request_params = {
                "mode": mode,
                "search_mode": search_mode,
                "max_records": max_records,
                "page_number": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "request_body": {},
                "response_samples": [],
            }
            _store_pacer_explore_run(
                mode=mode,
                court_id=(case_values or party_values or {}).get("court_id"),
                date_from=None,
                date_to=None,
                request_params=request_params,
                pages_fetched=0,
                receipts=[],
                observed_fields=None,
                error_summary=run_result["errors"][0],
            )
            return render_response(False)

        if token_record and not _pacer_token_matches_pcl():
            run_result["errors"].append(
                _pacer_token_mismatch_message(token_record.environment)
            )
            run_result["debug_bundle"] = _build_debug_bundle(
                mode=mode,
                search_mode=search_mode,
                court_id=(case_values or party_values or {}).get("court_id", ""),
                date_filed_from=(case_values or party_values or {}).get(
                    "date_filed_from", ""
                ),
                date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
                last_name=party_values.get("last_name") if party_values else None,
                exact_name_match=party_values.get("exact_name_match") if party_values else None,
                first_name=party_values.get("first_name") if party_values else None,
                max_records=max_records,
                requested_page=requested_page,
                unexpected_input_keys=unexpected_input_keys,
                pages_requested=0,
                pages_fetched=0,
                request_body={},
                request_urls=[],
                status_codes=[],
                records=[],
                page_infos=[],
                truncated_notice=None,
                error_message=run_result["errors"][0],
                response_snippets=[],
                environment=app.config.get("PACER_ENV_CONFIG"),
                token_diagnostics=token_diagnostics,
            )
            request_params = {
                "mode": mode,
                "search_mode": search_mode,
                "max_records": max_records,
                "page_number": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "request_body": {},
                "response_samples": [],
            }
            _store_pacer_explore_run(
                mode=mode,
                court_id=(case_values or party_values or {}).get("court_id"),
                date_from=None,
                date_to=None,
                request_params=request_params,
                pages_fetched=0,
                receipts=[],
                observed_fields=None,
                error_summary=run_result["errors"][0],
            )
            return render_response(False)

        if mode == "cases":
            if case_values["court_id"] not in court_ids:
                run_result["errors"].append("Select a valid court from the list.")

            date_from = _parse_iso_date(case_values["date_filed_from"])
            date_to = _parse_iso_date(case_values["date_filed_to"])
            if not date_from or not date_to:
                run_result["errors"].append(
                    "Enter a valid date filed range using YYYY-MM-DD."
                )
            elif date_from > date_to:
                run_result["errors"].append(
                    "Date filed from must be on or before date filed to."
                )
        else:
            if party_values["court_id"] and party_values["court_id"] not in court_ids:
                run_result["errors"].append("Select a valid court from the list.")
            if not party_values["last_name"]:
                run_result["errors"].append("Last name is required.")
            date_from = _parse_iso_date(party_values["date_filed_from"])
            date_to = _parse_iso_date(party_values["date_filed_to"])
            if party_values["date_filed_from"] or party_values["date_filed_to"]:
                if not date_from or not date_to:
                    run_result["errors"].append(
                        "Enter a valid filed date range using YYYY-MM-DD."
                    )
                elif date_from > date_to:
                    run_result["errors"].append(
                        "Date filed from must be on or before date filed to."
                    )

        if search_mode == "batch" and max_records_warning:
            run_result["warnings"].append(max_records_warning)

        pages_requested = 1
        pages_to_fetch = 1
        if search_mode == "batch":
            pages_requested = max(1, math.ceil(max_records / PCL_PAGE_SIZE))
            if pages_requested > PCL_BATCH_MAX_PAGES:
                run_result["errors"].append(
                    "Batch searches are limited to 2,000 pages. "
                    "Reduce max records or narrow the search."
                )
        else:
            if requested_page and requested_page > PCL_IMMEDIATE_MAX_PAGES:
                run_result["errors"].append(
                    "Immediate searches are limited to 100 pages. "
                    "Use Batch mode for larger runs."
                )

        if mode == "cases":
            request_body = build_case_search_payload(ui_inputs)
        else:
            request_body = build_party_search_payload(
                ui_inputs,
                include_date_range=bool(date_from and date_to),
            )

        endpoint_base = (
            f"{pcl_base_url}/cases/find"
            if mode == "cases"
            else f"{pcl_base_url}/parties/find"
        )
        batch_endpoint_base = (
            f"{pcl_base_url}/cases/download"
            if mode == "cases"
            else f"{pcl_base_url}/parties/download"
        )
        if search_mode == "immediate":
            api_page = max(0, (requested_page or 1) - 1)
            request_urls = [f"{endpoint_base}?page={api_page}"]
        else:
            request_urls = [batch_endpoint_base]

        if not run_result["errors"]:
            valid_payload, invalid_keys, missing_keys = validate_pcl_payload(
                mode, request_body
            )
            if not valid_payload:
                run_result["errors"].append(
                    "Internal payload validation failed before contacting PCL."
                )
                if invalid_keys:
                    run_result["errors"].append(
                        f"Invalid payload keys: {', '.join(invalid_keys)}."
                    )
                if missing_keys:
                    run_result["errors"].append(
                        f"Missing required payload keys: {', '.join(missing_keys)}."
                    )
                run_result["errors"].append(
                    "Next step: Copy debug bundle and open a fix request."
                )

        if run_result["errors"]:
            run_result["debug_bundle"] = _build_debug_bundle(
                mode=mode,
                search_mode=search_mode,
                court_id=(case_values or party_values or {}).get("court_id", ""),
                date_filed_from=(case_values or party_values or {}).get(
                    "date_filed_from", ""
                ),
                date_filed_to=(case_values or party_values or {}).get(
                    "date_filed_to", ""
                ),
                last_name=party_values.get("last_name") if party_values else None,
                exact_name_match=party_values.get("exact_name_match") if party_values else None,
                first_name=party_values.get("first_name") if party_values else None,
                max_records=max_records,
                requested_page=requested_page,
                unexpected_input_keys=unexpected_input_keys,
                pages_requested=pages_requested,
                pages_fetched=0,
                request_body=request_body,
                request_urls=request_urls,
                status_codes=[],
                records=[],
                page_infos=[],
                truncated_notice=truncated_notice,
                error_message="; ".join(run_result["errors"]),
                response_snippets=[],
                environment=app.config.get("PACER_ENV_CONFIG"),
                token_diagnostics=token_diagnostics,
            )
            request_params = {
                "mode": mode,
                "search_mode": search_mode,
                "max_records": max_records,
                "pages_requested": pages_requested,
                "page_number": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "request_body": request_body,
                "response_samples": [],
            }
            if mode == "cases":
                request_params.update(
                    {
                        "court_id": case_values["court_id"],
                        "date_filed_from": case_values["date_filed_from"],
                        "date_filed_to": case_values["date_filed_to"],
                        "case_types": case_values["case_types"],
                    }
                )
            else:
                request_params.update(
                    {
                        "court_id": party_values["court_id"],
                        "last_name": party_values["last_name"],
                        "exact_name_match": party_values["exact_name_match"],
                        "first_name": party_values["first_name"],
                        "date_filed_from": party_values["date_filed_from"],
                        "date_filed_to": party_values["date_filed_to"],
                    }
                )
            _store_pacer_explore_run(
                mode=mode,
                court_id=(case_values or party_values or {}).get("court_id"),
                date_from=date_from,
                date_to=date_to,
                request_params=request_params,
                pages_fetched=0,
                receipts=[],
                observed_fields=None,
                error_summary="; ".join(run_result["errors"]),
            )
            return render_response(_pacer_token_matches_pcl())

        if search_mode == "batch":
            app.logger.info(
                "PACER explore batch submit mode=%s",
                mode,
            )
            report_payload: Optional[Dict[str, Any]] = None
            report_error: Optional[str] = None
            report_details: Optional[str] = None
            report_code_details: Optional[str] = None
            try:
                if mode == "cases":
                    report_payload = pcl_client.start_case_download(request_body)
                else:
                    report_payload = pcl_client.start_party_download(request_body)
            except TokenExpired:
                report_error = (
                    "Token expired or invalid. Next step: re-authorize from the Get PACER Data page."
                )
            except PclApiError as exc:
                report_error = f"PCL request failed with status {exc.status_code}."
                report_details = exc.message
                report_code_details = _format_pacer_response_code(exc.status_code)
            except Exception as exc:  # pragma: no cover - defensive guardrail
                report_error = "Unexpected error while submitting batch report."
                report_details = str(exc)
                app.logger.exception("Unexpected PACER batch submit error.")

            if report_error:
                run_result["errors"].append(report_error)
                if report_details:
                    run_result["errors"].append(report_details)
                if report_code_details:
                    run_result["errors"].append(report_code_details)
                run_result["debug_bundle"] = _build_debug_bundle(
                    mode=mode,
                    search_mode=search_mode,
                    court_id=(case_values or party_values or {}).get("court_id", ""),
                    date_filed_from=(case_values or party_values or {}).get(
                        "date_filed_from", ""
                    ),
                    date_filed_to=(case_values or party_values or {}).get(
                        "date_filed_to", ""
                    ),
                    last_name=party_values.get("last_name") if party_values else None,
                    exact_name_match=party_values.get("exact_name_match") if party_values else None,
                    first_name=party_values.get("first_name") if party_values else None,
                    max_records=max_records,
                    requested_page=requested_page,
                    unexpected_input_keys=unexpected_input_keys,
                    pages_requested=pages_requested,
                    pages_fetched=0,
                    request_body=request_body,
                    request_urls=request_urls,
                    status_codes=[],
                    records=[],
                    page_infos=[],
                    truncated_notice=None,
                    error_message="; ".join(run_result["errors"]),
                    response_snippets=[],
                    environment=app.config.get("PACER_ENV_CONFIG"),
                    token_diagnostics=token_diagnostics,
                )
                request_params = {
                    "mode": mode,
                    "search_mode": search_mode,
                    "max_records": max_records,
                    "pages_requested": pages_requested,
                    "page_number": requested_page,
                    "page_size": PCL_PAGE_SIZE,
                    "request_body": request_body,
                    "response_samples": [],
                }
                _store_pacer_explore_run(
                    mode=mode,
                    court_id=(case_values or party_values or {}).get("court_id"),
                    date_from=date_from,
                    date_to=date_to,
                    request_params=request_params,
                    pages_fetched=0,
                    receipts=[],
                    observed_fields=None,
                    error_summary="; ".join(run_result["errors"]),
                )
                return render_response(_pacer_token_matches_pcl())

            report_info = _extract_report_info(report_payload or {})
            report_id = report_info.get("reportId") or report_payload.get("reportId")
            report_status = _normalize_report_status(report_info.get("status") or "SUBMITTED")
            criteria_payload = {
                "ui_inputs": ui_inputs,
                "request_body": request_body,
            }
            request_id = _store_pacer_search_request(
                search_type="case" if mode == "cases" else "party",
                search_mode=search_mode,
                criteria=criteria_payload,
                report_id=str(report_id) if report_id is not None else None,
                report_status=report_status,
                report_meta=report_info,
            )
            run_result.update(
                {
                    "status": "ok",
                    "endpoint": batch_endpoint_base,
                    "pages_requested": pages_requested,
                    "pages_fetched": 0,
                    "report_request": {
                        "request_id": request_id,
                        "report_id": report_id,
                        "status": report_status,
                        "info": report_info,
                    },
                }
            )
            request_params = {
                "mode": mode,
                "search_mode": search_mode,
                "max_records": max_records,
                "pages_requested": pages_requested,
                "page_number": requested_page,
                "page_size": PCL_PAGE_SIZE,
                "request_body": request_body,
                "response_samples": [],
            }
            _store_pacer_explore_run(
                mode=mode,
                court_id=(case_values or party_values or {}).get("court_id"),
                date_from=date_from,
                date_to=date_to,
                request_params=request_params,
                pages_fetched=0,
                receipts=[],
                observed_fields=None,
                error_summary=None,
            )
            return render_response(_pacer_token_matches_pcl())
        status_codes: List[int] = []
        response_snippets: List[Dict[str, Any]] = []
        all_records: List[Dict[str, Any]] = []
        receipts: List[Dict[str, Any]] = []
        page_infos: List[Dict[str, Any]] = []
        logs: List[Dict[str, Any]] = []

        if mode == "cases":
            app.logger.info(
                "PACER explore run mode=cases court=%s date_from=%s date_to=%s pages=%s",
                case_values["court_id"],
                case_values["date_filed_from"],
                case_values["date_filed_to"],
                pages_to_fetch,
            )
        else:
            app.logger.info(
                "PACER explore run mode=parties court=%s last_name=%s pages=%s",
                party_values["court_id"],
                party_values["last_name"],
                pages_to_fetch,
            )

        error_message: Optional[str] = None
        error_details: Optional[str] = None
        trace_text: Optional[str] = None

        api_page = max(0, (requested_page or 1) - 1)
        api_pages = [api_page]
        last_payload: Optional[Dict[str, Any]] = None

        for api_page in api_pages:
            display_page = api_page + 1
            endpoint_url = f"{endpoint_base}?page={api_page}"
            started = time.perf_counter()
            try:
                if mode == "cases":
                    response = pcl_client.immediate_case_search(api_page, request_body)
                else:
                    response = pcl_client.immediate_party_search(api_page, request_body)
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
                payload = response.payload
                last_payload = payload
                status_codes.append(response.status_code)
                response_snippets.append(
                    {
                        "page": display_page,
                        "api_page": api_page,
                        "status_code": response.status_code,
                        "endpoint": endpoint_url,
                        "snippet": _truncate_value(payload),
                    }
                )
                if mode == "cases":
                    page_records = _extract_case_records(payload)
                else:
                    page_records = _extract_party_records(payload)
                all_records.extend(page_records)
                receipt = payload.get("receipt") or payload.get("receiptData")
                if isinstance(receipt, dict):
                    receipts.append({"page": display_page, "receipt": receipt})
                page_info = payload.get("pageInfo")
                if isinstance(page_info, dict):
                    page_infos.append(
                        {
                            "human_display_page": display_page,
                            "api_page": api_page,
                            "page_info": page_info,
                        }
                    )
                if mode == "cases":
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                        "caseType": request_body.get("caseType", []),
                    }
                else:
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "lastName": request_body.get("lastName"),
                        "exactNameMatch": request_body.get("exactNameMatch"),
                        "firstName": request_body.get("firstName"),
                        "ssn": request_body.get("ssn"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                    }
                logs.append(
                    {
                        "page": display_page,
                        "human_display_page": display_page,
                        "api_page": api_page,
                        "timestamp": datetime.utcnow().isoformat(),
                        "endpoint": endpoint_url,
                        "status_code": response.status_code,
                        "elapsed_ms": elapsed_ms,
                        "request_summary": request_summary,
                    }
                )
            except TokenExpired:
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
                error_message = (
                    "Token expired or invalid. Next step: re-authorize from the Get PACER Data page."
                )
                status_codes.append(401)
                if mode == "cases":
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                        "caseType": request_body.get("caseType", []),
                    }
                else:
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "lastName": request_body.get("lastName"),
                        "exactNameMatch": request_body.get("exactNameMatch"),
                        "firstName": request_body.get("firstName"),
                        "ssn": request_body.get("ssn"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                    }
                logs.append(
                    {
                        "page": display_page,
                        "human_display_page": display_page,
                        "api_page": api_page,
                        "timestamp": datetime.utcnow().isoformat(),
                        "endpoint": endpoint_url,
                        "status_code": 401,
                        "elapsed_ms": elapsed_ms,
                        "request_summary": request_summary,
                    }
                )
                response_snippets.append(
                    {
                        "page": display_page,
                        "api_page": api_page,
                        "status_code": 401,
                        "endpoint": endpoint_url,
                        "snippet": {"message": error_message},
                    }
                )
                break
            except PclApiError as exc:
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
                status_codes.append(exc.status_code)
                snippet_payload = _truncate_value(exc.details or {"message": exc.message})
                code_details = _format_pacer_response_code(exc.status_code)
                response_snippets.append(
                    {
                        "page": display_page,
                        "api_page": api_page,
                        "status_code": exc.status_code,
                        "endpoint": endpoint_url,
                        "snippet": snippet_payload,
                    }
                )
                if exc.status_code == 401:
                    error_message = (
                        "Token expired or invalid. Next step: re-authorize from the Get PACER Data page."
                    )
                elif exc.status_code == 406:
                    error_message = "PCL rejected the request parameters."
                else:
                    error_message = f"PCL request failed with status {exc.status_code}."
                if exc.status_code == 406:
                    error_details = (
                        f"Status {exc.status_code} · Endpoint: {endpoint_url} · "
                        f"Response: {snippet_payload}. Next step: Copy debug bundle and open a fix request."
                    )
                else:
                    error_details = exc.message
                if code_details:
                    error_details = f"{error_details} {code_details}" if error_details else code_details
                if mode == "cases":
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                        "caseType": request_body.get("caseType", []),
                    }
                else:
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "lastName": request_body.get("lastName"),
                        "exactNameMatch": request_body.get("exactNameMatch"),
                        "firstName": request_body.get("firstName"),
                        "ssn": request_body.get("ssn"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                    }
                logs.append(
                    {
                        "page": display_page,
                        "human_display_page": display_page,
                        "api_page": api_page,
                        "timestamp": datetime.utcnow().isoformat(),
                        "endpoint": endpoint_url,
                        "status_code": exc.status_code,
                        "elapsed_ms": elapsed_ms,
                        "request_summary": request_summary,
                    }
                )
                break
            except Exception as exc:  # pragma: no cover - defensive guardrail
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
                error_message = "Unexpected error while running PACER explore."
                error_details = str(exc)
                trace_text = traceback.format_exc()
                status_codes.append(0)
                if mode == "cases":
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                        "caseType": request_body.get("caseType", []),
                    }
                else:
                    request_summary = {
                        "courtId": request_body.get("courtId"),
                        "lastName": request_body.get("lastName"),
                        "exactNameMatch": request_body.get("exactNameMatch"),
                        "firstName": request_body.get("firstName"),
                        "ssn": request_body.get("ssn"),
                        "dateFiledFrom": request_body.get("dateFiledFrom"),
                        "dateFiledTo": request_body.get("dateFiledTo"),
                    }
                logs.append(
                    {
                        "page": display_page,
                        "human_display_page": display_page,
                        "api_page": api_page,
                        "timestamp": datetime.utcnow().isoformat(),
                        "endpoint": endpoint_url,
                        "status_code": 0,
                        "elapsed_ms": elapsed_ms,
                        "request_summary": request_summary,
                    }
                )
                response_snippets.append(
                    {
                        "page": display_page,
                        "api_page": api_page,
                        "status_code": 0,
                        "endpoint": endpoint_url,
                        "snippet": {"message": error_message},
                    }
                )
                app.logger.exception("Unexpected PACER explore error.")
                break

        records_limited = all_records[:max_records]
        observed_fields: Sequence[Dict[str, Any]] = []
        party_observed_fields: Sequence[Dict[str, Any]] = []
        court_case_observed_fields: Sequence[Dict[str, Any]] = []
        if mode == "cases":
            observed_fields = _observed_fields(records_limited)
        else:
            party_field_report = _observed_party_fields(records_limited)
            party_observed_fields = party_field_report["party"]
            court_case_observed_fields = party_field_report["court_case"]

        billable_pages_total = 0
        fee_totals: Dict[str, float] = {}
        for receipt_row in receipts:
            receipt_payload = receipt_row["receipt"]
            billable_pages_value = receipt_payload.get("billablePages")
            if isinstance(billable_pages_value, (int, float)):
                billable_pages_total += int(billable_pages_value)
            for key, value in receipt_payload.items():
                if "fee" not in str(key).lower():
                    continue
                if isinstance(value, (int, float)):
                    fee_totals[str(key)] = fee_totals.get(str(key), 0.0) + float(value)

        pages_fetched = len({log["page"] for log in logs})
        if pages_fetched and len(all_records) > max_records and not truncated_notice:
            truncated_notice = (
                f"Showing the first {max_records} records out of {len(all_records)} returned."
            )
            run_result["warnings"].append(truncated_notice)

        if error_message:
            run_result["errors"].append(error_message)
            if error_details:
                run_result["errors"].append(error_details)

        run_result.update(
            {
                "status": "ok" if not run_result["errors"] else "error",
                "logs": logs,
                "receipts": receipts,
                "page_infos": page_infos,
                "cases": records_limited if mode == "cases" else [],
                "parties": records_limited if mode == "parties" else [],
                "observed_fields": observed_fields,
                "party_observed_fields": party_observed_fields,
                "court_case_observed_fields": court_case_observed_fields,
                "cost_summary": {
                    "billable_pages": billable_pages_total,
                    "fee_totals": fee_totals,
                },
                "response_snippets": response_snippets,
                "pages_requested": pages_requested,
                "pages_fetched": pages_fetched,
                "truncated_notice": truncated_notice,
                "endpoint": endpoint_base,
                "page_number": requested_page,
                "raw_response": last_payload,
                "cases_view": _build_case_view_rows(
                    records_limited, default_court_id=default_court_id
                )
                if mode == "cases" and records_limited
                else None,
            }
        )
        if page_infos:
            run_result["page_info"] = page_infos[-1].get("page_info")
        if records_limited:
            run_result["store_payload"] = _build_store_payload(
                mode=mode,
                search_mode=search_mode,
                criteria={"ui_inputs": ui_inputs, "request_body": request_body},
                results=records_limited,
                receipts=receipts,
                page_info=run_result.get("page_info"),
                raw_response=last_payload,
                report_request=None,
            )

        run_result["debug_bundle"] = _build_debug_bundle(
            mode=mode,
            search_mode=search_mode,
            court_id=(case_values or party_values or {}).get("court_id", ""),
            date_filed_from=(case_values or party_values or {}).get("date_filed_from", ""),
            date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
            last_name=party_values.get("last_name") if party_values else None,
            exact_name_match=party_values.get("exact_name_match") if party_values else None,
            first_name=party_values.get("first_name") if party_values else None,
            max_records=max_records,
            requested_page=requested_page,
            unexpected_input_keys=unexpected_input_keys,
            pages_requested=pages_requested,
            pages_fetched=pages_fetched,
            request_body=request_body,
            request_urls=request_urls,
            status_codes=status_codes,
            records=records_limited,
            page_infos=page_infos,
            truncated_notice=truncated_notice,
            error_message="\n".join(run_result["errors"]) if run_result["errors"] else None,
            response_snippets=response_snippets,
            environment=app.config.get("PACER_ENV_CONFIG"),
            token_diagnostics=token_diagnostics,
        )
        if trace_text and run_result["errors"]:
            run_result["debug_bundle"] += f"\n\ntraceback:\n{trace_text}"

        if mode == "cases":
            run_result["next_steps"] = _build_next_steps(
                status_codes=status_codes,
                observed_fields=observed_fields,
            )
        else:
            run_result["next_steps"] = _build_next_steps(
                status_codes=status_codes,
                observed_fields=party_observed_fields,
                nested_observed_fields=court_case_observed_fields,
            )

        request_params = {
            "mode": mode,
            "search_mode": search_mode,
            "max_records": max_records,
            "pages_requested": pages_requested,
            "page_number": requested_page,
            "page_size": PCL_PAGE_SIZE,
            "request_body": request_body,
            "response_samples": response_snippets[:3],
        }
        if mode == "cases":
            request_params.update(
                {
                    "court_id": case_values["court_id"],
                    "date_filed_from": case_values["date_filed_from"],
                    "date_filed_to": case_values["date_filed_to"],
                    "case_types": case_values["case_types"],
                }
            )
            observed_fields_payload: Optional[Any] = observed_fields
        else:
            request_params.update(
                {
                    "court_id": party_values["court_id"],
                    "last_name": party_values["last_name"],
                    "exact_name_match": party_values["exact_name_match"],
                    "first_name": party_values["first_name"],
                    "ssn": party_values.get("ssn"),
                    "date_filed_from": party_values["date_filed_from"],
                    "date_filed_to": party_values["date_filed_to"],
                }
            )
            observed_fields_payload = {
                "party": party_observed_fields,
                "court_case": court_case_observed_fields,
            }

        _store_pacer_explore_run(
            mode=mode,
            court_id=(case_values or party_values or {}).get("court_id"),
            date_from=date_from,
            date_to=date_to,
            request_params=request_params,
            pages_fetched=pages_fetched,
            receipts=receipts,
            observed_fields=observed_fields_payload,
            error_summary="\n".join(run_result["errors"]) if run_result["errors"] else None,
        )

        if saved_search_id and not run_result["errors"]:
            _touch_pacer_saved_search(saved_search_id)

        return render_response(_pacer_token_matches_pcl())

    @app.post("/admin/pacer/explore/batch/status")
    @admin_required
    def admin_pacer_explore_batch_status():
        require_csrf()
        request_id = int(request.form.get("request_id") or 0)
        search_request = _load_pacer_search_request(request_id)
        if not search_request:
            run_result = {
                "status": "error",
                "mode": "cases",
                "search_mode": "batch",
                "errors": ["Batch request not found."],
                "warnings": [],
                "logs": [],
                "receipts": [],
                "page_infos": [],
                "cases": [],
                "parties": [],
                "observed_fields": [],
                "party_observed_fields": [],
                "court_case_observed_fields": [],
                "cost_summary": {"billable_pages": 0, "fee_totals": {}},
                "debug_bundle": "",
                "response_snippets": [],
                "pages_requested": 0,
                "pages_fetched": 0,
                "truncated_notice": None,
                "endpoint": "",
                "report_request": None,
                "page_info": None,
                "page_number": None,
                "next_steps": [],
            }
            return _render_pacer_explore_with_result(
                mode="cases",
                case_values=None,
                party_values=None,
                run_result=run_result,
                pacer_authorized=_pacer_token_matches_pcl(),
            )

        search_type = search_request.get("search_type") or "case"
        mode = "cases" if search_type == "case" else "parties"
        search_mode = search_request.get("search_mode") or "batch"
        criteria = _parse_search_request_criteria(search_request.get("criteria_json"))
        ui_inputs = criteria.get("ui_inputs") or {}
        case_values, party_values = _hydrate_explore_values(mode, ui_inputs, search_mode)
        report_id = search_request.get("report_id")

        run_result = {
            "status": "error",
            "mode": mode,
            "search_mode": search_mode,
            "errors": [],
            "warnings": [],
            "logs": [],
            "receipts": [],
            "page_infos": [],
            "cases": [],
            "parties": [],
            "observed_fields": [],
            "party_observed_fields": [],
            "court_case_observed_fields": [],
            "cost_summary": {"billable_pages": 0, "fee_totals": {}},
            "debug_bundle": "",
            "response_snippets": [],
            "pages_requested": 0,
            "pages_fetched": 0,
            "truncated_notice": None,
            "endpoint": "",
            "report_request": None,
            "page_info": None,
            "page_number": None,
            "next_steps": [],
        }

        if not report_id:
            run_result["errors"].append("Missing report ID for this batch request.")
            return _render_pacer_explore_with_result(
                mode=mode,
                case_values=case_values,
                party_values=party_values,
                run_result=run_result,
                pacer_authorized=_pacer_token_matches_pcl(),
            )

        status_payload: Optional[Dict[str, Any]] = None
        try:
            if mode == "cases":
                status_payload = pcl_client.get_case_download_status(str(report_id))
            else:
                status_payload = pcl_client.get_party_download_status(str(report_id))
        except TokenExpired:
            run_result["errors"].append(
                "Token expired or invalid. Next step: re-authorize from the Get PACER Data page."
            )
        except PclApiError as exc:
            _append_pcl_api_error(
                run_result["errors"],
                exc,
                prefix="PCL status check failed with",
            )
        except Exception as exc:  # pragma: no cover - defensive guardrail
            run_result["errors"].append("Unexpected error while checking report status.")
            run_result["errors"].append(str(exc))
            app.logger.exception("Unexpected PACER batch status error.")

        report_info = _extract_report_info(status_payload or {})
        report_status = _normalize_report_status(report_info.get("status"))
        if report_info:
            _update_pacer_search_request(
                request_id,
                report_status=report_status,
                report_meta=report_info,
            )
        run_result.update(
            {
                "status": "ok" if not run_result["errors"] else "error",
                "report_request": {
                    "request_id": request_id,
                    "report_id": report_id,
                    "status": report_status,
                    "info": report_info,
                },
            }
        )
        max_records, _ = _clamp_max_records(ui_inputs.get("max_records", ""))
        run_result["pages_requested"] = max(1, math.ceil(max_records / PCL_PAGE_SIZE))
        run_result["debug_bundle"] = _build_debug_bundle(
            mode=mode,
            search_mode=search_mode,
            court_id=(case_values or party_values or {}).get("court_id", ""),
            date_filed_from=(case_values or party_values or {}).get("date_filed_from", ""),
            date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
            last_name=party_values.get("last_name") if party_values else None,
            exact_name_match=party_values.get("exact_name_match") if party_values else None,
            first_name=party_values.get("first_name") if party_values else None,
            max_records=max_records,
            requested_page=None,
            unexpected_input_keys=[],
            pages_requested=run_result["pages_requested"],
            pages_fetched=0,
            request_body=criteria.get("request_body") or {},
            request_urls=[],
            status_codes=[],
            records=[],
            page_infos=[],
            truncated_notice=None,
            error_message="\n".join(run_result["errors"]) if run_result["errors"] else None,
            response_snippets=[],
            environment=app.config.get("PACER_ENV_CONFIG"),
            token_diagnostics=None,
        )

        return _render_pacer_explore_with_result(
            mode=mode,
            case_values=case_values,
            party_values=party_values,
            run_result=run_result,
            pacer_authorized=_pacer_token_matches_pcl(),
        )

    @app.post("/admin/pacer/explore/batch/load")
    @admin_required
    def admin_pacer_explore_batch_load():
        require_csrf()
        request_id = int(request.form.get("request_id") or 0)
        search_request = _load_pacer_search_request(request_id)
        if not search_request:
            abort(404, description="Batch request not found.")

        search_type = search_request.get("search_type") or "case"
        mode = "cases" if search_type == "case" else "parties"
        search_mode = search_request.get("search_mode") or "batch"
        criteria = _parse_search_request_criteria(search_request.get("criteria_json"))
        ui_inputs = criteria.get("ui_inputs") or {}
        case_values, party_values = _hydrate_explore_values(mode, ui_inputs, search_mode)
        report_id = search_request.get("report_id")

        run_result = {
            "status": "error",
            "mode": mode,
            "search_mode": search_mode,
            "errors": [],
            "warnings": [],
            "logs": [],
            "receipts": [],
            "page_infos": [],
            "cases": [],
            "parties": [],
            "observed_fields": [],
            "party_observed_fields": [],
            "court_case_observed_fields": [],
            "cost_summary": {"billable_pages": 0, "fee_totals": {}},
            "debug_bundle": "",
            "response_snippets": [],
            "pages_requested": 0,
            "pages_fetched": 0,
            "truncated_notice": None,
            "endpoint": "",
            "report_request": None,
            "page_info": None,
            "page_number": None,
            "next_steps": [],
        }

        if not report_id:
            run_result["errors"].append("Missing report ID for this batch request.")
            return _render_pacer_explore_with_result(
                mode=mode,
                case_values=case_values,
                party_values=party_values,
                run_result=run_result,
                pacer_authorized=_pacer_token_matches_pcl(),
            )

        status_payload: Optional[Dict[str, Any]] = None
        try:
            if mode == "cases":
                status_payload = pcl_client.get_case_download_status(str(report_id))
            else:
                status_payload = pcl_client.get_party_download_status(str(report_id))
        except TokenExpired:
            run_result["errors"].append(
                "Token expired or invalid. Next step: re-authorize from the Get PACER Data page."
            )
        except PclApiError as exc:
            _append_pcl_api_error(
                run_result["errors"],
                exc,
                prefix="PCL status check failed with",
            )
        except Exception as exc:  # pragma: no cover - defensive guardrail
            run_result["errors"].append("Unexpected error while checking report status.")
            run_result["errors"].append(str(exc))
            app.logger.exception("Unexpected PACER batch status error.")

        report_info = _extract_report_info(status_payload or {})
        report_status = _normalize_report_status(report_info.get("status"))
        if report_info:
            _update_pacer_search_request(
                request_id,
                report_status=report_status,
                report_meta=report_info,
            )

        if report_status != "COMPLETED":
            run_result["errors"].append("Report is not complete yet. Refresh status and try again.")
            run_result["report_request"] = {
                "request_id": request_id,
                "report_id": report_id,
                "status": report_status,
                "info": report_info,
            }
            return _render_pacer_explore_with_result(
                mode=mode,
                case_values=case_values,
                party_values=party_values,
                run_result=run_result,
                pacer_authorized=_pacer_token_matches_pcl(),
            )

        payload: Optional[Dict[str, Any]] = None
        try:
            if mode == "cases":
                payload = pcl_client.download_case_report(str(report_id))
            else:
                payload = pcl_client.download_party_report(str(report_id))
        except TokenExpired:
            run_result["errors"].append(
                "Token expired or invalid. Next step: re-authorize from the Get PACER Data page."
            )
        except PclApiError as exc:
            _append_pcl_api_error(
                run_result["errors"],
                exc,
                prefix="PCL report download failed with",
            )
        except Exception as exc:  # pragma: no cover - defensive guardrail
            run_result["errors"].append("Unexpected error while downloading report.")
            run_result["errors"].append(str(exc))
            app.logger.exception("Unexpected PACER batch download error.")

        records = _extract_case_records(payload or {}) if mode == "cases" else _extract_party_records(payload or {})
        if payload and not run_result["errors"]:
            run_result.update(
                {
                    "status": "ok",
                    "cases": records if mode == "cases" else [],
                    "parties": records if mode == "parties" else [],
                    "report_request": {
                        "request_id": request_id,
                        "report_id": report_id,
                        "status": report_status,
                        "info": report_info,
                    },
                    "raw_response": payload,
                }
            )
            if records:
                run_result["store_payload"] = _build_store_payload(
                    mode=mode,
                    search_mode=search_mode,
                    criteria=criteria,
                    results=records,
                    receipts=[],
                    page_info=None,
                    raw_response=payload,
                    report_request=run_result["report_request"],
                )

        max_records, _ = _clamp_max_records(ui_inputs.get("max_records", ""))
        run_result["pages_requested"] = max(1, math.ceil(max_records / PCL_PAGE_SIZE))
        run_result["debug_bundle"] = _build_debug_bundle(
            mode=mode,
            search_mode=search_mode,
            court_id=(case_values or party_values or {}).get("court_id", ""),
            date_filed_from=(case_values or party_values or {}).get("date_filed_from", ""),
            date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
            last_name=party_values.get("last_name") if party_values else None,
            exact_name_match=party_values.get("exact_name_match") if party_values else None,
            first_name=party_values.get("first_name") if party_values else None,
            max_records=max_records,
            requested_page=None,
            unexpected_input_keys=[],
            pages_requested=run_result["pages_requested"],
            pages_fetched=0,
            request_body=criteria.get("request_body") or {},
            request_urls=[],
            status_codes=[],
            records=records,
            page_infos=[],
            truncated_notice=None,
            error_message="\n".join(run_result["errors"]) if run_result["errors"] else None,
            response_snippets=[],
            environment=app.config.get("PACER_ENV_CONFIG"),
            token_diagnostics=None,
        )

        return _render_pacer_explore_with_result(
            mode=mode,
            case_values=case_values,
            party_values=party_values,
            run_result=run_result,
            pacer_authorized=_pacer_token_matches_pcl(),
        )

    @app.post("/admin/pacer/explore/store")
    @admin_required
    def admin_pacer_explore_store():
        require_csrf()
        payload_text = request.form.get("store_payload") or ""
        try:
            payload = json.loads(payload_text) if payload_text else {}
        except json.JSONDecodeError:
            payload = {}

        mode = (payload.get("mode") or "cases").strip().lower()
        if mode not in {"cases", "parties"}:
            mode = "cases"
        search_mode = (payload.get("search_mode") or "immediate").strip().lower()
        if search_mode not in {"immediate", "batch"}:
            search_mode = "immediate"

        run_result = _base_run_result(mode, search_mode)
        criteria = payload.get("criteria") if isinstance(payload.get("criteria"), dict) else {}
        ui_inputs = criteria.get("ui_inputs") if isinstance(criteria.get("ui_inputs"), dict) else {}
        case_values, party_values = _hydrate_explore_values(mode, ui_inputs, search_mode)

        results = payload.get("results") if isinstance(payload.get("results"), list) else []
        receipts = payload.get("receipts") if isinstance(payload.get("receipts"), list) else []
        page_info = payload.get("page_info") if isinstance(payload.get("page_info"), dict) else None
        raw_response = payload.get("raw_response") if isinstance(payload.get("raw_response"), dict) else None
        report_request = (
            payload.get("report_request")
            if isinstance(payload.get("report_request"), dict)
            else None
        )
        report_id = report_request.get("report_id") if report_request else None
        report_status = report_request.get("status") if report_request else None

        if not results:
            run_result["errors"].append("No results available to store.")
            return _render_pacer_explore_with_result(
                mode=mode,
                case_values=case_values,
                party_values=party_values,
                run_result=run_result,
                pacer_authorized=_pacer_token_matches_pcl(),
            )

        counts = _store_pacer_search_run(
            search_type="case" if mode == "cases" else "party",
            search_mode=search_mode,
            criteria=criteria,
            receipts=receipts,
            page_info=page_info,
            raw_response=raw_response,
            results=results,
            report_id=str(report_id) if report_id is not None else None,
            report_status=report_status,
        )
        run_result["save_summary"] = counts

        if mode == "cases":
            run_result["cases"] = results
            observed_fields = _observed_fields(results)
            run_result["observed_fields"] = observed_fields
            run_result["next_steps"] = _build_next_steps(
                status_codes=[],
                observed_fields=observed_fields,
            )
        else:
            run_result["parties"] = results
            party_field_report = _observed_party_fields(results)
            run_result["party_observed_fields"] = party_field_report["party"]
            run_result["court_case_observed_fields"] = party_field_report["court_case"]
            run_result["next_steps"] = _build_next_steps(
                status_codes=[],
                observed_fields=run_result["party_observed_fields"],
                nested_observed_fields=run_result["court_case_observed_fields"],
            )

        billable_pages_total = 0
        fee_totals: Dict[str, float] = {}
        for receipt_row in receipts:
            receipt_payload = receipt_row.get("receipt") if isinstance(receipt_row, dict) else None
            if not isinstance(receipt_payload, dict):
                continue
            billable_pages_value = receipt_payload.get("billablePages")
            if isinstance(billable_pages_value, (int, float)):
                billable_pages_total += int(billable_pages_value)
            for key, value in receipt_payload.items():
                if "fee" not in str(key).lower():
                    continue
                if isinstance(value, (int, float)):
                    fee_totals[str(key)] = fee_totals.get(str(key), 0.0) + float(value)

        run_result.update(
            {
                "status": "ok",
                "receipts": receipts,
                "page_info": page_info,
                "cost_summary": {
                    "billable_pages": billable_pages_total,
                    "fee_totals": fee_totals,
                },
                "report_request": report_request,
                "raw_response": raw_response,
            }
        )
        run_result["store_payload"] = _build_store_payload(
            mode=mode,
            search_mode=search_mode,
            criteria=criteria,
            results=results,
            receipts=receipts,
            page_info=page_info,
            raw_response=raw_response,
            report_request=report_request,
        )

        run_result["debug_bundle"] = _build_debug_bundle(
            mode=mode,
            search_mode=search_mode,
            court_id=(case_values or party_values or {}).get("court_id", ""),
            date_filed_from=(case_values or party_values or {}).get("date_filed_from", ""),
            date_filed_to=(case_values or party_values or {}).get("date_filed_to", ""),
            last_name=party_values.get("last_name") if party_values else None,
            exact_name_match=party_values.get("exact_name_match") if party_values else None,
            first_name=party_values.get("first_name") if party_values else None,
            max_records=len(results),
            requested_page=page_info.get("number") + 1 if page_info and page_info.get("number") is not None else None,
            unexpected_input_keys=[],
            pages_requested=1,
            pages_fetched=1,
            request_body=criteria.get("request_body") or {},
            request_urls=[],
            status_codes=[],
            records=results,
            page_infos=[{"page_info": page_info}] if page_info else [],
            truncated_notice=None,
            error_message=None,
            response_snippets=[],
            environment=app.config.get("PACER_ENV_CONFIG"),
            token_diagnostics=None,
        )

        flash(
            "Stored cases: {cases_inserted} new, {cases_updated} updated · "
            "Parties: {parties_inserted} new, {parties_updated} updated.".format(**counts),
            "success",
        )
        return _render_pacer_explore_with_result(
            mode=mode,
            case_values=case_values,
            party_values=party_values,
            run_result=run_result,
            pacer_authorized=_pacer_token_matches_pcl(),
        )

    @app.get("/admin/pacer/explore/batch/download/<int:request_id>")
    @admin_required
    def admin_pacer_explore_batch_download(request_id: int):
        search_request = _load_pacer_search_request(request_id)
        if not search_request:
            abort(404, description="Batch request not found.")
        report_id = search_request.get("report_id")
        if not report_id:
            abort(404, description="Batch request is missing a report ID.")
        search_type = search_request.get("search_type") or "case"
        try:
            if search_type == "case":
                payload = pcl_client.download_case_report(str(report_id))
            else:
                payload = pcl_client.download_party_report(str(report_id))
        except TokenExpired as exc:
            abort(401, description=str(exc))
        except PclApiError as exc:
            details = _format_pacer_response_code(exc.status_code)
            description = f"{exc.message} {details}" if details else exc.message
            abort(exc.status_code, description=description)

        response = make_response(json.dumps(payload, indent=2, sort_keys=True, default=str))
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="pcl-report-{report_id}.json"'
        )
        return response

    @app.post("/admin/pacer/explore/runs/<int:run_id>/delete")
    @admin_required
    def admin_pacer_explore_run_delete(run_id: int):
        require_csrf()
        pacer_explore_runs = pcl_tables["pacer_explore_runs"]
        with engine.begin() as conn:
            conn.execute(delete(pacer_explore_runs).where(pacer_explore_runs.c.id == run_id))
        flash("Explore PACER run deleted.", "success")
        mode = (request.form.get("mode") or "cases").strip().lower()
        if mode not in {"cases", "parties"}:
            mode = "cases"
        return redirect(url_for("admin_pacer_explore", mode=mode))

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
                session["pacer_search_disabled"] = False
                session["pacer_search_disabled_reason"] = None
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

        if not client_code:
            client_code = (
                json_payload.get("clientCode")
                or json_payload.get("pacer_client_code")
                or request.form.get("pacer_client_code", "")
            ).strip()

        if login_id.strip().upper() == "CPDADMIN":
            session["pacer_needs_otp"] = False
            session["pacer_client_code_required"] = False
            session["pacer_redaction_required"] = False
            session["pacer_search_disabled"] = False
            session["pacer_search_disabled_reason"] = None
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
            session["pacer_search_disabled"] = False
            session["pacer_search_disabled_reason"] = None
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
            session["pacer_search_disabled"] = False
            session["pacer_search_disabled_reason"] = None
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
            session["pacer_client_code_required"] = bool(result.needs_client_code)
            session["pacer_redaction_required"] = False
            session["pacer_search_disabled"] = bool(result.search_disabled)
            session["pacer_search_disabled_reason"] = result.search_disabled_reason
            if wants_json:
                return jsonify(
                    {
                        "authorized": True,
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": "authorized",
                        "search_enabled": not result.search_disabled,
                    }
                )
            if result.search_disabled:
                flash(
                    "PACER authenticated, but searching is disabled until a client code is supplied.",
                    "warning",
                )
            else:
                flash("PACER authentication successful.", "success")
        else:
            session["pacer_needs_otp"] = bool(result.needs_otp)
            session["pacer_client_code_required"] = bool(result.needs_client_code)
            session["pacer_redaction_required"] = bool(result.needs_redaction_ack)
            session["pacer_search_disabled"] = False
            session["pacer_search_disabled_reason"] = None
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
        session["pacer_search_disabled"] = False
        session["pacer_search_disabled_reason"] = None
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

    def _parse_federal_logs_limit() -> int:
        limit_raw = (request.args.get("limit") or "50").strip()
        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 50
        return max(1, min(limit, 200))

    def _get_federal_data_logs(limit: int) -> Dict[str, Any]:
        court_import_runs = pcl_tables["court_import_runs"]
        pacer_explore_runs = pcl_tables["pacer_explore_runs"]
        pcl_batch_searches = pcl_tables["pcl_batch_searches"]
        pcl_batch_requests = pcl_tables["pcl_batch_requests"]
        pcl_batch_segments = pcl_tables["pcl_batch_segments"]
        pcl_remote_jobs = pcl_tables["pcl_remote_jobs"]
        pcl_receipts = pcl_tables["pcl_receipts"]
        pcl_batch_receipts = pcl_tables["pcl_batch_receipts"]
        docket_enrichment_jobs = pcl_tables["docket_enrichment_jobs"]
        docket_enrichment_receipts = pcl_tables["docket_enrichment_receipts"]

        def _format_dt(value: Any) -> Optional[str]:
            if value is None:
                return None
            if hasattr(value, "isoformat"):
                try:
                    return value.isoformat(sep=" ", timespec="seconds")
                except TypeError:
                    return value.isoformat()
            return str(value)

        def _parse_json_value(value: Any) -> Any:
            if value is None:
                return None
            if isinstance(value, (dict, list)):
                return value
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return value

        def _serialize_rows(
            rows: Sequence[Dict[str, Any]],
            dt_fields: Sequence[str],
            json_fields: Sequence[str],
        ) -> List[Dict[str, Any]]:
            serialized: List[Dict[str, Any]] = []
            for row in rows:
                payload = dict(row)
                for field in dt_fields:
                    if field in payload:
                        payload[field] = _format_dt(payload.get(field))
                for field in json_fields:
                    if field in payload:
                        payload[field] = _parse_json_value(payload.get(field))
                serialized.append(payload)
            return serialized

        with engine.connect() as conn:
            court_import_rows = (
                conn.execute(
                    select(court_import_runs)
                    .order_by(
                        court_import_runs.c.created_at.desc(),
                        court_import_runs.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pacer_explore_rows = (
                conn.execute(
                    select(pacer_explore_runs)
                    .order_by(
                        pacer_explore_runs.c.created_at.desc(),
                        pacer_explore_runs.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pcl_batch_search_rows = (
                conn.execute(
                    select(pcl_batch_searches)
                    .order_by(
                        pcl_batch_searches.c.created_at.desc(),
                        pcl_batch_searches.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pcl_batch_request_rows = (
                conn.execute(
                    select(pcl_batch_requests)
                    .order_by(
                        pcl_batch_requests.c.created_at.desc(),
                        pcl_batch_requests.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pcl_batch_segment_rows = (
                conn.execute(
                    select(pcl_batch_segments)
                    .order_by(
                        pcl_batch_segments.c.created_at.desc(),
                        pcl_batch_segments.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pcl_remote_job_rows = (
                conn.execute(
                    select(pcl_remote_jobs)
                    .order_by(
                        pcl_remote_jobs.c.submitted_at.desc(),
                        pcl_remote_jobs.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pcl_receipt_rows = (
                conn.execute(
                    select(pcl_receipts)
                    .order_by(pcl_receipts.c.created_at.desc(), pcl_receipts.c.id.desc())
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            pcl_batch_receipt_rows = (
                conn.execute(
                    select(pcl_batch_receipts)
                    .order_by(
                        pcl_batch_receipts.c.created_at.desc(),
                        pcl_batch_receipts.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            docket_enrichment_job_rows = (
                conn.execute(
                    select(docket_enrichment_jobs)
                    .order_by(
                        docket_enrichment_jobs.c.created_at.desc(),
                        docket_enrichment_jobs.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            docket_enrichment_receipt_rows = (
                conn.execute(
                    select(docket_enrichment_receipts)
                    .order_by(
                        docket_enrichment_receipts.c.created_at.desc(),
                        docket_enrichment_receipts.c.id.desc(),
                    )
                    .limit(limit)
                )
                .mappings()
                .all()
            )

        court_import_runs_data = _serialize_rows(
            court_import_rows,
            dt_fields=["created_at", "completed_at"],
            json_fields=["details"],
        )
        pacer_explore_runs_data = _serialize_rows(
            pacer_explore_rows,
            dt_fields=["created_at", "date_from", "date_to"],
            json_fields=["request_params", "receipts", "observed_fields"],
        )
        pcl_batch_searches_data = _serialize_rows(
            pcl_batch_search_rows,
            dt_fields=["created_at", "updated_at", "date_filed_from", "date_filed_to"],
            json_fields=["advanced_filters"],
        )
        pcl_batch_requests_data = _serialize_rows(
            pcl_batch_request_rows,
            dt_fields=[
                "created_at",
                "updated_at",
                "date_filed_from",
                "date_filed_to",
                "last_run_at",
            ],
            json_fields=[],
        )
        pcl_batch_segments_data = _serialize_rows(
            pcl_batch_segment_rows,
            dt_fields=[
                "created_at",
                "updated_at",
                "date_filed_from",
                "date_filed_to",
                "segment_from",
                "segment_to",
                "submitted_at",
                "completed_at",
                "next_poll_at",
            ],
            json_fields=[],
        )
        pcl_remote_jobs_data = _serialize_rows(
            pcl_remote_job_rows,
            dt_fields=["submitted_at", "last_polled_at", "deleted_from_pacer_at"],
            json_fields=[],
        )
        pcl_receipts_data = _serialize_rows(
            pcl_receipt_rows,
            dt_fields=["created_at"],
            json_fields=["raw_payload"],
        )
        pcl_batch_receipts_data = _serialize_rows(
            pcl_batch_receipt_rows,
            dt_fields=["created_at"],
            json_fields=["receipt_json"],
        )
        docket_enrichment_jobs_data = _serialize_rows(
            docket_enrichment_job_rows,
            dt_fields=["created_at", "updated_at", "started_at", "finished_at"],
            json_fields=[],
        )
        docket_enrichment_receipts_data = _serialize_rows(
            docket_enrichment_receipt_rows,
            dt_fields=["created_at"],
            json_fields=["receipt_json"],
        )

        return {
            "limit": limit,
            "court_import_runs": court_import_runs_data,
            "pacer_explore_runs": pacer_explore_runs_data,
            "pcl_batch_searches": pcl_batch_searches_data,
            "pcl_batch_requests": pcl_batch_requests_data,
            "pcl_batch_segments": pcl_batch_segments_data,
            "pcl_remote_jobs": pcl_remote_jobs_data,
            "pcl_receipts": pcl_receipts_data,
            "pcl_batch_receipts": pcl_batch_receipts_data,
            "docket_enrichment_jobs": docket_enrichment_jobs_data,
            "docket_enrichment_receipts": docket_enrichment_receipts_data,
        }

    @app.get("/admin/federal-data-dashboard/case-cards")
    @admin_required
    def admin_federal_data_dashboard_case_cards():
        return _render_federal_data_placeholder("Case Cards", "case_cards")

    @app.get("/admin/federal-data-dashboard/logs")
    @admin_required
    def admin_federal_data_dashboard_logs():
        limit = _parse_federal_logs_limit()
        logs_payload = _get_federal_data_logs(limit)

        return render_template(
            "admin_federal_data_logs.html",
            active_page="federal_data_dashboard",
            active_subnav="logs",
            **logs_payload,
        )

    @app.get("/admin/federal-data-dashboard/logs/export")
    @admin_required
    def admin_federal_data_dashboard_logs_export():
        limit = _parse_federal_logs_limit()
        logs_payload = _get_federal_data_logs(limit)
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        filename = f"federal-data-logs-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.txt"

        def _format_value(value: Any) -> str:
            if value is None:
                return "—"
            if isinstance(value, (dict, list)):
                return json.dumps(value, indent=2, sort_keys=True)
            return str(value)

        def _append_field(lines: List[str], key: str, value: Any) -> None:
            rendered = _format_value(value)
            if "\n" in rendered:
                lines.append(f"{key}:")
                for line in rendered.splitlines():
                    lines.append(f"  {line}")
            else:
                lines.append(f"{key}: {rendered}")

        def _append_section(lines: List[str], title: str, rows: List[Dict[str, Any]]) -> None:
            lines.append("")
            lines.append(f"## {title} ({len(rows)} records)")
            if not rows:
                lines.append("No records found.")
                return
            for index, row in enumerate(rows, start=1):
                lines.append("")
                lines.append(f"Record {index}")
                for key in sorted(row.keys()):
                    _append_field(lines, key, row.get(key))

        requested_by = "Admin"
        if g.current_user:
            requested_by = (
                g.current_user.get("email")
                or g.current_user.get("name")
                or str(g.current_user.get("id") or "Admin")
            )

        lines = [
            "# Federal Data Dashboard Logs Export",
            f"Generated at: {generated_at}",
            f"Limit per section: {limit}",
            f"Requested by: {requested_by}",
            "",
            "Summary counts:",
            f"- Court import runs: {len(logs_payload['court_import_runs'])}",
            f"- PACER explore runs: {len(logs_payload['pacer_explore_runs'])}",
            f"- PCL batch searches: {len(logs_payload['pcl_batch_searches'])}",
            f"- PCL batch requests: {len(logs_payload['pcl_batch_requests'])}",
            f"- PCL batch segments: {len(logs_payload['pcl_batch_segments'])}",
            f"- PCL remote jobs: {len(logs_payload['pcl_remote_jobs'])}",
            f"- PCL receipts: {len(logs_payload['pcl_receipts'])}",
            f"- PCL batch receipts: {len(logs_payload['pcl_batch_receipts'])}",
            f"- Docket enrichment jobs: {len(logs_payload['docket_enrichment_jobs'])}",
            f"- Docket enrichment receipts: {len(logs_payload['docket_enrichment_receipts'])}",
        ]

        _append_section(lines, "Court import runs", logs_payload["court_import_runs"])
        _append_section(lines, "PACER explore runs", logs_payload["pacer_explore_runs"])
        _append_section(lines, "PCL batch searches", logs_payload["pcl_batch_searches"])
        _append_section(lines, "PCL batch requests", logs_payload["pcl_batch_requests"])
        _append_section(lines, "PCL batch segments", logs_payload["pcl_batch_segments"])
        _append_section(lines, "PCL remote jobs", logs_payload["pcl_remote_jobs"])
        _append_section(lines, "PCL receipts", logs_payload["pcl_receipts"])
        _append_section(lines, "PCL batch receipts", logs_payload["pcl_batch_receipts"])
        _append_section(lines, "Docket enrichment jobs", logs_payload["docket_enrichment_jobs"])
        _append_section(
            lines,
            "Docket enrichment receipts",
            logs_payload["docket_enrichment_receipts"],
        )

        response = make_response("\n".join(lines))
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response

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
        court_stmt = (
            select(pcl_courts.c.pcl_court_id, pcl_courts.c.name)
            .where(pcl_courts.c.active.is_(True))
            .order_by(pcl_courts.c.pcl_court_id.asc())
        )
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
            court_rows = conn.execute(court_stmt).mappings().all()
        segments_by_batch: Dict[int, List[Dict[str, Any]]] = {}
        for row in segment_rows:
            segments_by_batch.setdefault(row["batch_request_id"], []).append(row)
        court_options: List[Dict[str, str]] = []
        for row in court_rows:
            name = row.get("name") or ""
            court_id = row["pcl_court_id"]
            label = f"{court_id}, {name}".strip().rstrip(",")
            court_options.append(
                {
                    "court_id": court_id,
                    "name": name,
                    "label": label,
                }
            )
        return render_template(
            "admin_pcl_batch_search.html",
            active_page="federal_data_dashboard",
            active_subnav="get_pacer_data",
            batch_requests=batch_rows,
            segments_by_batch=segments_by_batch,
            court_options=court_options,
            supported_case_types=PCL_CRIMINAL_CASE_TYPES,
            csrf_token=get_csrf_token(),
            pcl_base_url=pcl_base_url,
        )

    @app.post("/admin/federal-data-dashboard/pcl-batch-search/create")
    @admin_required
    def admin_federal_data_dashboard_pcl_batch_search_create():
        require_csrf()
        court_id = (request.form.get("court_id") or "").strip().lower()
        date_from = (request.form.get("date_filed_from") or "").strip()
        date_to = (request.form.get("date_filed_to") or "").strip()
        case_types = request.form.getlist("case_types")
        if not court_id or not date_from or not date_to:
            flash("Court ID and date range are required.", "error")
            return redirect(url_for("admin_federal_data_dashboard_pcl_batch_search"))
        with engine.connect() as conn:
            court_exists = (
                conn.execute(
                    select(func.count())
                    .select_from(pcl_courts)
                    .where(pcl_courts.c.pcl_court_id == court_id)
                    .where(pcl_courts.c.active.is_(True))
                ).scalar_one()
                > 0
            )
        if not court_exists:
            flash("Court ID is not recognized. Please select a valid court.", "error")
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
            saved_searches=_load_pacer_saved_searches(limit=6),
            search_run_history=_load_pacer_search_runs(limit=6),
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
