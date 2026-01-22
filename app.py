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
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote_plus

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
    Date,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    bindparam,
    create_engine,
    delete,
    func,
    inspect,
    insert,
    literal_column,
    select,
    update,
)
from sqlalchemy import text as sa_text
from sqlalchemy.exc import IntegrityError, NoSuchTableError, OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

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

VALID_JURISDICTION_TYPES = {"ap", "bk", "cr", "cv", "mdl", "mj"}


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

    # Create the users/newsletter/case_stage1/case_data_one tables if they don't exist.
    try:
        metadata.create_all(
            engine, tables=[users, newsletter_subscriptions, case_stage1, case_data_one]
        )
    except OperationalError as exc:
        if "already exists" in str(exc).lower():
            app.logger.warning("Database tables already exist; skipping create_all.")
        else:
            raise

    def _ensure_case_data_one_columns() -> None:
        column_specs = {
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
        }
        try:
            inspector = inspect(engine)
            existing_columns = {
                column["name"] for column in inspector.get_columns("case_data_one")
            }
        except Exception:
            app.logger.exception("Unable to inspect case_data_one columns.")
            return

        missing = [name for name in column_specs if name not in existing_columns]
        if not missing:
            return

        try:
            with engine.begin() as conn:
                for name in missing:
                    conn.execute(
                        sa_text(
                            f"ALTER TABLE case_data_one ADD COLUMN {name} {column_specs[name]}"
                        )
                    )
        except Exception:
            app.logger.exception("Unable to add missing case_data_one columns.")

    _ensure_case_data_one_columns()

    case_stage1_imports: Dict[str, Dict[str, Any]] = {}
    case_data_one_imports: Dict[str, Dict[str, Any]] = {}

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

    def _normalize_text(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned.lower() if cleaned else None

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
            stmt = insert(table).values(rows)
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
            stmt = insert(table).values(rows)
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
            "You are assisting with diagnosing Case Data One import errors.",
            "The file is pipe-delimited and each error includes a row number, message, and record.",
            "Return a concise diagnosis with likely root causes and suggested fixes.",
            "Provide bullet points plus any recommended data cleaning steps.",
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

    def _call_openai_chat_completion(prompt: str) -> str:
        api_key = _first_env_or_secret_file("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key is not configured.")

        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
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
                    "Invalid cs_type value; expected ap, bk, cr, cv, mdl, or mj "
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

        try:
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

                def _update_case_data_one_progress(force: bool = False) -> None:
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
                        status="processing",
                        total_rows=total_rows,
                        processed_rows=processed_rows,
                        inserted_rows=inserted_rows,
                        updated_rows=updated_rows,
                        skipped_rows=skipped_rows,
                        error_rows=error_rows,
                        error_details=error_details,
                        message=(
                            "Processing rows. "
                            f"Processed {processed_rows} of {total_rows}."
                        ),
                    )
                    last_progress_update = now
                    rows_since_update = 0

                with engine.begin() as conn:
                    case_data_one_table = case_data_one
                    date_columns = CASE_DATA_ONE_DATE_COLUMNS
                    data_columns = CASE_DATA_ONE_IMPORT_COLUMNS

                    batch: List[Dict[str, Any]] = []
                    for row_index, row in enumerate(reader, start=2):
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
                                    record=row,
                                )
                                row_valid = False
                            if row_valid and row_data["cs_caseid"] is None:
                                skipped_rows += 1
                                error_rows += 1
                                _record_case_data_one_error(
                                    error_details,
                                    row_number=row_index,
                                    message="Missing cs_caseid value.",
                                    record=row,
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

                                processed_rows += 1
                                batch.append(row_data)
                        except Exception as exc:
                            error_rows += 1
                            _record_case_data_one_error(
                                error_details,
                                row_number=row_index,
                                message=f"Row parsing failed: {exc}",
                                record=row,
                            )
                        rows_since_update += 1
                        _update_case_data_one_progress()

                        if len(batch) >= CASE_DATA_ONE_CHUNK_SIZE:
                            inserted, updated = _upsert_case_data_one_batch(
                                conn,
                                case_data_one_table,
                                batch,
                                track_counts=not _is_postgres(),
                            )
                            inserted_rows += inserted
                            updated_rows += updated
                            batch = []
                            _update_case_data_one_progress(force=True)

                    if batch:
                        inserted, updated = _upsert_case_data_one_batch(
                            conn,
                            case_data_one_table,
                            batch,
                            track_counts=not _is_postgres(),
                        )
                        inserted_rows += inserted
                        updated_rows += updated
                        _update_case_data_one_progress(force=True)

                if _is_postgres():
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
                completion_message = (
                    f"{completion_message} Download the error report or check the "
                    "server logs for details."
                )

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

        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        return jsonify({"response": response_text, "model": model})

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
