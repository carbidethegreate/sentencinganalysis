import csv
import hmac
import os
import re
import secrets
import tempfile
import threading
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


def _first_env(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
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
    url = _first_env(
        "DATABASE_URL",
        "InternalDatabaseURL",
        "Internal_Database_URL",
        "ExternalDatabaseURL",
        "External_Database_URL",
    )
    if url:
        return _normalize_database_url(url)

    # Fall back to discrete parts if present.
    host = _first_env("Hostname", "HOSTNAME")
    port = _first_env("Port", "PORT")
    dbname = _first_env("Database", "DB_NAME")
    user = _first_env("Username", "DB_USER")
    password = _first_env("Password", "DB_PASSWORD")
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
    secret_key = _first_env("SECRET_KEY", "Secrets", "SECRETS")
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

    # Create the users/newsletter/case_stage1 tables if they don't exist.
    try:
        metadata.create_all(engine, tables=[users, newsletter_subscriptions, case_stage1])
    except OperationalError as exc:
        if "already exists" in str(exc).lower():
            app.logger.warning("Database tables already exist; skipping create_all.")
        else:
            raise

    case_stage1_imports: Dict[str, Dict[str, Any]] = {}

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

    def _set_case_stage1_import(job_id: str, **fields: Any) -> None:
        case_stage1_imports.setdefault(job_id, {}).update(fields)

    def _latest_case_stage1_import() -> Optional[Dict[str, Any]]:
        latest_id = case_stage1_imports.get("latest")
        if not latest_id:
            return None
        return case_stage1_imports.get(latest_id)

    _ensure_case_stage1_search_index()

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
            if t.lower() not in {"users", "newsletter_subscriptions", "case_stage1"}
        ]
        return jsonify(sorted(tables))

    @app.route("/api/<table_name>", methods=["GET", "POST"])
    def table_records(table_name: str):
        if table_name.lower() in {"users", "newsletter_subscriptions", "case_stage1"}:
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
