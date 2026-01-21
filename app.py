import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from sqlalchemy import MetaData, Table, create_engine, insert, select
from sqlalchemy.exc import NoSuchTableError

DEFAULT_DB_FILENAME = "case_filed_rpt.sqlite"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    db_path = os.environ.get("DB_PATH")
    if not db_path:
        db_path = str(Path(__file__).with_name(DEFAULT_DB_FILENAME))
    database_url = os.environ.get("DATABASE_URL", f"sqlite:///{db_path}")

    engine = create_engine(database_url, future=True)
    metadata = MetaData()

    def load_table(table_name: str) -> Table:
        try:
            return Table(table_name, metadata, autoload_with=engine)
        except NoSuchTableError as exc:
            raise KeyError(f"Table '{table_name}' not found") from exc

    @app.route("/")
    def index():
        return send_from_directory(Path(__file__).parent, "index.html")

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/tables")
    def list_tables():
        metadata.reflect(bind=engine)
        return jsonify(sorted(metadata.tables.keys()))

    @app.route("/api/<table_name>", methods=["GET", "POST"])
    def table_records(table_name: str):
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
