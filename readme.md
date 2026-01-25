# SentencingAnalysis (CourtDataPro)

This repository is a starter Flask application intended to run on Render.

## What is included

- Dynamic server-rendered pages: Home, Pricing, News, About, Contact
- User authentication: Sign Up, Login, Logout
- User dashboard placeholder: `/dashboard`
- Profile page for updating stored fields: `/profile`
- Admin area:
  - Admin login: `/admin/login`
  - Admin home: `/admin`
  - Admin users list: `/admin/users`

## Environment variables

Do not commit secrets. In production (Render), set these as environment variables or via an environment group.

Required for production
- `SECRET_KEY` (or `Secrets`): Flask session signing key
- `CPD_ADMIN_KEY`: master admin password (username is always `CPDADMIN`)

Federal data dashboard
- `PACER_AUTH_BASE_URL`: PACER authentication base URL (default `https://qa-login.uscourts.gov`, use `https://pacer.login.uscourts.gov` for Production)
- `PCL_BASE_URL`: PACER Case Locator API base URL (default `https://qa-pcl.uscourts.gov/pcl-public-api/rest`)
- QA and Production endpoints require **separate PACER accounts**. Keep `PACER_AUTH_BASE_URL` and `PCL_BASE_URL` aligned to the same environment or PCL calls will be blocked locally.
- PCL requests must include the `X-NEXT-GEN-CSO` header returned by PACER auth. Some accounts also require a PACER client code to enable searching; re-authorize with the client code if searches are disabled.

Database
The app will try these, in order:
- `DATABASE_URL`
- `InternalDatabaseURL` or `Internal_Database_URL`
- `ExternalDatabaseURL` or `External_Database_URL`
- If none are set, it falls back to a local SQLite file.

## Runtime entrypoints

All runtime entrypoints call the same Flask app factory (`create_app()`), which ensures a consistent configuration path.

- Local development: `python app.py` (invokes `create_app()` in `__main__`).
- Docker (`Dockerfile`): `gunicorn --bind 0.0.0.0:${PORT:-5000} --timeout ${GUNICORN_TIMEOUT:-180} "app:create_app()"`.
- Render (`render.yaml`): same gunicorn `app:create_app()` target as Docker.

## Configuration loading order (summary)

- `SECRET_KEY`: read from `SECRET_KEY`/`Secrets`/`SECRETS`, then `SECRET_KEY_PATH` file (default `.secret_key` next to `app.py`), otherwise generated and persisted (or ephemeral if the file cannot be written).
- `PACER_AUTH_BASE_URL` and `PCL_BASE_URL`: read directly from environment variables, with defaults for QA endpoints.
- Database URL: `DATABASE_URL` (or Render variants), then discrete `Hostname`/`Port`/`Database`/`Username`/`Password`, otherwise local SQLite via `DB_PATH` or `case_filed_rpt.sqlite`.

## Notes about the existing API

The generic table APIs are still available:
- `GET /api/tables`
- `GET/POST /api/<table_name>`

For safety, the `users` table is blocked from these endpoints.

## Planning docs

- PACER/PCL pipeline implementation plan: [`docs/pacer_pcl_pipeline_plan.md`](docs/pacer_pcl_pipeline_plan.md)

## PCL batch indexing

- Create batch searches from the Federal Data Dashboard → "PCL Batch Search".
- Run the worker via the "Start run" button or by calling `PclBatchWorker.run_once(...)` from a cron/Render worker.
- The worker downloads completed reports, ingests raw + normalized cases, and deletes the remote report after ingestion.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="dev-only"
python app.py
```

Then visit:
- `http://127.0.0.1:5000/`

## Docker

```bash
docker build -t sentencinganalysis .
docker run -e PORT=5000 -p 5000:5000 sentencinganalysis
```
