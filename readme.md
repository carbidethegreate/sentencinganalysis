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
- `PACER_AUTH_BASE_URL`: PACER authentication base URL (defaults to `https://pacer.login.uscourts.gov`; use `https://qa-login.uscourts.gov` for QA testing)

Database
The app will try these, in order:
- `DATABASE_URL`
- `InternalDatabaseURL` or `Internal_Database_URL`
- `ExternalDatabaseURL` or `External_Database_URL`
- If none are set, it falls back to a local SQLite file.

## Notes about the existing API

The generic table APIs are still available:
- `GET /api/tables`
- `GET/POST /api/<table_name>`

For safety, the `users` table is blocked from these endpoints.

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
