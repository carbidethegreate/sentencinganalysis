import os
import sys
import tempfile
from pathlib import Path

from sqlalchemy import MetaData, Table, create_engine, select

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import USER_TYPES, build_database_url, create_app


def get_csrf(client):
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf_token"]


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "newsletter.sqlite")
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

        engine = create_engine(build_database_url(), future=True)
        metadata = MetaData()
        users = Table("users", metadata, autoload_with=engine)
        newsletter = Table("newsletter_subscriptions", metadata, autoload_with=engine)

        csrf = get_csrf(client)
        payload = {"email": "Test@Example.com", "csrf_token": csrf}
        client.post("/newsletter/subscribe", data=payload, follow_redirects=True)
        client.post("/newsletter/subscribe", data=payload, follow_redirects=True)

        with engine.connect() as conn:
            rows = (
                conn.execute(
                    select(newsletter.c.id).where(newsletter.c.email == "test@example.com")
                )
                .mappings()
                .all()
            )
        assert len(rows) == 1, "Expected a single newsletter row after duplicate signup."

        csrf = get_csrf(client)
        signup_payload = {
            "csrf_token": csrf,
            "first_name": "Testy",
            "last_name": "McTest",
            "user_type": USER_TYPES[0],
            "email": "test@example.com",
            "password": "password123",
        }
        client.post("/signup", data=signup_payload, follow_redirects=True)

        with engine.connect() as conn:
            user_row = (
                conn.execute(select(users).where(users.c.email == "test@example.com"))
                .mappings()
                .first()
            )
            newsletter_row = (
                conn.execute(select(newsletter).where(newsletter.c.email == "test@example.com"))
                .mappings()
                .first()
            )
        assert user_row, "Expected user to be created."
        assert newsletter_row, "Expected newsletter row to exist."
        assert (
            newsletter_row["user_id"] == user_row["id"]
        ), "Expected newsletter row to link user id."

        csrf = get_csrf(client)
        profile_payload = {
            "csrf_token": csrf,
            "first_name": user_row["first_name"],
            "last_name": user_row["last_name"],
            "user_type": user_row["user_type"],
            "email": user_row["email"],
        }
        client.post("/profile", data=profile_payload, follow_redirects=True)

        with engine.connect() as conn:
            newsletter_row = (
                conn.execute(select(newsletter).where(newsletter.c.email == "test@example.com"))
                .mappings()
                .first()
            )
        assert newsletter_row and not newsletter_row["opt_in"], "Expected opt_in to be false."

        response = client.get("/admin/newsletter")
        assert response.status_code == 302, "Expected admin access to require login."
        assert "/admin/login" in response.headers.get("Location", ""), "Expected admin login redirect."

    print("Newsletter verification complete.")


if __name__ == "__main__":
    main()
