import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as honeypot


class HoneypotAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "honeypot.db"
        honeypot.app.config.update(
            TESTING=True,
            DATABASE=str(self.database),
            ADMIN_TOKEN="test-admin-token",
        )
        honeypot.init_db()
        self.client = honeypot.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_login_records_event_without_raw_credentials(self):
        captured_stdout = io.StringIO()
        with contextlib.redirect_stdout(captured_stdout):
            response = self.client.post(
                "/",
                data={
                    "sap-user": "alice@example.test",
                    "sap-password": "not-a-real-secret",
                },
                headers={"User-Agent": "honeypot-test-agent"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alice@example.test", captured_stdout.getvalue())
        self.assertNotIn("not-a-real-secret", captured_stdout.getvalue())

        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM attacks").fetchone()
            columns = {
                column[1] for column in connection.execute("PRAGMA table_info(attacks)")
            }

        self.assertNotIn("username", columns)
        self.assertNotIn("password", columns)
        self.assertEqual(row["username_supplied"], 1)
        self.assertEqual(row["password_supplied"], 1)
        self.assertNotIn("alice@example.test", repr(dict(row)))
        self.assertNotIn("not-a-real-secret", repr(dict(row)))

    def test_dashboard_is_disabled_without_an_admin_token(self):
        honeypot.app.config["ADMIN_TOKEN"] = None

        response = self.client.get("/admin_dashboard")

        self.assertEqual(response.status_code, 503)

    def test_dashboard_requires_the_configured_bearer_token(self):
        missing = self.client.get("/admin_dashboard")
        wrong = self.client.get(
            "/admin_dashboard", headers={"Authorization": "Bearer wrong-token"}
        )
        allowed = self.client.get(
            "/admin_dashboard",
            headers={"Authorization": "Bearer test-admin-token"},
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(missing.headers["WWW-Authenticate"], "Bearer")

    def test_init_db_migrates_legacy_raw_credential_columns(self):
        self.database.unlink(missing_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """
                CREATE TABLE attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip_address TEXT,
                    username TEXT,
                    password TEXT,
                    user_agent TEXT
                )
                """
            )
            connection.execute(
                """
                INSERT INTO attacks
                    (timestamp, ip_address, username, password, user_agent)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "2026-01-01T00:00:00+00:00",
                    "127.0.0.1",
                    "legacy-user",
                    "legacy-pass",
                    "test",
                ),
            )

        honeypot.init_db()

        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            columns = {
                column[1] for column in connection.execute("PRAGMA table_info(attacks)")
            }
            row = connection.execute("SELECT * FROM attacks").fetchone()

        self.assertNotIn("username", columns)
        self.assertNotIn("password", columns)
        self.assertEqual(row["username_supplied"], 1)
        self.assertEqual(row["password_supplied"], 1)
        database_bytes = self.database.read_bytes()
        self.assertNotIn(b"legacy-user", database_bytes)
        self.assertNotIn(b"legacy-pass", database_bytes)


if __name__ == "__main__":
    unittest.main()
