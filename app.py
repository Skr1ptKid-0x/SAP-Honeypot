import hmac
import logging
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, render_template, request

app = Flask(__name__)
app.config.update(
    DATABASE=os.getenv("SAP_HONEYPOT_DB_PATH", "honeypot.db"),
    ADMIN_TOKEN=os.getenv("SAP_HONEYPOT_ADMIN_TOKEN"),
    MAX_CONTENT_LENGTH=16 * 1024,
)
logger = logging.getLogger("sap_honeypot")

# --- DATABASE SETUP ---
SECURE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        username_supplied INTEGER NOT NULL CHECK (username_supplied IN (0, 1)),
        password_supplied INTEGER NOT NULL CHECK (password_supplied IN (0, 1)),
        user_agent TEXT NOT NULL
    )
"""


def _database_path():
    return app.config["DATABASE"]


def _ensure_secure_schema(connection):
    """Create the privacy-preserving schema and sanitize the legacy schema."""
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(attacks)").fetchall()
    }
    if not columns:
        connection.execute(SECURE_SCHEMA)
        return False

    legacy_columns = {"username", "password"}
    if columns.intersection(legacy_columns):
        connection.execute("DROP TABLE IF EXISTS attacks_sanitized")
        connection.execute(SECURE_SCHEMA.replace("attacks", "attacks_sanitized", 1))
        username_flag = (
            "CASE WHEN username IS NOT NULL AND trim(username) != '' THEN 1 ELSE 0 END"
            if "username" in columns
            else "0"
        )
        password_flag = (
            "CASE WHEN password IS NOT NULL AND trim(password) != '' THEN 1 ELSE 0 END"
            if "password" in columns
            else "0"
        )
        connection.execute(
            f"""
            INSERT INTO attacks_sanitized (
                id, timestamp, ip_address, username_supplied,
                password_supplied, user_agent
            )
            SELECT
                id,
                COALESCE(timestamp, ''),
                COALESCE(ip_address, 'unknown'),
                {username_flag},
                {password_flag},
                COALESCE(user_agent, '')
            FROM attacks
            """
        )
        connection.execute("DROP TABLE attacks")
        connection.execute("ALTER TABLE attacks_sanitized RENAME TO attacks")
        return True

    expected_columns = {
        "id",
        "timestamp",
        "ip_address",
        "username_supplied",
        "password_supplied",
        "user_agent",
    }
    if not expected_columns.issubset(columns):
        raise RuntimeError("Unsupported attacks table schema")
    return False


def init_db():
    """Initialize storage without retaining submitted credential values."""
    connection = sqlite3.connect(_database_path())
    try:
        migrated = _ensure_secure_schema(connection)
        connection.commit()
        if migrated:
            # Rebuild the file so deleted raw values are not left in free pages.
            connection.execute("VACUUM")
    finally:
        connection.close()


def log_attack(ip, username_supplied, password_supplied, agent):
    """Store event metadata; submitted credential values never cross this boundary."""
    connection = sqlite3.connect(_database_path())
    try:
        connection.execute(
            """
            INSERT INTO attacks (
                timestamp, ip_address, username_supplied,
                password_supplied, user_agent
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                (ip or "unknown")[:64],
                int(bool(username_supplied)),
                int(bool(password_supplied)),
                (agent or "")[:512],
            ),
        )
        connection.commit()
    finally:
        connection.close()
    logger.warning("Honeypot event recorded from %s", ip or "unknown")


def _admin_is_authorized(expected_token):
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")
    return (
        bool(expected_token)
        and bool(separator)
        and scheme.lower() == "bearer"
        and hmac.compare_digest(supplied_token, expected_token)
    )


# --- ROUTES ---


@app.route("/", methods=["GET", "POST"])
def login():
    """
    The Trap: Mimics an SAP NetWeaver Login Screen.
    """
    if request.method == "POST":
        username_supplied = bool(request.form.get("sap-user", "").strip())
        password_supplied = bool(request.form.get("sap-password", ""))
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        log_attack(ip_address, username_supplied, password_supplied, user_agent)

        # Fake a login error (Stall the attacker)
        return render_template("login.html", error="Logon failed. Correct the entries.")

    return render_template("login.html")


@app.route("/admin_dashboard")
def admin():
    """Show event metadata only to a caller with the configured bearer token."""
    expected_token = app.config.get("ADMIN_TOKEN")
    if not expected_token:
        return "Admin dashboard is disabled until an admin token is configured.", 503
    if not _admin_is_authorized(expected_token):
        return "Unauthorized", 401, {"WWW-Authenticate": "Bearer"}

    connection = sqlite3.connect(_database_path())
    connection.row_factory = sqlite3.Row
    try:
        logs = connection.execute("SELECT * FROM attacks ORDER BY id DESC").fetchall()
    finally:
        connection.close()
    return render_template("dashboard.html", logs=logs)


if __name__ == "__main__":
    print("[*] Initializing SAP Honeypot System...")
    init_db()
    print("[*] SAP NetWeaver Trap is running on port 8080...")
    app.run(host="0.0.0.0", port=8080, debug=False)
