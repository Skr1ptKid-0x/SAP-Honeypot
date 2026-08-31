# SAP Honeypot

> A small Flask proof of concept for studying login activity in an isolated, authorized lab.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Docker](https://img.shields.io/badge/Docker-Container-2496ED)
![Security](https://img.shields.io/badge/Focus-Deception_Technology-orange)
![CI](https://github.com/osmankaankars/SAP-Honeypot/actions/workflows/ci.yml/badge.svg)

## What it demonstrates

- A login page that resembles a generic SAP NetWeaver sign-in flow.
- Collection of event metadata: UTC time, source IP, User-Agent, and whether the username/password fields were populated.
- SQLite-backed event storage.
- An admin dashboard protected by a configurable bearer token.

Submitted usernames and passwords are deliberately **not stored or printed**. On startup, the application also migrates the repository's earlier database schema by replacing raw credential columns with boolean `username_supplied` and `password_supplied` fields. The database is rebuilt during that migration so removed values are not retained in free SQLite pages.

## Run locally

```bash
git clone https://github.com/osmankaankars/SAP-Honeypot.git
cd SAP-Honeypot
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SAP_HONEYPOT_ADMIN_TOKEN="replace-with-a-long-random-token"
python app.py
```

The login page is available at `http://localhost:8080`.

Read the protected dashboard with the configured token:

```bash
curl -H "Authorization: Bearer $SAP_HONEYPOT_ADMIN_TOKEN" \
  http://localhost:8080/admin_dashboard
```

If `SAP_HONEYPOT_ADMIN_TOKEN` is absent, the dashboard is disabled and returns HTTP 503. An invalid or missing bearer token returns HTTP 401.

Optional configuration:

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `SAP_HONEYPOT_ADMIN_TOKEN` | unset | Enables authenticated dashboard access |
| `SAP_HONEYPOT_DB_PATH` | `honeypot.db` | Sets the runtime SQLite path |

Runtime databases, logs, local environment files, and virtual environments are excluded from version control.

## Docker

```bash
docker build -t sap-honeypot .
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  -e SAP_HONEYPOT_ADMIN_TOKEN="replace-with-a-long-random-token" \
  sap-honeypot
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover credential minimization, legacy-schema sanitization, secure dashboard defaults, and bearer-token checks.

## Security and operational limits

This repository is a learning PoC, not a production honeypot or an SAP product. It is not affiliated with or endorsed by SAP SE.

- Run it only on systems and networks you own or are authorized to monitor.
- The built-in Flask server does not provide production TLS, rate limiting, retention controls, or hardened deployment defaults.
- IP addresses and User-Agent strings can still be personal or sensitive data. Define retention, access, and deletion policies appropriate to your jurisdiction.
- A bearer token is only a baseline dashboard control. For a real deployment, place the dashboard behind a separate identity-aware reverse proxy and network allowlist.
- The interface is a visual simulation; it does not emulate SAP protocols or validate resistance to real attackers.

## Author

Osman Kaan Kars — Senior Cybersecurity Engineer at SchutzOn
