# vsc-be — Nexus Engine Backend

FastAPI + PostgreSQL backend for the Nexus Engine control plane: Command Center,
Anomaly Detection, Compliance Monitor, Config Manager, Audit Log, HSM Security,
and Tenancy Orchestration. Pairs with the `vsc-fe` frontend.

## Stack

- **FastAPI** (async) + **Uvicorn**
- **PostgreSQL** via **SQLAlchemy 2.0** (async, `asyncpg`) + **Alembic** migrations
- **JWT** auth (`python-jose`) with **bcrypt** password hashing
- Audit log entries are hash-chained (SHA-256) and signed with a real
  **ECDSA P-384** key, with a DB-level trigger that rejects any `UPDATE`/`DELETE`
  against the audit table — immutability doesn't depend on the application layer alone.

## Project layout

```
app/
  core/       settings, JWT/password hashing, ECDSA signing key management
  db/         async session, declarative base
  models/     SQLAlchemy ORM models, one module per domain
  schemas/    Pydantic request/response models
  services/   business logic (scoring, chain verification, derived statuses, ...)
  api/v1/     route handlers, aggregated in api.py
  main.py     app instance, CORS, router mount
alembic/      migrations, including hand-written DDL for the audit trigger
scripts/      seed_data.py — realistic demo data for every domain
tests/        pytest suite
```

## Running the API

### Option A — Docker (recommended)

```bash
cp .env.example .env        # edit SECRET_KEY / POSTGRES_PASSWORD as desired
docker compose up --build
```

This starts Postgres and the API together (migrations run automatically on
container start, via `docker-entrypoint.sh`). Then seed demo data:

```bash
docker compose exec api python scripts/seed_data.py
```

Stop everything with `docker compose down` (add `-v` to also drop the Postgres volume).

API is available at `http://localhost:8000`, interactive docs at
`http://localhost:8000/api/v1/docs`.

### Option B — Without Docker (local Postgres + venv)

**1. Get a Postgres server.** If you already have one, skip to step 2 and
point the `POSTGRES_*` variables in `.env` at it. Otherwise, initialize a
local, user-owned cluster (no root/sudo required — useful in sandboxed or
restricted environments):

```bash
# adjust the postgresql binary path/version for your distro if needed
/usr/lib/postgresql/12/bin/initdb -D ~/pgdata-vscbe -U vscbe --auth=trust

mkdir -p ~/pgdata-vscbe/sockets
/usr/lib/postgresql/12/bin/pg_ctl -D ~/pgdata-vscbe \
  -o "-p 5433 -k ~/pgdata-vscbe/sockets" \
  -l ~/pgdata-vscbe/logfile start

createdb -h 127.0.0.1 -p 5433 -U vscbe vsc_be
```

Stop it later with:

```bash
/usr/lib/postgresql/12/bin/pg_ctl -D ~/pgdata-vscbe stop
```

**2. Set up and run the app:**

```bash
python3.10 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env        # point POSTGRES_HOST/PORT/USER/PASSWORD/DB at
                             # whichever Postgres you're using (5433 if you
                             # used the initdb steps above)

alembic upgrade head
python scripts/seed_data.py

uvicorn app.main:app --reload --port 8000
```

API is available at `http://localhost:8000`, interactive docs at
`http://localhost:8000/api/v1/docs`.

## Auth

All endpoints except `/health` and `/api/v1/auth/*` require a bearer token.
Access tokens use an HMAC JWT algorithm allowlist (`HS256`, `HS384`, `HS512`).
In production (`ENVIRONMENT=production`, `prod`, or `release`) startup rejects
`DEBUG=true` and development/default JWT secrets. Refresh tokens are stored as
hashes, rotate on redemption, and expiry checks handle both timezone-aware and
naive PostgreSQL datetimes.

**Demo credentials** (created by `scripts/seed_data.py` — change them before deploying anywhere real):

| Email          | Password         |
|----------------|-------------------|
| `admin@nexus`  | `NexusAdmin!2026` |

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@nexus", "password": "NexusAdmin!2026"}'
```

Use the returned `access_token` as `Authorization: Bearer <token>` on subsequent requests.

In the Swagger UI (`/api/v1/docs`), click **Authorize** and paste just the raw
token — no username/password/client-id fields, since the docs use `HTTPBearer`
rather than the full OAuth2 password flow.

## API surface

Mounted under `/api/v1`:

| Prefix          | Domain                                  |
|------------------|------------------------------------------|
| `/auth`          | Login, current user                      |
| `/engine`        | Command Center (cluster, etcd, metrics)  |
| `/anomalies`     | Anomaly Detection                        |
| `/compliance`    | Compliance Monitor                       |
| `/config`        | Config Manager (staged changes)          |
| `/audit-log`     | Audit Log (hash chain, verification)     |
| `/hsm`           | HSM Security (keys, ceremonies, attestation) |
| `/tenancy`       | Tenancy Orchestration (isolation, provisioning) |

Current generated OpenAPI inventory: 36 paths and 41 HTTP operations. Full
request/response schemas are in the OpenAPI docs at `/api/v1/docs`; a concise
endpoint count is maintained in `docs/API_INVENTORY.md`.

Tenant-aware endpoints expose explicit tenant filters where implemented. The
backend does not claim implicit tenant isolation for every request.

## Security and integrity notes

- Anomaly API responses recursively redact sensitive metadata keys at any
  nesting depth without mutating stored anomaly metadata.
- Audit metadata is recursively sanitized before the canonical hash payload,
  previous-hash linkage, ECDSA signature, and database insert are produced.
- Audit entries are SHA-256 hash-chained, signed with ECDSA P-384, and protected
  by a PostgreSQL trigger that rejects `UPDATE` and `DELETE` on the audit table.
- Config apply and audited anomaly mutations use one transaction for the domain
  mutation plus audit append. Audit failures roll back the domain mutation, and
  failed domain mutations leave no audit row.
- Sensitive config values marked `is_sensitive` are masked in config API
  responses and redacted from config audit descriptions/metadata.

## Migrations

```bash
alembic revision --autogenerate -m "description"
alembic upgrade head
```

Note: `alembic/versions/*_audit_log_immutability_trigger.py` and
`*_audit_log_sequence_as_identity_column.py` contain hand-written raw SQL
(trigger DDL and an `IDENTITY` column conversion) — autogenerate can't produce
either of those correctly, so don't regenerate over them.

Current migration head: `20260703_1400_4bb68c116149_add_refresh_tokens.py`
(`4bb68c116149`).

## Tests

```bash
pytest
```

The suite is PostgreSQL-backed because the schema uses PostgreSQL UUID, JSON,
identity sequence, and trigger behavior. It covers health, JWT auth hardening,
refresh-token hashing/rotation/expiry, recursive anomaly redaction, audit
metadata sanitization, hash-chain/ECDSA verification, config/audit atomicity,
anomaly/audit atomicity, and cross-module integration.

See `docs/ARCHITECTURE.md` for transaction ownership, audit integrity, and
known limitations.
