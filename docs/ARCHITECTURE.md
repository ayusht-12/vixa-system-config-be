# Architecture

This backend is an async FastAPI application backed by PostgreSQL through
SQLAlchemy 2.x async sessions and Alembic migrations.

## Modules

- `auth`: JWT login, refresh, logout, and current-user lookup.
- `engine`: command-center overview data.
- `anomalies`: anomaly ingestion, listing, overview, and lifecycle updates.
- `compliance`: compliance overview data.
- `config`: staged configuration changes and apply/revert workflows.
- `audit-log`: immutable audit entries, hash-chain summary, and verification.
- `hsm`: HSM security overview, ceremonies, and attestation run records.
- `tenancy`: tenant records, provisioning jobs, and breach-alert actions.
- `dashboard`: activity, trend, summary, and tenant-health views.

## Security Hardening

- Production settings reject `DEBUG=true` and known development/default JWT
  secrets.
- JWT algorithms are normalized and restricted to `HS256`, `HS384`, and `HS512`.
- Refresh tokens are stored as hashes, rotate on redemption, and expiry checks
  accept both timezone-aware and naive PostgreSQL datetimes.
- Anomaly response metadata is recursively redacted for sensitive keys in nested
  dictionaries and lists. Stored anomaly metadata is not mutated by response
  redaction.
- Audit metadata is recursively sanitized before it participates in canonical
  hash computation, previous-hash linkage, ECDSA signing, or database storage.
- Sensitive config values marked `is_sensitive` are masked in API responses and
  redacted from config audit descriptions and metadata.

Sensitive metadata keys currently include:

`password`, `secret`, `secret_key`, `api_key`, `apikey`, `access_token`,
`refresh_token`, `token`, `authorization`, `credential`, `credentials`, and
`private_key`.

## Audit Integrity

Audit entries are append-only application records with database reinforcement:

- `entry_hash` is a SHA-256 digest of a canonical JSON payload.
- `prev_hash` links each entry to the previous persisted entry.
- `signature` is an ECDSA P-384 signature of `entry_hash`.
- The signing key is loaded from `AUDIT_SIGNING_KEY_PATH` and generated at
  bootstrap if absent.
- Migration `d45ebfc59718` installs a PostgreSQL trigger that rejects
  `UPDATE` and `DELETE` on `audit_log_entries`.
- Migration `89569d590a49` converts the audit sequence to an identity column.

The current migration head is `4bb68c116149`
(`20260703_1400_4bb68c116149_add_refresh_tokens.py`).

## Transaction Ownership

Authenticated API requests often read the current user with the same
`AsyncSession` before invoking domain services. Domain services that need to
commit audited changes therefore avoid starting nested transactions that would
conflict with SQLAlchemy autobegin.

- Standalone audit writes use `append_entry`, which appends and commits.
- Caller-owned audit writes use `append_entry_in_transaction`, which flushes but
  does not commit.
- Config apply commits config mutations and corresponding audit entries once, at
  the end of the operation. A config or audit failure rolls back the whole apply.
- Anomaly creation and status changes flush the anomaly mutation, append the
  audit entry in the same transaction, then commit. An audit failure rolls back
  the anomaly mutation.

The current config apply contract is all-or-nothing for pending items. A failure
on a later pending item must not commit earlier items or leave partial audit
rows.

## PostgreSQL Requirements

Tests and production runtime require PostgreSQL behavior for UUID columns, JSON
columns, identity sequences, asyncpg compatibility, and audit immutability
trigger semantics. SQLite is not used for the test suite.

## Testing Approach

The pytest suite creates PostgreSQL tables from SQLAlchemy metadata for speed.
The suite covers:

- production JWT configuration validation and algorithm allowlisting
- refresh-token hashing, rotation, and timezone-safe expiry checks
- recursive anomaly response redaction
- recursive audit metadata sanitization before hash/sign/store
- audit hash-chain and ECDSA verification
- config/audit and anomaly/audit atomicity
- cross-module auth/config/audit and auth/anomaly/audit flows

## Known Limitations

- Tenant filters are explicit where implemented; this backend does not claim
  implicit tenant isolation for every request.
- HSM endpoints model HSM security workflows and attestation records in the
  application database; this document does not claim integration with a physical
  HSM appliance.
- No Kafka or streaming broker behavior is implemented in this backend.
- Observability is limited to the current API/service behavior in this repo.
