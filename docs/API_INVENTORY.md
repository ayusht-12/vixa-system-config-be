# API Inventory

Generated from the target FastAPI OpenAPI schema during Phase 7.

- OpenAPI path count: 36
- HTTP operation count: 41

## Per-Module Counts

| Module | Paths | HTTP operations |
|---|---:|---:|
| `health` | 1 | 1 |
| `auth` | 4 | 4 |
| `engine` | 1 | 1 |
| `anomalies` | 7 | 8 |
| `compliance` | 1 | 1 |
| `config` | 4 | 4 |
| `audit-log` | 3 | 4 |
| `hsm` | 4 | 4 |
| `tenancy` | 7 | 10 |
| `dashboard` | 4 | 4 |

## Paths

| Path | Methods |
|---|---|
| `/health` | `GET` |
| `/api/v1/auth/login` | `POST` |
| `/api/v1/auth/logout` | `POST` |
| `/api/v1/auth/me` | `GET` |
| `/api/v1/auth/refresh` | `POST` |
| `/api/v1/engine/overview` | `GET` |
| `/api/v1/anomalies/overview` | `GET` |
| `/api/v1/anomalies/events` | `GET`, `POST` |
| `/api/v1/anomalies/events/{event_id}` | `GET` |
| `/api/v1/anomalies/events/{event_id}/acknowledge` | `POST` |
| `/api/v1/anomalies/events/{event_id}/resolve` | `POST` |
| `/api/v1/anomalies/events/{event_id}/dismiss` | `POST` |
| `/api/v1/anomalies/events/{event_id}/reopen` | `POST` |
| `/api/v1/compliance/overview` | `GET` |
| `/api/v1/config/overview` | `GET` |
| `/api/v1/config/parameters/{parameter_id}` | `PATCH` |
| `/api/v1/config/parameters/{parameter_id}/revert` | `POST` |
| `/api/v1/config/apply` | `POST` |
| `/api/v1/audit-log/entries` | `GET`, `POST` |
| `/api/v1/audit-log/summary` | `GET` |
| `/api/v1/audit-log/verify` | `POST` |
| `/api/v1/hsm/overview` | `GET` |
| `/api/v1/hsm/ceremonies/{ceremony_id}/approve` | `POST` |
| `/api/v1/hsm/ceremonies/{ceremony_id}/complete` | `POST` |
| `/api/v1/hsm/attestation/run` | `POST` |
| `/api/v1/tenancy/overview` | `GET` |
| `/api/v1/tenancy/breach-alerts/{alert_id}/dismiss` | `POST` |
| `/api/v1/tenancy/provisioning/{job_id}/advance` | `POST` |
| `/api/v1/tenancy/tenants` | `GET`, `POST` |
| `/api/v1/tenancy/tenants/{tenant_id}` | `DELETE`, `GET`, `PATCH` |
| `/api/v1/tenancy/tenants/{tenant_id}/activate` | `POST` |
| `/api/v1/tenancy/tenants/{tenant_id}/deactivate` | `POST` |
| `/api/v1/dashboard/summary` | `GET` |
| `/api/v1/dashboard/activity` | `GET` |
| `/api/v1/dashboard/event-trends` | `GET` |
| `/api/v1/dashboard/tenant-health` | `GET` |

## Notes

- All routes except `/health` and `/api/v1/auth/*` require bearer
  authentication.
- Admin-only checks are enforced by endpoint dependencies where implemented.
- Tenant filtering is explicit where a route exposes a tenant filter; this file
  does not claim implicit tenant isolation.
