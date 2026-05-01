# Asset Registry

**Phase:** 0 (Foundations)
**Module:** 0.1
**Status:** Shipped
**Owner:** Argus core

The Asset Registry is the polymorphic catalog of every external entity Argus
monitors. **Every later module in the platform — EASM, DMARC, Brand Protection,
TPRM, Impersonation — reads from and writes to this registry.** It must be
correct, performant, and tenant-isolated.

---

## Asset types

| Type | Canonical `value` form | Required `details` schema |
|------|------------------------|---------------------------|
| `domain` | lowercased apex domain (no trailing dot) | `DomainDetails` |
| `subdomain` | lowercased FQDN | `SubdomainDetails` (parent_domain required) |
| `ip_address` | normalized IPv4/IPv6 (`ipaddress` module) | `IPAddressDetails` |
| `ip_range` | normalized CIDR | `IPRangeDetails` (cidr required) |
| `service` | `host:port` (host lowercased) | `ServiceDetails` |
| `email_domain` | lowercased domain | `EmailDomainDetails` |
| `executive` | whitespace-collapsed full name | `ExecutiveDetails` |
| `brand` | whitespace-collapsed brand name | `BrandDetails` |
| `mobile_app` | bundle id / package name | `MobileAppDetails` |
| `social_handle` | `platform:handle` (handle stripped of `@`) | `SocialHandleDetails` |
| `vendor` | whitespace-collapsed legal name | `VendorDetails` |
| `code_repository` | `provider:org[/repo]` | `CodeRepositoryDetails` |
| `cloud_account` | `provider:account_id` | `CloudAccountDetails` |

Type-specific schemas live in `src/models/asset_schemas.py`.

## Common fields (all types)

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Primary key |
| `organization_id` | UUID | Tenant scope. Every query filters on this. |
| `asset_type` | string | One of the values above (CHECK constraint enforced) |
| `value` | string | Canonical identifier (validated + normalized) |
| `details` | JSONB | Type-specific structured data, validated against the relevant schema |
| `criticality` | enum | `crown_jewel` / `high` / `medium` / `low` |
| `tags` | string[] | GIN-indexed for tag filters |
| `monitoring_profile` | JSONB (`MonitoringProfile`) | Per-asset cadence, severity floor, etc. |
| `owner_user_id` | UUID | Analyst responsible. Set automatically to the creator. |
| `parent_asset_id` | UUID | Optional hierarchy (e.g. subdomain → root domain). Must reference an asset in the same org. |
| `discovery_method` | enum | `manual`, `bulk_import`, `easm_discovery`, `cert_transparency`, etc. |
| `discovered_at`, `verified_at`, `last_scanned_at`, `last_change_at` | timestamps | Lifecycle markers |
| `is_active`, `monitoring_enabled` | bool | Soft-delete + monitoring kill-switch |
| `created_at`, `updated_at` | timestamps | Standard mixins |

## Constraints

- **Unique** `(organization_id, asset_type, value)` — duplicates within an org return HTTP 409.
- **CHECK** `criticality IN ('crown_jewel','high','medium','low')`
- **CHECK** `asset_type IN (...)` whitelist (Postgres-side defense in depth even though the API layer also validates).
- **GIN index** on `tags` for fast `tag = X` filters.
- **B-tree index** on `(organization_id, asset_type)`, `(organization_id, asset_type, value)` (unique), `criticality`, `parent_asset_id`.

## API surface

All endpoints require an analyst-or-admin role.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/assets` | Create one |
| `GET` | `/api/v1/assets?organization_id=…` | List with rich filters |
| `GET` | `/api/v1/assets/count?organization_id=…` | Totals + per-type + per-criticality |
| `GET` | `/api/v1/assets/{id}` | Fetch one |
| `PATCH` | `/api/v1/assets/{id}` | Partial update |
| `DELETE` | `/api/v1/assets/{id}` | Hard delete |
| `POST` | `/api/v1/assets/bulk` | Bulk JSON import (idempotent on duplicates) |
| `POST` | `/api/v1/assets/bulk/csv` | Bulk CSV import |
| `GET` | `/api/v1/assets/types/schema` | JSON-schema for every detail type (used by dashboard form generator) |

### Filters on `GET /assets`

`asset_type`, `criticality`, `tag`, `is_active`, `monitoring_enabled`, `q` (substring on `value`), `limit`, `offset`.

### CSV format

```
asset_type,value,criticality,tags,details_json
domain,example.com,high,public;external,
executive,Jane Doe,crown_jewel,,{"full_name":"Jane Doe","title":"CFO"}
```

`tags` is semicolon-separated. `details_json` is a single JSON-encoded
string. Unknown / extra columns are ignored. Per-row failures don't
abort the batch — they're returned in the `errors` array.

## Validation pipeline

1. **API layer:** Pydantic parses the request body (`AssetCreate` / `AssetUpdate`).
2. **Canonicalization:** `canonicalize_asset_value(asset_type, value)` enforces format + returns the storage form.
3. **Type-specific details:** `validate_asset_details(asset_type, details)` routes to the schema in `ASSET_DETAIL_SCHEMAS` and rejects unknown shapes.
4. **Monitoring profile:** `validate_monitoring_profile()` parses with sane defaults.
5. **DB layer:** unique index + check constraints catch any drift the API missed.

A request that fails any step gets HTTP 422 with field-scoped error
details (Pydantic-formatted).

## Audit log

Every mutating call writes an `AuditLog` row with one of:
`asset_create`, `asset_update`, `asset_delete`, `asset_bulk_import`,
`asset_discover`. The audit log is queried via `/api/v1/audit` (existing).

## Tenant isolation

- `parent_asset_id` is verified to belong to the same organization as the new asset.
- Every list/get endpoint scopes by `organization_id`.
- Cross-tenant access returns 404 (not 403) to avoid leaking existence.
- Tenant-isolation tests live in `tests/test_assets.py::test_cross_org_listing_isolated` and `::test_parent_asset_must_match_org`.

## How later phases consume the registry

| Phase | Module | Reads which asset types |
|-------|--------|--------------------------|
| 1 | EASM | `domain`, `subdomain`, `ip_address`, `ip_range`, `service` |
| 1 | Security Rating | All — rolls up signals |
| 2 | DMARC360 | `email_domain` |
| 3 | Brand Protection | `domain`, `brand` |
| 3 | Logo abuse | `brand` (logo evidence hashes) |
| 4 | Exec impersonation | `executive`, `social_handle` |
| 4 | Mobile app | `mobile_app`, `brand` |
| 5 | DLP | `domain`, `code_repository`, `brand` |
| 6 | Cloud hunting | `cloud_account` |
| 7 | TPRM | `vendor`, `domain` (vendor's), `email_domain` (vendor's) |

## Tests

`tests/test_assets.py` — 14 integration tests covering type validation,
canonicalization, CRUD, filters, count, bulk JSON, bulk CSV,
duplicates, cross-tenant isolation, parent-asset validation, auth
gating, schema introspection, and audit-log emission. All run against
the real test Postgres via `pytest-asyncio + httpx`.

Run:

```bash
ARGUS_TEST_DB_URL=postgresql+asyncpg://argus:argus@localhost:5432/argus_test \
  pytest tests/test_assets.py -v
```

## Not yet built (deliberate — comes in later Phase 0 sub-modules)

- Onboarding wizard UI (Phase 0.2)
- Evidence vault MinIO storage referenced from `photo_evidence_hashes` / `logo_evidence_hashes` (Phase 0.3)
- Case management linkage (Phase 0.4)
- Notification routing on asset changes (Phase 0.5)
- MITRE ATT&CK tagging on findings that reference assets (Phase 0.6)
- Asset health background scheduler — refreshes WHOIS/DNS hourly (Phase 1 prereq)

These are tracked in `CTM360_PARITY_PLAN.md`.
