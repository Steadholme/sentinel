# Hindsight — incident evidence comparator

Hindsight is the Steadholme operator surface for comparing Watchtower audit records, Sift
log records, and Vitals metric classifications over one explicit time window. It presents an
evidence register; it does not infer a root cause, rewrite source payloads, or hide a degraded
source behind an empty result.

The service is internal-only behind Sluice at `rca.w33d.xyz` with `auth=sso`. It has no login
screen. Every read and mutation route independently requires the bounded
`X-Auth-Subject` gateway identity; `X-Auth-Email` is optional display metadata and is never an
authority.

## Evidence model

The three source channels are acquired independently and retain their own state, coverage,
counts, boundedness, source keys, and payload tuples. A failed channel does not erase a loaded
sibling. Exact duplicates collapse; same-key, different-payload records remain visible as a
conflict. Millisecond evidence stays millisecond-precise, while the legacy JSON fields keep
their established seconds-based names, types, units, and source labels.

The acquisition states distinguish:

- configuration absent or invalid;
- transport unavailable;
- non-success HTTP response;
- oversize/truncated response;
- invalid source schema;
- loaded evidence.

The displayed evidence budget is global and deterministic. Source-preserving allocation,
clipping, lower-bound coverage, and completeness gaps are shown as presentation truth instead
of being converted into a generic “available” flag.

## Routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | none | Container liveness only; it is not readiness |
| `GET` | `/` | SSO subject | Dashboard, three evidence channels, and bounded incident register |
| `GET` | `/incident/{id}` | SSO subject | Frozen incident window, evidence, notes, and resolution mark |
| `GET` | `/api/timeline?from=&to=` | SSO subject | Legacy seconds-compatible fields plus JSON v2 truth |
| `GET` | `/api/timeline?from_ms=&to_ms=` | SSO subject | Exact millisecond JSON v2 window |
| `POST` | `/api/incidents` | SSO subject + CSRF | Open an incident |
| `POST` | `/api/incidents/{id}/notes` | SSO subject + CSRF | Add an operator note |
| `POST` | `/api/incidents/{id}/resolve` | SSO subject + CSRF | Atomically resolve with an idempotency command |

Queries and native forms use closed schemas: unknown fields, duplicates, malformed
percent-encoding, invalid UTF-8, oversized bodies, and mixed legacy/exact JSON window families
are rejected. Mutation redirects are closed product-relative paths. A resolution persists one
observation instant and one public mark; same-command retries return the same truth, while a
different command receives a safe conflict response.

Opening an incident makes one best-effort, non-blocking Watchtower audit attempt. The UI never
claims that the event was enqueued, delivered, or stored. Adding a note and resolving an incident
do not emit audit events.

## Storage and migration

`HINDSIGHT_STORE=memory` is the zero-configuration default. Persistent deployments use
`HINDSIGHT_STORE=postgres` with `DATABASE_URL`.

The PostgreSQL migration is additive and transactional. It:

- performs a read-only legacy census before changing schema;
- preserves legacy `created_by` values as unclassified actor truth;
- adds verified actor subject and optional display-email columns;
- adds `resolution_marks` with unique command and public-mark identities;
- validates the post-migration schema fingerprint before the service is ready.

Invalid legacy lifecycle values, malformed identifiers, inconsistent timestamps, and orphaned
notes fail closed. Rollback means running the previous image against the additive schema; it does
not delete the new columns or `resolution_marks`.

## Source configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:9180` | Listen address |
| `HINDSIGHT_STORE` | `memory` | `memory` or `postgres` |
| `DATABASE_URL` | — | Hindsight-owned PostgreSQL database |
| `SIFT_DATABASE_URL` | — | Read-only Sift PostgreSQL source; unset is explicitly unconfigured |
| `VITALS_URL` | `http://vitals:8300` | Vitals base URL |
| `WATCHTOWER_URL` | `http://watchtower:8500` | Watchtower read and audit-ingest base URL |
| `AUDIT_ENABLED` | `false` | Enable the best-effort open-incident audit attempt |
| `AUDIT_INGEST_TOKEN` | — | Bearer token for Watchtower ingest |

Outbound source acquisition is bounded, strict UTF-8, and fail-closed. Logs and errors must not
contain URLs, DSNs, bearer tokens, response bodies, SQL text, or raw transport/database errors.

## Build and test

From the Sentinel repository root:

```sh
cargo fmt --manifest-path crates/hindsight/Cargo.toml -- --check
cargo check --manifest-path crates/hindsight/Cargo.toml --all-targets
cargo test --manifest-path crates/hindsight/Cargo.toml
cargo test --all-targets
```

The PostgreSQL concurrency and migration contract tests require a dedicated disposable test DSN.
Browser, accessibility, response-header, and live source probes are release gates for the joint
Sentinel deployment rather than substitutes for the Rust contract suite.
