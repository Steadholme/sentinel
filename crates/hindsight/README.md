# Hindsight — incident timeline / RCA correlator

The observability **capstone** of the Steadholme estate. Hindsight correlates metrics + logs +
audit into one queryable, time-ordered **incident timeline**, lets operators **open incidents**
over a window, and threads **notes** onto them for root-cause analysis.

Internal-only, behind Sluice at `rca.w33d.xyz` (`auth=sso`). No login UI of its own — it trusts
the gateway-injected `X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope` and strips any inbound
copies.

## Data sources (resilient, concurrent)

The timeline merges three feeds, fetched concurrently. Any down source degrades to
**"unavailable"** — the page never crashes.

| Feed | Transport | Endpoint / table |
|------|-----------|------------------|
| Watchtower audit events | plain HTTP (open internally) | `GET http://watchtower:8500/api/events?limit=N` |
| Sift error/warn logs | READ-ONLY Postgres pool | `SIFT_DATABASE_URL` → `logs` table |
| Vitals anomalies | plain HTTP (open internally) | `GET http://vitals:8300/api/metrics?since=` |

All timestamps are normalized to **epoch seconds** before merge (Watchtower stamps `ts` in ms).

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/` | sso | Dashboard: merged timeline over a window + incidents list |
| GET | `/incident/{id}` | sso | One incident + its merged evidence window + notes |
| POST | `/api/incidents` | sso + CSRF | Open an incident over a time window |
| POST | `/api/incidents/{id}/notes` | sso + CSRF | Thread a note onto an incident |
| GET | `/api/timeline?from=&to=` | sso | JSON merged timeline |
| GET | `/healthz` | none | Liveness (container HEALTHCHECK) |

Opening an incident emits a non-blocking `hindsight.incident.open` audit event to Watchtower.

## Storage

Boots **zero-config** in-memory (`HINDSIGHT_STORE=memory`, the default). For persistence set
`HINDSIGHT_STORE=postgres` + `DATABASE_URL`; the schema (portable standard SQL only, runtime
queries — no macros, no vendor types) is migrated on startup:

- `incidents(id, title, status, from_ts, to_ts, created_by, created_at)`
- `notes(id, incident_id, body, author_sub, created_at)`

## Configuration

| Env | Default | Purpose |
|-----|---------|---------|
| `BIND_ADDR` | `0.0.0.0:9180` | Listen address |
| `HINDSIGHT_STORE` | `memory` | `memory` or `postgres` |
| `DATABASE_URL` | — | Own incidents/notes DB (required when `postgres`) |
| `SIFT_DATABASE_URL` | — | READ-ONLY Sift logs DB (feed empty if unset) |
| `VITALS_URL` | `http://vitals:8300` | Vitals base URL |
| `WATCHTOWER_URL` | `http://watchtower:8500` | Watchtower base URL (events + audit ingest) |
| `AUDIT_ENABLED` | `false` | Enable the non-blocking Watchtower audit emitter |
| `AUDIT_INGEST_TOKEN` | — | Bearer token for audit ingest |

## Build / test

```sh
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test
```
