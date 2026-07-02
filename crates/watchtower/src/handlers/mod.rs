//! HTTP handlers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`events`] — append-only ingest (`POST /events`, bearer) + read APIs (`GET /api/verify`,
//!   `GET /api/events`, search/export).
//! - [`alerts`] — alert-rule creation (`POST /api/alert-rules`, SSO + CSRF) + match listing.
//! - [`checkpoints`] — Merkle checkpoint seal (`POST /api/checkpoint`, SSO + CSRF) + list with
//!   live re-verification (`GET /api/checkpoints`).
//! - [`dashboard`] — the server-rendered SSO mini-SIEM (`GET /` and any gateway-prefixed path),
//!   reading the Sluice-injected `X-Auth-Email`.

pub mod alerts;
pub mod checkpoints;
pub mod dashboard;
pub mod events;
pub mod health;
