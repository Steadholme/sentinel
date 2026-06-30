//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so
//! the in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/keyward. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8500).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8500";
/// Dev/test default ingest bearer token. Production MUST override `AUDIT_INGEST_TOKEN`.
pub const DEFAULT_INGEST_TOKEN: &str = "watchtower-dev-ingest-token-change-me";
/// Hard cap on how many rows a single `/api/events` (or dashboard timeline) query returns.
/// Keeps an unfiltered dashboard load bounded; the full chain still verifies in `/api/verify`.
pub const QUERY_LIMIT: usize = 500;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Bearer token guarding `POST /events` ingest (`AUDIT_INGEST_TOKEN`). Also the keying
    /// secret for the `POST /api/checkpoint` CSRF token (no separate secret to manage).
    pub ingest_token: String,
    /// Optional allowlist of SSO emails permitted to seal a checkpoint
    /// (`WATCHTOWER_ADMIN_EMAILS`, comma-separated). Empty = any gateway-SSO user (the default
    /// that matches the `auth=sso` route).
    pub admin_emails: Vec<String>,
    /// Periodic auto-checkpoint cadence in seconds (`WATCHTOWER_CHECKPOINT_INTERVAL_SECS`).
    /// `0` (the default) disables the background sealer; on-demand `POST /api/checkpoint` still
    /// works regardless.
    pub checkpoint_interval_secs: u64,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            ingest_token: DEFAULT_INGEST_TOKEN.to_string(),
            admin_emails: Vec::new(),
            checkpoint_interval_secs: 0,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("AUDIT_INGEST_TOKEN") {
            config.ingest_token = v;
        }
        if let Some(v) = env_nonempty("WATCHTOWER_ADMIN_EMAILS") {
            config.admin_emails = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(v) = env_nonempty("WATCHTOWER_CHECKPOINT_INTERVAL_SECS") {
            if let Ok(secs) = v.parse::<u64>() {
                config.checkpoint_interval_secs = secs;
            }
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
