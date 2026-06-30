//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like the rest of
//! the estate. Production overrides each via the environment.
//!
//! Hindsight reads from THREE upstreams to build its merged timeline:
//! - Vitals metrics over plain HTTP (`<VITALS_URL>/api/metrics`, open internally);
//! - Watchtower events over plain HTTP (`<WATCHTOWER_URL>/api/events`, open internally);
//! - Sift logs over a READ-ONLY Postgres pool (`SIFT_DATABASE_URL`, Sift's `logs` table).
//! Any down upstream degrades to "unavailable" — it never blocks or fails a page.

/// Default listen address (all interfaces, internal-only port 9180).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9180";
/// Default INTERNAL Vitals base URL. The timeline appends `/api/metrics` for host gauges.
pub const DEFAULT_VITALS_URL: &str = "http://vitals:8300";
/// Default INTERNAL Watchtower base URL. The timeline appends `/api/events` for audit events,
/// and the non-blocking audit emitter POSTs to `<url>/events`.
pub const DEFAULT_WATCHTOWER_URL: &str = "http://watchtower:8500";

/// Hard cap on how many incidents the list renders (keeps an unbounded list bounded).
pub const LIST_LIMIT: usize = 200;
/// Default timeline window, in hours, when the dashboard is loaded without a `?window=` choice.
pub const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Hard cap on merged timeline events returned per request (bounds work + page length).
pub const TIMELINE_LIMIT: usize = 300;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// INTERNAL Vitals base URL (`VITALS_URL`); the timeline hits `<url>/api/metrics`.
    pub vitals_url: String,
    /// INTERNAL Watchtower base URL (`WATCHTOWER_URL`); the timeline hits `<url>/api/events`
    /// and the audit emitter POSTs to `<url>/events`.
    pub watchtower_url: String,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            vitals_url: DEFAULT_VITALS_URL.to_string(),
            watchtower_url: DEFAULT_WATCHTOWER_URL.to_string(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("VITALS_URL") {
            config.vitals_url = v;
        }
        if let Some(v) = env_nonempty("WATCHTOWER_URL") {
            config.watchtower_url = v;
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
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
