//! Where the shared state lives, in this process or on a cache server,
//! and how much the store caches keep.

use std::fmt;
use std::time::Duration;

use ianua_domain::shared::security::secret::Secret;
use ianua_infra::cache::EntryKeeping;

use crate::env::{ConfigError, Env, Read};

/// Where the shared state lives.
#[derive(Clone)]
pub enum CachePlace {
    /// In this process, holding at most `entries` entries.
    Memory {
        /// `CACHE_MEMORY_ENTRIES` (100000).
        entries: usize,
    },
    /// On the cache server `url` names. The URL may hold a password, so
    /// it is a secret.
    Server {
        /// `CACHE_URL`, such as `redis://cache.internal:6379`, or
        /// `CACHE_URL_FILE`.
        url: Secret,
    },
}

impl fmt::Debug for CachePlace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory { entries } => f.debug_struct("Memory").field("entries", entries).finish(),
            Self::Server { .. } => f.write_str("Server(redacted)"),
        }
    }
}

/// The shared state and the store caches in front of the stores.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Where the shared state lives: on a server when `CACHE_URL` is set.
    pub place: CachePlace,
    /// `CACHE_TIMEOUT_SECONDS` (5): the longest one call to the cache
    /// server may take.
    pub timeout: Duration,
    /// `STORE_CACHE_LIFETIME_SECONDS` (20) and `STORE_CACHE_CALLERS`
    /// (50000): how long and how many resolved callers are kept.
    pub callers: EntryKeeping,
    /// `STORE_CACHE_LIFETIME_SECONDS` (20) and `STORE_CACHE_HOLDINGS`
    /// (20000): how long and how many holders' access records are kept.
    pub holdings: EntryKeeping,
}

impl CacheConfig {
    /// The cache `vars` names.
    ///
    /// # Errors
    ///
    /// A `CACHE_URL` that is no cache address, or a number out of range.
    /// The store caches' lifetime is held to 1 to 300 seconds: it is how
    /// long a revoked grant may still be served.
    pub fn read(vars: &Env) -> Read<Self> {
        let lifetime = vars.seconds_in(
            "STORE_CACHE_LIFETIME_SECONDS",
            Duration::from_secs(20),
            1..=300,
        )?;
        Ok(Self {
            place: place(vars)?,
            timeout: vars.seconds("CACHE_TIMEOUT_SECONDS", Duration::from_secs(5))?,
            callers: EntryKeeping {
                lifetime,
                capacity: vars.number_in("STORE_CACHE_CALLERS", 50_000, 1..=10_000_000)?,
            },
            holdings: EntryKeeping {
                lifetime,
                capacity: vars.number_in("STORE_CACHE_HOLDINGS", 20_000, 1..=10_000_000)?,
            },
        })
    }

    /// Whether the shared state lives in this process.
    #[must_use]
    pub fn in_process(&self) -> bool {
        matches!(self.place, CachePlace::Memory { .. })
    }
}

/// Where the shared state lives.
fn place(vars: &Env) -> Read<CachePlace> {
    let Some(url) = vars.secret("CACHE_URL")? else {
        return Ok(CachePlace::Memory {
            entries: vars.number_in("CACHE_MEMORY_ENTRIES", 100_000, 1..=100_000_000)?,
        });
    };
    let reads = url::Url::parse(url.expose()).is_ok_and(|parsed| {
        matches!(parsed.scheme(), "redis" | "rediss") && parsed.host_str().is_some()
    });
    if !reads {
        return Err(ConfigError::invalid(
            "CACHE_URL",
            "must be a redis:// or rediss:// address",
        ));
    }
    Ok(CachePlace::Server { url })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no cache server named, the state lives in this process and the
    /// store caches keep the documented amounts.
    #[test]
    fn with_no_server_the_state_lives_in_this_process() {
        let config = CacheConfig::read(&Env::of([])).unwrap();

        assert!(config.in_process());
        assert_eq!(config.callers.capacity, 50_000);
        assert_eq!(config.holdings.capacity, 20_000);
        assert_eq!(config.callers.lifetime, Duration::from_secs(20));
    }

    /// Debug output for a configured cache omits the address's password.
    #[test]
    fn the_cache_address_never_prints() {
        let config = CacheConfig::read(&Env::of([(
            "CACHE_URL",
            "redis://:hunter2@cache.internal:6379",
        )]))
        .unwrap();

        assert!(!format!("{config:?}").contains("hunter2"));
    }

    /// An unsupported cache URL is refused by setting name without its password.
    #[test]
    fn an_address_that_is_no_cache_address_is_refused_without_repeating_it() {
        let read = CacheConfig::read(&Env::of([("CACHE_URL", "http://:hunter2@cache.internal")]));

        let message = read.unwrap_err().to_string();
        assert!(message.starts_with("CACHE_URL"));
        assert!(!message.contains("hunter2"));
    }

    /// An hour-long store cache lifetime is refused at configuration time.
    #[test]
    fn a_store_cache_lifetime_past_five_minutes_is_refused() {
        let read = CacheConfig::read(&Env::of([("STORE_CACHE_LIFETIME_SECONDS", "3600")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "STORE_CACHE_LIFETIME_SECONDS")
        );
    }
}
