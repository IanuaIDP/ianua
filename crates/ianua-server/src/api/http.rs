//! How the API's HTTP layer behaves, from the configuration: what it serves,
//! whom it lets in from a browser, and what it bounds.

use std::num::NonZeroUsize;
use std::sync::Arc;

use ianua_api::credential_use::RecentUse;
use ianua_api::middleware::sign_in_admission::SignInAdmission;
use ianua_api::state::http::HttpSettings;
use ianua_api::ws_limits::StreamLimiter;
use ianua_boot::env::Read;

use crate::assembly::settings::count;
use crate::config::Config;

/// How the HTTP layer behaves.
pub(super) fn http(config: &Config) -> Read<HttpSettings> {
    let http = &config.http;
    Ok(HttpSettings {
        streams: Arc::new(StreamLimiter::new(http.streams_per_owner)),
        stream_recheck: http.stream_recheck,
        stream_lifetime: http.stream_lifetime,
        credential_use: Arc::new(RecentUse::new(
            http.credential_use_interval,
            config.cache.callers.capacity,
        )),
        sso_cookie_lifetime_secs: count(
            "AUTH_FEDERATION_FLOW_TTL_SECONDS",
            config.sign_in.federation_flow_ttl.as_secs(),
        )?,
        api_docs: http.api_docs,
        cors_origin: http.cors_origin.clone(),
        rate: config.limits.rate,
        sign_ins: sign_in_admission(config),
        public_listener: http.public_limits,
        internal_listener: http.internal_limits,
    })
}

/// The sign-ins a node works on at once: as many as it hashes passwords
/// at once, but never more than half its database connections, so a crowd
/// of sign-ins always leaves connections for everybody else. A sign-in
/// waits for a place as long as it would for a hash.
fn sign_in_admission(config: &Config) -> SignInAdmission {
    let hashing = config.crypto.hashing;
    let half_the_connections = usize::try_from(config.database.pools.platform_connections / 2)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(NonZeroUsize::MIN);
    SignInAdmission::new(hashing.concurrency.min(half_the_connections), hashing.wait)
}
