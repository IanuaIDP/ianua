//! How the HTTP layer itself behaves: what it serves, whom it lets in from
//! a browser, and what it bounds. Filled by the composition root from its
//! settings.

/// How the HTTP layer itself behaves: what it serves, whom it lets in from
/// a browser, and what it bounds.
#[derive(Clone)]
pub struct HttpSettings {
    /// Counts each identity's live streams on this node.
    pub streams: std::sync::Arc<crate::ws_limits::StreamLimiter>,
    /// The longest a live stream goes without asking the app again whether
    /// its caller may still read it.
    pub stream_recheck: std::time::Duration,
    /// The longest a live stream stays open before its client connects
    /// again and is admitted from scratch.
    pub stream_lifetime: std::time::Duration,
    /// When each request's credential was last marked used, so it is
    /// marked once an interval rather than on every request.
    pub credential_use: std::sync::Arc<crate::credential_use::RecentUse>,
    /// How long the browser keeps the secret of a single sign-on: as long
    /// as the identity provider's answer may take, in seconds.
    pub sso_cookie_lifetime_secs: u32,
    /// Whether the Swagger UI and OpenAPI JSON are served.
    pub api_docs: ApiDocs,
    /// The one origin a browser may call the API from; `None` denies
    /// cross-origin browser requests, `*` allows any without credentials.
    pub cors_origin: Option<String>,
    /// How often one address or person may call the public endpoints.
    pub rate: RateLimits,
    /// The sign-ins this node works on at once, admitted before any reaches
    /// the database.
    pub sign_ins: crate::middleware::sign_in_admission::SignInAdmission,
    /// What the public listener takes on.
    pub public_listener: ListenerLimits,
    /// What the internal listener takes on.
    pub internal_listener: ListenerLimits,
}

/// How often one address or person may call the public endpoints.
#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    /// Sign-in and other public auth requests one address may make a minute.
    pub login_per_minute: u32,
    /// Agent relay requests one address may make a minute.
    pub agent_relay_per_minute: u32,
    /// SCIM requests one address may make a minute.
    pub scim_per_minute: u32,
    /// Single sign-on and sign-in page requests one address may make.
    pub sso: RateWindow,
    /// Sensitive requests, such as a password reset, one address may make.
    pub sensitive: RateWindow,
    /// Sensitive requests one signed-in person may make.
    pub user: RateWindow,
    /// Addresses the per-address limits track at once.
    pub max_tracked_ips: usize,
    /// API requests a tenant may make a minute when its organization's own
    /// limit cannot be read.
    pub api_default_per_minute: u32,
    /// How long an organization's request limit is cached.
    pub limit_cache_ttl: std::time::Duration,
}

/// So many requests in so long.
#[derive(Debug, Clone, Copy)]
pub struct RateWindow {
    /// Requests allowed in one window.
    pub max: u32,
    /// The window's length.
    pub window: std::time::Duration,
}

/// What one listener takes on at once.
#[derive(Debug, Clone, Copy)]
pub struct ListenerLimits {
    /// Requests served at once; more wait.
    pub max_concurrency: usize,
    /// Largest request body, in bytes.
    pub max_body_bytes: usize,
    /// Longest a request's handler may take before it is answered `504` and
    /// its writes dropped. A handler that finishes in time is committed and
    /// answered however long the commit takes.
    pub timeout: std::time::Duration,
}

/// Whether the API describes itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiDocs {
    /// The Swagger UI and OpenAPI JSON are served.
    Served,
    /// Neither is served, so the endpoint surface is not disclosed.
    Hidden,
}
