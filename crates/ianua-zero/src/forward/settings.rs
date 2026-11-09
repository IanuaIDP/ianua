//! What the operator sets for the upstream side of the gateway.
//!
//! Read once at start by the configuration and handed in. Nothing here
//! reads the environment, and every value is a bound: a time something may
//! take, or how many of something may run at once.

use std::num::NonZeroUsize;
use std::time::Duration;

use ianua_domain::shared::security::ssrf::UpstreamNetworks;

/// How the gateway reaches backends and holds what it opens to them.
#[derive(Debug, Clone)]
pub(crate) struct ForwardSettings {
    /// The internal networks a backend may be in, beside public addresses.
    /// It must be the list the control plane checks upstreams against when
    /// they are written, or a route it accepted is refused here.
    pub networks: UpstreamNetworks,
    /// The longest a connection to a backend may take to open.
    pub connect_timeout: Duration,
    /// The longest a whole response may take, from the request leaving to
    /// the last byte of the answer. A service's own timeout bounds only the
    /// wait for the answer to start.
    pub response_deadline: Duration,
    /// The longest a long-lived answer, server-sent events or a stream the
    /// route marks, may send nothing. It is held to this instead of the
    /// response deadline.
    pub long_lived_idle: Duration,
    /// How long an unused pooled connection is kept open.
    pub pool_idle_timeout: Duration,
    /// The most unused connections kept open to one backend.
    pub pool_max_idle_per_backend: usize,
    /// How tunnels opened by a protocol switch are held.
    pub tunnels: TunnelLimits,
}

/// How many tunnels may be open at once, and what closes one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TunnelLimits {
    /// The most tunnels open at once. A switch asked for beyond it is
    /// refused before any backend is contacted.
    pub max_open: NonZeroUsize,
    /// The longest a tunnel stays open, whatever else holds. A credential
    /// that expires sooner closes it sooner.
    pub lifetime: Duration,
    /// How long a tunnel may carry nothing before it is closed. Also the
    /// longest both sides may take to complete the switch.
    pub idle: Duration,
    /// How often the authority a tunnel was opened under is asked again.
    pub recheck_every: Duration,
    /// How long that question may take before the tunnel is closed for it.
    pub recheck_timeout: Duration,
}

/// How hard the health probes may press on backends.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProbeSettings {
    /// The most probes in flight at once, across every service.
    pub max_in_flight: NonZeroUsize,
}

/// How often names are looked up, and how hard.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DiscoverySettings {
    /// How often the watch looks for services whose refresh interval has
    /// passed. It bounds how late a lookup can be, not how often one runs.
    pub tick: Duration,
    /// The longest one lookup may take before it counts as failed.
    pub lookup_timeout: Duration,
    /// The most lookups in flight at once.
    pub max_in_flight: NonZeroUsize,
}
