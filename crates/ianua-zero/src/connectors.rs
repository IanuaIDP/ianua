//! Reaching services inside tenants' own networks, through the connectors
//! the tenants run there.
//!
//! A connector dials out to the gateway's connector listener over mutual
//! TLS and holds one HTTP/2 connection open, its link, with the gateway as
//! the HTTP/2 client. No port in the tenant's network is opened to the
//! internet. When a request is for a service reached through a connector,
//! the service's pool opens its connection to the backend by sending a
//! `CONNECT host:port` down one of the connector's links, and the
//! connector dials the backend from inside. Everything above that
//! connection, TLS to the backend, the request with its stripped and
//! signed identity, a protocol switch, is exactly what any other upstream
//! gets.
//!
//! Deny by default at every step. A connection without a certificate from
//! the connector authority, one whose certificate names a connector its
//! tenant does not hold enrolled with that key, or a revoked one, never
//! becomes a link. A backend outside the connector's scope is never asked
//! for. A service whose connector holds no link here is answered as
//! unavailable, never dialled straight from the gateway. Each tenant's
//! enrolled connectors are what the follower last read; every read judges
//! the tenant's links again, so a revocation closes a link as soon as it is
//! heard.

mod dialer;
mod links;
mod listener;
mod sightings;
mod tls;

use std::time::Duration;

pub(crate) use dialer::{LinkDialer, LinkError, LinkedStream, link_error_in};
pub(crate) use links::ConnectorLinks;
pub(crate) use listener::{ConnectorListener, ConnectorListenerParts};
pub(crate) use tls::server_config;

/// What connector links are held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinkLimits {
    /// The most links open at once across every connector.
    pub max_links: usize,
    /// The most links one connector may hold at once.
    pub links_per_connector: usize,
    /// The most connections to backends one link carries at once.
    pub streams_per_link: usize,
    /// The longest the TLS handshake, and the HTTP/2 one after it, may
    /// take.
    pub handshake: Duration,
    /// The longest opening one connection down a link may take.
    pub open: Duration,
    /// How often a link is pinged, and how long the answer may take.
    pub keepalive: Duration,
    /// How often a link that stays open is noted as seen.
    pub sighting: Duration,
}

#[cfg(test)]
mod tests;
