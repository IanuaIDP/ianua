//! Where a routing change asks the proxy to connect, and the check that it
//! may.

use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::stream::StreamBackend;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

use crate::error::AppError;
use crate::services::routing::reachability::{
    reject_private_stream_backends, reject_private_upstream,
};

/// A new place the proxy is to connect to on the tenant's behalf.
#[derive(Clone, Copy)]
pub(crate) enum Destination<'a> {
    /// A service's upstream, with every weighted backend in it.
    Upstream(&'a Upstream),
    /// The backends a stream route splices connections to.
    StreamBackends(&'a [StreamBackend]),
}

/// Refuses `destination`, when a change brings a new one, on an internal
/// address `networks` does not allow.
///
/// # Errors
///
/// `AppError::Domain` when a target is a refused internal address.
pub(crate) fn ensure_reachable(
    destination: Option<Destination<'_>>,
    networks: &UpstreamNetworks,
) -> Result<(), AppError> {
    let refusal = match destination {
        None => return Ok(()),
        Some(Destination::Upstream(upstream)) => reject_private_upstream(upstream, networks),
        Some(Destination::StreamBackends(backends)) => {
            reject_private_stream_backends(backends, networks)
        }
    };
    refusal.map_err(AppError::from_domain)
}
