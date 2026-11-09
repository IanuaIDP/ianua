//! Keeping the gateway off addresses no backend may be at.
//!
//! The control plane refuses an upstream naming an internal address when
//! it is written, but a name is only as good as what it resolves to when
//! the gateway connects, and an answer from discovery is an address nobody
//! wrote at all. So every address is screened again here: a literal before
//! anything is sent to it, a name each time it resolves.

use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::shared::validation::UrlHost;
use ianua_domain::types::HttpUrl;
use tower_service::Service;

/// Resolves names as the system does, then keeps only the addresses the
/// networks permit. A name left with none fails to resolve.
#[derive(Clone)]
pub(super) struct ScreenedResolver {
    inner: GaiResolver,
    networks: Arc<UpstreamNetworks>,
}

impl ScreenedResolver {
    /// A resolver held to `networks`.
    pub(super) fn new(networks: Arc<UpstreamNetworks>) -> Self {
        Self {
            inner: GaiResolver::new(),
            networks,
        }
    }
}

impl Service<Name> for ScreenedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let mut inner = self.inner.clone();
        let networks = Arc::clone(&self.networks);
        Box::pin(async move {
            let resolved = inner.call(name).await?;
            let addresses = permitted(resolved, &networks);
            if addresses.is_empty() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, ScreenedOut));
            }
            Ok(addresses.into_iter())
        })
    }
}

/// A name every address of which the gateway may not reach.
#[derive(Debug, thiserror::Error)]
#[error("the name resolves to no address the gateway may reach")]
pub(super) struct ScreenedOut;

/// Whether the gateway may send to `url`: a name passes here and is
/// screened when it resolves, an address written out must be permitted.
pub(super) fn permits_literal(url: &HttpUrl, networks: &UpstreamNetworks) -> bool {
    match url.host() {
        UrlHost::Address(ip) => networks.permits(ip),
        UrlHost::Name(_) => true,
    }
}

/// Whether the screen refusing a name caused `error`.
///
/// An `io::Error` hides what it wraps from `source`, so each one in the
/// chain is opened as well.
pub(super) fn refused_by_screen(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(current) = cause {
        if is_screened_out(current) {
            return true;
        }
        cause = current.source();
    }
    false
}

/// Whether `cause` is the screen's refusal, or an `io::Error` wrapping it.
fn is_screened_out(cause: &(dyn Error + 'static)) -> bool {
    cause.is::<ScreenedOut>()
        || cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .is_some_and(<dyn Error + Send + Sync>::is::<ScreenedOut>)
}

/// The addresses `networks` permits, in the order resolved.
fn permitted(
    addresses: impl Iterator<Item = SocketAddr>,
    networks: &UpstreamNetworks,
) -> Vec<SocketAddr> {
    addresses
        .filter(|address| networks.permits(address.ip()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn url(text: &str) -> HttpUrl {
        HttpUrl::new(text).unwrap()
    }

    #[test]
    fn only_permitted_addresses_are_dialled() {
        let resolved = addresses(&["93.184.216.34:443", "10.0.0.5:443", "169.254.169.254:80"]);

        let kept = permitted(resolved.into_iter(), &UpstreamNetworks::public_only());

        assert_eq!(kept, addresses(&["93.184.216.34:443"]));
    }

    /// The self-hosted case: the operator listed the cluster network, and
    /// the metadata service stays out whatever is listed.
    #[test]
    fn a_listed_network_never_opens_the_metadata_service() {
        let listed = UpstreamNetworks::parse_list("0.0.0.0/0").unwrap();
        let resolved = addresses(&["10.42.0.17:8080", "169.254.169.254:80"]);

        let kept = permitted(resolved.into_iter(), &listed);

        assert_eq!(kept, addresses(&["10.42.0.17:8080"]));
    }

    #[test]
    fn an_address_written_out_must_be_permitted() {
        let public = UpstreamNetworks::public_only();
        let loopback = UpstreamNetworks::parse_list("127.0.0.0/8").unwrap();

        assert!(!permits_literal(&url("http://169.254.169.254/"), &public));
        assert!(!permits_literal(&url("http://127.0.0.1:8080/"), &public));
        assert!(permits_literal(&url("http://127.0.0.1:8080/"), &loopback));
        assert!(permits_literal(
            &url("http://orders.internal:8080/"),
            &public
        ));
    }

    #[test]
    fn a_screened_out_name_is_recognised_inside_an_io_error() {
        let wrapped = io::Error::new(io::ErrorKind::PermissionDenied, ScreenedOut);
        let other = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");

        assert!(refused_by_screen(&wrapped));
        assert!(!refused_by_screen(&other));
    }
}
