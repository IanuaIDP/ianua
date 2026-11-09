//! Reaching a destination the policy let out: its name resolved by the
//! egress gateway itself, so services need no DNS of their own, and every
//! address screened before it is dialled.
//!
//! A public name can be made to resolve to an internal address. Each
//! address it resolves to is held to the deployment's networks, public
//! addresses only unless the operator lists internal ones, so a listed
//! host whose name was pointed at the cloud's metadata address reaches
//! nothing.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use ianua_domain::domains::routing::egress::EgressTarget;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use tokio::net::TcpStream;

/// Turns a host name into addresses.
pub trait Resolve: Send + Sync + 'static {
    /// The addresses `host` resolves to, each with `port`.
    ///
    /// # Errors
    ///
    /// The lookup's error.
    fn addresses(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}

/// The operating system's resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    async fn addresses(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Where destinations are looked up and which addresses they may be.
#[derive(Debug, Clone)]
pub struct Reach<R> {
    /// Looks names up.
    pub resolver: R,
    /// The addresses a destination may resolve to.
    pub networks: UpstreamNetworks,
    /// The longest resolving and connecting may take.
    pub timeout: Duration,
}

impl<R: Resolve> Reach<R> {
    /// A connection to `target`, on the first of its permitted addresses
    /// that answers.
    ///
    /// # Errors
    ///
    /// Returns the lookup's or the last connection's error, one saying no
    /// address is permitted, or one saying the time ran out.
    pub async fn dial(&self, target: &EgressTarget) -> io::Result<TcpStream> {
        tokio::time::timeout(self.timeout, self.connected(target))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the destination did not answer in time",
                )
            })?
    }

    async fn connected(&self, target: &EgressTarget) -> io::Result<TcpStream> {
        let permitted: Vec<SocketAddr> = self
            .resolver
            .addresses(target.host().as_str(), target.port())
            .await?
            .into_iter()
            .filter(|address| self.networks.permits(address.ip()))
            .collect();
        let mut last = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the destination resolves to no address it may reach",
        );
        for address in permitted {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::CidrRange;

    use super::*;

    /// A resolver answering every name with `address`.
    struct Fixed(SocketAddr);

    impl Resolve for Fixed {
        async fn addresses(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::new(self.0.ip(), port)])
        }
    }

    fn reach(address: SocketAddr, networks: UpstreamNetworks) -> Reach<Fixed> {
        Reach {
            resolver: Fixed(address),
            networks,
            timeout: Duration::from_secs(5),
        }
    }

    /// A listed host resolving to a permitted address is reached.
    #[tokio::test]
    async fn a_permitted_address_is_dialled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let loopback = UpstreamNetworks::new(vec![CidrRange::new("127.0.0.0/8").unwrap()]);
        let target = EgressTarget::new("api.github.com", address.port()).unwrap();

        let dialled = reach(address, loopback).dial(&target).await;

        assert!(dialled.is_ok());
    }

    /// A host resolving to loopback is denied when only public addresses
    /// are permitted, despite a listener at that address.
    #[tokio::test]
    async fn an_internal_address_is_never_dialled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = EgressTarget::new("api.github.com", address.port()).unwrap();

        let dialled = reach(address, UpstreamNetworks::public_only())
            .dial(&target)
            .await;

        assert_eq!(dialled.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
