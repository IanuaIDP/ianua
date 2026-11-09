//! Reaching a target the allow list let through: a listed address dialled
//! as it is, a listed name resolved here and each address it leads to
//! held to the list's rule for names, all within the dial timeout.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::targets::{AllowList, Target};

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

/// Why a target was not reached.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DialError {
    /// Resolving and connecting took longer than the dial timeout.
    #[error("the target did not answer in time")]
    TimedOut,
    /// The name leads to no address the list lets it lead to.
    #[error("the target's name leads to no address it may")]
    NoAddress,
    /// Every address refused or failed.
    #[error("the target could not be reached")]
    Failed(#[source] io::Error),
}

/// Where targets are looked up and how long reaching one may take.
#[derive(Debug, Clone)]
pub(crate) struct Dialer<R> {
    /// Looks names up.
    pub resolver: R,
    /// The list a name's addresses are held to.
    pub targets: AllowList,
    /// The longest resolving and connecting may take.
    pub timeout: Duration,
}

impl<R: Resolve> Dialer<R> {
    /// A connection to `target`, which the list already let through, on
    /// the first of its addresses that answers.
    ///
    /// # Errors
    ///
    /// [`DialError`] when the time runs out, no address may be dialled, or
    /// none answers.
    pub(crate) async fn dial(&self, target: &Target) -> Result<TcpStream, DialError> {
        tokio::time::timeout(self.timeout, self.connected(target))
            .await
            .map_err(|_| DialError::TimedOut)?
    }

    async fn connected(&self, target: &Target) -> Result<TcpStream, DialError> {
        let addresses = self.addresses_of(target).await?;
        let mut last = DialError::NoAddress;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last = DialError::Failed(error),
            }
        }
        Err(last)
    }

    async fn addresses_of(&self, target: &Target) -> Result<Vec<SocketAddr>, DialError> {
        let (name, port) = match target {
            Target::Address { address, port } => return Ok(vec![SocketAddr::new(*address, *port)]),
            Target::Name { name, port } => (name, *port),
        };
        let resolved = self
            .resolver
            .addresses(name, port)
            .await
            .map_err(DialError::Failed)?;
        Ok(resolved
            .into_iter()
            .filter(|address| self.targets.admits_resolved(address.ip(), port))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver answering every name with `address`.
    struct Fixed(SocketAddr);

    impl Resolve for Fixed {
        async fn addresses(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::new(self.0.ip(), port)])
        }
    }

    fn dialer(address: SocketAddr, entries: &[&str]) -> Dialer<Fixed> {
        Dialer {
            resolver: Fixed(address),
            targets: AllowList::parse(entries.iter().copied()).unwrap(),
            timeout: Duration::from_secs(5),
        }
    }

    /// A listed wiki name resolving to the metadata address fails with
    /// no permitted address to dial.
    #[tokio::test]
    async fn a_name_leading_to_the_metadata_address_is_never_dialled() {
        let metadata: SocketAddr = "169.254.169.254:443".parse().unwrap();
        let dialer = dialer(metadata, &["wiki.corp.internal:443"]);

        let dialled = dialer
            .dial(&Target::parse("wiki.corp.internal:443").unwrap())
            .await;

        assert!(matches!(dialled, Err(DialError::NoAddress)));
    }

    /// A listed loopback service is reached through its listed address.
    #[tokio::test]
    async fn a_listed_address_is_dialled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let entry = address.to_string();
        let dialer = dialer(address, &[entry.as_str()]);

        let dialled = dialer.dial(&Target::parse(&entry).unwrap()).await;

        assert!(dialled.is_ok());
    }
}
