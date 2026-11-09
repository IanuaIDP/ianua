//! What the certificate provisioner needs inside itself and asks others
//! for: the account it holds with an authority, and a place to publish a
//! DNS-01 proof. Neither is an app port, since no use case asks for them.

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::dns_zone::TxtValue;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DomainName;

/// The directory of a certificate authority, the address an ACME client
/// starts from.
///
/// Always `https`, but for an authority on this machine's loopback, such
/// as a local test authority, which may answer over plain `http`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AcmeDirectory(url::Url);

impl AcmeDirectory {
    /// The directory at `address`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `address` is not a URL, or is
    /// plain `http` on anything but this machine's loopback.
    pub fn parse(address: &str) -> Result<Self, DomainError> {
        let url = url::Url::parse(address).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-acme-directory-is-not-a",
                "the ACME directory is not a URL"
            ))
        })?;
        match (url.scheme(), url.host_str()) {
            ("https", Some(_)) | ("http", Some("127.0.0.1" | "localhost" | "[::1]")) => {
                Ok(Self(url))
            }
            _ => Err(DomainError::invalid(message!(
                "infra-the-acme-directory-must-be-an",
                "the ACME directory must be an https address"
            ))),
        }
    }

    /// The directory as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The account held with each certificate authority.
///
/// Registration is rate limited by every authority, so an account is made
/// once and reused. It is keyed by directory, so a staging account and a
/// production one live side by side. The credentials hold the account's
/// private key, so a store seals them before they reach storage.
#[async_trait]
pub trait AcmeAccountStore: Send + Sync {
    /// The credentials held for `directory`, if any.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read or
    /// opened.
    async fn load(&self, directory: &AcmeDirectory) -> Result<Option<Secret>, DomainError>;

    /// Keeps `credentials` for `directory`, replacing any held before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be sealed or
    /// written.
    async fn save(
        &self,
        directory: &AcmeDirectory,
        credentials: &Secret,
    ) -> Result<(), DomainError>;
}

/// Where a DNS-01 proof is published: the `TXT` record at
/// `_acme-challenge.{zone}` of a zone we answer for.
///
/// Not tenant-scoped, since a renewal runs with nobody to act for, but
/// bound to the hostname: the zone the proof lands in must be held by the
/// tenant that registered that hostname. A wildcard's proof goes into its
/// parent's zone, so this matters most there.
#[async_trait]
pub trait AcmeDnsChallengeStore: Send + Sync {
    /// Publishes `value` as a proof for `hostname`, beside any other proof
    /// there.
    ///
    /// `auth.acme.com` and `*.auth.acme.com` are proved under the same
    /// name, often at once, and an authority takes any value it finds
    /// there. Replacing the proofs there would fail the other order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::NotFound` when no registration holds the
    /// hostname, or its tenant holds no zone for it, and
    /// `DomainError::Infrastructure` when the write fails.
    async fn publish(&self, hostname: &DomainName, value: &TxtValue) -> Result<(), DomainError>;

    /// Withdraws the proof `value` for `hostname`, leaving any other proof
    /// there. A proof that is not there is not an error.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the removal fails.
    async fn withdraw(&self, hostname: &DomainName, value: &TxtValue) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An https directory is taken as written.
    #[test]
    fn an_https_directory_is_accepted() {
        let directory =
            AcmeDirectory::parse("https://acme-v02.api.letsencrypt.org/directory").unwrap();

        assert_eq!(
            directory.as_str(),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    /// Directory parsing rejects remote plain HTTP and malformed URLs while
    /// permitting HTTP on the local loopback.
    #[test]
    fn plain_http_is_refused_off_the_loopback() {
        assert!(AcmeDirectory::parse("http://acme.example.com/directory").is_err());
        assert!(AcmeDirectory::parse("http://127.0.0.1:14000/dir").is_ok());
        assert!(AcmeDirectory::parse("not a url").is_err());
    }
}
