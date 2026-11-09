//! Registered domains as a test sets them up, read back as storage would
//! keep them.

use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomain, RegisteredDomainRow,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{DomainId, DomainName};
use time::OffsetDateTime;

/// The challenge token every seeded domain was given.
pub const TEST_CHALLENGE_TOKEN: &str = "challenge-token";

/// A registered domain a test describes, built with [`DomainSeed::build`].
///
/// Starts tenant-managed, never proved and needing no certificate, made
/// now. Each method changes one thing.
#[derive(Debug, Clone)]
pub struct DomainSeed {
    name: String,
    connection: DomainConnection,
    proof: DomainProof,
    tls_status: TlsStatus,
    created_at: OffsetDateTime,
}

impl DomainSeed {
    /// `name`, registered just now and not yet proved.
    #[must_use]
    pub fn pending(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            connection: DomainConnection::SelfManaged,
            proof: DomainProof::Unproved,
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now(),
        }
    }

    /// `name`, registered and proved just now.
    #[must_use]
    pub fn verified(name: &str) -> Self {
        Self::pending(name).proved_at(clock::now())
    }

    /// Delegated to us, with the certificate a delegated domain starts
    /// waiting for.
    #[must_use]
    pub fn delegated(self) -> Self {
        Self {
            connection: DomainConnection::Delegated,
            tls_status: TlsStatus::Provisioning,
            ..self
        }
    }

    /// Proved at `at`, registered no later.
    #[must_use]
    pub fn proved_at(self, at: OffsetDateTime) -> Self {
        Self {
            proof: DomainProof::Verified { at },
            created_at: self.created_at.min(at),
            ..self
        }
    }

    /// Proved when it was registered, and the proof lost just now.
    #[must_use]
    pub fn lost(self) -> Self {
        self.lost_at(clock::now())
    }

    /// Proved when it was registered, and the proof lost at `at`.
    #[must_use]
    pub fn lost_at(self, at: OffsetDateTime) -> Self {
        Self {
            proof: DomainProof::Lost {
                verified_at: self.created_at,
                failed_at: at,
            },
            ..self
        }
    }

    /// Registered at `at`.
    #[must_use]
    pub fn created_at(self, at: OffsetDateTime) -> Self {
        Self {
            created_at: at,
            ..self
        }
    }

    /// With its certificate standing at `tls_status`.
    #[must_use]
    pub fn tls(self, tls_status: TlsStatus) -> Self {
        Self { tls_status, ..self }
    }

    /// The registration, under a fresh id.
    ///
    /// # Panics
    ///
    /// If the name is not a valid domain, or the seed describes a row the
    /// domain refuses. Tests describe ones it accepts.
    #[must_use]
    pub fn build(self) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: DomainName::new(self.name).expect("a valid domain"),
            connection: self.connection,
            proof: self.proof,
            dns_challenge_token: DomainVerificationToken::new(TEST_CHALLENGE_TOKEN)
                .expect("a valid token"),
            tls_status: self.tls_status,
            created_at: self.created_at,
        })
        .expect("a seeded domain is a consistent row")
    }
}
