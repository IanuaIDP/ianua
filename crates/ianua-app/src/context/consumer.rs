//! A consumer calling in a tenant, known only by the credential it came
//! with.

use ianua_domain::types::{CertificateFingerprint, FederatedSubject, Issuer, KeyPrefix, TokenHash};

use crate::tenancy::ScopedTenant;

/// The credential a consumer's request came with, as the gateway checked
/// it.
#[derive(Debug, Clone)]
pub enum PresentedCredential {
    /// An API key: its visible prefix and the digest of the whole key.
    Key {
        /// The prefix the key starts with, which finds the consumer.
        prefix: KeyPrefix,
        /// The digest of the key the request carried.
        digest: TokenHash,
    },
    /// The fingerprint of the client certificate the connection proved it
    /// holds.
    Certificate(CertificateFingerprint),
    /// The claims of a token whose signature the gateway checked against
    /// the keys the consumer publishes.
    Token {
        /// The token's `iss` claim.
        issuer: Issuer,
        /// The token's `sub` claim.
        subject: FederatedSubject,
    },
}

/// Whether a consumer's sign-in counts against its quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaCharge {
    /// A request: it is counted, and refused once the period's allowance
    /// is spent.
    PerRequest,
    /// A check, while a connection stays open, that its credential still
    /// works. The connection was counted when it opened, so the check is
    /// not counted again, and a consumer kept in a long tunnel never spends
    /// its allowance on being asked about.
    AlreadyCounted,
}

/// A consumer calling in a tenant, known only by the credential it came
/// with.
#[derive(Debug, Clone)]
pub struct ConsumerCaller {
    tenant: ScopedTenant,
    credential: PresentedCredential,
    charge: QuotaCharge,
}

impl ConsumerCaller {
    /// A consumer of `tenant`, the tenant the request was addressed to,
    /// calling with `credential`, its request counted against its quota.
    #[must_use]
    pub fn new(tenant: ScopedTenant, credential: PresentedCredential) -> Self {
        Self {
            tenant,
            credential,
            charge: QuotaCharge::PerRequest,
        }
    }

    /// This caller, counted against its quota as `charge` says.
    #[must_use]
    pub fn charged(self, charge: QuotaCharge) -> Self {
        Self { charge, ..self }
    }

    /// Whether its sign-in counts against its quota.
    #[must_use]
    pub fn charge(&self) -> QuotaCharge {
        self.charge
    }

    /// The tenant the request was addressed to.
    #[must_use]
    pub fn tenant(&self) -> &ScopedTenant {
        &self.tenant
    }

    /// The credential the request came with.
    #[must_use]
    pub fn credential(&self) -> &PresentedCredential {
        &self.credential
    }
}
