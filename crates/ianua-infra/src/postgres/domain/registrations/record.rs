//! A registered domain as its row holds it, and the claim on its name as
//! the platform holds it: read back into the domain, and written out from
//! it.

use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainProof, DomainVerificationToken, RegisteredDomain, RegisteredDomainRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainId, DomainName, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const REGISTERED_DOMAIN: Stored = Stored("registered domain");

const DOMAIN_CLAIM: Stored = Stored("domain claim");

/// A registered domain as it is read, with its tenant. The store's checked
/// queries fill it.
pub(super) struct DomainRecord {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
    pub(super) domain: String,
    pub(super) connection: String,
    pub(super) verification_status: String,
    pub(super) verified_at: Option<OffsetDateTime>,
    pub(super) failed_at: Option<OffsetDateTime>,
    pub(super) dns_challenge_token: String,
    pub(super) tls_status: String,
    pub(super) created_at: OffsetDateTime,
}

impl DomainRecord {
    /// The registered domain the record holds, with its tenant, rebuilt
    /// through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// registration keeps.
    pub(super) fn into_listed(
        self,
    ) -> Result<(TenantId, RegisteredDomain<ResolvedTenant>), DomainError> {
        let tenant = TenantId::from_uuid(self.tenant_id);
        self.into_domain().map(|domain| (tenant, domain))
    }

    /// The registered domain the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// registration keeps.
    pub(super) fn into_domain(self) -> Result<RegisteredDomain<ResolvedTenant>, DomainError> {
        let proof = DomainProof::from_stored(
            REGISTERED_DOMAIN.choice(&self.verification_status)?,
            self.verified_at,
            self.failed_at,
        )?;
        RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::from_uuid(self.id),
            domain: REGISTERED_DOMAIN.value("domain", DomainName::new(self.domain))?,
            connection: REGISTERED_DOMAIN.choice(&self.connection)?,
            proof,
            dns_challenge_token: REGISTERED_DOMAIN.value(
                "challenge token",
                DomainVerificationToken::new(self.dns_challenge_token),
            )?,
            tls_status: REGISTERED_DOMAIN.choice(&self.tls_status)?,
            created_at: self.created_at,
        })
    }
}

/// A registered domain's columns, as they are written.
pub(super) struct DomainColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) domain: &'a str,
    pub(super) connection: &'static str,
    pub(super) verification_status: &'static str,
    pub(super) verified_at: Option<OffsetDateTime>,
    pub(super) failed_at: Option<OffsetDateTime>,
    pub(super) dns_challenge_token: &'a str,
    pub(super) tls_status: &'static str,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> DomainColumns<'a> {
    /// The columns `domain` is written to.
    pub(super) fn of(domain: &'a RegisteredDomain<ResolvedTenant>) -> Self {
        Self {
            id: domain.id().as_uuid(),
            domain: domain.domain().as_str(),
            connection: domain.connection().word(),
            verification_status: domain.verification_status().word(),
            verified_at: domain.verified_at(),
            failed_at: domain.failed_at(),
            dns_challenge_token: domain.dns_challenge_token().as_str(),
            tls_status: domain.tls_status().word(),
            created_at: domain.created_at(),
        }
    }
}

/// A claim on a hostname as it is read. The store's checked queries fill
/// it.
pub(super) struct ClaimRecord {
    pub(super) hostname: String,
    pub(super) tenant_id: Uuid,
    pub(super) domain_id: Uuid,
}

/// Who holds a hostname: the tenant, and the registration it holds it by.
pub(super) struct Claim {
    pub(super) hostname: DomainName,
    pub(super) tenant: TenantId,
    pub(super) domain_id: DomainId,
}

impl ClaimRecord {
    /// The claim the record holds, its hostname read back through its own
    /// rules.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the stored hostname is not
    /// a domain name.
    pub(super) fn into_claim(self) -> Result<Claim, DomainError> {
        Ok(Claim {
            hostname: DOMAIN_CLAIM.value("hostname", DomainName::new(self.hostname))?,
            tenant: TenantId::from_uuid(self.tenant_id),
            domain_id: DomainId::from_uuid(self.domain_id),
        })
    }
}
