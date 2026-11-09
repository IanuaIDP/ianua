//! An agent credential as its row holds it: read back into the aggregate,
//! and written out from it. Only the public key is kept; the attestation a
//! credential was issued against fills its two columns.

use ianua_domain::domains::agents::identity::attestation::{AttestationRef, AttestedSubject};
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, AgentCredentialRow, CredentialOrigin,
};
use ianua_domain::domains::crypto::key_status::KeyState;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentCredentialId, AgentId, KeyId, PublicKeyPem};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CREDENTIAL: Stored = Stored("agent credential");

/// A credential as it is read. The store's checked queries fill it.
pub(super) struct CredentialRecord {
    pub(super) id: Uuid,
    pub(super) agent_id: Uuid,
    pub(super) kid: String,
    pub(super) algorithm: String,
    pub(super) public_key: String,
    pub(super) status: String,
    pub(super) rotated_at: Option<OffsetDateTime>,
    pub(super) attested_method: Option<String>,
    pub(super) attested_subject: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl CredentialRecord {
    /// The credential the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, half an attestation is kept, or the row
    /// breaks a rule the credential keeps.
    pub(super) fn into_credential(self) -> Result<AgentCredential<ResolvedTenant>, DomainError> {
        let origin = origin_from(self.attested_method.as_deref(), self.attested_subject)?;
        AgentCredential::reconstitute(AgentCredentialRow {
            id: AgentCredentialId::from_uuid(self.id),
            agent_id: AgentId::from_uuid(self.agent_id),
            kid: CREDENTIAL.value("kid", KeyId::new(self.kid))?,
            algorithm: CREDENTIAL.choice(&self.algorithm)?,
            public_key: CREDENTIAL.value("public key", PublicKeyPem::new(self.public_key))?,
            state: KeyState::from_stored(CREDENTIAL.choice(&self.status)?, self.rotated_at)?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            origin,
            updated_at: self.updated_at,
        })
    }
}

/// How a credential came to be, from its two attestation columns: enrolled
/// by hand when both are empty.
fn origin_from(
    method: Option<&str>,
    subject: Option<String>,
) -> Result<CredentialOrigin, DomainError> {
    match (method, subject) {
        (None, None) => Ok(CredentialOrigin::Enrolled),
        (Some(method), Some(subject)) => Ok(CredentialOrigin::Attested(AttestationRef::new(
            CREDENTIAL.choice(method)?,
            CREDENTIAL.value("attested subject", AttestedSubject::new(subject))?,
        ))),
        (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
            CREDENTIAL.0,
            "half an attestation",
        )),
    }
}

/// A credential's columns, as they are written.
pub(super) struct CredentialColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) agent_id: &'a Uuid,
    pub(super) kid: &'a str,
    pub(super) algorithm: &'static str,
    pub(super) public_key: &'a str,
    pub(super) status: &'static str,
    pub(super) rotated_at: Option<OffsetDateTime>,
    pub(super) attested_method: Option<&'static str>,
    pub(super) attested_subject: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> CredentialColumns<'a> {
    /// The columns `credential` is written to.
    pub(super) fn of(credential: &'a AgentCredential<ResolvedTenant>) -> Self {
        let attestation = match credential.origin() {
            CredentialOrigin::Enrolled => None,
            CredentialOrigin::Attested(attestation) => Some(attestation),
        };
        Self {
            id: credential.id().as_uuid(),
            agent_id: credential.agent_id().as_uuid(),
            kid: credential.kid().as_str(),
            algorithm: credential.algorithm().word(),
            public_key: credential.public_key().as_str(),
            status: credential.status().word(),
            rotated_at: credential.rotated_at(),
            attested_method: attestation.map(|attestation| attestation.method().word()),
            attested_subject: attestation.map(|attestation| attestation.subject().as_str()),
            created_at: credential.created_at(),
            expires_at: credential.expires_at(),
            updated_at: credential.updated_at(),
        }
    }
}
