//! A member's passkey as its row holds it: read back into the credential,
//! and written out from it.

use ianua_domain::domains::authentication::credentials::passkey::{
    PasskeyCredential, PasskeyCredentialRow,
};
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, OrgUserId, OrganizationId, PasskeyCredentialId, PasskeyId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const PASSKEY: Stored = Stored("organization passkey");

/// A passkey as it is read. The store's checked queries fill it.
pub(super) struct PasskeyRecord {
    pub(super) id: Uuid,
    pub(super) org_user_id: Uuid,
    pub(super) credential_id: Vec<u8>,
    pub(super) public_key: Vec<u8>,
    pub(super) sign_count: i64,
    pub(super) authenticator_type: String,
    pub(super) attestation: String,
    pub(super) name: String,
    pub(super) last_used_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl PasskeyRecord {
    /// The passkey the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, a value
    /// no longer passes its rules, or the row breaks a rule the passkey
    /// keeps.
    pub(super) fn into_passkey(
        self,
    ) -> Result<PasskeyCredential<ResolvedOrganization>, DomainError> {
        PasskeyCredential::reconstitute(PasskeyCredentialRow {
            id: PasskeyId::from_uuid(self.id),
            user_id: OrgUserId::from_uuid(self.org_user_id),
            credential_id: PASSKEY.value(
                "credential id",
                PasskeyCredentialId::new(self.credential_id),
            )?,
            public_key: self.public_key,
            sign_count: u32::try_from(self.sign_count).map_err(DomainError::infra)?,
            authenticator_type: PASSKEY.choice(&self.authenticator_type)?,
            attestation: PASSKEY.choice(&self.attestation)?,
            name: PASSKEY.value("name", Label::new("name", self.name))?,
            last_used_at: self.last_used_at,
            created_at: self.created_at,
        })
    }
}

/// A passkey's columns, as they are written.
pub(super) struct PasskeyColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) org_user_id: &'a Uuid,
    pub(super) credential_id: &'a [u8],
    pub(super) public_key: &'a [u8],
    pub(super) sign_count: i64,
    pub(super) authenticator_type: &'static str,
    pub(super) attestation: &'static str,
    pub(super) name: &'a str,
    pub(super) last_used_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> PasskeyColumns<'a> {
    /// The columns `credential` is written to, as `org_user_id`'s in
    /// `organization_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the passkey is another
    /// member's: it would be written where it does not belong.
    pub(super) fn of(
        organization_id: &'a OrganizationId,
        org_user_id: &'a OrgUserId,
        credential: &'a PasskeyCredential<ResolvedOrganization>,
    ) -> Result<Self, DomainError> {
        if credential.user_id() != org_user_id {
            return Err(DomainError::invalid(message!(
                "infra-a-passkey-is-saved-for-the",
                "a passkey is saved for the member it belongs to"
            )));
        }
        Ok(Self {
            id: credential.id().as_uuid(),
            organization_id: organization_id.as_uuid(),
            org_user_id: org_user_id.as_uuid(),
            credential_id: credential.credential_id().as_bytes(),
            public_key: credential.public_key(),
            sign_count: i64::from(credential.sign_count()),
            authenticator_type: credential.authenticator_type().word(),
            attestation: credential.attestation().word(),
            name: credential.name().as_str(),
            last_used_at: credential.last_used_at(),
            created_at: credential.created_at(),
        })
    }
}
