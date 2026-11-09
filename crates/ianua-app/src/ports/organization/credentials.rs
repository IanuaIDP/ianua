//! Members' second factors, passkeys, recovery codes and tokens.

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::time_step::TimeStep;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::domains::identity::tokens::purpose::TokenPurpose;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::domains::organization::access::token::OrgToken;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CeremonyId, OrgUserId, OrganizationId, PasskeyCredentialId, PasskeyId, TokenHash,
};

/// Dyn-safe port for org user MFA enrollments.
///
/// Stores MFA state in `org_mfa_enrollments` (control plane DB).
#[async_trait]
pub trait OrgMfaEnrollmentStore: Send + Sync {
    /// Finds the MFA enrollment for an org user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, DomainError>;

    /// Finds the MFA enrollment for an org user and holds it until the unit
    /// of work the caller runs in ends, for a caller that will count an
    /// answer on it, or otherwise change it, and save it.
    ///
    /// The lock rules are the domain's, so storage does not count in SQL:
    /// it locks the row, and a second answer to the same factor waits until
    /// this one is saved, then reads its count. Two wrong codes sent at once
    /// both count.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn hold_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, DomainError>;

    /// Saves a new or updated MFA enrollment.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `enrollment` is another person's
    ///   than `org_user_id`'s.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        org_user_id: &OrgUserId,
        enrollment: &MfaEnrollment<ResolvedOrganization>,
    ) -> Result<(), DomainError>;

    /// Records `step` as the org user's latest accepted code, in one atomic
    /// update, and answers whether it was later than every step accepted
    /// before. `false` means the code was already used, or one after it was,
    /// or the org user has no enrollment to accept a code for.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn claim_step(
        &self,
        org_user_id: &OrgUserId,
        step: TimeStep,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for org user passkey credentials.
///
/// Stores credentials in `org_passkey_credentials` (control plane DB). The
/// credential-id lookup is global rather than org-scoped: the login plane is
/// flat, so the credential is what names the organization.
#[async_trait]
pub trait OrgPasskeyStore: Send + Sync {
    /// Lists the requested members' passkeys together. Repeated member ids do
    /// not repeat credentials; each member's keys keep creation-time and id order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup or reconstitution failure.
    async fn list_by_users(
        &self,
        org_user_ids: &[OrgUserId],
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, DomainError>;

    /// Lists the passkeys registered by one org user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, DomainError>;

    /// Finds a credential by its `WebAuthn` credential id. The credential
    /// names the member who owns it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_credential_id(
        &self,
        credential_id: &PasskeyCredentialId,
    ) -> Result<Option<PasskeyCredential<ResolvedOrganization>>, DomainError>;

    /// Saves a new or updated credential for an org user.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `credential` belongs to another
    ///   member than `org_user_id`.
    /// - `DomainError::Conflict` when another passkey already holds its
    ///   `WebAuthn` credential id: the id names one member only.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        credential: &PasskeyCredential<ResolvedOrganization>,
    ) -> Result<(), DomainError>;

    /// Deletes a credential by its internal id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, id: &PasskeyId) -> Result<(), DomainError>;
}

/// Dyn-safe port for in-flight management-plane `WebAuthn` ceremonies.
///
/// Stores ceremonies in `org_passkey_ceremonies` (control plane DB). Lookups
/// are by id alone: the login plane carries no organization in its URL, and
/// the id is single-use, unguessable, and short-lived.
#[async_trait]
pub trait OrgPasskeyCeremonyStore: Send + Sync {
    /// Records a newly opened ceremony.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, ceremony: &OrgPasskeyCeremony) -> Result<(), DomainError>;

    /// Loads a ceremony by id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &CeremonyId) -> Result<Option<OrgPasskeyCeremony>, DomainError>;

    /// Settles the ceremony, refusing to settle one that already was.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] if the ceremony was already
    /// consumed, the check that makes single-use hold under concurrency.
    async fn mark_consumed(&self, ceremony: &OrgPasskeyCeremony) -> Result<(), DomainError>;
}

/// Dyn-safe port for org user recovery codes.
///
/// Stores recovery codes in `org_recovery_codes` (control plane DB).
#[async_trait]
pub trait OrgRecoveryCodeStore: Send + Sync {
    /// Finds the recovery code set for an org user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedOrganization>>, DomainError>;

    /// Saves a new or updated recovery code set.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `codes` are another person's than
    ///   `org_user_id`'s.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        org_user_id: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
    ) -> Result<(), DomainError>;

    /// Stores the code with `hash` in `codes`, just spent, as used, only if
    /// the stored code is still unused. Returns whether this call spent it:
    /// of two sign-ins offering one code at once, only one gets through.
    /// Storage does it in one statement, such as `UPDATE org_recovery_codes
    /// SET used_at = $3 WHERE org_user_id = $1 AND code_hash = $2 AND
    /// used_at IS NULL`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `codes` are another person's than
    ///   `org_user_id`'s, or hold no spent code with `hash`.
    /// - `DomainError::Infrastructure` if the code cannot be written.
    async fn spend(
        &self,
        org_user_id: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for the single-use tokens issued to org users.
///
/// One store serves every purpose, verification, password reset, because the
/// token differs only in its `Purpose` marker. The marker keeps them apart at
/// compile time, so a reset link can never be redeemed as a verification.
#[async_trait]
pub trait OrgTokenStore<Purpose: TokenPurpose + Send + Sync + 'static>: Send + Sync {
    /// Finds a token by its hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_hash(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<OrgToken<Purpose>>, DomainError>;

    /// Saves a new or updated token. A use is never undone: a save over a
    /// spent one is refused.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the stored token was spent
    /// already or is of another purpose, or `DomainError::Infrastructure`
    /// on persistence failure.
    async fn save(&self, token: &OrgToken<Purpose>) -> Result<(), DomainError>;

    /// Stores `token`, just used, as spent at the time it was used, only
    /// while the stored token of this purpose is still unused. Returns
    /// whether this call spent it: of two requests following one link at
    /// once, only one gets through, and the other learns it lost. Storage
    /// does it in one statement, such as `UPDATE org_tokens SET consumed_at
    /// = $3 WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `token` was not used.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn spend(&self, token: &OrgToken<Purpose>) -> Result<bool, DomainError>;

    /// Consumes every unused token this org user holds for this purpose.
    ///
    /// Issuing a replacement supersedes the previous link rather than leaving
    /// both live, so resending an email invalidates whatever was sent before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume_outstanding(&self, org_user_id: &OrgUserId) -> Result<(), DomainError>;

    /// The most recently issued token for this org user, spent or not.
    ///
    /// When the last email went out, which is what a resend cooldown is
    /// measured from. The token the caller presents cannot answer it: issuing
    /// a replacement supersedes it, so its age stops moving and every later
    /// request would look old enough to send again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_latest_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgToken<Purpose>>, DomainError>;
}
