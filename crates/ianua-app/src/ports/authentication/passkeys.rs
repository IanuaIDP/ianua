//! Passkeys: the stored keys and the ceremonies that register and use them.

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, KeyAttestation, PasskeyCredential,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::PasskeyCeremony;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CeremonyId, Email, PasskeyCredentialId, PasskeyId, TenantId, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving passkey credentials.
#[async_trait]
pub trait PasskeyStore: Send + Sync + TenantScoped {
    /// Lists all passkeys for a user.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the passkeys cannot be read.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential<ResolvedTenant>>, DomainError>;

    /// Finds a passkey by its `WebAuthn` credential id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the passkey cannot be read.
    async fn find_by_credential_id(
        &self,
        tenant_id: &ScopedTenant,
        credential_id: &PasskeyCredentialId,
    ) -> Result<Option<PasskeyCredential<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated passkey credential.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the passkey cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        credential: &PasskeyCredential<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a passkey by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the passkey cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &PasskeyId) -> Result<(), DomainError>;
}

/// A started `WebAuthn` ceremony, split along the trust boundary.
///
/// The two halves must not be confused: `client_payload` is what the browser
/// needs and may be handed out, `server_state` is what the answer will be
/// checked against and must never leave the server. Returning them as one
/// blob is what allowed a caller to supply the state their own assertion was
/// verified against.
pub struct StartedCeremony {
    /// The `WebAuthn` options for `navigator.credentials.*`. Public.
    pub client_payload: Vec<u8>,
    /// Opaque verifier state to store and replay at confirm. Secret.
    pub server_state: Vec<u8>,
}

/// Dyn-safe port for `WebAuthn` ceremony orchestration.
///
/// Wraps the domain's `PasskeyVerifier` trait into a dyn-safe
/// async version for use in app-layer use cases.
#[async_trait]
pub trait PasskeyVerifier: Send + Sync {
    /// Starts a registration ceremony for a new passkey of `user_id`, shown
    /// on the authenticator under `user_name`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be generated.
    async fn start_registration(
        &self,
        user_id: &UserId,
        user_name: &Email,
    ) -> Result<StartedCeremony, DomainError>;

    /// Starts an authentication ceremony against existing passkeys.
    ///
    /// Each entry is the opaque credential blob returned by
    /// `verify_registration`, stored as `public_key` in `PasskeyCredential`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be generated.
    async fn start_authentication(
        &self,
        stored_credentials: &[Vec<u8>],
    ) -> Result<StartedCeremony, DomainError>;

    /// Starts a decoy authentication ceremony for `address`, which has no
    /// passkey to answer one: no account, or one without passkeys.
    ///
    /// It must read as [`start_authentication`](Self::start_authentication)
    /// reads for an account holding one passkey: the same options, with an
    /// `allowCredentials` list of one credential id. The id is derived from
    /// `address` under a key only the server holds, so the same address gets
    /// the same id every time, as a real account does, and nobody without
    /// that key can tell it from a real one. Its state is never kept, so no
    /// answer to it verifies.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be generated.
    async fn start_decoy_authentication(
        &self,
        address: &Email,
    ) -> Result<StartedCeremony, DomainError>;

    /// Verifies a registration response against the stored ceremony state.
    ///
    /// Returns the credential id, public key, sign count, authenticator type
    /// and attestation taken from the response.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the response does not verify.
    async fn verify_registration(
        &self,
        server_state: &[u8],
        response: &[u8],
    ) -> Result<PasskeyRegistrationResult, DomainError>;

    /// Verifies an authentication assertion against the stored ceremony state.
    ///
    /// Returns the credential id and the authenticator's reported sign count.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the assertion does not verify.
    async fn verify_authentication(
        &self,
        server_state: &[u8],
        response: &[u8],
        public_key: &[u8],
        sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError>;

    /// Starts a discoverable-credential ceremony: no user named, no
    /// credential list; the authenticator offers what it holds.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be generated.
    async fn start_discoverable_authentication(&self) -> Result<StartedCeremony, DomainError>;

    /// Verifies a discoverable-credential assertion against the stored
    /// ceremony state and the credential the assertion claims to be from.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the assertion does not verify.
    async fn verify_discoverable_authentication(
        &self,
        server_state: &[u8],
        response: &[u8],
        public_key: &[u8],
        sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError>;
}

/// Dyn-safe port for the in-flight ceremonies a tenant is holding.
#[async_trait]
pub trait PasskeyCeremonyStore: Send + Sync {
    /// Records a newly opened ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the ceremony cannot be written.
    async fn save(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError>;

    /// Loads a ceremony by id within one tenant.
    ///
    /// Whether it is still answerable is the aggregate's call, not this
    /// port's: an expired or already-settled ceremony is returned so the
    /// caller can refuse it for the right reason.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the ceremony cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &TenantId,
        id: &CeremonyId,
    ) -> Result<Option<PasskeyCeremony>, DomainError>;

    /// Persists a ceremony's settled state, refusing to settle one that
    /// already was. Storage does it in one statement, such as an
    /// `UPDATE .. WHERE consumed_at IS NULL`, so of two answers arriving
    /// together only one settles it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the ceremony was already consumed.
    /// - [`DomainError::Infrastructure`] if the ceremony cannot be written.
    async fn mark_consumed(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError>;

    /// Deletes ceremonies past their expiry that were never answered, and
    /// answers how many went.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the ceremonies cannot be deleted.
    async fn purge_expired(&self) -> Result<u64, DomainError>;
}

/// Result of verifying a `WebAuthn` registration attestation.
pub struct PasskeyRegistrationResult {
    /// The credential id from the authenticator.
    pub credential_id: PasskeyCredentialId,
    /// The public key from the authenticator.
    pub public_key: Vec<u8>,
    /// The initial sign count.
    pub sign_count: u32,
    /// Whether this is a platform or roaming authenticator.
    pub authenticator_type: AuthenticatorType,
    /// What the attestation, checked here, showed about where the key lives.
    pub attestation: KeyAttestation,
}

/// Result of verifying a `WebAuthn` authentication assertion.
pub struct PasskeyAuthenticationResult {
    /// The credential id that was used.
    pub credential_id: PasskeyCredentialId,
    /// The updated sign count from the authenticator.
    pub new_sign_count: u32,
}
