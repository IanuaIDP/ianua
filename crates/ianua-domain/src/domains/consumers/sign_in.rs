//! Proof that a consumer signed in with its own credential just now.
//!
//! A consumer acts with every role it is given. If the gateway could act as
//! one by naming it, any caller would make topics and subscribe in
//! "billing-sync"'s name. So a consumer acts only with this proof, which
//! only its own credential check makes: the API key it holds, the
//! certificate it presents, or a token from the issuer it names.
//!
//! A credential works until it expires. After a rotation, the old one works
//! too, until its overlap ends. See
//! [`ConsumerCredentials`](crate::domains::consumers::credentials::ConsumerCredentials).

use crate::domains::consumers::consumer::Consumer;
use crate::domains::consumers::credential::ConsumerCredentialKind;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{
    CertificateFingerprint, ConsumerId, Expiry, FederatedSubject, Issuer, TokenHash,
};

/// Proof that one consumer signed in with its own credential just now.
///
/// Only [`Consumer`]'s sign-in checks make one. It is neither `Clone` nor
/// `Copy`, so one proof answers one request.
#[derive(Debug, PartialEq, Eq)]
pub struct ConsumerSignIn {
    consumer: ConsumerId,
    until: Expiry,
}

impl ConsumerSignIn {
    /// Proof that `consumer` signed in with a credential that works until
    /// `until`, once it was checked.
    fn of(consumer: ConsumerId, until: Expiry) -> Self {
        Self { consumer, until }
    }

    /// The consumer that signed in.
    #[must_use]
    pub fn consumer(&self) -> &ConsumerId {
        &self.consumer
    }

    /// When the credential it signed in with stops working: its expiry, or
    /// for a rotated-out credential the end of its overlap if sooner. A
    /// tunnel opened with it closes then.
    #[must_use]
    pub fn until(&self) -> Expiry {
        self.until
    }
}

/// The claims of a token a consumer presented, once the gateway checked
/// its signature against the keys the consumer publishes, with the
/// algorithm each key names.
#[derive(Debug, Clone, Copy)]
pub struct PresentedToken<'a> {
    /// The token's `iss` claim.
    pub issuer: &'a Issuer,
    /// The token's `sub` claim.
    pub subject: &'a FederatedSubject,
}

impl<T: TenantScope> Consumer<T> {
    /// Proof that this consumer signed in with `presented`, the digest of
    /// the API key the request carried.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the consumer is disabled.
    /// - [`DomainError::Forbidden`] when no working credential is an API key
    ///   whose digest is `presented`.
    pub fn sign_in_with_key(&self, presented: &TokenHash) -> Result<ConsumerSignIn, DomainError> {
        self.signed_in_if(|kind| {
            matches!(kind, ConsumerCredentialKind::ApiKey { key_hash, .. } if key_hash == presented)
        })
    }

    /// Proof that this consumer signed in with the client certificate whose
    /// fingerprint is `presented`, once the gateway checked the connection
    /// holds its key.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the consumer is disabled.
    /// - [`DomainError::Forbidden`] when no working credential is the
    ///   certificate `presented`.
    pub fn sign_in_with_certificate(
        &self,
        presented: &CertificateFingerprint,
    ) -> Result<ConsumerSignIn, DomainError> {
        self.signed_in_if(|kind| {
            matches!(kind, ConsumerCredentialKind::ClientCert { fingerprint } if fingerprint == presented)
        })
    }

    /// Proof that this consumer signed in with `token`, from the issuer it
    /// names and for its own subject, while the tenant's issuer is
    /// `tenant_issuer`.
    ///
    /// Eve runs her own issuer and sends a token naming "billing-sync" as
    /// its subject. It names another issuer, so it is refused. A token from
    /// the consumer's issuer for another of its subjects is refused too.
    ///
    /// # Errors
    ///
    /// - The cases [`Self::ensure_trusts_token_from`] lists.
    /// - [`DomainError::Forbidden`] when no working credential names both
    ///   the token's issuer and its subject.
    pub fn sign_in_with_token(
        &self,
        token: PresentedToken<'_>,
        tenant_issuer: &Issuer,
    ) -> Result<ConsumerSignIn, DomainError> {
        self.ensure_trusts_token_from(token.issuer, tenant_issuer)?;
        self.signed_in_if(|kind| {
            matches!(
                kind,
                ConsumerCredentialKind::JwtBearer { issuer, subject, .. }
                    if issuer == token.issuer && subject == token.subject
            )
        })
    }

    /// Refuses a token from `token_issuer` unless this consumer is active and
    /// trusts that issuer, and the issuer is not the tenant's own.
    ///
    /// The gateway calls this on every token, with the tenant's issuer as it
    /// stands now. The check at [`Consumer::create`] is not enough: a tenant
    /// can later take a consumer's issuer as its own custom issuer.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the consumer is disabled.
    /// - [`DomainError::Forbidden`] when every working credential refuses
    ///   the token, or none works any more. See
    ///   [`ConsumerCredentialKind::ensure_accepts_token_from`].
    pub fn ensure_trusts_token_from(
        &self,
        token_issuer: &Issuer,
        tenant_issuer: &Issuer,
    ) -> Result<(), DomainError> {
        self.ensure_active()?;
        self.credentials()
            .live()
            .map(|kind| kind.ensure_accepts_token_from(token_issuer, tenant_issuer))
            .reduce(Result::or)
            .unwrap_or_else(|| Err(credential_refused()))
    }

    /// Proof of sign-in when the consumer is active and one of its working
    /// credentials is the one `presented` describes.
    fn signed_in_if(
        &self,
        presented: impl Fn(&ConsumerCredentialKind) -> bool,
    ) -> Result<ConsumerSignIn, DomainError> {
        self.ensure_active()?;
        let (_, until) = self
            .credentials()
            .live_until()
            .find(|(kind, _)| presented(kind))
            .ok_or_else(credential_refused)?;
        Ok(ConsumerSignIn::of(*self.id(), until))
    }

    /// Refuses a disabled consumer.
    fn ensure_active(&self) -> Result<(), DomainError> {
        if !self.is_active() {
            return Err(DomainError::forbidden(message!(
                "consumers-the-consumer-is-disabled",
                "the consumer is disabled"
            )));
        }
        Ok(())
    }
}

/// The refusal of a credential that is not the consumer's, or no longer
/// works. It names no detail, so a caller learns nothing about the
/// credential it guessed.
fn credential_refused() -> DomainError {
    DomainError::forbidden(message!(
        "consumers-the-credential-is-not-the-consumer",
        "the credential is not the consumer's"
    ))
}
