//! Sending a Security Event Token to a stream: signed with the tenant's key
//! under the tenant's issuer, then pushed to the stream's endpoint or held
//! for its receiver to poll, as the stream takes it.
//!
//! Signals and verification events, the endpoint challenge among them, go
//! out the same way, so a receiver checks every token it is sent alike.

use std::sync::Arc;

use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningKey;
use ianua_domain::domains::signals::delivery::ReceiverAuthorization;
use ianua_domain::domains::signals::set::SecurityEventTokenClaims;
use ianua_domain::domains::signals::stream::{DeliveryMethod, SignalStream};
use ianua_domain::domains::signals::verification::VerificationEvent;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Issuer, SignalId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::crypto::{JwtSigner, JwtSigningKey, SigningKeyStore};
use crate::ports::signals::{
    QueuedEvent, ReceiverCredential, SecurityEventToken, SetPush, SignalDeliverer,
    SignalDeliveryOutcome, SignalPollQueue,
};
use crate::services::issuers::TenantIssuers;
use crate::services::sealing::opened_text;
use crate::tenancy::ScopedTenant;
use crate::use_cases::signals::streams::verification::receiver_header::header_place;

/// The ports sending a token to a stream needs, which every use case that
/// sends one holds together.
#[derive(ianua_macros::Fakes)]
pub struct TransmitPorts {
    /// The tenant's signing keys.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Signs the token.
    pub jwt_signer: Arc<dyn JwtSigner>,
    /// Pushes the token to a push stream's endpoint.
    pub deliverer: Arc<dyn SignalDeliverer>,
    /// Holds the token for a poll stream's receiver.
    pub poll_queue: Arc<dyn SignalPollQueue>,
    /// Opens a receiver's sealed `Authorization` header to push, and seals
    /// a new one.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The issuer the tenant's tokens carry.
    pub issuers: TenantIssuers,
}

impl TransmitPorts {
    /// What sends a token through these ports.
    pub(super) fn transmitter(&self) -> Transmitter<'_> {
        Transmitter {
            keys: self.key_store.as_ref(),
            issuers: &self.issuers,
            signer: self.jwt_signer.as_ref(),
            deliverer: self.deliverer.as_ref(),
            queue: self.poll_queue.as_ref(),
            encryptor: self.encryptor.as_ref(),
        }
    }
}

/// Everything sending a token to a stream needs.
pub(super) struct Transmitter<'a> {
    /// The tenant's signing keys.
    pub(super) keys: &'a dyn SigningKeyStore,
    /// The issuer the tenant's tokens carry.
    pub(super) issuers: &'a TenantIssuers,
    /// Signs the token.
    pub(super) signer: &'a dyn JwtSigner,
    /// Pushes the token to a push stream's endpoint.
    pub(super) deliverer: &'a dyn SignalDeliverer,
    /// Holds the token for a poll stream's receiver.
    pub(super) queue: &'a dyn SignalPollQueue,
    /// Opens the receiver's sealed `Authorization` header for one push.
    pub(super) encryptor: &'a dyn SecretEncryptor,
}

/// The tenant's issuer and the key it signs with now: what every token it
/// sends carries.
pub(super) struct SetSigning {
    issuer: Issuer,
    key: SigningKey,
}

impl SetSigning {
    /// The issuer, the `iss` of every token.
    pub(super) fn issuer(&self) -> &Issuer {
        &self.issuer
    }
}

impl Transmitter<'_> {
    /// The tenant's issuer and signing key now, or `None`, logged, when the
    /// tenant has no key: then nothing is sent rather than sent unsigned.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its organization is gone.
    /// - `AppError::Internal` when the keys or records cannot be read.
    pub(super) async fn signing(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Option<SetSigning>, AppError> {
        let issuer = self.issuers.of(tenant).await?;
        let key = self
            .keys
            .find(tenant)
            .await
            .or_internal()?
            .and_then(|set| set.active_key(clock::now()).cloned());
        let Some(key) = key else {
            tracing::warn!(tenant_id = %**tenant, "signals: no active signing key, nothing sent");
            return Ok(None);
        };
        Ok(Some(SetSigning { issuer, key }))
    }

    /// `claims` signed as a security event with `signing`'s key.
    ///
    /// # Errors
    ///
    /// `DomainError::Infrastructure` when the claims cannot be written or
    /// signed.
    pub(super) async fn signed(
        &self,
        signing: &SetSigning,
        claims: &SecurityEventTokenClaims,
    ) -> Result<SecurityEventToken, DomainError> {
        let claims_json =
            serde_json::to_string(claims).map_err(|e| DomainError::infra_msg(e.to_string()))?;
        let key = JwtSigningKey {
            kid: signing.key.kid(),
            algorithm: signing.key.algorithm(),
            private_key: signing.key.private_key(),
        };
        self.signer
            .sign_typed(&claims_json, JwtType::SecurityEvent, key)
            .await
            .map(SecurityEventToken::new)
    }

    /// Hands `token`, whose `jti` is `jti`, to `stream` as it takes tokens.
    /// How the receiver answers a push is the receiver's to show: a stream
    /// whose endpoint never echoes its challenge stays waiting.
    ///
    /// # Errors
    ///
    /// `DomainError` when the header cannot be opened, the endpoint is
    /// refused, or the token cannot be queued.
    async fn hand(
        &self,
        tenant: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        jti: SignalId,
        token: SecurityEventToken,
    ) -> Result<(), DomainError> {
        match stream.delivery_method() {
            DeliveryMethod::Push => self.pushed(tenant, stream, &token).await.map(drop),
            DeliveryMethod::Poll => self.queue(tenant, stream, jti, token).await,
        }
    }

    /// Holds `token`, whose `jti` is `jti`, for `stream`'s receiver to
    /// poll.
    ///
    /// # Errors
    ///
    /// `DomainError::Infrastructure` when it cannot be queued.
    pub(super) async fn queue(
        &self,
        tenant: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        jti: SignalId,
        token: SecurityEventToken,
    ) -> Result<(), DomainError> {
        let event = QueuedEvent { jti, token };
        self.queue.enqueue(tenant, stream.id(), &event).await
    }

    /// Sends `event` down `stream`. A failure is logged, not returned: the
    /// stream stands either way, and one that waits on its endpoint keeps
    /// delivering nothing, which is the safe way round.
    pub(super) async fn verify(
        &self,
        tenant: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        event: &VerificationEvent,
    ) {
        if let Err(error) = self.verification_sent(tenant, stream, event).await {
            tracing::warn!(
                stream_id = %stream.id(),
                endpoint = %stream.endpoint().origin(),
                %error,
                "signals: the verification event could not be sent"
            );
        }
    }

    /// Signs `event` and hands it to `stream`.
    ///
    /// # Errors
    ///
    /// `AppError` when it cannot be signed or handed over.
    async fn verification_sent(
        &self,
        tenant: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        event: &VerificationEvent,
    ) -> Result<(), AppError> {
        let Some(signing) = self.signing(tenant).await? else {
            return Ok(());
        };
        let claims = SecurityEventTokenClaims::verification(signing.issuer().clone(), event);
        let token = self.signed(&signing, &claims).await.or_internal()?;
        self.hand(tenant, stream, claims.jti, token)
            .await
            .or_internal()?;
        Ok(())
    }

    /// Pushes `token` to the endpoint of `tenant`'s `stream` with the header
    /// it asked for.
    ///
    /// # Errors
    ///
    /// `DomainError` when the header cannot be opened or the endpoint is
    /// refused.
    pub(super) async fn pushed(
        &self,
        tenant: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        token: &SecurityEventToken,
    ) -> Result<SignalDeliveryOutcome, DomainError> {
        let place = header_place(tenant, stream.id());
        let credential = self.credential(stream.authorization(), &place).await?;
        self.deliverer
            .deliver(SetPush {
                endpoint: stream.endpoint(),
                token,
                credential: &credential,
            })
            .await
    }

    /// The header `authorization` asks for, opened from `place` for one
    /// push.
    ///
    /// # Errors
    ///
    /// `DomainError` when the sealed header cannot be opened there, or
    /// opens to something that is not text.
    async fn credential(
        &self,
        authorization: &ReceiverAuthorization,
        place: &SealedFor,
    ) -> Result<ReceiverCredential, DomainError> {
        let ReceiverAuthorization::Header(sealed) = authorization else {
            return Ok(ReceiverCredential::Omitted);
        };
        let header = opened_text(self.encryptor, sealed, place).await?;
        Ok(ReceiverCredential::Header(header))
    }
}
