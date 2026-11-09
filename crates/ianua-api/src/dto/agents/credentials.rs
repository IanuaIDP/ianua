//! Agent credential bodies: the public keys agents enrol, the credentials
//! that come of them, the attestation challenge, and the token exchange.

use ianua_app::context::AgentAssertion;
use ianua_app::ports::agents::EnrolledKey;
use ianua_app::use_cases::agents::credentials::{
    ExchangeTokenForAgentRequest, MintRequest, RotateRequest,
};
use ianua_domain::domains::agents::authority::capability::{DelegationConstraints, TaskBinding};
use ianua_domain::domains::agents::identity::challenge::AttestationChallenge;
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, CredentialOrigin, RotationGrace,
};
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentCredentialId, AgentId, PublicKeyPem, Seconds, Setting};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::attestation::method_name;
use crate::dto::agents::capabilities::CapabilitySetDto;
use crate::dto::agents::delegation::UnknownFields;
use crate::error::ApiError;

/// The public half of a key pair an agent made for itself. The private
/// half never leaves the agent: the platform neither generates nor returns
/// one.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct EnrolledKeyDto {
    /// Signing algorithm of the key pair (`EdDSA`, `ES256`, `RS256`).
    pub algorithm: String,
    /// PEM-encoded public key (`-----BEGIN PUBLIC KEY-----`).
    pub public_key: String,
}

impl EnrolledKeyDto {
    /// The key named.
    ///
    /// # Errors
    ///
    /// - A validation error for an algorithm ianua does not sign with, or a
    ///   key that is not PEM.
    pub(crate) fn into_enrolled(self) -> Result<EnrolledKey, ApiError> {
        Ok(EnrolledKey {
            algorithm: algorithm_named(&self.algorithm)?,
            public_key: PublicKeyPem::new(self.public_key).map_err(ApiError::validation)?,
        })
    }
}

/// The signing algorithm a JOSE name names, in any case.
fn algorithm_named(value: &str) -> Result<SigningAlgorithm, ApiError> {
    match value.to_ascii_uppercase().as_str() {
        "RS256" => Ok(SigningAlgorithm::Rs256),
        "ES256" => Ok(SigningAlgorithm::Es256),
        "EDDSA" => Ok(SigningAlgorithm::EdDsa),
        _ => Err(ApiError::validation(message!(
            "api-unknown-algorithm",
            format!("unknown algorithm: {value}")
        ))),
    }
}

/// A signing algorithm's JOSE name.
fn algorithm_name(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::Rs256 => "RS256",
        SigningAlgorithm::Es256 => "ES256",
        SigningAlgorithm::EdDsa => "EdDSA",
    }
}

/// A key's lifecycle status on the wire.
fn key_status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Active => "active",
        KeyStatus::Rotated => "rotated",
        KeyStatus::Revoked => "revoked",
    }
}

/// Request to enrol an agent credential.
///
/// Enrolling takes no attestation binding. An attestation records a proof
/// the platform verified, and an enrolment carries no proof to verify; bind
/// a credential by bootstrapping the agent against its attestation instead.
/// The `kid` is server-generated: it is unique per tenant and is the lookup
/// key at token exchange, so a caller-chosen one would be a namespace an
/// outsider could probe and collide with.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct MintCredentialBody {
    /// The public key the agent made for itself.
    #[serde(flatten)]
    pub key: EnrolledKeyDto,
    /// Optional lifetime in seconds, after which the credential must be
    /// rotated. The deployment's default when left out.
    #[serde(default)]
    pub expires_in_seconds: Option<u32>,
}

impl MintCredentialBody {
    /// The enrolment of this key for `agent_id`.
    ///
    /// # Errors
    ///
    /// - A validation error when the key is not valid.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<MintRequest, ApiError> {
        let expires_at = match self.expires_in_seconds {
            Some(seconds) => Setting::Set(clock::now() + Seconds::new(seconds).duration()),
            None => Setting::Unset,
        };
        Ok(MintRequest {
            agent_id,
            key: self.key.into_enrolled()?,
            expires_at,
        })
    }
}

/// Request to rotate a credential: the replacement public key the agent
/// made.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RotateCredentialBody {
    /// The replacement public key.
    #[serde(flatten)]
    pub key: EnrolledKeyDto,
}

impl RotateCredentialBody {
    /// The rotation of `credential_id`, the agent's, onto this key.
    ///
    /// # Errors
    ///
    /// - A validation error when the key is not valid.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
        credential_id: AgentCredentialId,
    ) -> Result<RotateRequest, ApiError> {
        Ok(RotateRequest {
            agent_id,
            credential_id,
            key: self.key.into_enrolled()?,
        })
    }
}

/// The verified attestation a credential is bound to.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialAttestationResponse {
    /// Attestation method (`spiffe`, `aws`, `gcp`, `tpm`).
    pub method: String,
    /// The attested workload identity: a SPIFFE ID, instance id, or TPM
    /// subject (e.g. `spiffe://northwind/ns/prod/sa/invoice-triage`).
    pub subject: String,
}

/// An agent identity credential: public metadata only, never a private
/// key.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialResponse {
    /// Credential identifier.
    pub id: Uuid,
    /// The agent this credential authenticates.
    pub agent_id: Uuid,
    /// The key id (JWT `kid`) the agent stamps on its assertions.
    pub kid: String,
    /// Signing algorithm (`EdDSA`, `ES256`, `RS256`).
    pub algorithm: String,
    /// Lifecycle status (`active`, `rotated`, `revoked`).
    pub status: String,
    /// PEM-encoded public key used to verify the agent's assertions.
    pub public_key: String,
    /// The attestation this credential is bound to, for one issued by
    /// bootstrap. `null` for an enrolled credential, which attests nothing.
    pub attestation: Option<CredentialAttestationResponse>,
    /// When it was minted.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// When rotation retired this credential. `null` unless it was rotated.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub rotated_at: Option<OffsetDateTime>,
    /// When a rotated credential stops verifying: the countdown's end.
    /// `null` for an active credential and for a revoked one, whose
    /// retirement is immediate rather than graceful.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub grace_ends_at: Option<OffsetDateTime>,
    /// The grace window's full length in seconds, the countdown's
    /// denominator. Set exactly when `grace_ends_at` is.
    pub grace_period_seconds: Option<u32>,
}

impl From<&AgentCredential<ResolvedTenant>> for CredentialResponse {
    fn from(credential: &AgentCredential<ResolvedTenant>) -> Self {
        let grace = credential.rotation_grace();
        Self {
            id: *credential.id().as_uuid(),
            agent_id: *credential.agent_id().as_uuid(),
            kid: credential.kid().as_str().to_owned(),
            algorithm: algorithm_name(credential.algorithm()).to_owned(),
            status: key_status_name(credential.status()).to_owned(),
            public_key: credential.public_key().as_str().to_owned(),
            attestation: match credential.origin() {
                CredentialOrigin::Attested(attestation) => Some(CredentialAttestationResponse {
                    method: method_name(attestation.method()).to_owned(),
                    subject: attestation.subject().as_str().to_owned(),
                }),
                CredentialOrigin::Enrolled => None,
            },
            created_at: credential.created_at(),
            expires_at: credential.expires_at(),
            rotated_at: credential.rotated_at(),
            grace_ends_at: grace.map(RotationGrace::ends_at),
            grace_period_seconds: grace.map(RotationGrace::seconds),
        }
    }
}

/// A challenge to sign before bootstrapping.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AttestationChallengeResponse {
    /// The nonce to sign and return as the bootstrap's `signature`.
    pub nonce: String,
    /// When the challenge stops being accepted.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl From<&AttestationChallenge<ResolvedTenant>> for AttestationChallengeResponse {
    fn from(challenge: &AttestationChallenge<ResolvedTenant>) -> Self {
        Self {
            nonce: challenge.nonce().as_str().to_owned(),
            expires_at: challenge.expires_at(),
        }
    }
}

/// Request to exchange an agent's self-signed assertion for a task token.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ExchangeTokenBody {
    /// The compact JWS the agent signed with its identity credential.
    pub assertion: String,
    /// The capabilities the agent asks for this task token.
    #[serde(default)]
    pub granted: CapabilitySetDto,
    /// Task-token lifetime in seconds.
    pub ttl_seconds: u32,
    /// Maximum sub-delegation depth.
    #[serde(default)]
    pub max_depth: u8,
    /// Optional task binding describing the intended work.
    #[serde(default)]
    pub task: Option<String>,
    /// Binds the token to the agent's active credential key: the proxy then
    /// requires a DPoP proof signed with that key on every request, so the
    /// token alone is useless to whoever copies it.
    #[serde(default)]
    pub sender_constrained: bool,
    /// Fields the body does not know, refused.
    #[serde(flatten)]
    #[schema(ignore)]
    pub unknown: UnknownFields,
}

impl ExchangeTokenBody {
    /// The exchange `agent_id` asks for.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown field, or capabilities, a
    ///   lifetime or a task binding that is not valid.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
    ) -> Result<ExchangeTokenForAgentRequest, ApiError> {
        self.unknown.ensure_none()?;
        let granted = self.granted.to_domain()?;
        let constraints = self.constraints()?;
        Ok(ExchangeTokenForAgentRequest {
            presented: AgentAssertion {
                agent_id,
                assertion: self.assertion,
            },
            granted,
            constraints,
        })
    }

    /// The limits asked for.
    fn constraints(&self) -> Result<DelegationConstraints, ApiError> {
        let mut constraints =
            DelegationConstraints::new(Seconds::new(self.ttl_seconds), self.max_depth)
                .map_err(ApiError::validation)?;
        if let Some(task) = &self.task {
            constraints = constraints
                .with_task(TaskBinding::new(task.as_str()).map_err(ApiError::validation)?);
        }
        if self.sender_constrained {
            constraints = constraints.sender_constrained();
        }
        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// The exchange `body` asks for, for a new agent.
    fn exchange(body: Value) -> Result<ExchangeTokenForAgentRequest, ApiError> {
        let body: ExchangeTokenBody = serde_json::from_value(body).unwrap();
        body.into_request(AgentId::new())
    }

    /// An agent asking for a key-bound token gets the binding it named.
    #[test]
    fn an_exchange_naming_known_fields_keeps_its_key_binding() {
        let Ok(request) = exchange(json!({
            "assertion": "header.claims.signature",
            "ttl_seconds": 300,
            "sender_constrained": true
        })) else {
            panic!("a body naming only known fields is read");
        };

        assert!(request.constraints.is_sender_constrained());
    }

    /// A misspelled sender-constraint field is rejected during deserialization.
    #[test]
    fn an_exchange_with_a_misspelt_field_is_refused() {
        let result = exchange(json!({
            "assertion": "header.claims.signature",
            "ttl_seconds": 300,
            "sender_constraind": true
        }));

        assert!(result.is_err());
    }
}
