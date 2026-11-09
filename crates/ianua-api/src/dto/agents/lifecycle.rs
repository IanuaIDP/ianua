//! Agent bodies: an agent, creating and changing one, stopping them, and
//! bootstrapping one from a platform attestation.

use ianua_app::ports::agents::{AttestationPresentation, AttestationProof};
use ianua_app::use_cases::agents::lifecycle::{
    BootstrapAgentRequest, CreateAgentRequest, CreatedAgent, OfferAgentRequest, UpdateAgentRequest,
};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
use ianua_domain::domains::agents::identity::standing::AgentStanding;
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, Label, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::attestation::{
    AttestationPolicyResponse, WorkloadTrustDto, method_named, method_names, policy_from_fields,
    policy_update_from_fields, sources_of,
};
use crate::dto::agents::credentials::{CredentialResponse, EnrolledKeyDto};
use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// Request body for creating an agent identity. The caller owns it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateAgentBody {
    /// Display name, such as `nightly-report`.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Trusted attestation methods (`spiffe`, `aws`, `gcp`, `tpm`). Given
    /// together with `re_attest_every`.
    #[serde(default)]
    pub trusted_methods: Option<Vec<String>>,
    /// Maximum interval between re-attestations, in seconds. Given together
    /// with `trusted_methods`.
    #[serde(default)]
    pub re_attest_every: Option<u32>,
    /// The cloud accounts, projects or workloads the agent may attest from
    /// (`aws:<account>`, `gcp:<project>`, `spiffe://<trust domain>/<path>`,
    /// `tpm:<id>`). With a policy, it and `workload_trusts` name at least
    /// one source between them: any VM in any account can attest.
    #[serde(default)]
    pub allowed_origins: Option<Vec<String>>,
    /// The workload tokens that prove the agent, one for each token method
    /// trusted (`kubernetes`, `github_actions`, `oidc`). Given only
    /// with a policy.
    #[serde(default)]
    pub workload_trusts: Option<Vec<WorkloadTrustDto>>,
    /// The public key the agent made for itself, when it will sign in with
    /// a durable key. Left out for an agent that will bootstrap from a
    /// platform attestation instead.
    #[serde(default)]
    pub key: Option<EnrolledKeyDto>,
}

impl TryFrom<CreateAgentBody> for CreateAgentRequest {
    type Error = ApiError;

    fn try_from(body: CreateAgentBody) -> Result<Self, Self::Error> {
        let attestation_policy = policy_from_fields(
            body.trusted_methods.as_deref(),
            body.re_attest_every,
            sources_of(
                body.allowed_origins.as_deref(),
                body.workload_trusts.as_deref(),
            ),
        )?;
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            description: body
                .description
                .map(|d| Label::new("description", d))
                .transpose()
                .map_err(ApiError::validation)?,
            attestation_policy,
            key: body.key.map(EnrolledKeyDto::into_enrolled).transpose()?,
        })
    }
}

/// Request body for updating an agent's details.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateAgentBody {
    /// New display name.
    pub name: String,
    /// New description (cleared when left out).
    pub description: Option<String>,
    /// Replacement trusted attestation methods (`spiffe`, `aws`, `gcp`,
    /// `tpm`). Absent leaves the policy unchanged, `null` clears it, a list
    /// sets it. Agrees with `re_attest_every` on which of the three this
    /// is: the two name one policy together.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub trusted_methods: Option<Option<Vec<String>>>,
    /// Replacement re-attestation interval, in seconds. Absent leaves the
    /// policy unchanged, `null` clears it, a number sets it. Agrees with
    /// `trusted_methods` on which of the three this is.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<u32>)]
    pub re_attest_every: Option<Option<u32>>,
    /// The accounts, projects or workloads the agent may attest from. Given
    /// only when the policy is set.
    #[serde(default)]
    pub allowed_origins: Option<Vec<String>>,
    /// The workload tokens that prove the agent, for the token methods.
    /// Given only when the policy is set.
    #[serde(default)]
    pub workload_trusts: Option<Vec<WorkloadTrustDto>>,
}

impl UpdateAgentBody {
    /// The change this body asks of agent `agent_id`.
    ///
    /// # Errors
    ///
    /// - A validation error for an invalid name, description or policy, or
    ///   when the two policy fields disagree.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<UpdateAgentRequest, ApiError> {
        Ok(UpdateAgentRequest {
            agent_id,
            name: Label::new("name", self.name).map_err(ApiError::validation)?,
            description: self
                .description
                .map(|d| Label::new("description", d))
                .transpose()
                .map_err(ApiError::validation)?,
            attestation_policy: policy_update_from_fields(
                self.trusted_methods,
                self.re_attest_every,
                sources_of(
                    self.allowed_origins.as_deref(),
                    self.workload_trusts.as_deref(),
                ),
            )?,
        })
    }
}

/// A newly created agent and the credential it was born with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateAgentResponse {
    /// The agent's unique identifier.
    pub id: Uuid,
    /// The credential enrolled from the key the agent brought. `null` for
    /// an agent that brought none and will bootstrap from an attestation.
    pub credential: Option<CredentialResponse>,
}

impl From<CreatedAgent> for CreateAgentResponse {
    fn from(created: CreatedAgent) -> Self {
        Self {
            id: *created.agent_id.as_uuid(),
            credential: created.credential.as_ref().map(CredentialResponse::from),
        }
    }
}

/// Whether an agent may act right now, and if not, why.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum AgentStandingDto {
    /// Free to act.
    Active,
    /// Blocked until it proves what it is again.
    MustReattest,
    /// Stopped until someone resumes it.
    Suspended,
    /// Stopped for good.
    Revoked,
}

impl From<AgentStanding> for AgentStandingDto {
    fn from(standing: AgentStanding) -> Self {
        match standing {
            AgentStanding::Active => Self::Active,
            AgentStanding::MustReattest => Self::MustReattest,
            AgentStanding::Suspended => Self::Suspended,
            AgentStanding::Revoked => Self::Revoked,
        }
    }
}

/// An agent identity.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AgentResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// The person who owns it.
    pub owner: OwnerDto,
    /// Lifecycle status: `Active`, `Suspended` or `Revoked`.
    #[schema(schema_with = crate::dto::schemas::agent_status)]
    pub status: AgentStatus,
    /// Whether it may act right now. An `Active` agent that owes a
    /// re-attestation is `MustReattest` until it proves what it is again.
    pub standing: AgentStandingDto,
    /// The attestation policy accepted for secret-zero bootstrap, if
    /// configured.
    pub attestation_policy: Option<AttestationPolicyResponse>,
    /// Trusted attestation methods, when a policy is configured.
    pub trusted_methods: Option<Vec<String>>,
    /// Maximum interval between re-attestations in seconds, when a policy
    /// is configured.
    pub re_attest_every: Option<u32>,
    /// When the agent was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the agent was last changed: its details, status, attestation
    /// policy, or a recorded attestation.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// The person the agent was offered to, while the offer stands.
    pub offered_to: Option<OwnerDto>,
    /// When the standing offer lapses unanswered.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub offer_expires_at: Option<OffsetDateTime>,
}

impl From<AgentIdentity<ResolvedTenant>> for AgentResponse {
    fn from(agent: AgentIdentity<ResolvedTenant>) -> Self {
        let policy = agent.attestation_policy();
        let offer = agent.offer();
        let offered_to = offer.open_to(clock::now()).map(OwnerDto::from_human);
        let offer_expires_at = offered_to.as_ref().and(offer.expires_at());
        Self {
            id: *agent.id().as_uuid(),
            name: agent.name().as_str().to_owned(),
            description: agent.description().map(|d| d.as_str().to_owned()),
            owner: OwnerDto::from_human(agent.owner()),
            status: agent.status(),
            standing: agent.standing(clock::now()).into(),
            attestation_policy: policy.map(AttestationPolicyResponse::from),
            trusted_methods: policy.map(method_names),
            re_attest_every: policy.map(|p| p.reattest_interval_seconds().get()),
            created_at: agent.created_at(),
            updated_at: agent.updated_at(),
            offered_to,
            offer_expires_at,
        }
    }
}

/// Result of containing an agent: the fleet kill-switch.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ContainAgentResponse {
    /// How many delegations were revoked: the agent's holdings plus their
    /// subtrees.
    pub revoked_count: u32,
}

/// Result of stopping every agent in a tenant.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SuspendAllAgentsResponse {
    /// How many active agents were suspended.
    pub suspended_count: u32,
}

/// A platform attestation an agent presents to bootstrap its identity.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AttestationDto {
    /// Attestation method (`spiffe`, `aws`, `gcp`, `tpm`, `kubernetes`,
    /// `github_actions`, `oidc`).
    pub method: String,
    /// Method-specific payload: the SVID, the signed AWS
    /// `sts:GetCallerIdentity` request (JSON of `method`, `url`, `headers`
    /// and `body`), the GCP identity token or the TPM quote, or for a token
    /// method the workload token itself (a Kubernetes service account
    /// token, a GitHub Actions OIDC token, an OIDC issuer's token). Every
    /// payload carries the binding of the nonce and the enrolled public
    /// key: SHA-256 of `ianua-attestation-binding-v1`, a zero byte, the
    /// nonce, a zero byte and the key's DER, in lower-case hex. A workload
    /// token carries it as its only audience (`aud`).
    pub material: String,
    /// The challenge nonce this bootstrap answers, from
    /// `POST .../bootstrap/challenge`.
    pub nonce: String,
    /// For SPIFFE, the base64url (unpadded) signature over
    /// `ianua-attestation-proof-v1:` and the binding in hex, made with the
    /// SVID's private key: DER for ECDSA and RSA, raw for Ed25519. Empty for
    /// the other methods.
    pub signature: String,
}

/// Request to bootstrap an agent from a platform attestation.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct BootstrapAgentBody {
    /// The public key the workload made for itself.
    #[serde(flatten)]
    pub key: EnrolledKeyDto,
    /// The platform attestation the agent presents.
    pub attestation: AttestationDto,
}

impl BootstrapAgentBody {
    /// The bootstrap of agent `agent_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error for an invalid key, an unknown method or a
    ///   nonce that is not one.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<BootstrapAgentRequest, ApiError> {
        let attestation = self.attestation;
        Ok(BootstrapAgentRequest {
            agent_id,
            key: self.key.into_enrolled()?,
            attestation: AttestationPresentation {
                method: method_named(&attestation.method)?,
                material: attestation.material,
                proof: AttestationProof {
                    nonce: AttestationNonce::new(attestation.nonce)
                        .map_err(ApiError::validation)?,
                    signature: attestation.signature,
                },
            },
        })
    }
}

/// Request body for offering an agent to another person.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OfferAgentBody {
    /// The tenant user the agent is offered to. They become its owner once
    /// they accept.
    pub recipient: Uuid,
}

impl OfferAgentBody {
    /// The offer of agent `agent_id` this body makes.
    #[must_use]
    pub(crate) fn into_request(self, agent_id: AgentId) -> OfferAgentRequest {
        OfferAgentRequest {
            agent_id,
            recipient: UserId::from_uuid(self.recipient),
        }
    }
}
