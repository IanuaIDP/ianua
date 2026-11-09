//! Agent credential handlers: the keys an agent signs in with, the
//! attestation it proves itself by, and the task token it mints for itself
//! with a signed assertion.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::credentials::{RevokeRequest, SetAttestationPolicyRequest};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::attestation::{AttestationPolicyResponse, SetAttestationPolicyBody};
use crate::dto::agents::credentials::{
    AttestationChallengeResponse, CredentialResponse, ExchangeTokenBody, MintCredentialBody,
    RotateCredentialBody,
};
use crate::dto::agents::delegation::GrantDelegationResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::AgentEndpoint;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::{AgentCredentialPath, AgentPath};
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/require-reattestation",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Require an agent to re-attest
///
/// Makes the agent prove itself again: from the next request the proxy
/// refuses every token it presents until it bootstraps again with a fresh
/// platform attestation. Unlike containment this leaves its delegations in
/// place; it earns them back by attesting. Asking twice changes nothing
/// more. Records `agents.reattestation_required`. Requires the agent's
/// owner or `Agents(Update)`.
pub(crate) async fn require_reattestation(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<NoContent, ApiError> {
    agents
        .credentials
        .require_reattestation
        .execute(&tenant.caller, &tenant.auditor, path.agent())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/attestation-policy",
    tag = "Agents",
    request_body = SetAttestationPolicyBody,
    responses(
        (status = 200, description = "The configured policy", body = AttestationPolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Set an agent's attestation policy
///
/// Configures which platform attestations (`spiffe`, `aws`, `gcp`, `tpm`)
/// the agent accepts for secret-zero bootstrap, from which accounts,
/// projects or workloads, and how often it must re-attest. Deny by
/// default: bootstrap succeeds only for a verified attestation this policy
/// trusts. `404` if the agent does not exist, `422` for an unknown method,
/// no methods, no origins, or a zero interval. Records
/// `agents.agent_updated`. Requires the agent's owner or `Agents(Update)`.
pub(crate) async fn set_attestation_policy(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<SetAttestationPolicyBody>,
) -> Result<Json<AttestationPolicyResponse>, ApiError> {
    let request = SetAttestationPolicyRequest {
        agent_id: path.agent(),
        policy: body.policy()?,
    };
    let response = AttestationPolicyResponse::from(&request.policy);
    agents
        .credentials
        .set_attestation_policy
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/credentials",
    tag = "Agents",
    request_body = MintCredentialBody,
    responses(
        (status = 201, description = "Created: the enrolled credential", body = CredentialResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody),
        (status = 409, description = "Agent not active", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Enrol an agent credential
///
/// Enrols the public half of a key pair the agent made for itself
/// (`algorithm`, `public_key`) and returns the credential's metadata (`id`,
/// `kid`, `algorithm`, `public_key`). The private half never leaves the
/// agent: the platform neither generates nor returns one. The agent signs
/// assertions with its key for the token exchange.
///
/// An enrolled credential is unattested (`attestation` is `null`) and its
/// `kid` is generated by the server; neither is settable here. Attestation
/// binding happens only through `POST .../bootstrap`, where the platform
/// has a proof to verify.
///
/// `404` if the agent does not exist, `409` if it is not active, `422` for
/// an unknown algorithm or a key that is not a public key of it. Records
/// `agents.credential_minted`. Requires the agent's owner or
/// `Agents(Update)`.
pub(crate) async fn mint_credential(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<MintCredentialBody>,
) -> Result<Created<CredentialResponse>, ApiError> {
    let credential = agents
        .credentials
        .mint
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(Created(CredentialResponse::from(&credential)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/credentials",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<CredentialResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// List an agent's credentials
///
/// Returns the identity credentials the agent holds, active and rotated
/// ones, as public metadata (never a private key). Requires the agent's
/// owner or `Agents(View)`.
pub(crate) async fn list_credentials(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<Vec<CredentialResponse>>, ApiError> {
    let credentials = agents
        .credentials
        .list
        .execute(&tenant.caller, path.agent())
        .await?;
    Ok(Json(
        credentials.iter().map(CredentialResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/credentials/{credential_id}/rotate",
    tag = "Agents",
    request_body = RotateCredentialBody,
    responses(
        (status = 201, description = "Created: the replacement credential", body = CredentialResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Credential not found", body = ErrorBody),
        (status = 422, description = "Credential already revoked", body = ErrorBody)
    )
)]
/// Rotate an agent credential
///
/// Retires the credential (it stays verifiable during a grace period but no
/// longer signs) and enrols the replacement public key the agent made, with
/// the same expiry. A refused key leaves the old credential as it was.
/// Returns the new credential; the retired one reports its `rotated_at`,
/// `grace_ends_at` and `grace_period_seconds` when listed, so the window it
/// counts down is visible. `404` if the credential is not the agent's,
/// `422` if it was revoked. Records `agents.credential_rotated`. Requires
/// the agent's owner or `Agents(Update)`.
pub(crate) async fn rotate_credential(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentCredentialPath>,
    Json(body): Json<RotateCredentialBody>,
) -> Result<Created<CredentialResponse>, ApiError> {
    let credential = agents
        .credentials
        .rotate
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.agent(), path.credential())?,
        )
        .await?;
    Ok(Created(CredentialResponse::from(&credential)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/credentials/{credential_id}",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already revoked", body = ErrorBody)
    )
)]
/// Revoke an agent credential
///
/// Revokes an identity credential for good: assertions signed by it no
/// longer verify. `404` if the credential is not the agent's, `422` if it
/// was revoked already. Records `agents.credential_revoked`. Requires the
/// agent's owner or `Agents(Delete)`.
pub(crate) async fn revoke_credential(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentCredentialPath>,
) -> Result<NoContent, ApiError> {
    agents
        .credentials
        .revoke
        .execute(
            &tenant.caller,
            &tenant.auditor,
            RevokeRequest {
                agent_id: path.agent(),
                credential_id: path.credential(),
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/token",
    tag = "Agents",
    request_body = ExchangeTokenBody,
    responses(
        (status = 201, description = "Created: the minted task token", body = GrantDelegationResponse),
        (status = 403, description = "Assertion refused or agent not active", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Exchange an assertion for a task token (client credentials)
///
/// The agent proves it holds its identity key by presenting an `assertion`
/// it signed for this tenant's token endpoint; the platform verifies it
/// against the agent's stored public key, spends it so it cannot be used
/// twice, and mints a task token for at most the authority the agent holds
/// through its live delegations. No session: the agent signs in by the
/// assertion, and every failure to sign in is `403`, the same whether the
/// agent exists or not. Rate limited per address. Records
/// `agents.token_issued`. A refusal that looks like an attack (a replayed
/// or forged assertion, or one naming another agent) records
/// `agents.token_attack_refused` about the agent it named, at most once an
/// hour per agent and kind of attack, and alerts the tenant's
/// administrators.
pub(crate) async fn exchange_token(
    State(agents): State<AgentState>,
    agent: AgentEndpoint,
    Path(path): Path<AgentPath>,
    Json(body): Json<ExchangeTokenBody>,
) -> Result<Created<GrantDelegationResponse>, ApiError> {
    let exchanged = agents
        .credentials
        .exchange_token
        .execute(
            &agent.tenant,
            &agent.auditor,
            body.into_request(path.agent())?,
        )
        .await?;
    Ok(Created(GrantDelegationResponse::from(exchanged)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/bootstrap/challenge",
    tag = "Agents",
    responses(
        (status = 201, description = "A single-use challenge to sign", body = AttestationChallengeResponse),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Request an attestation challenge (step 1 of bootstrap)
///
/// Returns a single-use nonce bound to this agent. Bind it to the public key
/// the workload will enrol (SHA-256 of `ianua-attestation-binding-v1`, a
/// zero byte, the nonce, a zero byte and the key's DER), carry that binding
/// in the attestation, and send both to `/bootstrap`. Attestation material,
/// a SPIFFE SVID say, is a public document, so presenting it alone proves
/// nothing; the binding is what proves the caller is the workload, now,
/// enrolling its own key, rather than someone holding a copy of its
/// certificate or a token seen in passing. The challenge expires within
/// minutes and is spent on first use, so a captured request cannot be
/// replayed. No session; rate limited per address. Records
/// `agents.attestation_challenge_issued`.
pub(crate) async fn request_attestation_challenge(
    State(agents): State<AgentState>,
    agent: AgentEndpoint,
    Path(path): Path<AgentPath>,
) -> Result<Created<AttestationChallengeResponse>, ApiError> {
    let challenge = agents
        .credentials
        .attestation_challenge
        .execute(&agent.tenant, &agent.auditor, path.agent())
        .await?;
    Ok(Created(AttestationChallengeResponse::from(&challenge)))
}
