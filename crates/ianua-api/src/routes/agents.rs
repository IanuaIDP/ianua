//! Agent endpoints: agents and their owners, their keys, delegations and
//! the delegations they ask for, checks, evidence, approvals, runs,
//! reviewers, templates, tools, model providers, sightings, channels and
//! the relay.
//!
//! Three groups. [`routes`] holds what people call with a session or key.
//! [`agent_signed_routes`] holds what an agent calls with what it presents
//! itself (an attestation, or an assertion its key signed), and
//! [`relay_routes`] what it calls with its task token or as a reviewer;
//! the auth layer sees no caller on those, so the router gives each of the
//! two its own per-address limit. Apart from them, [`internal_routes`] is
//! served on the internal listener alone: the gateway's sealed questions
//! about approvals.

use axum::Router;
use ianua_app::ports::agents::APPROVAL_RELAY_PATH;
use utoipa::OpenApi;

use crate::dto::agents::access::{
    AuthorizeCheckBody, AuthorizeCheckResponse, AuthorizeResourceBody,
};
use crate::dto::agents::approvals::{
    ApprovalFactsResponse, ApprovalResponse, ChannelInDto, HeldCallDto, RequestApprovalBody,
};
use crate::dto::agents::attestation::{
    AttestationPolicyResponse, SetAttestationPolicyBody, WorkloadTrustDto,
};
use crate::dto::agents::capabilities::{
    BudgetDto, CapabilitySetDto, PubSubDto, ResourceCapabilityDto, TopicCapabilityDto,
};
use crate::dto::agents::channels::{ChannelResponse, OpenChannelBody, RelayedMessageResponse};
use crate::dto::agents::credentials::{
    AttestationChallengeResponse, CredentialAttestationResponse, CredentialResponse,
    EnrolledKeyDto, ExchangeTokenBody, MintCredentialBody, RotateCredentialBody,
};
use crate::dto::agents::delegation::{
    AttenuateDelegationBody, BlastRadiusResponse, DelegationLimitsDto, DelegationRefDto,
    DelegationRequestResponse, DelegationResponse, DriftModeDto, EffectiveCapabilitiesResponse,
    GrantDelegationBody, GrantDelegationResponse, IntentGrantDto, IntentSummaryDto,
    RequestDelegationBody, ResourceGrantBody,
};
use crate::dto::agents::evidence::{
    AgentActivityEntryResponse, EvidencePageResponse, EvidenceRecordResponse,
};
use crate::dto::agents::intent::{CompileIntentBody, CompileIntentResponse, ResetExposureBody};
use crate::dto::agents::lifecycle::{
    AgentResponse, AttestationDto, BootstrapAgentBody, ContainAgentResponse, CreateAgentBody,
    CreateAgentResponse, OfferAgentBody, SuspendAllAgentsResponse, UpdateAgentBody,
};
use crate::dto::agents::model_providers::{
    ChangeModelProviderClearanceBody, ChangeModelProviderModelBody, ConnectModelProviderBody,
    ConnectModelProviderResponse, ModelPricingDto, ModelProviderResponse, OfferEmbeddingsBody,
    RotateModelProviderKeyBody, TestModelProviderResponse, UpdateModelProviderStatusBody,
};
use crate::dto::agents::principal::{OwnerDto, PrincipalKind};
use crate::dto::agents::reviews::{AssignReviewerBody, ReviewAssignmentResponse, VerdictBody};
use crate::dto::agents::runs::{
    ApproveRunBody, ReplyToRunCallBody, ReviseRunCallBody, RevisedRunCallResponse, RunAgentBody,
    RunDecidedResponse, RunResponse, RunStepDto, RunSummaryResponse, RunUsageDto,
};
use crate::dto::agents::sightings::{RegisterSightingBody, SightingResponse};
use crate::dto::agents::task_templates::{ProposeTaskTemplateBody, TaskTemplateResponse};
use crate::dto::agents::tools::{
    RegisterToolBody, RegisterToolResponse, ToolResponse, UpdateToolStatusBody,
};
use crate::handlers::agents::{
    access, approvals, channels, credentials, delegation, delegation_requests, evidence, intent,
    lifecycle, model_providers, ownership, reviews, runs, sightings, task_templates, tools,
};
use crate::method::{delete, get, patch, post, put, shared};
use crate::state::ApiState;

/// Where every agents path starts: the tenant the request acts in.
const TENANT: &str = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";

/// The agent endpoints people call with a session or key.
pub(crate) fn routes() -> Router<ApiState> {
    let agents = format!("{TENANT}/agents");
    let agent = format!("{agents}/{{id}}");
    lifecycle_routes(&agents, &agent)
        .merge(credential_routes(&agent))
        .merge(ownership_routes(&agent))
        .merge(delegation_routes(&agent))
        .merge(delegation_request_routes(&agent))
        .merge(oversight_routes(&agent))
        .merge(run_routes(&agents, &agent))
        .merge(catalogue_routes(&agents))
        .merge(sighting_routes(&agents))
        .route(
            &format!("{TENANT}/messaging/channels"),
            post(channels::open_channel).get(shared(channels::list_channels)),
        )
        .route(
            &format!("{TENANT}/messaging/channels/{{id}}/close"),
            post(channels::close_channel),
        )
}

/// Registration, changes in standing, and removal of agents.
fn lifecycle_routes(agents: &str, agent: &str) -> Router<ApiState> {
    Router::new()
        .route(
            agents,
            post(lifecycle::create_agent).get(shared(lifecycle::list_agents)),
        )
        .route(
            agent,
            get(lifecycle::get_agent)
                .patch(shared(lifecycle::update_agent))
                .put(shared(lifecycle::update_agent))
                .delete(shared(lifecycle::delete_agent)),
        )
        .route(
            &format!("{agents}/suspend-all"),
            post(lifecycle::suspend_all_agents),
        )
        .route(&format!("{agent}/suspend"), post(lifecycle::suspend_agent))
        .route(&format!("{agent}/resume"), post(lifecycle::resume_agent))
        .route(&format!("{agent}/revoke"), post(lifecycle::revoke_agent))
        .route(&format!("{agent}/contain"), post(lifecycle::contain_agent))
}

/// Credential issuance, rotation, revocation, and attestation requirements.
fn credential_routes(agent: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{agent}/require-reattestation"),
            post(credentials::require_reattestation),
        )
        .route(
            &format!("{agent}/attestation-policy"),
            put(credentials::set_attestation_policy),
        )
        .route(
            &format!("{agent}/credentials"),
            post(credentials::mint_credential).get(shared(credentials::list_credentials)),
        )
        .route(
            &format!("{agent}/credentials/{{credential_id}}/rotate"),
            post(credentials::rotate_credential),
        )
        .route(
            &format!("{agent}/credentials/{{credential_id}}"),
            delete(credentials::revoke_credential),
        )
}

/// Handing an agent to another person, and the offers waiting for the
/// caller.
fn ownership_routes(agent: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{agent}/offer"),
            post(ownership::offer_agent).delete(shared(ownership::withdraw_agent_offer)),
        )
        .route(&format!("{agent}/accept"), post(ownership::accept_agent))
        .route(
            &format!("{agent}/take-over"),
            post(ownership::take_over_agent),
        )
        .route(
            &format!("{TENANT}/me/agent-offers"),
            get(ownership::list_my_agent_offers),
        )
}

/// Delegations, the checks over them, and the relationship graph.
fn delegation_routes(agent: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{agent}/grant"),
            post(delegation::grant_delegation),
        )
        .route(
            &format!("{agent}/delegations"),
            get(delegation::list_delegations),
        )
        .route(
            &format!("{TENANT}/me/delegations"),
            get(delegation::list_my_delegations),
        )
        .route(
            &format!("{agent}/delegations/{{delegation_id}}/renew"),
            post(delegation::renew_delegation),
        )
        .route(
            &format!("{agent}/blast-radius"),
            get(delegation::get_blast_radius),
        )
        .route(
            &format!("{agent}/delegations/{{delegation_id}}"),
            delete(delegation::revoke_delegation),
        )
        .merge(resource_routes(agent))
        .merge(access_routes(agent))
}

/// Resource grants and the capabilities they contribute to the agent.
fn resource_routes(agent: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{agent}/delegations/{{delegation_id}}/resources"),
            post(delegation::grant_delegation_resource)
                .delete(shared(delegation::revoke_delegation_resource)),
        )
        .route(
            &format!("{agent}/effective-capabilities"),
            get(delegation::effective_capabilities),
        )
        .route(
            &format!("{TENANT}/resource-grants"),
            put(delegation::grant_resource_relation)
                .delete(shared(delegation::revoke_resource_relation)),
        )
}

/// Access decisions, compiled intents, and exposure resets for an agent.
fn access_routes(agent: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{agent}/authorize-check"),
            post(access::authorize_check),
        )
        .route(
            &format!("{agent}/authorize-resource"),
            post(access::authorize_resource),
        )
        .route(
            &format!("{agent}/compile-intent"),
            post(intent::compile_intent),
        )
        .route(
            &format!("{agent}/exposure/reset"),
            post(intent::reset_exposure),
        )
}

/// The delegations agents asked people for, as people read and answer
/// them. The agent asks through [`agent_signed_routes`].
fn delegation_request_routes(agent: &str) -> Router<ApiState> {
    let request = format!("{agent}/delegation-requests/{{request_id}}");
    Router::new()
        .route(
            &format!("{agent}/delegation-requests"),
            get(delegation_requests::list_agent_delegation_requests),
        )
        .route(
            &format!("{request}/approve"),
            post(delegation_requests::approve_delegation_request),
        )
        .route(
            &format!("{request}/deny"),
            post(delegation_requests::deny_delegation_request),
        )
        .route(
            &format!("{TENANT}/me/delegation-requests"),
            get(delegation_requests::list_my_delegation_requests),
        )
}

/// Runs: starting, reading, stopping, deciding and steering them, an
/// agent's and the tenant's.
fn run_routes(agents: &str, agent: &str) -> Router<ApiState> {
    let run = format!("{agent}/runs/{{run_id}}");
    Router::new()
        .route(
            &format!("{agent}/runs"),
            post(runs::create_run).get(shared(runs::list_runs)),
        )
        .route(&format!("{agents}/runs"), get(runs::list_tenant_runs))
        .route(&run, get(runs::get_run))
        .route(&format!("{run}/cancel"), post(runs::cancel_run))
        .route(&format!("{run}/approve"), post(runs::approve_run))
        .route(&format!("{run}/deny"), post(runs::deny_run))
        .route(&format!("{run}/pause"), post(runs::pause_run))
        .route(&format!("{run}/resume"), post(runs::resume_run))
        .route(&format!("{run}/call"), put(runs::revise_run_call))
        .route(&format!("{run}/reply"), post(runs::reply_to_run_call))
        .route(
            &format!("{agents}/approvals"),
            get(approvals::list_tenant_approvals),
        )
}

/// The agents seen at work that nobody registered.
fn sighting_routes(agents: &str) -> Router<ApiState> {
    let sighting = format!("{agents}/sightings/{{id}}");
    Router::new()
        .route(
            &format!("{agents}/sightings"),
            get(sightings::list_sightings),
        )
        .route(
            &format!("{sighting}/register"),
            post(sightings::register_sighting),
        )
        .route(
            &format!("{sighting}/dismiss"),
            post(sightings::dismiss_sighting),
        )
}

/// What people read about an agent and decide for it: evidence,
/// approvals and reviewers.
fn oversight_routes(agent: &str) -> Router<ApiState> {
    let approval = format!("{agent}/approvals/{{approval_id}}");
    Router::new()
        .route(&format!("{agent}/activity"), get(evidence::agent_activity))
        .route(&format!("{agent}/evidence"), get(evidence::agent_evidence))
        .route(
            &format!("{agent}/approvals"),
            post(approvals::request_approval).get(shared(approvals::list_approvals)),
        )
        .route(
            &format!("{approval}/approve"),
            post(approvals::approve_action),
        )
        .route(&format!("{approval}/deny"), post(approvals::deny_action))
        .route(&format!("{approval}/facts"), get(approvals::approval_facts))
        .route(
            &format!("{agent}/reviewers"),
            post(reviews::assign_reviewer),
        )
        .route(&format!("{agent}/reviews"), get(reviews::list_reviews))
        .route(
            &format!("{agent}/reviews/{{assignment_id}}/end"),
            post(reviews::end_review),
        )
}

/// Task templates, tools and model providers.
fn catalogue_routes(agents: &str) -> Router<ApiState> {
    let templates = format!("{agents}/task-templates");
    let template = format!("{templates}/{{id}}");
    Router::new()
        .route(
            &templates,
            post(task_templates::propose_task_template)
                .get(shared(task_templates::list_task_templates)),
        )
        .route(&template, get(task_templates::get_task_template))
        .route(
            &format!("{template}/approve"),
            post(task_templates::approve_task_template),
        )
        .route(
            &format!("{template}/retire"),
            post(task_templates::retire_task_template),
        )
        .route(
            &format!("{TENANT}/tools"),
            post(tools::register_tool).get(shared(tools::list_tools)),
        )
        .route(
            &format!("{TENANT}/tools/{{id}}"),
            put(tools::edit_tool)
                .patch(shared(tools::update_tool_status))
                .delete(shared(tools::delete_tool)),
        )
        .merge(provider_routes())
}

/// Model provider connections and their operational status.
fn provider_routes() -> Router<ApiState> {
    let providers = format!("{TENANT}/model-providers");
    Router::new()
        .route(
            &providers,
            post(model_providers::connect_model_provider)
                .get(shared(model_providers::list_model_providers)),
        )
        .route(
            &format!("{providers}/{{id}}"),
            patch(model_providers::update_model_provider_status)
                .delete(shared(model_providers::delete_model_provider)),
        )
        .route(
            &format!("{providers}/{{id}}/test"),
            post(model_providers::test_model_provider),
        )
        .route(
            &format!("{providers}/{{id}}/rotate-key"),
            post(model_providers::rotate_model_provider_key),
        )
        .merge(provider_configuration_routes(&providers))
}

/// Model selection, clearance, and embeddings offered by a provider.
fn provider_configuration_routes(providers: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{providers}/{{id}}/model"),
            put(model_providers::change_model_provider_model),
        )
        .route(
            &format!("{providers}/{{id}}/clearance"),
            put(model_providers::change_model_provider_clearance),
        )
        .route(
            &format!("{providers}/{{id}}/embeddings"),
            put(model_providers::offer_model_provider_embeddings),
        )
}

/// The endpoints an agent calls with what it presents itself: an
/// attestation and its challenge, an assertion for a task token, an
/// assertion to pass a delegation on (which a person may call with a
/// session too), or an assertion to ask a person for a delegation.
pub(crate) fn agent_signed_routes() -> Router<ApiState> {
    let agent = format!("{TENANT}/agents/{{id}}");
    Router::new()
        .route(&format!("{agent}/token"), post(credentials::exchange_token))
        .route(
            &format!("{agent}/bootstrap"),
            post(lifecycle::bootstrap_agent),
        )
        .route(
            &format!("{agent}/bootstrap/challenge"),
            post(credentials::request_attestation_challenge),
        )
        .route(
            &format!("{agent}/delegations/{{delegation_id}}/attenuate"),
            post(delegation::attenuate_delegation),
        )
        .route(
            &format!("{agent}/delegation-requests"),
            post(delegation_requests::request_delegation),
        )
}

/// The internal listener's agent endpoint: the gateway's sealed questions
/// about approvals.
pub(crate) fn internal_routes() -> Router<ApiState> {
    Router::new().route(APPROVAL_RELAY_PATH, post(approvals::relay_question))
}

/// The message relay, called with a task token, and the review desk,
/// called by a reviewer agent with its assertion.
pub(crate) fn relay_routes() -> Router<ApiState> {
    let agents = format!("{TENANT}/agents");
    Router::new()
        .route(
            &format!("{agents}/messages/{{topic}}"),
            post(channels::publish_agent_message).get(shared(channels::read_agent_messages)),
        )
        .route(
            &format!("{agents}/review-desk/{{id}}/evidence"),
            get(reviews::review_desk_evidence),
        )
        .route(
            &format!("{agents}/review-desk/{{id}}/verdicts"),
            post(reviews::review_desk_verdict),
        )
}

/// The agents part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        lifecycle::create_agent,
        lifecycle::list_agents,
        lifecycle::get_agent,
        lifecycle::update_agent,
        lifecycle::delete_agent,
        lifecycle::suspend_all_agents,
        lifecycle::suspend_agent,
        lifecycle::resume_agent,
        lifecycle::revoke_agent,
        lifecycle::contain_agent,
        lifecycle::bootstrap_agent,
        ownership::offer_agent,
        ownership::withdraw_agent_offer,
        ownership::accept_agent,
        ownership::take_over_agent,
        ownership::list_my_agent_offers,
        credentials::require_reattestation,
        credentials::set_attestation_policy,
        credentials::mint_credential,
        credentials::list_credentials,
        credentials::rotate_credential,
        credentials::revoke_credential,
        credentials::exchange_token,
        credentials::request_attestation_challenge,
        delegation::grant_delegation,
        delegation::attenuate_delegation,
        delegation::grant_delegation_resource,
        delegation::revoke_delegation_resource,
        delegation::list_delegations,
        delegation::get_blast_radius,
        delegation::revoke_delegation,
        delegation::renew_delegation,
        delegation::list_my_delegations,
        delegation::effective_capabilities,
        delegation::grant_resource_relation,
        delegation::revoke_resource_relation,
        delegation_requests::request_delegation,
        delegation_requests::list_agent_delegation_requests,
        delegation_requests::list_my_delegation_requests,
        delegation_requests::approve_delegation_request,
        delegation_requests::deny_delegation_request,
        access::authorize_check,
        access::authorize_resource,
        evidence::agent_activity,
        evidence::agent_evidence,
        intent::compile_intent,
        intent::reset_exposure,
        approvals::request_approval,
        approvals::list_approvals,
        approvals::list_tenant_approvals,
        approvals::approve_action,
        approvals::approval_facts,
        approvals::deny_action,
        runs::create_run,
        runs::list_runs,
        runs::get_run,
        runs::cancel_run,
        runs::approve_run,
        runs::deny_run,
        runs::list_tenant_runs,
        runs::pause_run,
        runs::resume_run,
        runs::revise_run_call,
        runs::reply_to_run_call,
        reviews::assign_reviewer,
        reviews::list_reviews,
        reviews::end_review,
        reviews::review_desk_evidence,
        reviews::review_desk_verdict,
        task_templates::propose_task_template,
        task_templates::list_task_templates,
        task_templates::get_task_template,
        task_templates::approve_task_template,
        task_templates::retire_task_template,
        tools::register_tool,
        tools::list_tools,
        tools::edit_tool,
        tools::update_tool_status,
        tools::delete_tool,
        model_providers::connect_model_provider,
        model_providers::list_model_providers,
        model_providers::test_model_provider,
        model_providers::update_model_provider_status,
        model_providers::rotate_model_provider_key,
        model_providers::change_model_provider_model,
        model_providers::change_model_provider_clearance,
        model_providers::offer_model_provider_embeddings,
        model_providers::delete_model_provider,
        sightings::list_sightings,
        sightings::register_sighting,
        sightings::dismiss_sighting,
        channels::open_channel,
        channels::list_channels,
        channels::close_channel,
        channels::publish_agent_message,
        channels::read_agent_messages,
    ),
    components(schemas(
        OwnerDto,
        PrincipalKind,
        CapabilitySetDto,
        TopicCapabilityDto,
        PubSubDto,
        ResourceCapabilityDto,
        BudgetDto,
        AttestationPolicyResponse,
        SetAttestationPolicyBody,
        WorkloadTrustDto,
        OfferAgentBody,
        CreateAgentBody,
        UpdateAgentBody,
        CreateAgentResponse,
        AgentResponse,
        ContainAgentResponse,
        SuspendAllAgentsResponse,
        AttestationDto,
        BootstrapAgentBody,
        EnrolledKeyDto,
        MintCredentialBody,
        RotateCredentialBody,
        CredentialAttestationResponse,
        CredentialResponse,
        AttestationChallengeResponse,
        ExchangeTokenBody,
        DriftModeDto,
        IntentGrantDto,
        DelegationLimitsDto,
        GrantDelegationBody,
        RequestDelegationBody,
        DelegationRequestResponse,
        AttenuateDelegationBody,
        GrantDelegationResponse,
        IntentSummaryDto,
        DelegationResponse,
        BlastRadiusResponse,
        DelegationRefDto,
        EffectiveCapabilitiesResponse,
        ResourceGrantBody,
        AuthorizeCheckBody,
        AuthorizeResourceBody,
        AuthorizeCheckResponse,
        AgentActivityEntryResponse,
        EvidenceRecordResponse,
        EvidencePageResponse,
        CompileIntentBody,
        CompileIntentResponse,
        ResetExposureBody,
        RequestApprovalBody,
        ApprovalResponse,
        HeldCallDto,
        ChannelInDto,
        ApprovalFactsResponse,
        RunAgentBody,
        RunStepDto,
        RunUsageDto,
        RunResponse,
        RunSummaryResponse,
        ApproveRunBody,
        RunDecidedResponse,
        ReviseRunCallBody,
        RevisedRunCallResponse,
        ReplyToRunCallBody,
        AssignReviewerBody,
        ReviewAssignmentResponse,
        VerdictBody,
        ProposeTaskTemplateBody,
        TaskTemplateResponse,
        RegisterToolBody,
        UpdateToolStatusBody,
        RegisterToolResponse,
        ToolResponse,
        ModelPricingDto,
        ConnectModelProviderBody,
        UpdateModelProviderStatusBody,
        RotateModelProviderKeyBody,
        ChangeModelProviderModelBody,
        OfferEmbeddingsBody,
        ChangeModelProviderClearanceBody,
        ConnectModelProviderResponse,
        ModelProviderResponse,
        TestModelProviderResponse,
        RegisterSightingBody,
        SightingResponse,
        OpenChannelBody,
        ChannelResponse,
        RelayedMessageResponse,
    ))
)]
pub(crate) struct Document;

/// The internal listener's part of the OpenAPI document for agents, kept
/// out of the public one: no ingress routes to it, and only the gateway
/// calls it.
#[derive(OpenApi)]
#[openapi(paths(approvals::relay_question))]
pub(crate) struct InternalDocument;
