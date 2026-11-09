//! The agent use cases the API serves, by area: who an agent is and who
//! owns it, the keys and tokens it signs in with, the authority people hand
//! it and the authority it asks for, the checks and evidence people read
//! about it, its runs and their approvals, its reviewers, the templates,
//! tools and model providers it works with, the agents seen at work that
//! nobody registered, and the channels and relay it talks through.
//!
//! What only the worker or the gateway runs (driving runs, drift and
//! convergence detection, egress denials, the approval gate, recording a
//! sighting) is not here.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::services::authentication::approver_presence::{
    ApproverPresence, ApproverPresencePorts,
};
use ianua_app::services::issuers::TenantIssuers;
use ianua_app::use_cases::agents::{
    access, approvals, credentials, delegation, evidence, intent, lifecycle, model_providers,
    reviews, runs, sightings, task_templates, tools,
};
use ianua_app::use_cases::messaging::channels;

use crate::deps::{Adapters, Settings};

/// The agent use cases, by area.
#[derive(Clone)]
pub struct AgentState {
    /// An agent's life.
    pub lifecycle: LifecycleUseCases,
    pub ownership: OwnershipUseCases,
    pub credentials: CredentialUseCases,
    pub delegation: DelegationUseCases,
    pub requests: DelegationRequestUseCases,
    pub access: AccessUseCases,
    pub evidence: EvidenceUseCases,
    pub intent: IntentUseCases,
    pub approvals: ApprovalUseCases,
    pub runs: RunUseCases,
    pub steering: SteeringUseCases,
    pub reviews: ReviewUseCases,
    pub task_templates: TaskTemplateUseCases,
    pub tools: ToolUseCases,
    /// The model providers agents run on.
    pub model_providers: ModelProviderUseCases,
    pub sightings: SightingUseCases,
    pub channels: ChannelUseCases,
}

/// Creating, changing, stopping and bootstrapping agents.
#[derive(Clone)]
pub struct LifecycleUseCases {
    /// Makes a new agent.
    pub create: Arc<lifecycle::CreateAgentUseCase>,
    pub get: Arc<lifecycle::GetAgentUseCase>,
    pub list: Arc<lifecycle::ListAgentsUseCase>,
    pub update: Arc<lifecycle::UpdateAgentUseCase>,
    pub suspend: Arc<lifecycle::SuspendAgentUseCase>,
    pub suspend_all: Arc<lifecycle::SuspendAllAgentsUseCase>,
    pub resume: Arc<lifecycle::ResumeAgentUseCase>,
    pub revoke: Arc<lifecycle::RevokeAgentUseCase>,
    pub delete: Arc<lifecycle::DeleteAgentUseCase>,
    pub contain: Arc<lifecycle::ContainAgentUseCase>,
    pub bootstrap: Arc<lifecycle::BootstrapAgentUseCase>,
}

/// Handing an agent to another person: offering, accepting, withdrawing
/// and taking over.
#[derive(Clone)]
pub struct OwnershipUseCases {
    pub offer: Arc<lifecycle::OfferAgentUseCase>,
    pub accept: Arc<lifecycle::AcceptAgentUseCase>,
    pub withdraw: Arc<lifecycle::WithdrawAgentOfferUseCase>,
    pub take_over: Arc<lifecycle::TakeOverAgentUseCase>,
    pub list_offers: Arc<lifecycle::ListAgentOffersUseCase>,
}

/// An agent's keys, its attestation, and the token it mints itself.
#[derive(Clone)]
pub struct CredentialUseCases {
    pub list: Arc<credentials::ListUseCase>,
    pub mint: Arc<credentials::MintUseCase>,
    pub rotate: Arc<credentials::RotateUseCase>,
    pub revoke: Arc<credentials::RevokeUseCase>,
    pub require_reattestation: Arc<credentials::RequireReattestationUseCase>,
    pub set_attestation_policy: Arc<credentials::SetAttestationPolicyUseCase>,
    pub exchange_token: Arc<credentials::ExchangeTokenForAgentUseCase>,
    pub attestation_challenge: Arc<credentials::RequestAttestationChallengeUseCase>,
}

/// Authority handed to agents, and the resource relations behind it.
#[derive(Clone)]
pub struct DelegationUseCases {
    pub grant: Arc<delegation::GrantUseCase>,
    pub attenuate: Arc<delegation::AttenuateUseCase>,
    pub renew: Arc<delegation::RenewUseCase>,
    pub grant_resource: Arc<delegation::GrantResourceUseCase>,
    pub revoke_resource: Arc<delegation::RevokeResourceUseCase>,
    pub revoke: Arc<delegation::RevokeUseCase>,
    pub list: Arc<delegation::ListDelegationsUseCase>,
    pub list_granted: Arc<delegation::ListGrantedDelegationsUseCase>,
    pub blast_radius: Arc<delegation::GetBlastRadiusUseCase>,
    pub effective_capabilities: Arc<delegation::GetEffectiveCapabilitiesUseCase>,
    pub grant_relation: Arc<delegation::GrantResourceRelationUseCase>,
    pub revoke_relation: Arc<delegation::RevokeResourceRelationUseCase>,
}

/// The delegations agents ask people for, and the people answering.
#[derive(Clone)]
pub struct DelegationRequestUseCases {
    pub request: Arc<delegation::RequestUseCase>,
    pub approve: Arc<delegation::ApproveRequestUseCase>,
    pub deny: Arc<delegation::DenyRequestUseCase>,
    pub list: Arc<delegation::ListRequestsUseCase>,
}

/// Dry-run checks of what an agent may do.
#[derive(Clone)]
pub struct AccessUseCases {
    pub authorize: Arc<access::AuthorizeAgentUseCase>,
    pub authorize_resource: Arc<access::AuthorizeResourceUseCase>,
}

/// What the audit trail holds about an agent.
#[derive(Clone)]
pub struct EvidenceUseCases {
    pub activity: Arc<evidence::GetAgentActivityUseCase>,
    pub evidence: Arc<evidence::GetAgentUseCase>,
}

/// An agent's stated purpose and its data mark.
#[derive(Clone)]
pub struct IntentUseCases {
    pub compile: Arc<intent::CompileUseCase>,
    pub reset_exposure: Arc<intent::ResetExposureUseCase>,
}

/// Actions held for a person to approve.
#[derive(Clone)]
pub struct ApprovalUseCases {
    pub request: Arc<approvals::RequestUseCase>,
    pub list: Arc<approvals::ListPendingUseCase>,
    pub list_tenant: Arc<approvals::ListTenantUseCase>,
    pub approve: Arc<approvals::ApproveActionUseCase>,
    pub deny: Arc<approvals::DenyActionUseCase>,
    pub facts: Arc<approvals::GetFactsUseCase>,
    /// The gateway's sealed questions: hold an action for a person, or
    /// spend the approval a person gave.
    pub relay: Arc<approvals::RelayUseCase>,
}

/// Starting, reading, stopping and deciding runs.
#[derive(Clone)]
pub struct RunUseCases {
    pub start: Arc<runs::AgentUseCase>,
    pub get: Arc<runs::GetUseCase>,
    pub list: Arc<runs::ListUseCase>,
    pub list_tenant: Arc<runs::ListTenantUseCase>,
    pub cancel: Arc<runs::CancelUseCase>,
    pub approve: Arc<runs::ApproveUseCase>,
    pub deny: Arc<runs::DenyUseCase>,
}

/// A person steering a run: pausing and resuming it, changing the call it
/// holds, or answering that call in words.
#[derive(Clone)]
pub struct SteeringUseCases {
    pub pause: Arc<runs::PauseUseCase>,
    pub resume: Arc<runs::ResumeUseCase>,
    pub revise_call: Arc<runs::ReviseCallUseCase>,
    pub reply: Arc<runs::ReplyToCallUseCase>,
}

/// Reviewer agents and the desk they read and answer at.
#[derive(Clone)]
pub struct ReviewUseCases {
    pub assign: Arc<reviews::AssignReviewerUseCase>,
    pub end: Arc<reviews::EndUseCase>,
    pub list: Arc<reviews::ListUseCase>,
    pub read_evidence: Arc<reviews::ReadEvidenceUseCase>,
    pub submit_verdict: Arc<reviews::SubmitVerdictUseCase>,
}

/// The task templates delegations are granted under.
#[derive(Clone)]
pub struct TaskTemplateUseCases {
    pub propose: Arc<task_templates::ProposeUseCase>,
    pub decide: Arc<task_templates::DecideUseCase>,
    pub list: Arc<task_templates::ListUseCase>,
    pub get: Arc<task_templates::GetUseCase>,
}

/// The tools agents may call.
#[derive(Clone)]
pub struct ToolUseCases {
    pub register: Arc<tools::RegisterUseCase>,
    pub list: Arc<tools::ListUseCase>,
    pub edit: Arc<tools::EditUseCase>,
    pub update_status: Arc<tools::UpdateStatusUseCase>,
    pub delete: Arc<tools::DeleteUseCase>,
}

/// The model providers runs reason with.
#[derive(Clone)]
pub struct ModelProviderUseCases {
    /// Connects a model provider, sealing its key.
    pub connect: Arc<model_providers::ConnectUseCase>,
    pub list: Arc<model_providers::ListUseCase>,
    pub test: Arc<model_providers::TestUseCase>,
    pub update_status: Arc<model_providers::UpdateStatusUseCase>,
    pub rotate_key: Arc<model_providers::RotateKeyUseCase>,
    pub change_model: Arc<model_providers::ChangeModelUseCase>,
    pub offer_embeddings: Arc<model_providers::OfferEmbeddingsUseCase>,
    pub change_clearance: Arc<model_providers::ChangeClearanceUseCase>,
    pub delete: Arc<model_providers::DeleteUseCase>,
}

/// The agents seen at work that nobody registered.
#[derive(Clone)]
pub struct SightingUseCases {
    pub list: Arc<sightings::ListUseCase>,
    pub register: Arc<sightings::RegisterUseCase>,
    pub dismiss: Arc<sightings::DismissUseCase>,
}

/// Channels between agents, and the relay their messages pass.
#[derive(Clone)]
pub struct ChannelUseCases {
    pub open: Arc<channels::OpenUseCase>,
    pub list: Arc<channels::ListUseCase>,
    pub close: Arc<channels::CloseUseCase>,
    pub relay_publish: Arc<channels::RelayPublishUseCase>,
    pub relay_read: Arc<channels::RelayReadUseCase>,
}

/// Builds the agent use cases over `a`, tuned by `s`.
pub fn build(a: &Adapters, s: &Settings) -> AgentState {
    let decisions = Decisions {
        approve: approve_action(a, s),
        deny: deny_action(a),
    };
    AgentState {
        lifecycle: lifecycle(a, s),
        ownership: ownership(a),
        credentials: credentials(a, s),
        delegation: delegation(a, s),
        requests: delegation_requests(a, s),
        access: access(a),
        evidence: evidence(a),
        intent: intent(a),
        approvals: approvals(a, s, &decisions),
        runs: runs(a, s, decisions),
        steering: steering(a, s),
        reviews: reviews(a, s),
        task_templates: task_templates(a),
        tools: tools(a),
        model_providers: model_providers(a),
        sightings: sightings(a),
        channels: channels(a),
    }
}

/// The use cases that create, change, stop and bootstrap agents.
/// This exhaustive state initializer keeps each lifecycle operation's ports visible together.
#[allow(clippy::too_many_lines)]
fn lifecycle(a: &Adapters, s: &Settings) -> LifecycleUseCases {
    LifecycleUseCases {
        create: Arc::new(lifecycle::CreateAgentUseCase::new(
            s.tunables.credential_lifetimes,
            lifecycle::CreateAgentPorts {
                agent_store: a.agent_store.clone(),
                credential_store: a.agent_credential_store.clone(),
                key_decoder: a.public_key_decoder.clone(),
                limit_enforcer: a.limit_enforcer.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get: Arc::new(lifecycle::GetAgentUseCase::new(lifecycle::GetAgentPorts {
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(lifecycle::ListAgentsUseCase::new(
            lifecycle::ListAgentsPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        update: Arc::new(lifecycle::UpdateAgentUseCase::new(
            lifecycle::UpdateAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        suspend: Arc::new(lifecycle::SuspendAgentUseCase::new(
            lifecycle::SuspendAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        suspend_all: Arc::new(lifecycle::SuspendAllAgentsUseCase::new(
            lifecycle::SuspendAllAgentsPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        resume: Arc::new(lifecycle::ResumeAgentUseCase::new(
            lifecycle::ResumeAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        revoke: Arc::new(lifecycle::RevokeAgentUseCase::new(
            lifecycle::RevokeAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        delete: Arc::new(lifecycle::DeleteAgentUseCase::new(
            lifecycle::DeleteAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        contain: Arc::new(lifecycle::ContainAgentUseCase::new(
            lifecycle::ContainAgentPorts {
                delegation_store: a.delegation_store.clone(),
                agent_store: a.agent_store.clone(),
                credential_store: a.agent_credential_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        bootstrap: bootstrap(a, s),
    }
}

/// Bootstraps an agent from a platform attestation or a workload token.
fn bootstrap(a: &Adapters, s: &Settings) -> Arc<lifecycle::BootstrapAgentUseCase> {
    Arc::new(lifecycle::BootstrapAgentUseCase::new(
        lifecycle::BootstrapAgentPorts {
            agent_store: a.agent_store.clone(),
            attestor: a.agent_attestor.clone(),
            workload_verifier: a.workload_token_verifier.clone(),
            credential_store: a.agent_credential_store.clone(),
            key_decoder: a.public_key_decoder.clone(),
            challenge_store: a.attestation_challenge_store.clone(),
        },
        s.tunables.agent_credential_ttl,
        s.tunables.credential_lifetimes,
    ))
}

/// The use cases that hand an agent to another person.
fn ownership(a: &Adapters) -> OwnershipUseCases {
    OwnershipUseCases {
        offer: offer_agent(a),
        accept: Arc::new(lifecycle::AcceptAgentUseCase::new(
            lifecycle::AcceptAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        withdraw: Arc::new(lifecycle::WithdrawAgentOfferUseCase::new(
            lifecycle::WithdrawAgentOfferPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        take_over: Arc::new(lifecycle::TakeOverAgentUseCase::new(
            lifecycle::TakeOverAgentPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list_offers: Arc::new(lifecycle::ListAgentOffersUseCase::new(
            lifecycle::ListAgentOffersPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Offers ownership using the target account's current access records.
fn offer_agent(a: &Adapters) -> Arc<lifecycle::OfferAgentUseCase> {
    Arc::new(lifecycle::OfferAgentUseCase::new(
        lifecycle::OfferAgentPorts {
            agent_store: a.agent_store.clone(),
            user_store: a.user_store.clone(),
            access_records: a.access_record_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// The use cases for an agent's keys, its attestation and the token it
/// mints itself.
/// The exhaustive credential initializer keeps the configured lifetimes beside their ports.
#[allow(clippy::too_many_lines)]
fn credentials(a: &Adapters, s: &Settings) -> CredentialUseCases {
    CredentialUseCases {
        list: Arc::new(credentials::ListUseCase::new(credentials::ListPorts {
            agent_store: a.agent_store.clone(),
            credential_store: a.agent_credential_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        mint: Arc::new(credentials::MintUseCase::new(
            s.tunables.credential_lifetimes,
            credentials::MintPorts {
                agent_store: a.agent_store.clone(),
                credential_store: a.agent_credential_store.clone(),
                key_decoder: a.public_key_decoder.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        rotate: Arc::new(credentials::RotateUseCase::new(
            s.tunables.credential_lifetimes,
            credentials::RotatePorts {
                agent_store: a.agent_store.clone(),
                credential_store: a.agent_credential_store.clone(),
                key_decoder: a.public_key_decoder.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        revoke: Arc::new(credentials::RevokeUseCase::new(credentials::RevokePorts {
            agent_store: a.agent_store.clone(),
            credential_store: a.agent_credential_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        require_reattestation: Arc::new(credentials::RequireReattestationUseCase::new(
            credentials::RequireReattestationPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        set_attestation_policy: Arc::new(credentials::SetAttestationPolicyUseCase::new(
            credentials::SetAttestationPolicyPorts {
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        exchange_token: exchange_token(a, s),
        attestation_challenge: Arc::new(credentials::RequestAttestationChallengeUseCase::new(
            s.tunables.attestation_challenge_ttl,
            credentials::RequestAttestationChallengePorts {
                agent_store: a.agent_store.clone(),
                nonce_generator: a.attestation_nonce_generator.clone(),
                challenge_store: a.attestation_challenge_store.clone(),
            },
        )),
    }
}

/// Trades an agent's signed assertion for a task token it issues itself.
fn exchange_token(a: &Adapters, s: &Settings) -> Arc<credentials::ExchangeTokenForAgentUseCase> {
    Arc::new(credentials::ExchangeTokenForAgentUseCase::new(
        credentials::ExchangeTokenPorts {
            agent_actors: a.agent_actors.clone(),
            delegation_store: a.delegation_store.clone(),
            token_issuer: a.task_token_issuer.clone(),
            issuers: issuers(a, s),
            user_store: a.user_store.clone(),
            org_user_store: a.org_user_store.clone(),
            alert_throttle: a.alert_throttle.clone(),
        },
        s.agent_token_audience.clone(),
        s.tunables.task_token_max_ttl,
    ))
}

/// The use cases that hand authority to agents, narrow, renew or take it
/// back, and read what it adds up to.
fn delegation(a: &Adapters, s: &Settings) -> DelegationUseCases {
    let describer = describer(a);
    let relations = delegation::ResourceGrantPorts {
        resolver: a.relationship_resolver.clone(),
        grants: a.resource_grant_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    };
    delegation_use_cases(a, s, describer, relations)
}

/// Wires delegation operations around the shared listing and resource-grant dependencies.
/// The exhaustive initializer preserves which operations share and consume these adapters.
#[allow(clippy::too_many_lines)]
fn delegation_use_cases(
    a: &Adapters,
    s: &Settings,
    describer: Arc<delegation::DescribeDelegations>,
    relations: delegation::ResourceGrantPorts,
) -> DelegationUseCases {
    DelegationUseCases {
        grant: grant(a, s),
        attenuate: attenuate(a, s),
        renew: renew(a),
        grant_resource: grant_resource(a),
        revoke_resource: Arc::new(delegation::RevokeResourceUseCase::new(
            delegation::RevokeResourcePorts {
                delegation_store: a.delegation_store.clone(),
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        revoke: Arc::new(delegation::RevokeUseCase::new(delegation::RevokePorts {
            agent_store: a.agent_store.clone(),
            delegation_store: a.delegation_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(delegation::ListDelegationsUseCase::new(
            delegation::ListDelegationsPorts {
                agent_store: a.agent_store.clone(),
                delegation_store: a.delegation_store.clone(),
                describer: describer.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list_granted: Arc::new(delegation::ListGrantedDelegationsUseCase::new(
            delegation::ListGrantedDelegationsPorts {
                delegation_store: a.delegation_store.clone(),
                describer: describer.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        blast_radius: Arc::new(delegation::GetBlastRadiusUseCase::new(
            delegation::GetBlastRadiusPorts {
                agent_store: a.agent_store.clone(),
                delegation_store: a.delegation_store.clone(),
                describer,
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        effective_capabilities: Arc::new(delegation::GetEffectiveCapabilitiesUseCase::new(
            delegation::GetEffectiveCapabilitiesPorts {
                agent_store: a.agent_store.clone(),
                delegation_store: a.delegation_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        grant_relation: Arc::new(delegation::GrantResourceRelationUseCase::new(
            relations.clone(),
        )),
        revoke_relation: Arc::new(delegation::RevokeResourceRelationUseCase::new(relations)),
    }
}

/// Works out each tenant's own token issuer, which its agents' task tokens
/// name.
fn issuers(a: &Adapters, s: &Settings) -> TenantIssuers {
    TenantIssuers::new(
        a.tenant_store.clone(),
        a.organization_store.clone(),
        s.app_base_url.clone(),
    )
}

/// Grants a person's authority to an agent.
fn grant(a: &Adapters, s: &Settings) -> Arc<delegation::GrantUseCase> {
    Arc::new(delegation::GrantUseCase::new(delegation::GrantPorts {
        intent_compiler: a.intent_compiler.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        records: delegation::GrantRecordPorts {
            resource_type_store: a.resource_type_store.clone(),
            agent_store: a.agent_store.clone(),
            delegation_store: a.delegation_store.clone(),
            relationship_resolver: a.relationship_resolver.clone(),
            tool_store: a.tool_store.clone(),
            template_store: a.task_template_store.clone(),
            service_store: a.service_store.clone(),
        },
        tokens: delegation::TaskTokenPorts {
            token_issuer: a.task_token_issuer.clone(),
            issuers: issuers(a, s),
        },
        follow_up: delegation::FollowUpPorts {
            channel_store: a.agent_channel_store.clone(),
            review_store: a.review_assignment_store.clone(),
        },
    }))
}

/// Passes part of a delegation on to another agent.
fn attenuate(a: &Adapters, s: &Settings) -> Arc<delegation::AttenuateUseCase> {
    Arc::new(delegation::AttenuateUseCase::new(
        delegation::AttenuatePorts {
            tenant_authorities: a.tenant_authorities.clone(),
            agent_actors: a.agent_actors.clone(),
            alert_throttle: a.alert_throttle.clone(),
            records: delegation::AttenuationRecordPorts {
                resource_type_store: a.resource_type_store.clone(),
                agent_store: a.agent_store.clone(),
                delegation_store: a.delegation_store.clone(),
                relationship_resolver: a.relationship_resolver.clone(),
                tool_store: a.tool_store.clone(),
            },
            tokens: delegation::TaskTokenPorts {
                token_issuer: a.task_token_issuer.clone(),
                issuers: issuers(a, s),
            },
            follow_up: delegation::FollowUpPorts {
                channel_store: a.agent_channel_store.clone(),
                review_store: a.review_assignment_store.clone(),
            },
        },
        s.agent_token_audience.clone(),
    ))
}

/// Gives a delegation a fresh lifetime, while its delegator still holds
/// what it grants.
fn renew(a: &Adapters) -> Arc<delegation::RenewUseCase> {
    Arc::new(delegation::RenewUseCase::new(delegation::RenewPorts {
        delegation_store: a.delegation_store.clone(),
        agent_store: a.agent_store.clone(),
        relationship_resolver: a.relationship_resolver.clone(),
        tool_store: a.tool_store.clone(),
        review_store: a.review_assignment_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }))
}

/// Adds a resource to a delegation.
fn grant_resource(a: &Adapters) -> Arc<delegation::GrantResourceUseCase> {
    Arc::new(delegation::GrantResourceUseCase::new(
        delegation::GrantResourcePorts {
            resource_type_store: a.resource_type_store.clone(),
            delegation_store: a.delegation_store.clone(),
            agent_store: a.agent_store.clone(),
            tool_store: a.tool_store.clone(),
            relationship_resolver: a.relationship_resolver.clone(),
            accounts_now: a.accounts_now(),
            channel_store: a.agent_channel_store.clone(),
            review_store: a.review_assignment_store.clone(),
            template_store: a.task_template_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Names each delegator and reads each budget's use for a listing.
fn describer(a: &Adapters) -> Arc<delegation::DescribeDelegations> {
    Arc::new(delegation::DescribeDelegations::new(
        delegation::DescribeDelegationsPorts {
            user_store: a.user_store.clone(),
            org_user_store: a.org_user_store.clone(),
            agent_store: a.agent_store.clone(),
            budget_usage: a.budget_usage_reader.clone(),
        },
    ))
}

/// The use cases for the delegations agents ask people for: the agent
/// asking, and the people granting, refusing and reading the requests.
fn delegation_requests(a: &Adapters, s: &Settings) -> DelegationRequestUseCases {
    DelegationRequestUseCases {
        request: Arc::new(delegation::RequestUseCase::new(
            delegation::RequestPorts {
                agent_actors: a.agent_actors.clone(),
                alert_throttle: a.alert_throttle.clone(),
                request_store: a.delegation_request_store.clone(),
                user_store: a.user_store.clone(),
                org_user_store: a.org_user_store.clone(),
            },
            s.agent_token_audience.clone(),
        )),
        approve: approve_request(a),
        deny: Arc::new(delegation::DenyRequestUseCase::new(
            delegation::DenyRequestPorts {
                request_store: a.delegation_request_store.clone(),
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list: Arc::new(delegation::ListRequestsUseCase::new(
            delegation::ListRequestsPorts {
                request_store: a.delegation_request_store.clone(),
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Grants what an agent asked for, as a delegation from the person asked.
fn approve_request(a: &Adapters) -> Arc<delegation::ApproveRequestUseCase> {
    Arc::new(delegation::ApproveRequestUseCase::new(
        delegation::ApproveRequestPorts {
            request_store: a.delegation_request_store.clone(),
            agent_store: a.agent_store.clone(),
            delegation_store: a.delegation_store.clone(),
            relationship_resolver: a.relationship_resolver.clone(),
            tool_store: a.tool_store.clone(),
            review_store: a.review_assignment_store.clone(),
            channel_store: a.agent_channel_store.clone(),
            resource_type_store: a.resource_type_store.clone(),
            service_store: a.service_store.clone(),
            unit_of_work: a.unit_of_work.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// The dry-run checks of what an agent may reach.
fn access(a: &Adapters) -> AccessUseCases {
    AccessUseCases {
        authorize: Arc::new(access::AuthorizeAgentUseCase::new(
            access::AuthorizeAgentPorts {
                agent_store: a.agent_store.clone(),
                delegation_store: a.delegation_store.clone(),
                route_store: a.route_store.clone(),
                service_store: a.service_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
                policy_decisions: a.policy_decisions.clone(),
                access_records: a.access_record_store.clone(),
                member_standings: a.member_standings.clone(),
                policy_store: a.policy_store.clone(),
            },
        )),
        authorize_resource: Arc::new(access::AuthorizeResourceUseCase::new(
            access::AuthorizeResourcePorts {
                agent_store: a.agent_store.clone(),
                delegation_store: a.delegation_store.clone(),
                resolver: a.relationship_resolver.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that read what the audit trail holds about an agent.
fn evidence(a: &Adapters) -> EvidenceUseCases {
    EvidenceUseCases {
        activity: Arc::new(evidence::GetAgentActivityUseCase::new(
            evidence::GetAgentActivityPorts {
                agent_store: a.agent_store.clone(),
                activity_store: a.agent_activity_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        evidence: Arc::new(evidence::GetAgentUseCase::new(evidence::GetAgentPorts {
            agent_store: a.agent_store.clone(),
            evidence_store: a.evidence_store.clone(),
            chain_verdicts: a.audit_chain_verdict_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The use cases that compile an agent's stated purpose and reset its
/// data mark.
fn intent(a: &Adapters) -> IntentUseCases {
    IntentUseCases {
        compile: Arc::new(intent::CompileUseCase::new(intent::CompilePorts {
            compiler: a.intent_compiler.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        reset_exposure: Arc::new(intent::ResetExposureUseCase::new(
            intent::ResetExposurePorts {
                agent_store: a.agent_store.clone(),
                exposure: a.agent_exposure_gate.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The one place a paused action is approved and the one place it is
/// denied: the inbox and a run's own endpoints both decide through them.
struct Decisions {
    approve: Arc<approvals::ApproveActionUseCase>,
    deny: Arc<approvals::DenyActionUseCase>,
}

/// The use cases for actions held for a person to approve, deciding them
/// through the shared `decisions`.
fn approvals(a: &Adapters, s: &Settings, decisions: &Decisions) -> ApprovalUseCases {
    ApprovalUseCases {
        request: request_approval(a, s),
        list: Arc::new(approvals::ListPendingUseCase::new(
            approvals::ListPendingPorts {
                approval_store: a.approval_store.clone(),
                agent_store: a.agent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list_tenant: Arc::new(approvals::ListTenantUseCase::new(
            approvals::ListTenantPorts {
                approval_store: a.approval_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        approve: decisions.approve.clone(),
        deny: decisions.deny.clone(),
        facts: approval_facts(a, s),
        relay: approval_relay(a, s),
    }
}

/// Holds an action for approval under plan limits and the current human parties.
fn request_approval(a: &Adapters, s: &Settings) -> Arc<approvals::RequestUseCase> {
    Arc::new(approvals::RequestUseCase::new(
        s.tunables.approval_limits,
        approvals::RequestPorts {
            limit_enforcer: a.limit_enforcer.clone(),
            agent_store: a.agent_store.clone(),
            delegation_store: a.delegation_store.clone(),
            approval_store: a.approval_store.clone(),
            people: approvals::parties::PeoplePorts {
                user_store: a.user_store.clone(),
                org_user_store: a.org_user_store.clone(),
            },
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Answers the gateway's sealed questions about approvals: holding an
/// action for a person under the deployment's gate policy, and spending an
/// approval once.
fn approval_relay(a: &Adapters, s: &Settings) -> Arc<approvals::RelayUseCase> {
    let hold = approvals::HoldActionUseCase::new(
        s.tunables.gate_policy,
        approvals::HoldActionPorts {
            approval_store: a.approval_store.clone(),
            delegation_store: a.delegation_store.clone(),
            agent_store: a.agent_store.clone(),
            people: approvals::parties::PeoplePorts {
                user_store: a.user_store.clone(),
                org_user_store: a.org_user_store.clone(),
            },
            plan_limits: a.plan_limits_source.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
        },
    );
    let spend = approvals::SpendUseCase::new(approvals::SpendPorts {
        approval_store: a.approval_store.clone(),
        delegation_store: a.delegation_store.clone(),
    });
    Arc::new(approvals::RelayUseCase::new(
        approvals::RelayPorts {
            seal: a.approval_request_seal.clone(),
            nonces: a.nonce_ledger.clone(),
        },
        Arc::new(hold),
        Arc::new(spend),
    ))
}

/// Reads what ianua computed about a held action for the person deciding.
fn approval_facts(a: &Adapters, s: &Settings) -> Arc<approvals::GetFactsUseCase> {
    Arc::new(approvals::GetFactsUseCase::new(
        s.tunables.approval_facts_window,
        approvals::GetFactsPorts {
            approval_store: a.approval_store.clone(),
            agent_store: a.agent_store.clone(),
            delegation_store: a.delegation_store.clone(),
            tool_store: a.tool_store.clone(),
            exposure: a.agent_exposure_gate.clone(),
            activity_store: a.agent_activity_store.clone(),
            channel_store: a.agent_channel_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Approves an action once the approver answered their second factor where
/// the action needs it.
fn approve_action(a: &Adapters, s: &Settings) -> Arc<approvals::ApproveActionUseCase> {
    let presence = ApproverPresence::new(
        s.tunables.mfa_lockout,
        ApproverPresencePorts {
            tenant_mfa: a.mfa_enrollment_store.clone(),
            org_mfa: a.org_mfa_enrollment_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            sent_codes: a.sent_code_store.clone(),
            sent_code_generator: a.sent_code_generator.clone(),
        },
    );
    Arc::new(approvals::ApproveActionUseCase::new(
        s.tunables.approval_limits,
        approvals::ApproveActionPorts {
            decisions: decision_ports(a),
            delegation_store: a.delegation_store.clone(),
            audit_label_resolver: a.audit_label_resolver.clone(),
            presence: Arc::new(presence),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Denies an action and drops the call a paused run held for it.
fn deny_action(a: &Adapters) -> Arc<approvals::DenyActionUseCase> {
    Arc::new(approvals::DenyActionUseCase::new(
        approvals::DenyActionPorts {
            decisions: decision_ports(a),
            audit_label_resolver: a.audit_label_resolver.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Where a decision on a paused action, and the run it hands back, are kept.
fn decision_ports(a: &Adapters) -> approvals::DecisionPorts {
    approvals::DecisionPorts {
        approval_store: a.approval_store.clone(),
        run_store: a.run_store.clone(),
        run_drives: run_drives(a),
    }
}

/// The use cases that start, read, stop and decide runs, approving or
/// denying a paused run through `decisions`.
fn runs(a: &Adapters, s: &Settings, decisions: Decisions) -> RunUseCases {
    RunUseCases {
        start: start_run(a, s),
        get: Arc::new(runs::GetUseCase::new(runs::GetPorts {
            run_store: a.run_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(runs::ListUseCase::new(runs::ListPorts {
            run_store: a.run_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list_tenant: Arc::new(runs::ListTenantUseCase::new(runs::ListTenantPorts {
            run_store: a.run_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        cancel: cancel_run(a),
        approve: Arc::new(runs::ApproveUseCase::new(runs::ApprovePorts {
            approval_store: a.approval_store.clone(),
            run_store: a.run_store.clone(),
            approve_action: decisions.approve,
        })),
        deny: Arc::new(runs::DenyUseCase::new(runs::DenyPorts {
            approval_store: a.approval_store.clone(),
            run_store: a.run_store.clone(),
            deny_action: decisions.deny,
        })),
    }
}

/// Cancels a governed run through its cancellation signal and outstanding approvals.
fn cancel_run(a: &Adapters) -> Arc<runs::CancelUseCase> {
    Arc::new(runs::CancelUseCase::new(runs::CancelPorts {
        run_store: a.run_store.clone(),
        agent_store: a.agent_store.clone(),
        run_cancellation: a.run_cancellation.clone(),
        approval_store: a.approval_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }))
}

/// Tries a run's drive job gets. A run still left started with nobody
/// driving it is queued again by the reconciliation sweep.
const DRIVE_TRIES: NonZeroU32 = match NonZeroU32::new(3) {
    Some(tries) => tries,
    None => NonZeroU32::MIN,
};

/// Where the jobs that hand runs to a worker are queued.
fn run_drives(a: &Adapters) -> runs::RunDrives {
    runs::RunDrives {
        queue: a.job_queue.clone(),
        attempts: DRIVE_TRIES,
    }
}

/// Starts a governed run, which a worker then drives.
fn start_run(a: &Adapters, s: &Settings) -> Arc<runs::AgentUseCase> {
    Arc::new(runs::AgentUseCase::new(
        runs::AgentPorts {
            run_store: a.run_store.clone(),
            tool_store: a.tool_store.clone(),
            agent_store: a.agent_store.clone(),
            delegation_store: a.delegation_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            relationship_resolver: a.relationship_resolver.clone(),
            provider_store: a.model_provider_store.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            audit_label_resolver: a.audit_label_resolver.clone(),
            run_drives: run_drives(a),
        },
        s.tunables.run_steps,
    ))
}

/// The use cases a person steers a run with: pausing and resuming it,
/// changing the call it holds, or answering that call in words.
fn steering(a: &Adapters, s: &Settings) -> SteeringUseCases {
    SteeringUseCases {
        pause: Arc::new(runs::PauseUseCase::new(runs::PausePorts {
            run_store: a.run_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        resume: Arc::new(runs::ResumeUseCase::new(runs::ResumePorts {
            run_store: a.run_store.clone(),
            agent_store: a.agent_store.clone(),
            audit_label_resolver: a.audit_label_resolver.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            run_drives: run_drives(a),
        })),
        revise_call: revise_call(a, s),
        reply: Arc::new(runs::ReplyToCallUseCase::new(runs::ReplyToCallPorts {
            run_store: a.run_store.clone(),
            agent_store: a.agent_store.clone(),
            approval_store: a.approval_store.clone(),
            audit_label_resolver: a.audit_label_resolver.clone(),
            unit_of_work: a.unit_of_work.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            run_drives: run_drives(a),
        })),
    }
}

/// Revises a held tool call atomically with its approval and audit labels.
fn revise_call(a: &Adapters, s: &Settings) -> Arc<runs::ReviseCallUseCase> {
    Arc::new(runs::ReviseCallUseCase::new(
        runs::ReviseCallPorts {
            run_store: a.run_store.clone(),
            agent_store: a.agent_store.clone(),
            tool_store: a.tool_store.clone(),
            approval_store: a.approval_store.clone(),
            audit_label_resolver: a.audit_label_resolver.clone(),
            unit_of_work: a.unit_of_work.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
        s.tunables.run_approval_ttl,
    ))
}

/// The use cases that assign reviewer agents and run the desk they read
/// and answer at.
fn reviews(a: &Adapters, s: &Settings) -> ReviewUseCases {
    let desk = review_desk(a);
    ReviewUseCases {
        assign: Arc::new(reviews::AssignReviewerUseCase::new(
            reviews::AssignReviewerPorts {
                lineage: lineage(a),
                review_store: a.review_assignment_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        end: Arc::new(reviews::EndUseCase::new(reviews::EndPorts {
            review_store: a.review_assignment_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(reviews::ListUseCase::new(reviews::ListPorts {
            review_store: a.review_assignment_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        read_evidence: Arc::new(reviews::ReadEvidenceUseCase::new(
            desk.clone(),
            s.agent_token_audience.clone(),
        )),
        submit_verdict: Arc::new(reviews::SubmitVerdictUseCase::new(
            desk,
            s.agent_token_audience.clone(),
        )),
    }
}

/// Shares the authenticated review desk between evidence reads and verdict submissions.
fn review_desk(a: &Adapters) -> reviews::desk::DeskPorts {
    reviews::desk::DeskPorts {
        agent_actors: a.agent_actors.clone(),
        alert_throttle: a.alert_throttle.clone(),
        event_dispatcher: a.event_dispatcher.clone(),
        review_store: a.review_assignment_store.clone(),
        lineage: lineage(a),
        evidence_store: a.evidence_store.clone(),
        chain_verdicts: a.audit_chain_verdict_store.clone(),
    }
}

/// Where an agent's authority comes from: its owner, its delegations and
/// the people behind them.
fn lineage(a: &Adapters) -> delegation::LineagePorts {
    delegation::LineagePorts {
        agent_store: a.agent_store.clone(),
        delegation_store: a.delegation_store.clone(),
        user_store: a.user_store.clone(),
        org_user_store: a.org_user_store.clone(),
    }
}

/// The use cases that propose, decide and read task templates.
fn task_templates(a: &Adapters) -> TaskTemplateUseCases {
    TaskTemplateUseCases {
        propose: Arc::new(task_templates::ProposeUseCase::new(
            task_templates::ProposePorts {
                template_store: a.task_template_store.clone(),
                intent_compiler: a.intent_compiler.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        decide: Arc::new(task_templates::DecideUseCase::new(
            task_templates::DecidePorts {
                template_store: a.task_template_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list: Arc::new(task_templates::ListUseCase::new(
            task_templates::ListPorts {
                template_store: a.task_template_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get: Arc::new(task_templates::GetUseCase::new(task_templates::GetPorts {
            template_store: a.task_template_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The use cases that register, list, edit, switch and remove the tools
/// agents may call.
fn tools(a: &Adapters) -> ToolUseCases {
    ToolUseCases {
        register: Arc::new(tools::RegisterUseCase::new(tools::RegisterPorts {
            limit_enforcer: a.limit_enforcer.clone(),
            tool_store: a.tool_store.clone(),
            route_store: a.route_store.clone(),
            resource_grants: a.resource_grant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(tools::ListUseCase::new(tools::ListPorts {
            tool_store: a.tool_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        edit: Arc::new(tools::EditUseCase::new(tools::EditPorts {
            tool_store: a.tool_store.clone(),
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update_status: Arc::new(tools::UpdateStatusUseCase::new(tools::UpdateStatusPorts {
            tool_store: a.tool_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        delete: Arc::new(tools::DeleteUseCase::new(tools::DeletePorts {
            tool_store: a.tool_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The use cases that connect, test, change, switch and remove the model
/// providers runs reason with.
/// The exhaustive state initializer keeps each model-provider operation's distinct ports together.
#[allow(clippy::too_many_lines)]
fn model_providers(a: &Adapters) -> ModelProviderUseCases {
    ModelProviderUseCases {
        connect: Arc::new(model_providers::ConnectUseCase::new(
            model_providers::ConnectPorts {
                limit_enforcer: a.limit_enforcer.clone(),
                provider_store: a.model_provider_store.clone(),
                encryptor: a.secret_encryptor.clone(),
                resource_grants: a.resource_grant_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list: Arc::new(model_providers::ListUseCase::new(
            model_providers::ListPorts {
                provider_store: a.model_provider_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        test: Arc::new(model_providers::TestUseCase::new(
            model_providers::TestPorts {
                provider_store: a.model_provider_store.clone(),
                encryptor: a.secret_encryptor.clone(),
                model_client: a.model_client.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        update_status: Arc::new(model_providers::UpdateStatusUseCase::new(
            model_providers::UpdateStatusPorts {
                provider_store: a.model_provider_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        rotate_key: Arc::new(model_providers::RotateKeyUseCase::new(
            model_providers::RotateKeyPorts {
                provider_store: a.model_provider_store.clone(),
                encryptor: a.secret_encryptor.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        change_model: Arc::new(model_providers::ChangeModelUseCase::new(
            model_providers::ChangeModelPorts {
                provider_store: a.model_provider_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        offer_embeddings: Arc::new(model_providers::OfferEmbeddingsUseCase::new(
            model_providers::OfferEmbeddingsPorts {
                provider_store: a.model_provider_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        change_clearance: Arc::new(model_providers::ChangeClearanceUseCase::new(
            model_providers::ChangeClearancePorts {
                provider_store: a.model_provider_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        delete: Arc::new(model_providers::DeleteUseCase::new(
            model_providers::DeletePorts {
                provider_store: a.model_provider_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that list the agents seen at work that nobody registered,
/// and register or dismiss them.
fn sightings(a: &Adapters) -> SightingUseCases {
    SightingUseCases {
        list: Arc::new(sightings::ListUseCase::new(sightings::ListPorts {
            sighting_store: a.agent_sighting_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        register: Arc::new(sightings::RegisterUseCase::new(sightings::RegisterPorts {
            sighting_store: a.agent_sighting_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        dismiss: Arc::new(sightings::DismissUseCase::new(sightings::DismissPorts {
            sighting_store: a.agent_sighting_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The use cases that open and close channels between agents, and the
/// relay their messages pass.
fn channels(a: &Adapters) -> ChannelUseCases {
    let relay = agent_relay(a);
    ChannelUseCases {
        open: Arc::new(channels::OpenUseCase::new(channels::OpenPorts {
            channel_store: a.agent_channel_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(channels::ListUseCase::new(channels::ListPorts {
            channel_store: a.agent_channel_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        close: Arc::new(channels::CloseUseCase::new(channels::ClosePorts {
            channel_store: a.agent_channel_store.clone(),
            agent_store: a.agent_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        relay_publish: Arc::new(channels::RelayPublishUseCase::new(relay.clone())),
        relay_read: Arc::new(channels::RelayReadUseCase::new(relay)),
    }
}

/// Shares authentication, exposure checks and message provenance across both relay directions.
fn agent_relay(a: &Adapters) -> channels::agent_relay::AgentRelayPorts {
    channels::agent_relay::AgentRelayPorts {
        authenticator: a.broker_authenticator.clone(),
        standing: a.agent_standing_check.clone(),
        authorizer: a.topic_authorizer.clone(),
        topic_store: a.topic_store.clone(),
        shape: a.message_shape.clone(),
        exposure: a.agent_exposure_gate.clone(),
        provenance: Arc::new(channels::agent_message::AgentMessageChannel::new(
            a.payload_hasher.clone(),
            a.message_provenance_signer.clone(),
            a.message_provenance_verifier.clone(),
        )),
        channels: a.agent_channel_store.clone(),
        publisher: a.message_publisher.clone(),
        consumer: a.message_consumer.clone(),
    }
}
