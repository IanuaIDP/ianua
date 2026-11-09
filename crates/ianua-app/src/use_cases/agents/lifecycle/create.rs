//! Create agent: register a new agent in a tenant, owned by the person
//! creating it.
//!
//! An agent that will sign in with a durable key brings the public half of
//! a pair it made. One that will bootstrap from a platform attestation
//! brings none, and gets a short-lived credential when it bootstraps. Until
//! it has a credential an agent can prove nothing, so it can do nothing.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::{AgentIdentity, CreateAgentParams};
use ianua_domain::domains::agents::identity::attestation::AttestationPolicy;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, CredentialLifetimes, KeySource,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, Label, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentCredentialStore, AgentStore, EnrolledKey};
use crate::ports::crypto::PublicKeyDecoder;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::use_case::Command;
use crate::use_cases::agents::credentials::key_enrolment::{Enrolment, enrol};

/// Request to create a new agent.
pub struct CreateAgentRequest {
    /// Display name, such as `"nightly-report"`.
    pub name: Label,
    /// Optional description.
    pub description: Option<Label>,
    /// The attestation policy the agent proves itself under, if any.
    pub attestation_policy: Option<AttestationPolicy>,
    /// The public key the agent made for itself, when it will sign in with
    /// a durable key rather than bootstrap from an attestation.
    pub key: Option<EnrolledKey>,
}

/// A new agent and the credential it was born with, if it brought a key.
pub struct CreatedAgent {
    /// The new agent.
    pub agent_id: AgentId,
    /// Its first credential, enrolled from the key it brought.
    pub credential: Option<AgentCredential<ResolvedTenant>>,
}

/// The ports [`CreateAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateAgentPorts {
    /// Saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// Keeps the agent's first credential.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// Checks the offered key is a public key of its algorithm.
    pub key_decoder: Arc<dyn PublicKeyDecoder>,
    /// Checks the plan's agent limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Registers an identity and, when supplied, its first credential.
pub struct CreateAgentUseCase {
    lifetimes: CredentialLifetimes,
    ports: CreateAgentPorts,
}

impl CreateAgentUseCase {
    /// A use case enrolling a brought key under `lifetimes`, working
    /// through `ports`.
    #[must_use]
    pub fn new(lifetimes: CredentialLifetimes, ports: CreateAgentPorts) -> Self {
        Self { lifetimes, ports }
    }
}

impl Command for CreateAgentUseCase {
    type Caller = CallerContext;
    type Input = CreateAgentRequest;
    type Output = Result<CreatedAgent, AppError>;

    /// Creates an agent owned by the caller, enrolling the key it brought.
    ///
    /// The key is checked before anything is written, so a refused key
    /// leaves no half-made agent behind.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the plan's agent limit is reached, the
    ///   caller may not create agents, or a key is brought for an agent that
    ///   proves itself by attesting.
    /// - `AppError::Domain` when the key is not a public key of its
    ///   algorithm.
    /// - `AppError::Conflict` when another agent of the tenant has the name.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: CreateAgentRequest,
    ) -> Result<CreatedAgent, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &ctx.tenant(), ResourceKind::Agents)
            .await
            .map_err(AppError::from_domain)?;
        let control = AgentControl::new(&authority);
        let mut agent = new_agent(&control, &req)?;
        let mut credential = enrolled_credential(self, &control, &agent, req.key.as_ref())?;
        save(&self.ports, ctx, &agent, credential.as_ref()).await?;
        let tenant = ctx.tenant();
        let mut events = agent.take_events(&tenant);
        events.extend(
            credential
                .iter_mut()
                .flat_map(|key| key.take_events(&tenant)),
        );
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()?;
        Ok(CreatedAgent {
            agent_id: *agent.id(),
            credential,
        })
    }
}

/// The agent the request describes, owned by the person `control` names,
/// under its attestation policy if one was given.
fn new_agent(
    control: &AgentControl<'_>,
    req: &CreateAgentRequest,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    let params = CreateAgentParams {
        name: req.name.clone(),
        description: req.description.clone(),
    };
    let mut agent = AgentIdentity::create(control, params).map_err(AppError::from_domain)?;
    let Some(policy) = &req.attestation_policy else {
        return Ok(agent);
    };
    agent
        .trust_attestation(control, policy.clone())
        .map_err(AppError::from_domain)?;
    Ok(agent)
}

/// The credential enrolled from the key the agent brought, if it brought
/// one. An agent that proves itself by attesting is refused one.
fn enrolled_credential(
    use_case: &CreateAgentUseCase,
    control: &AgentControl<'_>,
    agent: &AgentIdentity<ResolvedTenant>,
    key: Option<&EnrolledKey>,
) -> Result<Option<AgentCredential<ResolvedTenant>>, AppError> {
    let Some(key) = key else {
        return Ok(None);
    };
    enrol(
        use_case.ports.key_decoder.as_ref(),
        &Enrolment {
            agent,
            source: KeySource::Enrolled(*control),
            key,
            expires_at: Setting::Unset,
            lifetimes: use_case.lifetimes,
        },
    )
    .map(Some)
}

/// Saves the agent, then its first credential when it has one.
async fn save(
    ports: &CreateAgentPorts,
    ctx: &CallerContext,
    agent: &AgentIdentity<ResolvedTenant>,
    credential: Option<&AgentCredential<ResolvedTenant>>,
) -> Result<(), AppError> {
    ports
        .agent_store
        .save(&ctx.tenant(), agent)
        .await
        .map_err(AppError::from_domain)?;
    let Some(credential) = credential else {
        return Ok(());
    };
    ports
        .credential_store
        .save(&ctx.tenant(), credential)
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {

    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::PublicKeyPem;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeKeyDecoder, caller_person, enrolled_key,
        spiffe_policy,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The stores a create writes to, and what it recorded.
    struct Written {
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Written {
        fn new() -> Self {
            Self {
                agents: Arc::new(FakeAgentStore::empty()),
                credentials: Arc::new(FakeAgentCredentialStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self, authorities: FakeTenantAuthorities) -> CreateAgentPorts {
            CreateAgentPorts {
                agent_store: self.agents.clone(),
                credential_store: self.credentials.clone(),
                key_decoder: Arc::new(FakeKeyDecoder),
                tenant_authorities: Arc::new(authorities),
                ..CreateAgentPorts::fakes()
            }
        }

        fn create(
            &self,
            ports: CreateAgentPorts,
            req: CreateAgentRequest,
        ) -> Result<CreatedAgent, AppError> {
            let use_case = CreateAgentUseCase::new(CredentialLifetimes::default(), ports);
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), req))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn creator() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Create)])
    }

    fn nightly_report(key: Option<EnrolledKey>) -> CreateAgentRequest {
        CreateAgentRequest {
            name: Label::new("name", "nightly-report").unwrap(),
            description: None,
            attestation_policy: None,
            key,
        }
    }

    /// Ann, who may create agents, creates "nightly-report". It is stored,
    /// owned by her, and its creation is recorded.
    #[test]
    fn the_creator_owns_the_new_agent_and_it_is_recorded() {
        let written = Written::new();

        let created = written
            .create(written.ports(creator()), nightly_report(None))
            .unwrap();

        let saved = written.agents.find_by_id_direct(&created.agent_id).unwrap();
        assert!(saved.owner().is_same_person_as(&caller_person()));
        assert_eq!(written.records(), ["agents.agent_created"]);
    }

    /// Ann creates an agent that attests under SPIFFE. It keeps that policy.
    #[test]
    fn the_attestation_policy_given_is_kept() {
        let written = Written::new();
        let req = CreateAgentRequest {
            attestation_policy: Some(spiffe_policy()),
            ..nightly_report(None)
        };

        let created = written.create(written.ports(creator()), req).unwrap();

        let saved = written.agents.find_by_id_direct(&created.agent_id).unwrap();
        assert_eq!(saved.attestation_policy(), Some(&spiffe_policy()));
    }

    /// Ann's agent brings the public half of a key it made. The key becomes
    /// its first credential, kept as offered, and the enrolment is recorded
    /// after the creation.
    #[test]
    fn the_key_an_agent_brings_is_enrolled_as_its_first_credential() {
        let written = Written::new();

        let created = written
            .create(
                written.ports(creator()),
                nightly_report(Some(enrolled_key())),
            )
            .unwrap();

        assert_eq!(
            created.credential.unwrap().public_key().as_str(),
            FakeKeyDecoder::VALID
        );
        assert_eq!(written.credentials.count(), 1);
        assert_eq!(
            written.records(),
            ["agents.agent_created", "agents.credential_minted"]
        );
    }

    /// An agent that will bootstrap from an attestation brings no key and
    /// holds no credential yet.
    #[test]
    fn an_agent_that_brings_no_key_has_no_credential_yet() {
        let written = Written::new();

        let created = written
            .create(written.ports(creator()), nightly_report(None))
            .unwrap();

        assert!(created.credential.is_none());
        assert_eq!(written.credentials.count(), 0);
    }

    /// Ann's agent brings something shaped like a key that no parser
    /// accepts. It is refused, and no agent is left behind.
    #[test]
    fn a_refused_key_leaves_no_agent_behind() {
        let written = Written::new();
        let key = EnrolledKey {
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            ..enrolled_key()
        };

        let result = written.create(written.ports(creator()), nightly_report(Some(key)));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(written.agents.count(), 0);
        assert_eq!(written.credentials.count(), 0);
    }

    /// Ann creates an agent that attests, and hands it a key as well. A key
    /// enrolled by hand is the long-lived secret attestation removes, so it
    /// is refused and no agent is left behind.
    #[test]
    fn an_agent_that_attests_takes_no_key_at_creation() {
        let written = Written::new();
        let req = CreateAgentRequest {
            attestation_policy: Some(spiffe_policy()),
            ..nightly_report(Some(enrolled_key()))
        };

        let result = written.create(written.ports(creator()), req);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.agents.count(), 0);
    }

    /// Creating a second agent named "nightly-report" returns a conflict;
    /// only the first agent and its creation record remain.
    #[test]
    fn a_name_another_agent_holds_is_a_conflict() {
        let written = Written::new();
        written.agents.keeps_names_unique();
        written
            .create(written.ports(creator()), nightly_report(None))
            .unwrap();

        let result = written.create(written.ports(creator()), nightly_report(None));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(written.agents.count(), 1);
        assert_eq!(written.records(), ["agents.agent_created"]);
    }

    /// The tenant's plan allows no more agents. Ann is refused, nothing is
    /// stored and nothing is recorded.
    #[test]
    fn a_create_past_the_plan_limit_is_refused() {
        let written = Written::new();
        let ports = CreateAgentPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..written.ports(creator())
        };

        let result = written.create(ports, nightly_report(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.agents.count(), 0);
        assert!(written.records().is_empty());
    }

    /// A caller with only the view right cannot create an agent, leaving
    /// the agent store empty.
    #[test]
    fn a_caller_who_may_not_create_agents_is_refused() {
        let written = Written::new();
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);

        let result = written.create(written.ports(sam), nightly_report(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.agents.count(), 0);
    }

    /// A signed-out caller cannot create an agent, and no agent is stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let written = Written::new();
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = written.create(written.ports(mallory), nightly_report(None));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(written.agents.count(), 0);
    }
}
