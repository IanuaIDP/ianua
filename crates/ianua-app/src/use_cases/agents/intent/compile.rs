//! Compile intent: narrow a requested scope to a declared intent.
//!
//! At grant/exchange the natural-language intent is compiled *once, offline*
//! into a narrowed capability set plus a digest, yielding an [`IntentBinding`]
//! to attach to the delegation's constraints. The proxy then enforces the
//! narrowed scope with the ordinary deny-by-default capability check, with no
//! model in the hot path.
//!
//! **Hard invariant:** intent may only attenuate, never grant. A compiler that
//! returns a scope broader than what was requested is rejected here, so a broken
//! or hostile compiler can never escalate authority.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::intent::{
    DriftPolicy, IntentBinding, IntentStatement,
};
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::message;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, IntentCompiler};
use crate::services::lookup::existing_agent;
use crate::use_case::Query;

/// Request to compile an intent against a requested scope.
pub struct CompileRequest {
    /// The agent the intent is compiled for.
    pub agent_id: AgentId,
    /// The natural-language intent the token is for.
    pub intent: IntentStatement,
    /// The capabilities requested (the ceiling the intent narrows within).
    pub requested: CapabilitySet,
    /// The drift policy to bind alongside the compiled intent.
    pub drift_policy: DriftPolicy,
}

/// The narrowed scope and the binding to attach to a delegation.
pub struct CompiledOutcome {
    /// The narrowed capability set (`⊆ requested`).
    pub scope: CapabilitySet,
    /// The intent binding (statement + digest + drift policy) for the delegation.
    pub binding: IntentBinding,
}

/// Ports needed by the compile intent use case.
#[derive(ianua_macros::Fakes)]
pub struct CompilePorts {
    /// Port for compiling the intent into a narrowed scope.
    pub compiler: Arc<dyn IntentCompiler>,
    /// The tenant's agents, so an intent is compiled only for one it has.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Narrows requested capabilities to an intent without granting new authority.
pub struct CompileUseCase {
    ports: CompilePorts,
}

impl CompileUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: CompilePorts) -> Self {
        Self { ports }
    }
}

impl Query for CompileUseCase {
    type Caller = CallerContext;
    type Input = CompileRequest;
    type Output = Result<CompiledOutcome, AppError>;

    /// Compiles the intent for one of the tenant's agents, for a caller who
    /// may view agents, enforcing that it only attenuates the request.
    /// Nothing is kept: it is a dry run.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents, or the
    ///   compiled scope exceeds the requested scope (intent must never
    ///   grant).
    /// - `AppError::NotFound` when the tenant has no such agent.
    /// - `AppError::Internal` if the store or the compiler backend fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        req: CompileRequest,
    ) -> Result<CompiledOutcome, AppError> {
        ensure_may_view_agent(&self.ports, ctx, &req.agent_id).await?;
        let compiled = self
            .ports
            .compiler
            .compile(&req.intent, &req.requested)
            .await
            .or_internal()?;

        if !compiled.scope().subset_of(&req.requested) {
            return Err(AppError::Forbidden(message!(
                "agents-compiled-intent-exceeds-requested-scope",
                "compiled intent exceeds requested scope"
            )));
        }

        let binding = IntentBinding::new(
            req.intent,
            *compiled.digest(),
            req.drift_policy,
            compiled.envelope().clone(),
        );

        Ok(CompiledOutcome {
            scope: compiled.scope().clone(),
            binding,
        })
    }
}

/// Refuses a caller who may not view agents, then an agent the tenant does
/// not have, so a refused caller learns nothing of which agents exist.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the caller's session or key no longer
///   counts.
/// - `AppError::Forbidden` when the caller may not view agents.
/// - `AppError::NotFound` when the tenant has no such agent.
/// - `AppError::Internal` on persistence failure.
async fn ensure_may_view_agent(
    ports: &CompilePorts,
    ctx: &CallerContext,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    let authority = ports.tenant_authorities.authority(ctx).await?;
    authority
        .ensure_holds(SystemPermission::Agents(AgentAction::View))
        .map_err(AppError::from_domain)?;
    existing_agent(ports.agent_store.as_ref(), &ctx.tenant(), agent_id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::agents::authority::capability::{
        PubSub, TopicCapability, TopicPattern,
    };
    use ianua_domain::domains::agents::authority::intent::{
        CompiledIntent, IntentDigest, IntentEnvelope,
    };
    use ianua_domain::domains::authorization::permission::RoutingAction;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::{block_on, test_ctx};

    /// Answers every intent with a fixed scope.
    struct FakeCompiler {
        scope: CapabilitySet,
    }

    #[async_trait]
    impl IntentCompiler for FakeCompiler {
        async fn compile(
            &self,
            _intent: &IntentStatement,
            _requested: &CapabilitySet,
        ) -> Result<CompiledIntent, DomainError> {
            Ok(CompiledIntent::new(
                self.scope.clone(),
                IntentDigest::new([9u8; 32]),
                IntentEnvelope::default(),
            ))
        }
    }

    fn topic(pattern: &str, rights: PubSub) -> TopicCapability {
        TopicCapability::new(TopicPattern::new(pattern).unwrap(), rights)
    }

    fn requested() -> CapabilitySet {
        CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![topic("ianua.msg.t1.>", PubSub::Both)],
        )
    }

    /// The tenant's one agent, and a use case whose compiler answers with
    /// `scope`, for a caller `authorities` describes.
    struct Fixture {
        uc: CompileUseCase,
        agent: AgentId,
    }

    fn fixture_for(scope: CapabilitySet, authorities: FakeTenantAuthorities) -> Fixture {
        let agent = AgentId::new();
        let uc = CompileUseCase::new(CompilePorts {
            compiler: Arc::new(FakeCompiler { scope }),
            agent_store: Arc::new(FakeAgentStore::with_active(agent)),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture { uc, agent }
    }

    fn fixture(scope: CapabilitySet) -> Fixture {
        fixture_for(
            scope,
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
        )
    }

    fn request(agent_id: AgentId, requested: CapabilitySet) -> CompileRequest {
        CompileRequest {
            agent_id,
            intent: IntentStatement::new("book a flight for the offsite").unwrap(),
            requested,
            drift_policy: DriftPolicy::Off,
        }
    }

    fn compile(f: &Fixture, req: CompileRequest) -> Result<CompiledOutcome, AppError> {
        block_on(f.uc.execute(&test_ctx(), req))
    }

    /// Ann asks for routing and topic rights to book a flight for the
    /// offsite. The compiler narrows them to viewing routes and publishing
    /// on one topic, and the narrowed scope comes back bound to her intent.
    #[test]
    fn narrowed_scope_is_accepted_and_bound() {
        let narrowed = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![topic("ianua.msg.t1.agents.a1", PubSub::Publish)],
        );
        let f = fixture(narrowed.clone());

        let outcome = compile(&f, request(f.agent, requested())).unwrap();

        assert_eq!(outcome.scope, narrowed);
        assert_eq!(
            outcome.binding.statement().as_str(),
            "book a flight for the offsite"
        );
    }

    /// Compiled capabilities exceeding the requested route-view scope are
    /// rejected.
    #[test]
    fn compiler_that_escalates_is_rejected() {
        let escalated = CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::Manage)],
            vec![topic("ianua.msg.t1.>", PubSub::Both)],
        );
        let f = fixture(escalated);

        let requested =
            CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![]);
        let result = compile(&f, request(f.agent, requested));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Compiling an agent's intent requires agent-view permission.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let f = fixture_for(requested(), FakeTenantAuthorities::holding(&[]));

        let result = compile(&f, request(f.agent, requested()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot compile an agent's intent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_for(
            requested(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = compile(&f, request(f.agent, requested()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Compiling intent for an unknown agent reports it as missing.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let f = fixture(requested());

        let result = compile(&f, request(AgentId::new(), requested()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
