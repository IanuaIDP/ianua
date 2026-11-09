//! Propose task template: a person writes down what one kind of task needs.
//!
//! The proposer is always the person signed in, never someone the request
//! names, so nobody passes their own template off as another's and then
//! approves it. Nothing is granted under a template until a second person
//! approves it.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::intent::{IntentEnvelope, IntentStatement};
use ianua_domain::domains::agents::authority::task_template::{
    ProposeTaskTemplateParams, TaskTemplate, TemplateLimits,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Label;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{IntentCompiler, TaskTemplateStore};
use crate::use_case::Command;

/// What a person proposes.
pub struct ProposeRequest {
    /// A short name people recognise the task by.
    pub name: Label,
    /// What the task is for, in words.
    pub purpose: IntentStatement,
    /// The most a delegation under the template may grant.
    pub ceiling: CapabilitySet,
    /// The kinds of action the task may take.
    pub classes: IntentEnvelope,
    /// The bounds on every delegation.
    pub limits: TemplateLimits,
}

/// The ports [`ProposeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ProposePorts {
    /// Keeps templates.
    pub template_store: Arc<dyn TaskTemplateStore>,
    /// Fingerprints the purpose.
    pub intent_compiler: Arc<dyn IntentCompiler>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Proposes a task template in the caller's tenant.
pub struct ProposeUseCase {
    ports: ProposePorts,
}

impl ProposeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ProposePorts) -> Self {
        Self { ports }
    }
}

impl Command for ProposeUseCase {
    type Caller = CallerContext;
    type Input = ProposeRequest;
    type Output = Result<TaskTemplate<ResolvedTenant>, AppError>;

    /// Keeps the proposal, awaiting a second person's approval.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller cannot act in the tenant.
    /// - `AppError::Domain` when the ceiling grants nothing, no kind of
    ///   action is allowed, or the limits are out of bounds.
    /// - `AppError::Internal` on compiler, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: ProposeRequest,
    ) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        let mut template = proposed(&self.ports, &authority, req).await?;
        self.ports
            .template_store
            .save(&tenant, &template)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), template.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(template)
    }
}

/// The template `req` describes, its purpose fingerprinted, proposed by the
/// person `authority` names.
async fn proposed(
    ports: &ProposePorts,
    authority: &TenantAuthority,
    req: ProposeRequest,
) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
    let compiled = ports
        .intent_compiler
        .compile(&req.purpose, &req.ceiling)
        .await
        .or_internal()?;
    let params = ProposeTaskTemplateParams {
        name: req.name,
        purpose: req.purpose,
        digest: *compiled.digest(),
        ceiling: req.ceiling,
        classes: req.classes,
        limits: req.limits,
    };
    TaskTemplate::propose(&AgentControl::new(authority), params).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::task_template::TemplateStatus;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeTaskTemplateStore, caller_person, report_template_params,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn request(classes: IntentEnvelope) -> ProposeRequest {
        let params = report_template_params();
        ProposeRequest {
            name: params.name,
            purpose: params.purpose,
            ceiling: params.ceiling,
            classes,
            limits: params.limits,
        }
    }

    fn propose(
        ports: ProposePorts,
        sink: &Arc<FakeEventDispatcher>,
        req: ProposeRequest,
    ) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
        block_on(ProposeUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    fn ports_over(store: &Arc<FakeTaskTemplateStore>) -> ProposePorts {
        ProposePorts {
            template_store: store.clone(),
            ..ProposePorts::fakes()
        }
    }

    /// Ann proposes the monthly reports template. It is kept awaiting
    /// approval, named as hers, and the proposal is recorded.
    #[test]
    fn a_proposal_is_kept_awaiting_approval_and_recorded() {
        let store = Arc::new(FakeTaskTemplateStore::default());
        let sink = Arc::new(FakeEventDispatcher::new());

        let template = propose(
            ports_over(&store),
            &sink,
            request(IntentEnvelope::new([ActionClass::Read])),
        )
        .unwrap();

        let stored = block_on(store.find_by_id(&test_ctx().tenant(), template.id()))
            .unwrap()
            .unwrap();
        assert_eq!(stored.status(), TemplateStatus::Proposed);
        assert!(stored.proposed_by().is_same_person_as(&caller_person()));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.task_template_proposed"]
        );
    }

    /// Ann proposes a template that allows no kind of action. It is refused
    /// and nothing is kept.
    #[test]
    fn a_proposal_allowing_no_action_is_refused_and_not_kept() {
        let store = Arc::new(FakeTaskTemplateStore::default());

        let result = propose(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            request(IntentEnvelope::new([])),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(
            block_on(store.list(&test_ctx().tenant()))
                .unwrap()
                .is_empty()
        );
    }

    /// A signed-out caller cannot propose a template; the template store
    /// remains empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeTaskTemplateStore::default());
        let ports = ProposePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = propose(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            request(IntentEnvelope::new([ActionClass::Read])),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(
            block_on(store.list(&test_ctx().tenant()))
                .unwrap()
                .is_empty()
        );
    }

    /// A caller denied access to the tenant cannot leave a stored template
    /// proposal.
    #[test]
    fn a_caller_the_tenant_turns_away_is_refused() {
        let store = Arc::new(FakeTaskTemplateStore::default());
        let ports = ProposePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
            ..ports_over(&store)
        };

        let result = propose(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            request(IntentEnvelope::new([ActionClass::Read])),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            block_on(store.list(&test_ctx().tenant()))
                .unwrap()
                .is_empty()
        );
    }
}
