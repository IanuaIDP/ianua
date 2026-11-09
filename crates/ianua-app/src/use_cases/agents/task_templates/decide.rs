//! Decide task template: a second person approves a template, or a person
//! retires one.
//!
//! Who decides is the person signed in. The domain refuses the proposer
//! approving their own template, an approver who could not hand out what
//! the template grants, and a retirement by anyone but the proposer or
//! someone allowed to delegate to agents.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::task_template::TaskTemplate;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::TaskTemplateId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::TaskTemplateStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::owned_task_template;

/// What a person decides about a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateDecision {
    /// Approve it, as a different person than proposed it.
    Approve,
    /// Withdraw it; nothing new can be granted under it.
    Retire,
}

/// Which template to decide on, and the decision.
pub struct DecideRequest {
    /// The template the decision applies to.
    pub template_id: TaskTemplateId,
    /// What the caller decides.
    pub decision: TemplateDecision,
}

/// The ports [`DecideUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DecidePorts {
    /// Keeps templates.
    pub template_store: Arc<dyn TaskTemplateStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Approves or retires a task template of the caller's tenant.
pub struct DecideUseCase {
    ports: DecidePorts,
}

impl DecideUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DecidePorts) -> Self {
        Self { ports }
    }
}

impl Command for DecideUseCase {
    type Caller = CallerContext;
    type Input = DecideRequest;
    type Output = Result<TaskTemplate<ResolvedTenant>, AppError>;

    /// Applies the caller's decision to the template.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such template, or the
    ///   caller neither proposed it nor may view agents, so that it answers
    ///   as one that does not exist.
    /// - `AppError::Forbidden` when the approver could not hand out what
    ///   the template grants, or the person retiring it neither proposed it
    ///   nor may delegate to agents.
    /// - `AppError::Domain` when the proposer approves their own template,
    ///   or the template is not in a state the decision applies to.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DecideRequest,
    ) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.template_store.as_ref();
        let mut template =
            owned_task_template(store, &tenant, &request.template_id, &control).await?;
        decide(&mut template, &control, request.decision).map_err(AppError::from_domain)?;
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

/// Applies `decision` to `template` as the person `control` names.
fn decide(
    template: &mut TaskTemplate<ResolvedTenant>,
    control: &AgentControl<'_>,
    decision: TemplateDecision,
) -> Result<(), DomainError> {
    match decision {
        TemplateDecision::Approve => template.approve(control),
        TemplateDecision::Retire => template.retire(control),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::task_template::TemplateStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeTaskTemplateStore, caller_person, someone_else, template_proposed_by, templates_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant keeping one template, and its id.
    fn kept(
        template: TaskTemplate<ResolvedTenant>,
    ) -> (Arc<FakeTaskTemplateStore>, TaskTemplateId) {
        let id = *template.id();
        (Arc::new(templates_holding([template])), id)
    }

    fn ports_over(store: &Arc<FakeTaskTemplateStore>) -> DecidePorts {
        DecidePorts {
            template_store: store.clone(),
            ..DecidePorts::fakes()
        }
    }

    fn decide(
        ports: DecidePorts,
        template_id: TaskTemplateId,
        decision: TemplateDecision,
    ) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
        block_on(DecideUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            DecideRequest {
                template_id,
                decision,
            },
        ))
    }

    fn status_of(store: &FakeTaskTemplateStore, id: &TaskTemplateId) -> TemplateStatus {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Bob proposed the monthly reports template. Ann, a second person,
    /// approves it, and the approval is kept.
    #[test]
    fn a_second_person_approves() {
        let (store, id) = kept(template_proposed_by(someone_else()));

        let template = decide(ports_over(&store), id, TemplateDecision::Approve).unwrap();

        assert_eq!(template.status(), TemplateStatus::Approved);
        assert_eq!(status_of(&store, &id), TemplateStatus::Approved);
    }

    /// Self-approval is refused and leaves the stored template proposed,
    /// awaiting another person's decision.
    #[test]
    fn the_proposer_cannot_approve_their_own() {
        let (store, id) = kept(template_proposed_by(caller_person()));

        let result = decide(ports_over(&store), id, TemplateDecision::Approve);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(status_of(&store, &id), TemplateStatus::Proposed);
    }

    /// An approver without the template's route rights is refused, and the
    /// template remains proposed.
    #[test]
    fn an_approver_who_could_not_hand_out_the_ceiling_is_refused() {
        let (store, id) = kept(template_proposed_by(someone_else()));
        let ports = DecidePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = decide(ports, id, TemplateDecision::Approve);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store, &id), TemplateStatus::Proposed);
    }

    /// Ann retires her own template. Retiring it again is refused.
    #[test]
    fn retiring_twice_is_refused() {
        let (store, id) = kept(template_proposed_by(caller_person()));
        decide(ports_over(&store), id, TemplateDecision::Retire).unwrap();

        let again = decide(ports_over(&store), id, TemplateDecision::Retire);

        assert!(matches!(
            again,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
    }

    /// The view right alone cannot retire another person's template;
    /// its stored status remains proposed.
    #[test]
    fn a_caller_who_may_not_delegate_cannot_retire_anothers_template() {
        let (store, id) = kept(template_proposed_by(someone_else()));
        let ports = DecidePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = decide(ports, id, TemplateDecision::Retire);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store, &id), TemplateStatus::Proposed);
    }

    /// A caller without template access gets the same missing response for
    /// a real and unknown id, and the real template remains proposed.
    #[test]
    fn a_caller_who_may_not_see_templates_learns_nothing_of_an_id() {
        let (store, id) = kept(template_proposed_by(someone_else()));
        let nothing = || DecidePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&store)
        };

        let real = decide(nothing(), id, TemplateDecision::Retire);
        let unknown = decide(nothing(), TaskTemplateId::new(), TemplateDecision::Retire);

        assert!(matches!(real, Err(AppError::NotFound(_))));
        assert_eq!(
            real.err().map(|error| error.to_string()),
            unknown.err().map(|error| error.to_string())
        );
        assert_eq!(status_of(&store, &id), TemplateStatus::Proposed);
    }

    /// Ann decides on a template the tenant does not have. It is not found.
    #[test]
    fn an_unknown_template_is_not_found() {
        let store = Arc::new(FakeTaskTemplateStore::default());

        let result = decide(
            ports_over(&store),
            TaskTemplateId::new(),
            TemplateDecision::Approve,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot approve a template, which remains proposed.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = kept(template_proposed_by(someone_else()));
        let ports = DecidePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = decide(ports, id, TemplateDecision::Approve);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status_of(&store, &id), TemplateStatus::Proposed);
    }
}
