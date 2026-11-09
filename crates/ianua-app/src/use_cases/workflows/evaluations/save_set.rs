//! Save evaluation set: an author saves a workflow's sample cases, and
//! whether publishing its draft needs the last evaluation to pass.
//!
//! A workflow has one set, so saving replaces the one saved before. It
//! adds nothing the plan counts: a set belongs to its workflow, which the
//! plan already counts, and holds at most a fixed number of cases.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::evaluation::case::EvaluationCase;
use ianua_domain::domains::workflows::evaluation::set::{EvaluationSet, PublishGate, SetParams};
use ianua_domain::domains::workflows::evaluation::view::SetView;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{EvaluationSetStore, WorkflowStore};
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::designed_version;

/// The set an author saves for a workflow.
pub struct SaveSetRequest {
    /// The workflow whose versions the cases try.
    pub workflow_id: WorkflowId,
    /// The cases, each named once.
    pub cases: Vec<EvaluationCase>,
    /// Whether publishing needs the draft's last evaluation to pass.
    pub gate: PublishGate,
}

/// The ports [`SaveSetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SaveSetPorts {
    /// The versions, for the workflow the set belongs to.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Keeps the sets.
    pub evaluation_sets: Arc<dyn EvaluationSetStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Saves workflows' evaluation sets.
pub struct SaveSetUseCase {
    ports: SaveSetPorts,
}

impl SaveSetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SaveSetPorts) -> Self {
        Self { ports }
    }

    /// Saves `set` in the tenant `ctx` acts in, then records its change as
    /// the person `ctx` names.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        set: &mut EvaluationSet<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        self.ports
            .evaluation_sets
            .save(&tenant, set)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), set.take_events(&tenant))
            .await
            .or_internal()
    }
}

impl Command for SaveSetUseCase {
    type Caller = CallerContext;
    type Input = SaveSetRequest;
    type Output = Result<SetView<ResolvedTenant>, AppError>;

    /// Saves `request`'s cases and gate as the workflow's set, for the
    /// person `ctx` names, and hands it back as they may read it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing tenant workflow.
    /// - `AppError::Forbidden` when the caller may not edit workflows.
    /// - `AppError::Domain` for too many cases, two of one name, too much data, or a gate with no case.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SaveSetRequest,
    ) -> Result<SetView<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let workflow = designed_version(
            self.ports.workflows.as_ref(),
            &tenant,
            &request.workflow_id,
            None,
        )
        .await?;
        let saved = self
            .ports
            .evaluation_sets
            .find(&tenant, &request.workflow_id)
            .await
            .or_internal()?;
        let params = SetParams {
            cases: request.cases,
            gate: request.gate,
        };
        let mut set = edited(saved, &workflow, &control, params).map_err(AppError::from_domain)?;
        self.keep(ctx, auditor, &mut set).await?;
        Ok(set.seen_by_author(control))
    }
}

/// `saved` with its cases and gate replaced by `params`, or the
/// workflow's first set when none was saved.
fn edited(
    saved: Option<EvaluationSet<ResolvedTenant>>,
    workflow: &Workflow<ResolvedTenant>,
    control: &WorkflowControl<'_>,
    params: SetParams,
) -> Result<EvaluationSet<ResolvedTenant>, DomainError> {
    let Some(mut set) = saved else {
        return EvaluationSet::create(workflow, control, params);
    };
    set.replace(workflow, control, params)?;
    Ok(set)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeEvaluationSetStore, FakeWorkflowStore, draft_by, parcel_case, person, tidy_step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann's draft, and what saves for it wrote and recorded.
    struct Saving {
        draft: Workflow<ResolvedTenant>,
        sets: Arc<FakeEvaluationSetStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Saving {
        fn new() -> Self {
            Self {
                draft: draft_by(
                    &person("ann@corp.test"),
                    vec![tidy_step("tidy")],
                    Vec::new(),
                ),
                sets: Arc::new(FakeEvaluationSetStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn save(
            &self,
            holds: &[SystemPermission],
            cases: Vec<EvaluationCase>,
        ) -> Result<SetView<ResolvedTenant>, AppError> {
            let use_case = SaveSetUseCase::new(SaveSetPorts {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(
                    &self.draft,
                ))),
                evaluation_sets: self.sets.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
            });
            let request = SaveSetRequest {
                workflow_id: *self.draft.id(),
                cases,
                gate: PublishGate::Off,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }
    }

    const EDITS: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Update)];

    /// Ann saves two cases, then saves again with one. The second save
    /// replaces the first, and each is recorded.
    #[test]
    fn saving_again_replaces_the_cases() {
        let saving = Saving::new();

        saving
            .save(&EDITS, vec![parcel_case("late"), parcel_case("lost")])
            .unwrap();
        saving.save(&EDITS, vec![parcel_case("late")]).unwrap();

        let kept = saving.sets.stored(saving.draft.id()).unwrap();
        assert_eq!(kept.cases().len(), 1);
        assert_eq!(
            saving.sink.records.lock().unwrap().as_slice(),
            [
                "workflows.evaluation_set_saved",
                "workflows.evaluation_set_saved"
            ]
        );
    }

    /// Someone who may only view workflows cannot save cases; nothing is
    /// kept.
    #[test]
    fn saving_needs_the_right_to_edit() {
        let saving = Saving::new();
        let views = [SystemPermission::Workflows(WorkflowAction::View)];

        let refused = saving.save(&views, vec![parcel_case("late")]);

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(saving.sets.stored(saving.draft.id()).is_none());
    }
}
