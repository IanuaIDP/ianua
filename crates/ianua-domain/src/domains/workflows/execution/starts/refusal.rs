//! Why a workflow may not start for the person it would act for.

use crate::domains::workflows::design::workflow::{Hold, Publication, Workflow};
use crate::domains::workflows::events::WorkflowStartRefused;
use crate::domains::workflows::execution::{Cause, StartExecutionParams};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{SavedFor, scoped};

/// Why an execution may not start for the person it would act for.
///
/// When a schedule, webhook or event is refused for one of these, the app
/// records it with [`recorded`](Self::recorded). Ann publishes the nightly
/// payroll run and then leaves. Its schedule keeps firing and is refused
/// each night. Without the record, nobody knows payroll stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartRefusal {
    /// The person it would act for may not run workflows now.
    PersonMayNotRun,
    /// A schedule, webhook or event would start it for someone other than
    /// the person who published it. Nobody else chose to have it act for
    /// them. A person starting it by hand acts for themselves.
    NotThePublisher,
    /// An event started it that the person it acts for may no longer see.
    /// Sam published a workflow on key events while he could read them.
    /// After he loses that right, the next key event does not reach his
    /// steps.
    EventNotVisible,
    /// The version is held: an account it acts through can no longer be
    /// used for its publisher, until a next version picks a usable one.
    NeedsAccount,
}

impl StartRefusal {
    /// Why `params` may not start `workflow`, or `None` when the person it
    /// acts for may have it run.
    #[must_use]
    pub fn of<T: TenantScope>(
        workflow: &Workflow<T>,
        params: &StartExecutionParams,
    ) -> Option<Self> {
        let person = params.acting_for.person();
        if !params.acting_for.may_run_for(person) {
            return Some(Self::PersonMayNotRun);
        }
        let for_its_publisher = match workflow.publication() {
            Publication::PublishedBy(publisher) => publisher == person,
            Publication::Unpublished => false,
        };
        if !params.cause.is_by_a_person() && !for_its_publisher {
            return Some(Self::NotThePublisher);
        }
        if workflow.hold() != &Hold::Clear {
            return Some(Self::NeedsAccount);
        }
        let Cause::Event { event, .. } = params.cause else {
            return None;
        };
        if !crate::types::EventVisibility::may_see(&params.acting_for, &event) {
            return Some(Self::EventNotVisible);
        }
        None
    }

    /// The record that `workflow`, fired by `cause`, did not start for the
    /// person who published it, for this reason, as a tenant event of the
    /// tenant `saved_for` names.
    ///
    /// No aggregate raises it: nothing is saved when a start is refused,
    /// and the version is only read. It is marked at the depth the start
    /// would have run at. A workflow it sets off continues that chain, so
    /// refusals cannot start each other without end.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when `workflow` was never published, so
    ///   nobody's start was refused.
    /// - [`DomainError::Forbidden`] when `cause` came from a chain of
    ///   executions already as long as any may be.
    pub fn recorded<T: TenantScope>(
        self,
        saved_for: &impl SavedFor,
        workflow: &Workflow<T>,
        cause: Cause,
    ) -> Result<DomainEvent, DomainError> {
        let Publication::PublishedBy(publisher) = workflow.publication() else {
            return Err(DomainError::conflict(message!(
                "workflows-the-workflow-was-never-published",
                "the workflow was never published"
            )));
        };
        let depth = cause.chain_depth()?;
        let refused = WorkflowStartRefused {
            version: workflow.version_ref(),
            acting_for: publisher.principal(),
            cause: cause.as_str(),
            refusal: self,
            occurred_at: crate::shared::clock::now(),
        };
        Ok(scoped(saved_for.saved_for(), refused).from_execution(depth))
    }

    /// The stored and audited name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PersonMayNotRun => "person_may_not_run",
            Self::NotThePublisher => "not_the_publisher",
            Self::EventNotVisible => "event_not_visible",
            Self::NeedsAccount => "needs_account",
        }
    }
}

impl From<StartRefusal> for DomainError {
    fn from(refusal: StartRefusal) -> Self {
        let reason = match refusal {
            StartRefusal::PersonMayNotRun => {
                "the person this would act for may not run workflows now"
            }
            StartRefusal::NotThePublisher => {
                "what its trigger starts acts for the person who published it"
            }
            StartRefusal::EventNotVisible => {
                "the person this acts for may not see the event that started it"
            }
            StartRefusal::NeedsAccount => {
                "this workflow needs an account; pick a usable account and publish it again"
            }
        };
        DomainError::forbidden(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::execution::tests::fixtures::{draft, published, transform};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::SlugLimits;
    use crate::shared::events::chain::{ChainDepth, EventOrigin};
    use crate::types::{TenantId, TenantSlug};

    fn acme() -> ResolvedTenant {
        ResolvedTenant::new(
            TenantId::new(),
            TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
        )
    }

    /// Ann published the nightly digest and then left, so its schedule is
    /// refused. The record names Acme, says why, and is marked at the depth
    /// the start would have run at.
    #[test]
    fn a_refused_start_is_recorded_for_the_tenant_at_its_depth() {
        let acme = acme();
        let workflow = published(vec![transform("tidy", Join::All)], Vec::new());

        let event = StartRefusal::PersonMayNotRun
            .recorded(&acme, &workflow, Cause::Schedule)
            .unwrap();

        assert_eq!(event.event_type().to_string(), "workflows.start_refused");
        assert_eq!(event.tenant_id(), Some(acme.tenant_id()));
        assert_eq!(event.payload().get("refusal"), Some("person_may_not_run"));
        assert_eq!(event.origin(), EventOrigin::Execution(ChainDepth::FIRST));
    }

    /// A draft nobody published has no publisher whose start was refused,
    /// so no record is made of it.
    #[test]
    fn a_version_never_published_has_no_refusal_to_record() {
        let workflow = draft(vec![transform("tidy", Join::All)], Vec::new());

        let recorded = StartRefusal::NotThePublisher.recorded(&acme(), &workflow, Cause::Webhook);

        assert!(matches!(recorded, Err(DomainError::Conflict(_))));
    }
}
