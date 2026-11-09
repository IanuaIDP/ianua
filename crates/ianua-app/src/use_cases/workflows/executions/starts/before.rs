//! Deciding a change before it happens: every published "before" workflow
//! on the change starts for its publisher, handed what the change would
//! do, and the change waits for each one's Allow or Refuse.
//!
//! Ann's rule refuses admins made on a weekend. Bob gives Pat an admin
//! role on a Saturday: the role waits while Ann's workflow runs, and is
//! refused when it ends in Refuse. Deny by default: a rule that refuses,
//! ends without deciding, may not start, or does not answer within
//! [`DECIDE_WITHIN`], refuses the change. With no rule on the change, it
//! goes ahead as before.
//!
//! Each rule's run is kept in a unit of its own before the change waits.
//! The change's request keeps the rest of its writes until it answers, and
//! a run kept with them would not reach the worker until then, so no rule
//! could ever decide in time. A run that started stays on the record
//! whether the change then goes ahead or not: it did run.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::{Cause, ExecutionStatus};
use ianua_domain::domains::workflows::triggers::before::{GuardedChange, Verdict};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::WorkflowExecutionId;
use time::Duration;

use crate::auditor::RequestAuditor;
use crate::ports::runtime::Pause;
use crate::ports::workflows::ChangeGuard;
use crate::services::kept_together::kept_apart;
use crate::tenancy::ScopedTenant;
use crate::use_cases::workflows::executions::starts::on_trigger::{
    TriggerStartPorts, TriggeredStart,
};
use crate::use_cases::workflows::executions::starts::triggered::{
    Admission, Firing, started_for_publisher,
};

/// How long a change waits for its rules to decide.
pub(crate) const DECIDE_WITHIN: Duration = Duration::seconds(10);

/// How often a waiting change looks at its rules' runs.
const LOOK_EVERY: Duration = Duration::milliseconds(200);

/// Decides changes through the tenant's published "before" workflows.
pub struct DecideBeforeUseCase {
    starts: TriggerStartPorts,
    pause: Arc<dyn Pause>,
}

/// What starting a change's rules came to.
enum Started {
    /// These runs started and are deciding.
    Deciding(Vec<WorkflowExecutionId>),
    /// A rule may not start, which refuses the change.
    Refused,
}

impl DecideBeforeUseCase {
    /// Starts rules through `starts`, waiting for them on `pause`.
    #[must_use]
    pub fn new(starts: TriggerStartPorts, pause: Arc<dyn Pause>) -> Self {
        Self { starts, pause }
    }

    /// Starts every published rule on `change`, handed `proposed`.
    async fn start_rules(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        change: GuardedChange,
        proposed: &FlowData,
    ) -> Result<Started, DomainError> {
        let rules = self
            .starts
            .workflows
            .list_published_before(tenant, change)
            .await?;
        let mut runs = Vec::new();
        for rule in &rules {
            let firing = Firing {
                cause: Cause::Before { change },
                admission: Admission::Trigger,
                input: proposed.clone(),
                exposure: DataClassLevel::Internal,
            };
            let start = started_for_publisher(&self.starts, tenant, auditor, rule, firing);
            let started = kept_apart(self.starts.unit_of_work.as_ref(), start)
                .await
                .map_err(DomainError::infra)?;
            let TriggeredStart::Started(run) = started else {
                return Ok(Started::Refused);
            };
            runs.push(run);
        }
        Ok(Started::Deciding(runs))
    }

    /// What `runs` decide: Allow once every one allowed, Refuse when one
    /// refuses, ends undecided, or [`DECIDE_WITHIN`] is up first.
    async fn verdict_of(
        &self,
        tenant: &ScopedTenant,
        mut runs: Vec<WorkflowExecutionId>,
    ) -> Result<Verdict, DomainError> {
        let deadline = clock::now().saturating_add(DECIDE_WITHIN);
        loop {
            let Some(waiting) = self.undecided(tenant, runs).await? else {
                return Ok(Verdict::Refuse);
            };
            if waiting.is_empty() {
                return Ok(Verdict::Allow);
            }
            if clock::now() >= deadline {
                return Ok(Verdict::Refuse);
            }
            self.pause.hold(LOOK_EVERY).await;
            runs = waiting;
        }
    }

    /// The runs of `runs` still to decide, or `None` once one refused or
    /// ended undecided.
    async fn undecided(
        &self,
        tenant: &ScopedTenant,
        runs: Vec<WorkflowExecutionId>,
    ) -> Result<Option<Vec<WorkflowExecutionId>>, DomainError> {
        let mut waiting = Vec::new();
        for run in runs {
            let Some(execution) = self.starts.executions.find_by_id(tenant, &run).await? else {
                return Ok(None);
            };
            match (execution.verdict(), execution.status()) {
                (Some(Verdict::Allow), _) => {}
                (None, ExecutionStatus::Running) => waiting.push(run),
                (Some(Verdict::Refuse) | None, _) => return Ok(None),
            }
        }
        Ok(Some(waiting))
    }
}

#[async_trait]
impl ChangeGuard for DecideBeforeUseCase {
    async fn decide(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        change: GuardedChange,
        proposed: FlowData,
    ) -> Result<Verdict, DomainError> {
        match self.start_rules(tenant, auditor, change, &proposed).await? {
            Started::Deciding(runs) => self.verdict_of(tenant, runs).await,
            Started::Refused => Ok(Verdict::Refuse),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::triggers::Trigger;
    use ianua_domain::types::Human;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, accounts_now_of, allow_step, draft_on,
        person, published_by,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// A pause that moves the frozen clock on by each wait, so the deadline
    /// passes without anyone waiting for it.
    struct ClockPause;

    #[async_trait]
    impl Pause for ClockPause {
        async fn hold(&self, wait: Duration) {
            let _ = clock::reach(clock::now().saturating_add(wait));
        }
    }

    /// Ann's rule on admin roles, published by her, allowing every one.
    fn admin_rule(ann: &Human) -> FakeWorkflowStore {
        let draft = draft_on(
            ann,
            vec![allow_step("allow")],
            Vec::new(),
            Trigger::Before(GuardedChange::AdminGiven),
        );
        FakeWorkflowStore::holding(&[published_by(ann, draft)])
    }

    /// Where the rules' runs are kept, and how.
    struct RunStores {
        executions: Arc<FakeWorkflowExecutionStore>,
        unit: Arc<RecordingUnitOfWork>,
    }

    impl RunStores {
        fn new() -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                unit: Arc::new(RecordingUnitOfWork::default()),
            }
        }
    }

    /// What the rules in `workflows`, published by `ann`, decide about an
    /// admin role, their runs kept as `keeping` says.
    fn decide(ann: &Human, workflows: FakeWorkflowStore, keeping: &RunStores) -> Verdict {
        let starts = TriggerStartPorts {
            workflows: Arc::new(workflows),
            executions: keeping.executions.clone(),
            accounts_now: Arc::new(accounts_now_of(&[(ann, SystemPermission::all())])),
            unit_of_work: keeping.unit.clone(),
            ..TriggerStartPorts::fakes()
        };
        let guard = DecideBeforeUseCase::new(starts, Arc::new(ClockPause));
        let _frozen = clock::freeze(clock::now());
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(guard.decide(
            &test_ctx().tenant(),
            &auditor,
            GuardedChange::AdminGiven,
            FlowData::null(),
        ))
        .unwrap()
    }

    /// No rule is published on admin roles. Tess gives one, and it goes
    /// ahead as before.
    #[test]
    fn with_no_rule_the_change_goes_ahead() {
        let ann = person("ann@corp.test");

        let verdict = decide(&ann, FakeWorkflowStore::default(), &RunStores::new());

        assert_eq!(verdict, Verdict::Allow);
    }

    /// Ann's rule starts for her, but no worker ever drives its run. Ten
    /// seconds pass without an answer, and Tess's change is refused.
    #[test]
    fn a_rule_that_never_answers_refuses_the_change() {
        let ann = person("ann@corp.test");
        let keeping = RunStores::new();

        let verdict = decide(&ann, admin_rule(&ann), &keeping);

        assert_eq!(verdict, Verdict::Refuse);
        assert_eq!(keeping.executions.all().len(), 1);
    }

    /// The rule's run is kept in a unit of its own and committed before the
    /// change waits, so a worker can see it while Tess's request waits.
    #[test]
    fn the_rules_run_is_kept_before_the_change_waits() {
        let ann = person("ann@corp.test");
        let keeping = RunStores::new();

        decide(&ann, admin_rule(&ann), &keeping);

        assert_eq!(keeping.unit.apart(), [Settlement::Commit]);
        assert_eq!(keeping.executions.all().len(), 1);
    }
}
