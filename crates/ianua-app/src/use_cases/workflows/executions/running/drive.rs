//! Drive execution: the worker that takes an execution as far as it goes.
//!
//! A wake-up hands it an execution. It claims it, so delivering the
//! wake-up twice drives it once, then moves it on one step at a time:
//! - past its run limit, it is expired;
//! - a decision window that closed lapses its approval, and a wait whose
//!   time came ends;
//! - each ready step starts: an approval is asked for, a wait begins, an
//!   agent run is started and handed to the agents' worker, an action's
//!   call is made through its integration, a loop starts its first
//!   passes, each an execution of its own, kept in the same unit of work,
//!   and a guardrail checks its text against the tenant's classification
//!   rules as they are read now.
//!
//! Before an agent run or an action, what the person the execution acts
//! for holds is worked out again from their account as it stands, and so
//! is whether an account's owner may still lend it. An agent run counts
//! toward the tenant's plan: while the plan has no room for another run in
//! flight, the step is put off and tried again a minute later, never
//! failed. The domain decides
//! from those whether the step may go ahead. An action's call is made
//! outside any unit of work, and its outcome is settled on the execution
//! read back afresh; a Protected apps step's call carries a pass made for
//! it alone. Each change is kept with its record, the agent runs
//! an ended execution gave up are ordered to stop, and the worker is woken
//! again when the next step falls due.

use std::sync::Arc;

use ianua_domain::types::WorkflowExecutionId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::PlanLimitsSource;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{ExecutionLease, WorkflowExecutionStore, WorkingCalendar};
use crate::services::account_now::AccountsNow;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::runs::control::stopping::StopPorts;
use crate::use_cases::workflows::executions::driving::{
    ActionPorts, AgentStepPorts, CompanyPorts, Driving, GuardrailPorts, MemoryPorts, drive,
};
use crate::use_cases::workflows::executions::running::Wakeups;

/// The ports [`DriveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DrivePorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// What memory steps keep texts in and search through.
    pub memory: MemoryPorts,
    /// What guardrail steps read the tenant's classification rules and
    /// hide fields through.
    pub guardrail: GuardrailPorts,
    /// What company steps act on the tenant through.
    pub company: CompanyPorts,
    /// What agent run steps start their runs through.
    pub agent_steps: AgentStepPorts,
    /// What action steps make their calls through.
    pub actions: ActionPorts,
    /// Keeps one worker on an execution at a time.
    pub lease: Arc<dyn ExecutionLease>,
    /// Drives an execution again when its next step falls due.
    pub wakeups: Wakeups,
    /// Stops the agent runs an execution gives up, should it end, and
    /// settles a paused one at once.
    pub run_stops: StopPorts,
    /// What the people a workflow acts for, and account owners, hold now.
    pub accounts_now: Arc<AccountsNow>,
    /// The tenant's plan, which caps the agent runs in flight and the
    /// texts memories keep, and which a company step acts under.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// Keeps each change and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// When working hours a wait step waits for next begin.
    pub calendar: Arc<dyn WorkingCalendar>,
}

/// Drives executions on a worker.
pub struct DriveUseCase {
    ports: DrivePorts,
}

impl DriveUseCase {
    /// A use case driving through `ports`.
    #[must_use]
    pub fn new(ports: DrivePorts) -> Self {
        Self { ports }
    }
}

impl Command for DriveUseCase {
    type Caller = ScopedTenant;
    type Input = WorkflowExecutionId;
    type Output = Result<(), AppError>;

    /// Takes the tenant's execution `id` as far as it goes now.
    ///
    /// A missing or ended execution, or one another worker holds, is left
    /// alone; the wake-up came round again or raced a cancel.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` or `AppError::Conflict` when the execution
    ///   refuses a change the worker read as due, as when it ran out of
    ///   time meanwhile. The next wake-up picks it up.
    /// - `AppError::Internal` when a store, the lease, the catalog or the
    ///   audit trail fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        id: WorkflowExecutionId,
    ) -> Result<(), AppError> {
        if !self.ports.lease.try_claim(&id).await.or_internal()? {
            return Ok(());
        }
        let driving = Driving {
            ports: &self.ports,
            tenant,
            auditor,
        };
        let driven = drive(&driving, &id).await;
        self.ports.lease.release(&id).await;
        driven
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use ianua_domain::domains::audit::builder::ActedThrough;
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::organization::billing::plan::PlanLimits;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use ianua_domain::domains::routing::stream::{
        LoginTls, LoginUser, StreamWorkflowUse, WorkflowLogin,
    };
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::design::node::Node;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
    use ianua_domain::domains::workflows::execution::step::{
        ActionOutcome, Attempt, StepFailure, StepRefusal, StepState, Underway,
    };
    use ianua_domain::domains::workflows::execution::{
        ExecutionStatus, RUN_LIMIT_PAUSE, WorkflowExecution,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{
        ActionClass, AgentId, Human, HumanAccount, OrganizationId, RouteId, SandboxVersionId,
        SealedSecret, StreamRouteId, UntrustedText,
    };

    use super::*;
    use crate::context::{CallerIdentity, Credential};
    use crate::ports::authentication::{PassReach, SealedAt};
    use crate::ports::limits::{LimitEnforcer, ResourceKind};
    use crate::ports::routing::StreamRouteStore as _;
    use crate::ports::runtime::UnitWork;
    use crate::ports::workflows::RunPassGrant;
    use crate::test_support::agents::{FakeAgentStore, FakeRunStore};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::routing::{
        FakeStreamRouteLogins, FakeStreamRouteStore, routing_admin, tunnel_on,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::workflows::{
        FakeActionRunner, FakeCompanySteps, FakeExecutionLease, FakeIntegrationAccountStore,
        FakeIntegrationCatalog, FakeRunPasses, FakeSandboxVersionStore, FakeWorkflowExecutionStore,
        QueuedWakeups, SHEETS_CREDENTIAL, account_credential_place, accounts_now_of, agent_step,
        app_read, app_step, append_row, append_step, approval_step, approval_workflow, code_step,
        data_query, data_step, draft_by, every_item_loop_step, held_version_of, listing_step,
        loop_step, next, person, published_by, sheets_account, sign_out, sign_out_step, started_by,
        step, tidy_step, wait_step,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx,
    };
    use crate::use_cases::agents::runs::{DRIVE_RUN_JOB, RunDrives};
    use crate::use_cases::routing::stream_routes::set_workflow_use::stream_route_login_place;

    const RUNS: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Run)];
    const LENDS: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::Run),
        SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
    ];

    /// The stores a worker writes to, and what it recorded.
    struct Worker {
        executions: Arc<FakeWorkflowExecutionStore>,
        wakeups: Arc<QueuedWakeups>,
        sink: Arc<FakeEventDispatcher>,
        id: WorkflowExecutionId,
    }

    impl Worker {
        fn over(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
            Self {
                executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
                wakeups: Arc::new(QueuedWakeups::none()),
                sink: Arc::new(FakeEventDispatcher::new()),
                id: *execution.id(),
            }
        }

        fn ports(&self) -> DrivePorts {
            DrivePorts {
                executions: self.executions.clone(),
                wakeups: self.wakeups.wakeups(),
                ..DrivePorts::fakes()
            }
        }

        fn drive(&self, ports: DrivePorts) {
            let use_case = DriveUseCase::new(ports);
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                self.id,
            ))
            .unwrap();
        }

        fn stored(&self) -> WorkflowExecution<ResolvedTenant> {
            self.executions.stored(&self.id).unwrap()
        }

        fn state_of(&self, name: &str) -> StepState {
            self.stored().step(&step(name)).unwrap().clone()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn run_of(author: &Human, acting_for: &Human, nodes: Vec<Node>) -> Worker {
        let workflow = published_by(author, draft_by(author, nodes, Vec::new()));
        Worker::over(&started_by(acting_for, &workflow))
    }

    /// A workflow whose one step appends to a sheet through `account`.
    fn appending(acting_for: &Human, account: &IntegrationAccount<ResolvedTenant>) -> Worker {
        let author = person("author@corp.test");
        run_of(
            &author,
            acting_for,
            vec![append_step("append", *account.id())],
        )
    }

    /// The ports a worker makes `account`'s call with, for the people in
    /// `people`, with the catalog offering "append row" and the call coming
    /// to `outcome`.
    fn calling(
        worker: &Worker,
        account: &IntegrationAccount<ResolvedTenant>,
        people: &[(&Human, &[SystemPermission])],
        runner: Arc<FakeActionRunner>,
    ) -> DrivePorts {
        DrivePorts {
            accounts_now: Arc::new(accounts_now_of(people)),
            actions: ActionPorts {
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
                    ActionClass::Write,
                )])),
                accounts: Arc::new(FakeIntegrationAccountStore::holding(account)),
                action_runner: runner,
                ..ActionPorts::fakes()
            },
            ..worker.ports()
        }
    }

    /// A completed action with no output and internal exposure.
    fn succeeded() -> ActionOutcome {
        ActionOutcome::Succeeded {
            output: FlowData::null(),
            exposure: DataClassLevel::Internal,
        }
    }

    /// An integration that accepts each append operation.
    fn appended() -> Arc<FakeActionRunner> {
        Arc::new(FakeActionRunner::answering(succeeded()))
    }

    /// An integration that accepts the action and returns a renewed account credential.
    fn appended_with_renewal(credential: SealedSecret) -> Arc<FakeActionRunner> {
        Arc::new(FakeActionRunner::answering(succeeded()).renewing(credential))
    }

    fn refused(refusal: StepRefusal) -> StepState {
        StepState::Failed(StepFailure::Refused(refusal))
    }

    /// Ann's run reaches a sign-off. The worker asks for it, and comes back
    /// when its hour is up.
    #[test]
    fn an_approval_step_is_asked_for() {
        let ann = person("ann@corp.test");
        let worker = Worker::over(&started_by(
            &ann,
            &approval_workflow(&ann, ActionClass::Write),
        ));

        worker.drive(worker.ports());

        let StepState::Running {
            underway: Underway::Approval(wait),
            ..
        } = worker.state_of("check")
        else {
            panic!("the approval was not asked for");
        };
        assert_eq!(worker.wakeups.last_for(&worker.id), Some(wait.closes_at));
        assert_eq!(worker.records(), ["workflows.step_started"]);
    }

    /// Starts a two-issue workflow whose loop waits for approval on each pass.
    fn looping_for(ann: &Human) -> Worker {
        let workflow = published_by(
            ann,
            draft_by(
                ann,
                vec![
                    listing_step("search", &["a", "b"]),
                    loop_step(
                        "each",
                        "search.issues",
                        vec![approval_step("check", ActionClass::Write)],
                    ),
                ],
                vec![next("search", "each")],
            ),
        );
        Worker::over(&started_by(ann, &workflow))
    }

    /// Ann's run lists two issues and loops over them, one at a time, each
    /// pass waiting for a sign-off. The worker starts the loop and its first
    /// pass, kept as an execution of its own, and records that the pass
    /// started, not that a run did.
    #[test]
    fn a_loop_starts_its_first_pass_as_an_execution_of_its_own() {
        let ann = person("ann@corp.test");
        let worker = looping_for(&ann);

        worker.drive(worker.ports());

        let passes = worker.executions.passes_of(&worker.id);
        assert!(matches!(
            worker.state_of("each"),
            StepState::Running {
                underway: Underway::Loop(_),
                ..
            }
        ));
        assert_eq!(passes.len(), 1);
        assert_eq!(passes[0].acting_for(), &ann);
        assert!(
            worker
                .records()
                .contains(&"workflows.pass_started".to_owned())
        );
        assert!(
            !worker
                .records()
                .contains(&"workflows.execution_started".to_owned())
        );
    }

    /// Ann's loop asks one approval for both issues as its first step. The
    /// worker starts the loop, keeps no pass, and comes back when the
    /// approval's hour is up.
    #[test]
    fn a_loop_asking_for_every_item_waits_with_no_pass() {
        let ann = person("ann@corp.test");
        let workflow = published_by(
            &ann,
            draft_by(
                &ann,
                vec![
                    listing_step("search", &["a", "b"]),
                    every_item_loop_step("each", "search.issues", ActionClass::Write),
                ],
                vec![next("search", "each")],
            ),
        );
        let worker = Worker::over(&started_by(&ann, &workflow));

        worker.drive(worker.ports());

        let StepState::Running {
            underway: Underway::Loop(progress),
            ..
        } = worker.state_of("each")
        else {
            panic!("the loop did not start");
        };
        let closes_at = progress.approval().waiting().map(|wait| wait.closes_at);
        assert!(closes_at.is_some());
        assert!(worker.executions.passes_of(&worker.id).is_empty());
        assert_eq!(worker.wakeups.last_for(&worker.id), closes_at);
    }

    /// Ann's run comes to its code step. The worker starts it, waiting on
    /// one run, and queues exactly that run in the same keep.
    #[test]
    fn a_code_step_starts_and_queues_its_one_run() {
        let ann = person("ann@corp.test");
        let worker = run_of(
            &ann,
            &ann,
            vec![code_step("clean", SandboxVersionId::new())],
        );

        worker.drive(DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(&ann, &RUNS)])),
            ..worker.ports()
        });

        let StepState::Running {
            underway: Underway::Code(work),
            ..
        } = worker.state_of("clean")
        else {
            panic!("the code step did not start");
        };
        assert_eq!(worker.wakeups.code_runs(), [work.run_id]);
    }

    /// A code step for a person holding only view rights fails for missing
    /// authority and queues no code run.
    #[test]
    fn no_code_runs_for_a_person_who_may_no_longer_run_workflows() {
        let ann = person("ann@corp.test");
        let worker = run_of(
            &ann,
            &ann,
            vec![code_step("clean", SandboxVersionId::new())],
        );
        let viewing = [SystemPermission::Workflows(WorkflowAction::View)];

        worker.drive(DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(&ann, &viewing)])),
            ..worker.ports()
        });

        assert_eq!(
            worker.state_of("clean"),
            refused(StepRefusal::PersonLacksAuthority)
        );
        assert!(worker.wakeups.code_runs().is_empty());
    }

    /// Ann's run waits an hour, then tidies up. The worker starts the wait.
    /// Woken after the hour, it ends the wait and the run finishes.
    #[test]
    fn a_wait_ends_when_its_time_came() {
        let ann = person("ann@corp.test");
        let workflow = published_by(
            &ann,
            draft_by(
                &ann,
                vec![wait_step("pause"), tidy_step("after")],
                vec![next("pause", "after")],
            ),
        );
        let worker = Worker::over(&started_by(&ann, &workflow));
        worker.drive(worker.ports());
        let _later = clock::freeze(clock::now() + time::Duration::minutes(61));

        worker.drive(worker.ports());

        assert_eq!(
            worker.stored().status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
    }

    /// Nobody signs off Ann's run, and it runs past its day. The worker
    /// expires it.
    #[test]
    fn a_run_past_its_limit_is_expired() {
        let ann = person("ann@corp.test");
        let worker = Worker::over(&started_by(
            &ann,
            &approval_workflow(&ann, ActionClass::Write),
        ));
        let _tomorrow = clock::freeze(clock::now() + time::Duration::days(2));

        worker.drive(worker.ports());

        assert_eq!(
            worker.stored().status(),
            ExecutionStatus::Ended(ExecutionEnd::TimedOut)
        );
    }

    /// Ann's run appends a row through Bob's shared sheets account. Ann may
    /// run workflows and Bob may still lend accounts. The call is made with
    /// Bob's sealed credential, and the step succeeds.
    #[test]
    fn an_action_calls_through_an_account_its_owner_may_lend() {
        let (ann, bob) = (person("ann@corp.test"), person("bob@corp.test"));
        let account = sheets_account(&bob, AccountSharing::Tenant);
        let worker = appending(&ann, &account);
        let runner = appended();

        worker.drive(calling(
            &worker,
            &account,
            &[(&ann, &RUNS), (&bob, &LENDS)],
            runner.clone(),
        ));

        assert!(matches!(
            worker.state_of("append"),
            StepState::Succeeded { .. }
        ));
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let place = account_credential_place(account.id());
        assert_eq!(
            calls[0].1,
            Some(SealedAt {
                secret: FakeEncryptor::sealed_for(SHEETS_CREDENTIAL, &place),
                place,
            })
        );
    }

    /// Bob's account holds a grant the service renews as it is used, as a
    /// Jira account does. Ann's step calls through it and the service hands
    /// back a renewed credential: the account keeps the new one, quietly
    /// recorded, before the step is settled.
    #[test]
    fn a_credential_the_service_renews_is_kept_on_the_account() {
        let (ann, bob) = (person("ann@corp.test"), person("bob@corp.test"));
        let account = sheets_account(&bob, AccountSharing::Tenant);
        let worker = appending(&ann, &account);
        let renewed =
            FakeEncryptor::sealed_for("renewed grant", &account_credential_place(account.id()));
        let accounts = Arc::new(FakeIntegrationAccountStore::holding(&account));
        let runner = appended_with_renewal(renewed.clone());

        let base = calling(&worker, &account, &[(&ann, &RUNS), (&bob, &LENDS)], runner);
        worker.drive(DrivePorts {
            actions: ActionPorts {
                accounts: accounts.clone(),
                ..base.actions
            },
            ..base
        });

        assert_eq!(
            accounts.stored(account.id()).unwrap().credential(),
            &renewed
        );
        assert!(
            worker
                .records()
                .contains(&"workflows.account_credential_renewed".to_owned())
        );
        assert!(matches!(
            worker.state_of("append"),
            StepState::Succeeded { .. }
        ));
    }

    /// A shared account with a missing owner is unusable; its action step fails
    /// with that refusal and makes no integration call.
    #[test]
    fn an_account_whose_owner_left_lends_nothing() {
        let (ann, bob) = (person("ann@corp.test"), person("bob@corp.test"));
        let account = sheets_account(&bob, AccountSharing::Tenant);
        let worker = appending(&ann, &account);
        let runner = appended();

        worker.drive(calling(&worker, &account, &[(&ann, &RUNS)], runner.clone()));

        assert_eq!(
            worker.state_of("append"),
            refused(StepRefusal::AccountNotUsable)
        );
        assert!(runner.calls().is_empty());
    }

    /// An owner-only account is unusable by another person's run. The action
    /// step fails with that refusal and makes no integration call.
    #[test]
    fn an_account_kept_to_its_owner_is_not_lent() {
        let (ann, bob) = (person("ann@corp.test"), person("bob@corp.test"));
        let account = sheets_account(&bob, AccountSharing::OwnerOnly);
        let worker = appending(&ann, &account);
        let runner = appended();

        worker.drive(calling(
            &worker,
            &account,
            &[(&ann, &RUNS), (&bob, &LENDS)],
            runner.clone(),
        ));

        assert_eq!(
            worker.state_of("append"),
            refused(StepRefusal::AccountNotUsable)
        );
        assert!(runner.calls().is_empty());
    }

    /// An action step for a person holding only view rights fails for missing
    /// authority and makes no integration call.
    #[test]
    fn a_person_who_may_no_longer_run_workflows_stops_their_run() {
        let (ann, bob) = (person("ann@corp.test"), person("bob@corp.test"));
        let account = sheets_account(&bob, AccountSharing::Tenant);
        let worker = appending(&ann, &account);
        let runner = appended();
        let viewing = [SystemPermission::Workflows(WorkflowAction::View)];

        worker.drive(calling(
            &worker,
            &account,
            &[(&ann, &viewing), (&bob, &LENDS)],
            runner.clone(),
        ));

        assert_eq!(
            worker.state_of("append"),
            refused(StepRefusal::PersonLacksAuthority)
        );
        assert!(runner.calls().is_empty());
    }

    /// An action absent from the current catalog fails as withdrawn without an
    /// integration call.
    #[test]
    fn an_operation_no_longer_offered_is_not_called() {
        let ann = person("ann@corp.test");
        let account = sheets_account(&ann, AccountSharing::OwnerOnly);
        let worker = appending(&ann, &account);
        let runner = appended();
        let base = calling(&worker, &account, &[(&ann, &LENDS)], runner.clone());
        let ports = DrivePorts {
            actions: ActionPorts {
                catalog: Arc::new(FakeIntegrationCatalog::offering_nothing()),
                ..base.actions
            },
            ..base
        };

        worker.drive(ports);

        assert_eq!(
            worker.state_of("append"),
            refused(StepRefusal::OperationWithdrawn)
        );
        assert!(runner.calls().is_empty());
    }

    /// The sheets integration is busy and turns Ann's call away. The step
    /// is ready again, and the worker comes back when it is due, not
    /// before.
    #[test]
    fn a_call_turned_away_is_made_again_when_due() {
        let ann = person("ann@corp.test");
        let account = sheets_account(&ann, AccountSharing::OwnerOnly);
        let worker = appending(&ann, &account);
        let busy = Arc::new(FakeActionRunner::answering(ActionOutcome::TurnedAway(
            UntrustedText::record("429 too many requests"),
        )));

        worker.drive(calling(&worker, &account, &[(&ann, &LENDS)], busy.clone()));

        let StepState::Ready {
            attempt: Attempt::Again { due, .. },
            ..
        } = worker.state_of("append")
        else {
            panic!("the turned-away call is not ready again");
        };
        assert_eq!(busy.calls().len(), 1);
        assert_eq!(worker.wakeups.last_for(&worker.id), Some(due));
    }

    /// The ports a worker makes Ann's Protected apps call with, the call
    /// coming back read, its pass made by `passes`.
    fn reaching_app(
        worker: &Worker,
        ann: &Human,
        runner: Arc<FakeActionRunner>,
        passes: Arc<FakeRunPasses>,
    ) -> DrivePorts {
        DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(ann, &RUNS)])),
            actions: ActionPorts {
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![app_read()])),
                action_runner: runner,
                run_passes: passes,
                ..ActionPorts::fakes()
            },
            ..worker.ports()
        }
    }

    /// Ann's run reads her orders app as Ann. The call carries one pass,
    /// made for that call, for Ann and for the orders route alone, and the
    /// step succeeds.
    #[test]
    fn a_protected_apps_step_calls_with_a_pass_for_its_person_and_route() {
        let ann = person("ann@corp.test");
        let route = RouteId::new();
        let worker = run_of(&ann, &ann, vec![app_step("orders", &route.to_string())]);
        let (runner, passes) = (appended(), Arc::new(FakeRunPasses::default()));

        worker.drive(reaching_app(&worker, &ann, runner.clone(), passes.clone()));

        let HumanAccount::User(user_id) = ann.account() else {
            panic!("Ann is a tenant user");
        };
        let calls = runner.calls();
        assert_eq!(
            passes.issued(),
            [RunPassGrant {
                call_id: calls[0].0.call_id,
                user_id,
                reaches: PassReach::Route(route),
            }]
        );
        assert_eq!(runner.passes().len(), 1);
        assert_eq!(calls[0].1, None);
        assert!(matches!(
            worker.state_of("orders"),
            StepState::Succeeded { .. }
        ));
    }

    /// Runs sign-out through the company action port with the run holder's current rights.
    fn signing_out(worker: &Worker, ann: &Human, company: Arc<FakeCompanySteps>) -> DrivePorts {
        DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(ann, &RUNS)])),
            actions: ActionPorts {
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![sign_out()])),
                ..ActionPorts::fakes()
            },
            company: CompanyPorts {
                steps: company,
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            },
            ..worker.ports()
        }
    }

    /// Ann's run signs Lee out. The platform makes the step itself, as Ann
    /// coming through this run, its records saying so and continuing the
    /// run's chain, and the step succeeds with what it did.
    #[test]
    fn a_company_step_is_made_as_the_runs_person_through_the_run() {
        let ann = person("ann@corp.test");
        let worker = run_of(&ann, &ann, vec![sign_out_step("sign-out")]);
        let company = Arc::new(FakeCompanySteps::answering(succeeded()));

        worker.drive(signing_out(&worker, &ann, company.clone()));

        let HumanAccount::User(ann_id) = ann.account() else {
            panic!("Ann is a tenant user");
        };
        let made = company.made();
        assert_eq!(made.len(), 1);
        assert_eq!(
            made[0].caller.identity(),
            &CallerIdentity::TenantUser(ann_id)
        );
        assert_eq!(
            made[0].caller.credential(),
            &Credential::WorkflowRun(worker.id)
        );
        assert_eq!(
            made[0].audit.acted_through(),
            ActedThrough::WorkflowRun {
                execution: worker.id
            }
        );
        assert_eq!(made[0].audit.origin(), made[0].call.origin);
        assert!(matches!(
            worker.state_of("sign-out"),
            StepState::Succeeded { .. }
        ));
    }

    /// A missing tenant fails the company step without invoking the company
    /// action port.
    #[test]
    fn a_company_step_in_a_tenant_that_is_gone_fails() {
        let ann = person("ann@corp.test");
        let worker = run_of(&ann, &ann, vec![sign_out_step("sign-out")]);
        let company = Arc::new(FakeCompanySteps::answering(ActionOutcome::Succeeded {
            output: ianua_domain::domains::workflows::data::FlowData::null(),
            exposure: DataClassLevel::Internal,
        }));
        let spec = sign_out();

        worker.drive(DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(&ann, &RUNS)])),
            actions: ActionPorts {
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![spec])),
                ..ActionPorts::fakes()
            },
            company: CompanyPorts {
                steps: company.clone(),
                ..CompanyPorts::fakes()
            },
            ..worker.ports()
        });

        assert!(company.made().is_empty());
        assert!(matches!(worker.state_of("sign-out"), StepState::Failed(_)));
    }

    /// The orders database as a worker finds it: the route, and the login
    /// kept apart from it.
    struct OrdersDatabase {
        id: StreamRouteId,
        routes: Arc<FakeStreamRouteStore>,
        logins: Arc<FakeStreamRouteLogins>,
    }

    /// The ports a worker makes Ann's Protected data call with, reaching
    /// `database`, the call coming back read.
    fn reaching_data(
        worker: &Worker,
        ann: &Human,
        runner: Arc<FakeActionRunner>,
        database: &OrdersDatabase,
    ) -> DrivePorts {
        DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(ann, &RUNS)])),
            actions: ActionPorts {
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![data_query()])),
                action_runner: runner,
                run_passes: Arc::new(FakeRunPasses::default()),
                stream_routes: database.routes.clone(),
                stream_route_logins: database.logins.clone(),
                ..ActionPorts::fakes()
            },
            ..worker.ports()
        }
    }

    /// The orders database, open to workflows with a reader login as
    /// `workflow_use` says.
    fn orders_database(workflow_use: StreamWorkflowUse) -> OrdersDatabase {
        let tenant = test_ctx().tenant();
        let mut route = tunnel_on(15432, StreamAccess::People(RoutePolicy::Authenticated));
        let logins = match workflow_use {
            StreamWorkflowUse::Open => {
                route
                    .open_to_workflows(&reader_login(), &routing_admin())
                    .unwrap();
                FakeStreamRouteLogins::holding(&tenant, *route.id(), reader_login())
            }
            StreamWorkflowUse::Closed => FakeStreamRouteLogins::default(),
        };
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&tenant, &route)).unwrap();
        OrdersDatabase {
            id: *route.id(),
            routes,
            logins: Arc::new(logins),
        }
    }

    fn reader_login() -> WorkflowLogin {
        WorkflowLogin::new(
            LoginUser::new("workflows_reader").unwrap(),
            SealedSecret::new("v1.AAECAwQF").unwrap(),
            LoginTls::Off,
        )
    }

    /// Ann's run queries the orders database as Ann. The call carries one
    /// pass for that call, for Ann and the orders database alone, and the
    /// route's login, its password sealed for that route; the step
    /// succeeds.
    #[test]
    fn a_protected_data_step_calls_with_a_pass_and_the_route_s_login() {
        let ann = person("ann@corp.test");
        let database = orders_database(StreamWorkflowUse::Open);
        let worker = run_of(
            &ann,
            &ann,
            vec![data_step("orders", &database.id.to_string())],
        );
        let runner = appended();

        worker.drive(reaching_data(&worker, &ann, runner.clone(), &database));

        let calls = runner.calls();
        let sealed = calls[0].1.clone().unwrap();
        assert_eq!(runner.passes().len(), 1);
        assert_eq!(&sealed.secret, reader_login().password());
        assert_eq!(
            sealed.place,
            stream_route_login_place(&test_ctx().tenant(), &database.id)
        );
        assert!(matches!(
            worker.state_of("orders"),
            StepState::Succeeded { .. }
        ));
    }

    /// A database route closed to workflows fails the protected data step
    /// without an integration call.
    #[test]
    fn a_protected_data_step_on_a_closed_route_fails_unsent() {
        let ann = person("ann@corp.test");
        let database = orders_database(StreamWorkflowUse::Closed);
        let worker = run_of(
            &ann,
            &ann,
            vec![data_step("orders", &database.id.to_string())],
        );
        let runner = appended();

        worker.drive(reaching_data(&worker, &ann, runner.clone(), &database));

        assert!(runner.calls().is_empty());
        assert!(matches!(worker.state_of("orders"), StepState::Failed(_)));
    }

    /// A protected app step using a route name instead of an ID fails without
    /// issuing a pass or making an integration call.
    #[test]
    fn a_protected_apps_step_naming_no_route_id_fails_unsent() {
        let ann = person("ann@corp.test");
        let worker = run_of(&ann, &ann, vec![app_step("orders", "orders")]);
        let (runner, passes) = (appended(), Arc::new(FakeRunPasses::default()));

        worker.drive(reaching_app(&worker, &ann, runner.clone(), passes.clone()));

        assert!(passes.issued().is_empty());
        assert!(runner.calls().is_empty());
        assert!(matches!(worker.state_of("orders"), StepState::Failed(_)));
    }

    /// The tenant's signing key cannot be read when Ann's step comes up.
    /// Nothing was sent, so the call is turned away and made again later.
    #[test]
    fn a_pass_that_cannot_be_made_turns_the_call_away() {
        let ann = person("ann@corp.test");
        let worker = run_of(
            &ann,
            &ann,
            vec![app_step("orders", &RouteId::new().to_string())],
        );
        let runner = appended();

        worker.drive(reaching_app(
            &worker,
            &ann,
            runner.clone(),
            Arc::new(FakeRunPasses::refusing()),
        ));

        assert!(runner.calls().is_empty());
        assert!(matches!(
            worker.state_of("orders"),
            StepState::Ready {
                attempt: Attempt::Again { .. },
                ..
            }
        ));
    }

    /// Ann's run has her summarising agent read the orders. The worker
    /// starts the agent's run acting for Ann, keeps it, and hands it to the
    /// agents' worker by queueing the job that drives it.
    #[test]
    fn an_agent_step_starts_a_run_for_the_person() {
        let ann = person("ann@corp.test");
        let agent = AgentId::new();
        let worker = run_of(&ann, &ann, vec![agent_step("summarise", agent)]);
        let runs = Arc::new(FakeRunStore::empty());
        let queue = Arc::new(FakeJobQueue::new());

        let base = summarising(&worker, &ann, agent, &runs, Arc::new(FakeLimitEnforcer));
        worker.drive(DrivePorts {
            agent_steps: AgentStepPorts {
                run_drives: RunDrives {
                    queue: queue.clone(),
                    attempts: std::num::NonZeroU32::MIN,
                },
                ..base.agent_steps
            },
            ..base
        });

        assert_eq!(runs.count(), 1);
        assert_eq!(queue.jobs_of(DRIVE_RUN_JOB).len(), 1);
        assert!(matches!(
            worker.state_of("summarise"),
            StepState::Running {
                underway: Underway::AgentRun(_),
                ..
            }
        ));
        assert!(worker.records().contains(&"agents.run_started".to_owned()));
    }

    /// The ports that start Ann's agent step with `agent`, keeping runs in
    /// `runs`, with the plan's run count checked by `limits`.
    fn summarising(
        worker: &Worker,
        ann: &Human,
        agent: AgentId,
        runs: &Arc<FakeRunStore>,
        limits: Arc<dyn LimitEnforcer>,
    ) -> DrivePorts {
        let agents = FakeAgentStore::empty();
        agents.add_owned_by(agent, person("owner@corp.test"));
        DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(ann, &RUNS)])),
            agent_steps: AgentStepPorts {
                agents: Arc::new(agents),
                runs: runs.clone(),
                limit_enforcer: limits,
                ..AgentStepPorts::fakes()
            },
            ..worker.ports()
        }
    }

    /// Acme already has as many agent runs in flight as its plan allows
    /// when Ann's step comes up. No run starts, and the step is not failed:
    /// it waits, ready, the worker comes back when it is due, and the wait
    /// is recorded.
    #[test]
    fn an_agent_step_waits_while_the_plan_is_full() {
        let ann = person("ann@corp.test");
        let agent = AgentId::new();
        let worker = run_of(&ann, &ann, vec![agent_step("summarise", agent)]);
        let runs = Arc::new(FakeRunStore::empty());

        worker.drive(summarising(
            &worker,
            &ann,
            agent,
            &runs,
            Arc::new(RejectingLimitEnforcer),
        ));

        let StepState::Ready {
            attempt: Attempt::Deferred { due },
            ..
        } = worker.state_of("summarise")
        else {
            panic!("the agent step is not waiting for room");
        };
        assert_eq!(runs.count(), 0);
        assert_eq!(worker.stored().status(), ExecutionStatus::Running);
        assert_eq!(worker.wakeups.last_for(&worker.id), Some(due));
        assert_eq!(worker.records(), ["workflows.step_deferred"]);
    }

    /// Ann's code step names a version holding an agent that summarises
    /// orders. The worker starts that agent's run, held to the version's
    /// check, the step waits on it, and no code run is queued.
    #[test]
    fn a_code_step_whose_version_holds_an_agent_starts_its_run() {
        let ann = person("ann@corp.test");
        let agent = AgentId::new();
        let version = held_version_of(agent);
        let worker = run_of(&ann, &ann, vec![code_step("summarise", *version.id())]);
        let runs = Arc::new(FakeRunStore::empty());
        let base = summarising(&worker, &ann, agent, &runs, Arc::new(FakeLimitEnforcer));

        worker.drive(DrivePorts {
            agent_steps: AgentStepPorts {
                sandbox_versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
                ..base.agent_steps
            },
            ..base
        });

        assert_eq!(runs.count(), 1);
        assert!(matches!(
            worker.state_of("summarise"),
            StepState::Running {
                underway: Underway::AgentRun(_),
                ..
            }
        ));
        assert!(worker.wakeups.code_runs().is_empty());
    }

    /// Ann's step waited for room. A run ends meanwhile, and when the
    /// worker comes back after the pause the step starts its run.
    #[test]
    fn an_agent_step_put_off_starts_once_the_plan_has_room() {
        let ann = person("ann@corp.test");
        let agent = AgentId::new();
        let worker = run_of(&ann, &ann, vec![agent_step("summarise", agent)]);
        let runs = Arc::new(FakeRunStore::empty());
        worker.drive(summarising(
            &worker,
            &ann,
            agent,
            &runs,
            Arc::new(RejectingLimitEnforcer),
        ));
        let _later = clock::freeze(clock::now() + RUN_LIMIT_PAUSE);

        worker.drive(summarising(
            &worker,
            &ann,
            agent,
            &runs,
            Arc::new(FakeLimitEnforcer),
        ));

        assert_eq!(runs.count(), 1);
        assert!(matches!(
            worker.state_of("summarise"),
            StepState::Running {
                underway: Underway::AgentRun(_),
                ..
            }
        ));
    }

    /// A unit of work that tells whether one is running, nested or not.
    #[derive(Default)]
    struct WatchedUnit {
        open: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl UnitOfWork for WatchedUnit {
        async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            self.run(work).await
        }

        async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            self.open.fetch_add(1, Ordering::SeqCst);
            work.await;
            self.open.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A plan with room, which notes for each count whether a unit of work
    /// was running when it was made.
    struct WatchingLimits {
        open: Arc<AtomicUsize>,
        counted_inside: Mutex<Vec<bool>>,
    }

    impl WatchingLimits {
        /// Records whether the count ran inside the unit that persists the run.
        fn note(&self) {
            let inside = self.open.load(Ordering::SeqCst) > 0;
            self.counted_inside.lock().unwrap().push(inside);
        }
    }

    #[async_trait]
    impl LimitEnforcer for WatchingLimits {
        async fn check_tenant_limit(
            &self,
            _: &PlanLimits,
            _: &ScopedTenant,
            _: ResourceKind,
        ) -> Result<(), DomainError> {
            self.note();
            Ok(())
        }

        async fn check_tenant_room(
            &self,
            _: &PlanLimits,
            _: &ScopedTenant,
            _: ResourceKind,
            _: u64,
        ) -> Result<(), DomainError> {
            self.note();
            Ok(())
        }

        async fn tenant_room(
            &self,
            _: &PlanLimits,
            _: &ScopedTenant,
            _: ResourceKind,
        ) -> Result<u64, DomainError> {
            self.note();
            Ok(1)
        }

        async fn check_org_limit(
            &self,
            _: &PlanLimits,
            _: &OrganizationId,
            _: ResourceKind,
        ) -> Result<(), DomainError> {
            self.note();
            Ok(())
        }
    }

    /// Starting an agent step checks plan capacity once inside the unit of work
    /// and saves one agent run.
    #[test]
    fn the_room_for_an_agent_run_is_counted_in_the_unit_that_keeps_it() {
        let ann = person("ann@corp.test");
        let agent = AgentId::new();
        let worker = run_of(&ann, &ann, vec![agent_step("summarise", agent)]);
        let runs = Arc::new(FakeRunStore::empty());
        let unit = WatchedUnit::default();
        let limits = Arc::new(WatchingLimits {
            open: Arc::clone(&unit.open),
            counted_inside: Mutex::new(Vec::new()),
        });

        worker.drive(DrivePorts {
            unit_of_work: Arc::new(unit),
            ..summarising(&worker, &ann, agent, &runs, limits.clone())
        });

        assert_eq!(runs.count(), 1);
        assert_eq!(*limits.counted_inside.lock().unwrap(), [true]);
    }

    /// A missing agent fails its step as unable to act and leaves no agent run saved.
    #[test]
    fn a_step_whose_agent_is_gone_starts_no_run() {
        let ann = person("ann@corp.test");
        let worker = run_of(&ann, &ann, vec![agent_step("summarise", AgentId::new())]);
        let runs = Arc::new(FakeRunStore::empty());

        worker.drive(DrivePorts {
            accounts_now: Arc::new(accounts_now_of(&[(&ann, &RUNS)])),
            agent_steps: AgentStepPorts {
                runs: runs.clone(),
                ..AgentStepPorts::fakes()
            },
            ..worker.ports()
        });

        assert_eq!(
            worker.state_of("summarise"),
            refused(StepRefusal::AgentMayNotAct)
        );
        assert_eq!(runs.count(), 0);
    }

    /// Another worker already drives Ann's run when a second wake-up
    /// arrives. The second worker leaves it alone.
    #[test]
    fn an_execution_another_worker_holds_is_left_alone() {
        let ann = person("ann@corp.test");
        let worker = Worker::over(&started_by(
            &ann,
            &approval_workflow(&ann, ActionClass::Write),
        ));

        worker.drive(DrivePorts {
            lease: Arc::new(FakeExecutionLease::held_elsewhere(worker.id)),
            ..worker.ports()
        });

        assert!(matches!(worker.state_of("check"), StepState::Ready { .. }));
        assert!(worker.records().is_empty());
    }
}
