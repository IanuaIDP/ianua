//! Action steps: one call of an integration's operation.
//!
//! The call is made only when all of these hold:
//! - the integration still offers the operation as the version was
//!   published against,
//! - the account lets the person the execution acts for use it for that
//!   operation,
//! - the step's input is no more sensitive than the operation may be
//!   handed.
//!
//! An integration that turns a call away is called again, a little later,
//! and every one of these is asked again first.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::account::AccountUse;
use crate::domains::workflows::data::{FieldName, FlowData, FlowValue};
use crate::domains::workflows::design::node::{NodeKey, NodeKind};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::acting::ActingAuthority;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::retry::tries_from;
use crate::domains::workflows::execution::step::{
    ActionOutcome, CallTries, StepFailure, StepRefusal, Underway,
};
use crate::domains::workflows::execution::steps::work::{ReadyStep, Settled};
use crate::domains::workflows::integration::risk_override::TenantOperation;
use crate::domains::workflows::integration::{
    ActionAccount, ActionStep, InputNeed, IntegrationKey, MEMORY_INPUT, OperationKey,
    OperationSpec, ROUTE_INPUT,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::{ChainDepth, EventOrigin};
use crate::types::{ActionCallId, DeclaredAction, MemoryId, RouteId, StreamRouteId};

/// What the integration catalog offers now for an action step's operation.
#[derive(Debug, Clone, Copy)]
pub enum Offer<'a> {
    /// The operation, as its integration declares it now, raised by the
    /// tenant's overrides.
    Current(&'a TenantOperation),
    /// The integration no longer offers it.
    Withdrawn,
}

/// What lets an action step act: permission to use the step's account, or
/// the fact that its operation needs none.
#[derive(Debug)]
pub enum ActionClearance<T: TenantScope> {
    /// The permission the account granted.
    Account(AccountUse<T>),
    /// The operation acts through no account.
    NoAccount,
}

/// One call of an integration's operation, for its adapter to make.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionCall {
    /// The call, which its outcome is reported under.
    pub call_id: ActionCallId,
    /// The catalogue namespace selecting the adapter that makes the call.
    pub integration: IntegrationKey,
    /// The catalogue action the adapter must invoke with these arguments.
    pub operation: OperationKey,
    /// The account to act through.
    pub account: ActionAccount,
    /// The arguments, built from the step's input.
    pub arguments: FlowData,
    /// What kind of action it is.
    pub effect: DeclaredAction,
    /// The most sensitive data in the arguments.
    pub exposure: DataClassLevel,
    /// The execution's place in its chain. The adapter hands it on with the
    /// call, so whatever the call sets off in the tenant comes back marked
    /// and a workflow it triggers continues the chain.
    pub origin: EventOrigin,
}

impl ActionCall {
    /// The route a call acting as the run's person reaches: the id its
    /// [`ROUTE_INPUT`] names. `None` when that argument is missing or not
    /// a route's id, so no pass is made for it.
    #[must_use]
    pub fn reached_route(&self) -> Option<RouteId> {
        self.reached_id(ROUTE_INPUT).map(RouteId::from_uuid)
    }

    /// The stream route a Protected data call reaches: the id its
    /// [`ROUTE_INPUT`] names. `None` when that argument is missing or not
    /// an id, so no pass is made for it.
    #[must_use]
    pub fn reached_stream_route(&self) -> Option<StreamRouteId> {
        self.reached_id(ROUTE_INPUT).map(StreamRouteId::from_uuid)
    }

    /// The memory a memory call reaches: the id its [`MEMORY_INPUT`] names.
    /// `None` when that argument is missing or not an id.
    #[must_use]
    pub fn reached_memory(&self) -> Option<MemoryId> {
        self.reached_id(MEMORY_INPUT).map(MemoryId::from_uuid)
    }

    /// The id the call's input `input` names, if it names one.
    fn reached_id(&self, input: &str) -> Option<uuid::Uuid> {
        let name = FieldName::new(input).ok()?;
        let FlowValue::Text(id) = self.arguments.field(&name)?.value() else {
            return None;
        };
        uuid::Uuid::parse_str(id).ok()
    }
}

/// What starting an action step came to.
#[derive(Debug)]
pub enum ActionStart {
    /// Make this call. The step waits for its outcome.
    Call(ActionCall, Vec<ExecutionRecord>),
    /// The step failed before anything was called.
    Stopped(Vec<ExecutionRecord>),
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Starts the ready action step `key`.
    ///
    /// The step fails, with a record and without any call, when any of
    /// these is true:
    /// - `acting` shows the person the execution acts for may not run
    ///   workflows now,
    /// - an approval right before the step has lapsed,
    /// - `offer` says the operation was withdrawn, or changed since the
    ///   version was published,
    /// - `clearance` is not permission for this person to use exactly the
    ///   step's account for its operation,
    /// - the input is more sensitive than the operation may be handed,
    /// - the arguments are too large,
    /// - an input the operation needs came to nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] for an absent step; [`DomainError::InvalidTransition`]
    /// unless ready or if the execution ended; [`DomainError::Conflict`] after timeout
    /// or before a refused call's retry is due; or [`DomainError::Validation`] unless
    /// the step is an action.
    pub fn begin_action(
        &mut self,
        key: &NodeKey,
        offer: Offer<'_>,
        clearance: &ActionClearance<T>,
        acting: &ActingAuthority,
    ) -> Result<ActionStart, DomainError> {
        let ready = self.ready_step(key)?;
        let NodeKind::Action(step) = ready.node.kind() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-does-not-call-an",
                "this step does not call an integration"
            )));
        };
        let now = crate::shared::clock::now();
        let tries = tries_from(ready.attempt, now)?;
        if !acting.may_run_for(&self.acting_for) {
            let failure = StepFailure::Refused(StepRefusal::PersonLacksAuthority);
            return Ok(ActionStart::Stopped(self.fail(ready.index, failure)));
        }
        if !self.approvals_before_still_hold(&ready.node) {
            return Ok(ActionStart::Stopped(
                self.fail(ready.index, StepFailure::ApprovalLapsed),
            ));
        }
        let arguments = match self.arguments_for(step, offer, clearance, &ready) {
            Ok(arguments) => arguments,
            Err(failure) => return Ok(ActionStart::Stopped(self.fail(ready.index, failure))),
        };
        let call = action_call(step, arguments, &ready, self.chain_depth);
        let underway = Underway::Action {
            call_id: call.call_id,
            tries,
        };
        let records = self.begin_step(ready, underway, now);
        Ok(ActionStart::Call(call, records))
    }

    /// The arguments `step` is called with, once it may be called now.
    fn arguments_for(
        &self,
        step: &ActionStep,
        offer: Offer<'_>,
        clearance: &ActionClearance<T>,
        ready: &ReadyStep,
    ) -> Result<FlowData, StepFailure> {
        let Offer::Current(offered) = offer else {
            return Err(StepFailure::Refused(StepRefusal::OperationWithdrawn));
        };
        let spec = offered.spec();
        if step.ensure_fits(spec).is_err() {
            return Err(StepFailure::Refused(StepRefusal::OperationChanged));
        }
        if !self.is_cleared(step, clearance) {
            return Err(StepFailure::Refused(StepRefusal::AccountNotUsable));
        }
        if ready.exposure > step.ceiling() {
            return Err(StepFailure::DataAboveCeiling {
                exposure: ready.exposure,
                ceiling: step.ceiling(),
            });
        }
        let arguments = step
            .inputs()
            .apply(&ready.input)
            .map_err(|_| StepFailure::InputTooLarge)?;
        ensure_required_given(spec, &arguments)?;
        Ok(arguments)
    }

    /// Whether `clearance` lets the person this execution acts for use
    /// exactly the account and operation `step` names. Also true when the
    /// step needs no account and none is given.
    fn is_cleared(&self, step: &ActionStep, clearance: &ActionClearance<T>) -> bool {
        match (step.account(), clearance) {
            (ActionAccount::Account(id), ActionClearance::Account(granted)) => {
                granted.account_id() == id
                    && granted.integration() == step.integration()
                    && granted.operation() == step.operation()
                    && granted.granted_to().is_same_account_as(&self.acting_for)
            }
            (ActionAccount::NoAccount, ActionClearance::NoAccount) => true,
            (ActionAccount::Account(_), ActionClearance::NoAccount)
            | (ActionAccount::NoAccount, ActionClearance::Account(_)) => false,
        }
    }

    /// Settles the action step `key` from how its call `call_id` went.
    ///
    /// Its output carries the more sensitive of its input and what the
    /// operation read. A call still under way when the execution ended is
    /// recorded, and nothing goes on from it.
    ///
    /// A round that left the work undone makes the step ready again for its
    /// next round, due when the outcome says, at the latest a week on and
    /// never after the deadline.
    ///
    /// A call the integration turned away makes the step ready again, due
    /// after a pause, with the same input. Starting it again asks every
    /// question [`begin_action`](Self::begin_action) asks. It fails instead
    /// once the call was made as often as
    /// `MAX_CALL_TRIES`
    /// allows, or when the next try would fall after the execution's
    /// deadline.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is neither
    ///   running nor abandoned.
    /// - [`DomainError::Conflict`] once a running execution ran out of
    ///   time.
    /// - [`DomainError::Forbidden`] when `call_id` is not the step's call.
    pub fn settle_action(
        &mut self,
        key: &NodeKey,
        call_id: ActionCallId,
        outcome: ActionOutcome,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let step = self.reporting_step(key)?;
        let tries = tries_of_call(&step.underway, call_id)?;
        let settled = match outcome {
            ActionOutcome::Succeeded {
                output,
                exposure: read,
            } => Settled::Output(output, step.exposure.max(read)),
            ActionOutcome::Failed(reason) => Settled::Failure(StepFailure::Reported(reason)),
            ActionOutcome::TurnedAway(reason) => return Ok(self.turned_away(step, tries, reason)),
            ActionOutcome::NotYet { due } => return Ok(self.next_round(step, due)),
        };
        Ok(self.settle_reported(step, settled))
    }
}

/// Which try `call_id` is, when it is the call `underway`.
fn tries_of_call(underway: &Underway, call_id: ActionCallId) -> Result<CallTries, DomainError> {
    match underway {
        Underway::Action {
            call_id: made,
            tries,
        } if *made == call_id => Ok(*tries),
        Underway::Action { .. }
        | Underway::AgentRun(_)
        | Underway::Approval(_)
        | Underway::Timer { .. }
        | Underway::Loop(_)
        | Underway::Code(_) => Err(DomainError::forbidden(message!(
            "workflows-this-is-not-the-step-s",
            "this is not the step's call"
        ))),
    }
}

/// Refuses arguments where an input `spec` needs came to nothing.
///
/// That is a path that found no value in this run, or found null.
fn ensure_required_given(spec: &OperationSpec, arguments: &FlowData) -> Result<(), StepFailure> {
    let missing = spec
        .inputs()
        .iter()
        .filter(|input| input.need() == InputNeed::Required)
        .find(|input| arguments.field(input.name()).is_none_or(FlowData::is_null));
    let Some(missing) = missing else {
        return Ok(());
    };
    Err(StepFailure::MissingInput(missing.name().clone()))
}

fn action_call(
    step: &ActionStep,
    arguments: FlowData,
    ready: &ReadyStep,
    depth: ChainDepth,
) -> ActionCall {
    ActionCall {
        call_id: ActionCallId::new(),
        integration: step.integration().clone(),
        operation: step.operation().clone(),
        account: step.account(),
        arguments,
        effect: step.effect(),
        exposure: ready.exposure,
        origin: EventOrigin::Execution(depth),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::workflows::account::IntegrationAccount;
    use crate::domains::workflows::data::{DataPath, FieldName};
    use crate::domains::workflows::design::node::{Join, Mapping, Port, Source};
    use crate::domains::workflows::execution::ExecutionStatus;
    use crate::domains::workflows::execution::record::{ExecutionEnd, StepRecord};
    use crate::domains::workflows::execution::step::StepState;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, acting, action, ann, append, append_row, approval, approve, bob, by_hand,
        condition, edge, frozen_at, key, managing, node, offered, published, sheet_account,
        spec_of, start_as, started, state, stored, transform,
    };
    use crate::domains::workflows::integration::risk_override::{
        OperationRiskOverride, RaiseRiskParams,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{ActionClass, UntrustedText};

    fn store_with(
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> (Execution, ActionClearance<ResolvedTenant>) {
        let execution = started(vec![action("store", *account.id())], Vec::new());
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );
        (execution, clearance)
    }

    fn call(execution: &mut Execution, clearance: &ActionClearance<ResolvedTenant>) -> ActionCall {
        let authority = acting(execution.acting_for());
        let ActionStart::Call(call, _) = execution
            .begin_action(
                &key("store"),
                Offer::Current(&offered(append_row())),
                clearance,
                &authority,
            )
            .unwrap()
        else {
            panic!("the action was not called");
        };
        call
    }

    fn stopped_as(
        execution: &mut Execution,
        offer: Offer<'_>,
        clearance: &ActionClearance<ResolvedTenant>,
    ) -> StepState {
        let authority = acting(execution.acting_for());
        let started = execution
            .begin_action(&key("store"), offer, clearance, &authority)
            .unwrap();
        assert!(matches!(started, ActionStart::Stopped(_)));
        state(execution, "store")
    }

    fn refused(refusal: StepRefusal) -> StepState {
        StepState::Failed(StepFailure::Refused(refusal))
    }

    /// Ann's append-row step fails with an unusable account when offered
    /// permission for another sheets account, a Slack account, a different
    /// operation on the right account, or no account.
    #[test]
    fn an_action_starts_only_with_leave_for_exactly_its_account_and_operation() {
        let account = sheet_account(&ann(), "google-sheets");
        let other_account = sheet_account(&ann(), "google-sheets");
        let other_integration = sheet_account(&ann(), "slack");
        let cases = [
            granted_to_ann(&other_account, &append()),
            granted_to_ann(&other_integration, &append()),
            granted_to_ann(&account, &OperationKey::new("delete-row").unwrap()),
            ActionClearance::NoAccount,
        ];

        for clearance in cases {
            let mut execution = started(vec![action("store", *account.id())], Vec::new());
            assert_eq!(
                stopped_as(
                    &mut execution,
                    Offer::Current(&offered(append_row())),
                    &clearance
                ),
                refused(StepRefusal::AccountNotUsable)
            );
        }
    }

    /// Grants Ann permission for the exact account and operation varied by the refusal test.
    fn granted_to_ann(
        account: &IntegrationAccount<ResolvedTenant>,
        operation: &OperationKey,
    ) -> ActionClearance<ResolvedTenant> {
        ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), operation, &acting(&ann()))
                .unwrap(),
        )
    }

    /// A Google Sheets operation naming a Slack account fails with an
    /// unusable account before producing a call, even when permission names
    /// that account and operation.
    #[test]
    fn an_account_of_another_integration_does_not_clear_an_action() {
        let slack = sheet_account(&ann(), "slack");
        let mut execution = started(vec![action("store", *slack.id())], Vec::new());
        let leave = ActionClearance::Account(
            slack
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );

        let stopped = stopped_as(
            &mut execution,
            Offer::Current(&offered(append_row())),
            &leave,
        );

        assert_eq!(stopped, refused(StepRefusal::AccountNotUsable));
    }

    /// Bob's execution cannot use Ann's permission for a shared account.
    /// The action fails with an unusable account.
    #[test]
    fn leave_granted_to_another_person_does_not_clear_an_action() {
        let account = sheet_account(&ann(), "google-sheets");
        let workflow = published(vec![action("store", *account.id())], Vec::new());
        let (mut bobs, _) = start_as(&workflow, &bob(), by_hand(DataClassLevel::Internal)).unwrap();
        let anns_leave = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );

        let stopped = stopped_as(
            &mut bobs,
            Offer::Current(&offered(append_row())),
            &anns_leave,
        );

        assert_eq!(stopped, refused(StepRefusal::AccountNotUsable));
    }

    /// Ann shared her account with the tenant, and Bob is granted his own
    /// permission to use it. His execution's step makes the call.
    #[test]
    fn a_shared_account_acts_for_another_person_with_their_own_leave() {
        let account = sheet_account(&ann(), "google-sheets");
        let workflow = published(vec![action("store", *account.id())], Vec::new());
        let (mut bobs, _) = start_as(&workflow, &bob(), by_hand(DataClassLevel::Internal)).unwrap();
        let bobs_leave = ActionClearance::Account(
            account
                .grant_use(&acting(&bob()), &append(), &acting(&ann()))
                .unwrap(),
        );

        let authority = acting(bobs.acting_for());
        let started = bobs
            .begin_action(
                &key("store"),
                Offer::Current(&offered(append_row())),
                &bobs_leave,
                &authority,
            )
            .unwrap();

        assert!(matches!(started, ActionStart::Call(..)));
    }

    /// Ann holds permission for exactly the step's account and operation.
    /// The call names that account, the write class and the execution's
    /// chain, and the step waits on that call.
    #[test]
    fn exact_leave_for_the_acting_person_calls_the_operation() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = store_with(&account);

        let call = call(&mut execution, &clearance);

        assert_eq!(call.account, ActionAccount::Account(*account.id()));
        assert_eq!(call.effect, DeclaredAction::Declared(ActionClass::Write));
        assert_eq!(call.origin, EventOrigin::Execution(execution.chain_depth()));
        assert!(matches!(
            state(&execution, "store"),
            StepState::Running {
                underway: Underway::Action { call_id: id, .. },
                ..
            } if id == call.call_id
        ));
    }

    /// The step fills the required `values` from a condition, which has no
    /// output. The step fails for the missing input, and the operation is
    /// never called with an empty value.
    #[test]
    fn a_required_input_that_comes_to_nothing_stops_the_step() {
        let account = sheet_account(&ann(), "google-sheets");
        let inputs = Mapping::new(vec![(
            FieldName::new("values").unwrap(),
            Source::Input(DataPath::parse("check").unwrap()),
        )])
        .unwrap();
        let store =
            ActionStep::new(&append_row(), ActionAccount::Account(*account.id()), inputs).unwrap();
        let mut execution = started(
            vec![
                condition("check"),
                node("store", NodeKind::Action(store), Join::All),
            ],
            vec![edge("check", Port::WhenTrue, "store")],
        );
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );

        let stopped = stopped_as(
            &mut execution,
            Offer::Current(&offered(append_row())),
            &clearance,
        );

        assert_eq!(
            stopped,
            StepState::Failed(StepFailure::MissingInput(FieldName::new("values").unwrap()))
        );
    }

    /// Ann's account permission cannot start an action after she loses her
    /// authority. No call is produced, and the step fails for that loss.
    #[test]
    fn an_action_for_someone_who_may_no_longer_run_workflows_is_not_called() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = store_with(&account);
        let left = ActingAuthority::assumed(ann(), CapabilitySet::empty());

        let started = execution
            .begin_action(
                &key("store"),
                Offer::Current(&offered(append_row())),
                &clearance,
                &left,
            )
            .unwrap();

        assert!(matches!(started, ActionStart::Stopped(_)));
        assert_eq!(
            state(&execution, "store"),
            refused(StepRefusal::PersonLacksAuthority)
        );
    }

    /// Ann raises "append row" to financial after the workflow was
    /// published. The next call is refused as a changed operation, until a
    /// version with the approval it now needs is published.
    #[test]
    fn an_operation_a_tenant_raised_after_publishing_is_not_called() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = store_with(&account);
        let raised = OperationRiskOverride::<ResolvedTenant>::raise(
            RaiseRiskParams {
                integration: append_row().integration().clone(),
                operation: append_row().operation().clone(),
                effect: DeclaredAction::Declared(ActionClass::Financial),
            },
            &managing(&ann()),
        )
        .unwrap();
        let as_raised = TenantOperation::of(append_row(), &[raised]);

        let stopped = stopped_as(&mut execution, Offer::Current(&as_raised), &clearance);

        assert_eq!(stopped, refused(StepRefusal::OperationChanged));
    }

    /// The integration has withdrawn "append row". The step is refused as
    /// withdrawn and the execution fails.
    #[test]
    fn an_operation_its_integration_withdrew_is_not_called() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = store_with(&account);

        let stopped = stopped_as(&mut execution, Offer::Withdrawn, &clearance);

        assert_eq!(stopped, refused(StepRefusal::OperationWithdrawn));
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// Since publishing, "append row" became a payment in one case and
    /// takes only public data in another. Each call is refused as a changed
    /// operation.
    #[test]
    fn an_operation_that_changed_since_publishing_is_not_called() {
        let account = sheet_account(&ann(), "google-sheets");
        let now_financial = spec_of(ActionClass::Financial, DataClassLevel::Internal);
        let now_public_only = spec_of(ActionClass::Write, DataClassLevel::Public);

        for changed in [&now_financial, &now_public_only] {
            let (mut execution, clearance) = store_with(&account);
            assert_eq!(
                stopped_as(
                    &mut execution,
                    Offer::Current(&offered(changed.clone())),
                    &clearance
                ),
                refused(StepRefusal::OperationChanged)
            );
        }
    }

    /// Bob's approval permits the action to start a minute later. Starting
    /// it two hours later produces no call and fails because approval lapsed.
    #[test]
    fn an_action_after_its_approval_closed_is_not_called() {
        let account = sheet_account(&ann(), "google-sheets");
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );
        let mut prompt = approved_at_noon(&account);
        let mut late = approved_at_noon(&account);

        let in_time = {
            let _soon = frozen_at(60);
            stopped_or_called(&mut prompt, &clearance)
        };
        let too_late = {
            let _hours_later = frozen_at(7200);
            stopped_or_called(&mut late, &clearance)
        };

        assert!(matches!(in_time, ActionStart::Call(..)));
        assert!(matches!(too_late, ActionStart::Stopped(_)));
        assert_eq!(
            state(&late, "store"),
            StepState::Failed(StepFailure::ApprovalLapsed)
        );
    }

    /// Opens the sheet action behind an approval completed at the fixed noon instant.
    fn approved_at_noon(account: &IntegrationAccount<ResolvedTenant>) -> Execution {
        let _noon = frozen_at(0);
        let mut execution = started(
            vec![approval("ok"), action("store", *account.id())],
            vec![edge("ok", Port::Next, "store")],
        );
        approve(&mut execution, "ok");
        execution
    }

    /// A transform sits between the approval and the action, and two hours
    /// pass. The check looks back through the transform, finds the window
    /// closed, and the action fails as lapsed.
    #[test]
    fn an_approval_behind_a_transform_still_lapses() {
        let account = sheet_account(&ann(), "google-sheets");
        let mut execution = {
            let _noon = frozen_at(0);
            let mut execution = started(
                vec![
                    approval("ok"),
                    transform("tidy", Join::All),
                    action("store", *account.id()),
                ],
                vec![
                    edge("ok", Port::Next, "tidy"),
                    edge("tidy", Port::Next, "store"),
                ],
            );
            approve(&mut execution, "ok");
            execution
        };
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );

        let _hours_later = frozen_at(7200);
        let too_late = stopped_or_called(&mut execution, &clearance);

        assert!(matches!(too_late, ActionStart::Stopped(_)));
        assert_eq!(
            state(&execution, "store"),
            StepState::Failed(StepFailure::ApprovalLapsed)
        );
    }

    fn stopped_or_called(
        execution: &mut Execution,
        clearance: &ActionClearance<ResolvedTenant>,
    ) -> ActionStart {
        let authority = acting(execution.acting_for());
        execution
            .begin_action(
                &key("store"),
                Offer::Current(&offered(append_row())),
                clearance,
                &authority,
            )
            .unwrap()
    }

    /// A run starts with restricted data and the operation takes data up to
    /// internal. The step fails without a call, naming both levels, and the
    /// execution fails.
    #[test]
    fn data_above_an_operations_ceiling_fails_the_step_without_calling_it() {
        let account = sheet_account(&ann(), "google-sheets");
        let workflow = published(vec![action("store", *account.id())], Vec::new());
        let (mut execution, _) =
            start_as(&workflow, &ann(), by_hand(DataClassLevel::Restricted)).unwrap();
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );

        let stopped = stopped_as(
            &mut execution,
            Offer::Current(&offered(append_row())),
            &clearance,
        );

        assert_eq!(
            stopped,
            StepState::Failed(StepFailure::DataAboveCeiling {
                exposure: DataClassLevel::Restricted,
                ceiling: DataClassLevel::Internal,
            })
        );
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// A step with internal input reports reading confidential data, and
    /// its output is confidential. Reporting public data leaves the output
    /// internal, never lower.
    #[test]
    fn what_an_action_read_raises_its_outputs_exposure_and_never_lowers_it() {
        let account = sheet_account(&ann(), "google-sheets");
        let settled = |read: DataClassLevel| {
            let (mut execution, clearance) = store_with(&account);
            let call = call(&mut execution, &clearance);
            execution
                .settle_action(
                    &key("store"),
                    call.call_id,
                    ActionOutcome::Succeeded {
                        output: FlowData::null(),
                        exposure: read,
                    },
                )
                .unwrap();
            state(&execution, "store")
        };

        assert!(matches!(
            settled(DataClassLevel::Confidential),
            StepState::Succeeded {
                exposure: DataClassLevel::Confidential,
                ..
            }
        ));
        assert!(matches!(
            settled(DataClassLevel::Public),
            StepState::Succeeded {
                exposure: DataClassLevel::Internal,
                ..
            }
        ));
    }

    /// A timeout reported for a different call is forbidden. The step keeps
    /// running with its original call.
    #[test]
    fn an_outcome_reported_under_another_call_does_not_settle_the_step() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = store_with(&account);
        call(&mut execution, &clearance);

        let settled = execution.settle_action(
            &key("store"),
            ActionCallId::new(),
            ActionOutcome::Failed(UntrustedText::record("timeout")),
        );

        assert!(matches!(settled, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            state(&execution, "store"),
            StepState::Running { .. }
        ));
    }

    /// Ann cancels an execution after its call was made, and the call then
    /// reports success. The success is recorded, since it may have acted,
    /// and the execution stays cancelled by Ann.
    #[test]
    fn a_call_left_behind_by_a_cancelled_execution_is_recorded_when_it_reports() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = store_with(&account);
        let call = call(&mut execution, &clearance);
        execution.cancel(&managing(&ann())).unwrap();

        let records = execution
            .settle_action(
                &key("store"),
                call.call_id,
                ActionOutcome::Succeeded {
                    output: FlowData::null(),
                    exposure: DataClassLevel::Internal,
                },
            )
            .unwrap();

        assert_eq!(
            records,
            vec![ExecutionRecord::step(
                &key("store"),
                StepRecord::Succeeded(Port::Next)
            )]
        );
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(ann().principal()))
        );
    }

    /// A transform leads to an action, and the execution is cancelled while
    /// the call runs. The late result still names the transform it saw, so
    /// the stored execution reads back.
    #[test]
    fn a_late_result_behind_another_step_leaves_a_loadable_execution() {
        let account = sheet_account(&ann(), "google-sheets");
        let mut execution = started(
            vec![transform("tidy", Join::All), action("store", *account.id())],
            vec![edge("tidy", Port::Next, "store")],
        );
        let clearance = ActionClearance::Account(
            account
                .grant_use(&acting(&ann()), &append(), &acting(&ann()))
                .unwrap(),
        );
        let call = call(&mut execution, &clearance);
        execution.cancel(&managing(&ann())).unwrap();

        execution
            .settle_action(
                &key("store"),
                call.call_id,
                ActionOutcome::Succeeded {
                    output: FlowData::null(),
                    exposure: DataClassLevel::Internal,
                },
            )
            .unwrap();

        assert!(Execution::reconstitute(stored(&execution)).is_ok());
    }

    /// A call to Ann's orders app names its route by id, and that is the
    /// route its pass is made for; a route given as a name names none.
    #[test]
    fn a_call_reaches_the_route_its_route_input_names() {
        let route = RouteId::new();
        let with_route = |value: &str| ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("apps").unwrap(),
            operation: OperationKey::new("get").unwrap(),
            account: ActionAccount::NoAccount,
            arguments: FlowData::map(vec![(
                FieldName::new(ROUTE_INPUT).unwrap(),
                FlowData::text(value).unwrap(),
            )])
            .unwrap(),
            effect: DeclaredAction::Declared(ActionClass::Read),
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Execution(ChainDepth::FIRST),
        };

        assert_eq!(with_route(&route.to_string()).reached_route(), Some(route));
        assert_eq!(with_route("orders").reached_route(), None);
        let database = StreamRouteId::new();
        assert_eq!(
            with_route(&database.to_string()).reached_stream_route(),
            Some(database)
        );
        assert_eq!(with_route("orders-db").reached_stream_route(), None);
    }
}
