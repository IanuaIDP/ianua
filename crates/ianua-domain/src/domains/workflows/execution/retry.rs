//! Calling an integration again after it turned an action step's call away.
//!
//! The step goes back to ready with the input it had, due after a pause.
//! Starting it again asks every question a first call asks, so a person who
//! left, an account taken away or an approval that lapsed still stops it.

use time::OffsetDateTime;

use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::record::{ExecutionRecord, StepRecord, TurnedAwayCall};
use crate::domains::workflows::execution::step::{
    Attempt, CallTries, LONGEST_ROUND_GAP, MAX_CALL_TRIES, StepFailure, StepState,
};
use crate::domains::workflows::execution::steps::work::{Phase, ReportingStep, Settled};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::UntrustedText;

impl<T: TenantScope> WorkflowExecution<T> {
    /// Makes the step ready to call again after its call `tries` was turned
    /// away, or fails it when it may not be tried again.
    pub(super) fn turned_away(
        &mut self,
        step: ReportingStep,
        tries: CallTries,
        reason: UntrustedText,
    ) -> Vec<ExecutionRecord> {
        let Some(due) = self.next_try_due(&step, tries) else {
            return self.settle_reported(step, Settled::Failure(StepFailure::Reported(reason)));
        };
        let Ok(input) = self.input_seen_by(&step.seen) else {
            return self.fail(step.index, StepFailure::InputTooLarge);
        };
        let Some(key) = self
            .graph
            .nodes()
            .get(step.index)
            .map(|node| node.key().clone())
        else {
            return Vec::new();
        };
        let ready = StepState::Ready {
            input,
            exposure: step.exposure,
            seen: step.seen,
            attempt: Attempt::Again { tries, due },
        };
        self.put(step.index, ready);
        let happened = StepRecord::CallTurnedAway(TurnedAwayCall { tries, due, reason });
        vec![ExecutionRecord::step(&key, happened)]
    }

    /// Makes the step ready again for its next round at `due`, or at the
    /// execution's deadline when that comes first, with the same input.
    pub(super) fn next_round(
        &mut self,
        step: ReportingStep,
        due: OffsetDateTime,
    ) -> Vec<ExecutionRecord> {
        let Ok(input) = self.input_seen_by(&step.seen) else {
            return self.fail(step.index, StepFailure::InputTooLarge);
        };
        let Some(key) = self
            .graph
            .nodes()
            .get(step.index)
            .map(|node| node.key().clone())
        else {
            return Vec::new();
        };
        let now = crate::shared::clock::now();
        let due = due
            .clamp(now, now.saturating_add(LONGEST_ROUND_GAP))
            .min(self.deadline);
        let ready = StepState::Ready {
            input,
            exposure: step.exposure,
            seen: step.seen,
            attempt: Attempt::NextRound { due },
        };
        self.put(step.index, ready);
        vec![ExecutionRecord::step(
            &key,
            StepRecord::StartDeferred { due },
        )]
    }

    /// When the step may call again after its call `tries` was turned away.
    ///
    /// `None` when the execution ended, the call was made as often as it
    /// may be, or the pause would run past the execution's deadline.
    fn next_try_due(&self, step: &ReportingStep, tries: CallTries) -> Option<OffsetDateTime> {
        if step.phase == Phase::Late {
            return None;
        }
        tries.next()?;
        let due = crate::shared::clock::now().saturating_add(tries.pause_before_next());
        (due < self.deadline).then_some(due)
    }
}

/// Which try a ready step's call is, once it is made at `now`.
pub(super) fn tries_from(attempt: Attempt, now: OffsetDateTime) -> Result<CallTries, DomainError> {
    let (tries, due) = match attempt {
        Attempt::Again { tries, due } => (tries, due),
        Attempt::NextRound { due } if now < due => {
            return Err(DomainError::conflict(message!(
                "workflows-the-next-round-is-not-due",
                "the step's next round is not due yet"
            )));
        }
        Attempt::First | Attempt::Deferred { .. } | Attempt::NextRound { .. } => {
            return Ok(CallTries::FIRST);
        }
    };
    if now < due {
        return Err(DomainError::conflict(message!(
            "workflows-the-call-was-turned-away-and",
            "the call was turned away and is not due to be made again yet"
        )));
    }
    tries.next().ok_or_else(|| {
        DomainError::conflict(message!(
            "workflows-a-call-is-made-at-most",
            format!("a call is made at most {MAX_CALL_TRIES} times")
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::account::IntegrationAccount;
    use crate::domains::workflows::data::FlowData;
    use crate::domains::workflows::execution::record::ExecutionEnd;
    use crate::domains::workflows::execution::step::{ActionOutcome, StepRefusal, Underway};
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, acting, action, ann, append, append_row, frozen_at, instant, key, managing,
        offered, sheet_account, started, state, stored,
    };
    use crate::domains::workflows::execution::{
        ActingAuthority, ActionCall, ActionClearance, ActionStart, ExecutionStatus, Offer,
    };
    use crate::isolation::scope::ResolvedTenant;

    fn storing(
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

    fn begin(
        execution: &mut Execution,
        clearance: &ActionClearance<ResolvedTenant>,
        acting: &ActingAuthority,
    ) -> Result<ActionStart, DomainError> {
        execution.begin_action(
            &key("store"),
            Offer::Current(&offered(append_row())),
            clearance,
            acting,
        )
    }

    fn called(
        execution: &mut Execution,
        clearance: &ActionClearance<ResolvedTenant>,
    ) -> ActionCall {
        let authority = acting(execution.acting_for());
        let Ok(ActionStart::Call(call, _)) = begin(execution, clearance, &authority) else {
            panic!("the action was not called");
        };
        call
    }

    fn turn_away(execution: &mut Execution, call: &ActionCall) -> Vec<ExecutionRecord> {
        execution
            .settle_action(
                &key("store"),
                call.call_id,
                ActionOutcome::TurnedAway(UntrustedText::record("rate limited")),
            )
            .unwrap()
    }

    /// The sheet answers "rate limited" at noon. The step is ready again,
    /// due thirty seconds later, with the record saying so. Starting it ten
    /// seconds in is refused. At thirty seconds it calls again, as the
    /// second try, under a new call id.
    #[test]
    fn a_call_turned_away_is_made_again_once_it_is_due() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance, first, records) = {
            let _noon = frozen_at(0);
            let (mut execution, clearance) = storing(&account);
            let first = called(&mut execution, &clearance);
            let records = turn_away(&mut execution, &first);
            (execution, clearance, first, records)
        };
        let too_soon = {
            let _soon = frozen_at(10);
            begin(&mut execution, &clearance, &acting(&ann()))
        };
        let again = {
            let _due = frozen_at(30);
            called(&mut execution, &clearance)
        };

        assert_rate_limit_record(&records);
        assert!(matches!(too_soon, Err(DomainError::Conflict(_))));
        assert_ne!(again.call_id, first.call_id);
        assert!(matches!(
            state(&execution, "store"),
            StepState::Running {
                underway: Underway::Action { tries, .. },
                ..
            } if tries.get() == 2
        ));
    }

    /// Checks that the first refusal records its reason and exact retry deadline.
    fn assert_rate_limit_record(records: &[ExecutionRecord]) {
        assert_eq!(
            records,
            [ExecutionRecord::step(
                &key("store"),
                StepRecord::CallTurnedAway(TurnedAwayCall {
                    tries: CallTries::FIRST,
                    due: instant(30),
                    reason: UntrustedText::record("rate limited"),
                })
            )]
        );
    }

    /// A reminder goes out at noon and the request is still open, so the
    /// step says its work is not done and the next round is in an hour.
    /// Starting it half an hour in is refused; at the hour it is made
    /// again, as a first try, and the record says it was put off.
    #[test]
    fn a_round_that_left_the_work_undone_comes_back_when_due() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance, records) = unfinished_at_noon(&account);
        let too_soon = {
            let _soon = frozen_at(1800);
            begin(&mut execution, &clearance, &acting(&ann()))
        };
        {
            let _due = frozen_at(3600);
            called(&mut execution, &clearance);
        }

        assert_eq!(
            records,
            vec![ExecutionRecord::step(
                &key("store"),
                StepRecord::StartDeferred { due: instant(3600) }
            )]
        );
        assert!(matches!(too_soon, Err(DomainError::Conflict(_))));
        assert!(matches!(
            state(&execution, "store"),
            StepState::Running {
                underway: Underway::Action { tries, .. },
                ..
            } if tries.get() == 1
        ));
    }

    /// Leaves the first action round unfinished at noon and due again one hour later.
    fn unfinished_at_noon(
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> (
        Execution,
        ActionClearance<ResolvedTenant>,
        Vec<ExecutionRecord>,
    ) {
        let _noon = frozen_at(0);
        let (mut execution, clearance) = storing(account);
        let first = called(&mut execution, &clearance);
        let records = execution
            .settle_action(
                &key("store"),
                first.call_id,
                ActionOutcome::NotYet { due: instant(3600) },
            )
            .unwrap();
        (execution, clearance, records)
    }

    /// The sheet turns the call away three times. The third fails the step
    /// with the integration's reason, and the execution fails.
    #[test]
    fn a_call_turned_away_on_every_try_fails_the_step() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = {
            let _noon = frozen_at(0);
            storing(&account)
        };

        for at in [0, 30, 150] {
            let _now = frozen_at(at);
            let call = called(&mut execution, &clearance);
            turn_away(&mut execution, &call);
        }

        assert_eq!(
            state(&execution, "store"),
            StepState::Failed(StepFailure::Reported(UntrustedText::record("rate limited")))
        );
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// Ann loses her authority before a turned-away call is due again.
    /// The retry stops before making another call and fails the step for
    /// lack of authority.
    #[test]
    fn a_second_try_asks_every_question_again() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = {
            let _noon = frozen_at(0);
            let (mut execution, clearance) = storing(&account);
            let call = called(&mut execution, &clearance);
            turn_away(&mut execution, &call);
            (execution, clearance)
        };
        let left = ActingAuthority::assumed(ann(), CapabilitySet::empty());

        let _due = frozen_at(30);
        let again = begin(&mut execution, &clearance, &left).unwrap();

        assert!(matches!(again, ActionStart::Stopped(_)));
        assert_eq!(
            state(&execution, "store"),
            StepState::Failed(StepFailure::Refused(StepRefusal::PersonLacksAuthority))
        );
    }

    /// Ann cancels the run while its call is out, and the sheet then turns
    /// the call away. It is recorded as failed, and nothing is called again.
    #[test]
    fn a_call_turned_away_after_the_run_ended_is_not_made_again() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = storing(&account);
        let call = called(&mut execution, &clearance);
        execution.cancel(&managing(&ann())).unwrap();

        turn_away(&mut execution, &call);

        assert_eq!(
            state(&execution, "store"),
            StepState::Failed(StepFailure::Reported(UntrustedText::record("rate limited")))
        );
    }

    /// A success reported for a turned-away call cannot settle its step.
    /// The report returns an error and the step stays ready for another try.
    #[test]
    fn the_first_call_does_not_settle_a_step_waiting_to_call_again() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = storing(&account);
        let call = called(&mut execution, &clearance);
        turn_away(&mut execution, &call);

        let late = execution.settle_action(
            &key("store"),
            call.call_id,
            ActionOutcome::Succeeded {
                output: FlowData::null(),
                exposure: DataClassLevel::Internal,
            },
        );

        assert!(late.is_err());
        assert!(matches!(
            state(&execution, "store"),
            StepState::Ready {
                attempt: Attempt::Again { .. },
                ..
            }
        ));
    }

    /// A step waiting to call again is stored and read back. Stored on a
    /// step that has used every try, or due a day later, it is refused as
    /// corrupt.
    #[test]
    fn a_stored_retry_keeps_to_its_tries_and_its_pause() {
        let account = sheet_account(&ann(), "google-sheets");
        let (mut execution, clearance) = storing(&account);
        let call = called(&mut execution, &clearance);
        turn_away(&mut execution, &call);
        let with_attempt = |attempt: Attempt| {
            let mut row = stored(&execution);
            if let Some(StepState::Ready { attempt: slot, .. }) = row.steps.get_mut(0) {
                *slot = attempt;
            }
            row
        };
        let Some(StepState::Ready {
            attempt: Attempt::Again { due, .. },
            ..
        }) = execution.step(&key("store")).cloned()
        else {
            panic!("the step does not wait to call again");
        };
        let spent = CallTries::from_stored(MAX_CALL_TRIES).unwrap();

        let as_written = Execution::reconstitute(stored(&execution));
        let no_tries_left =
            Execution::reconstitute(with_attempt(Attempt::Again { tries: spent, due }));
        let a_day_later = Execution::reconstitute(with_attempt(Attempt::Again {
            tries: CallTries::FIRST,
            due: due.saturating_add(time::Duration::days(1)),
        }));

        assert!(as_written.is_ok());
        assert!(matches!(no_tries_left, Err(DomainError::Infrastructure(_))));
        assert!(matches!(a_day_later, Err(DomainError::Infrastructure(_))));
    }

    /// A stored count of zero or four tries is refused as corrupt. One to
    /// three are read back.
    #[test]
    fn a_stored_try_count_stays_within_its_range() {
        assert!(CallTries::from_stored(0).is_err());
        assert!(CallTries::from_stored(MAX_CALL_TRIES + 1).is_err());
        assert!((1..=MAX_CALL_TRIES).all(|tries| CallTries::from_stored(tries).is_ok()));
    }
}
