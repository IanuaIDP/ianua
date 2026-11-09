//! Which change an execution is due next, read from where its steps stand
//! and the clock.

use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::step::{Attempt, StepState, Underway};
use ianua_domain::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use time::OffsetDateTime;

/// A change an execution is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Move {
    /// It ran past its run limit.
    Expire,
    /// This approval step's decision window closed, or that of this loop's
    /// approval of every item.
    Lapse(NodeKey),
    /// This wait step's time came.
    Elapse(NodeKey),
    /// This step is ready, and due to start.
    Start(NodeKey),
}

/// The change `execution` is due now, or `None` when it ended or waits on
/// people, the clock or work under way.
///
/// Its run limit comes first, then what the clock ended, then the steps
/// ready to start, in the graph's order.
pub(super) fn next_move(execution: &WorkflowExecution<ResolvedTenant>) -> Option<Move> {
    if execution.status() != ExecutionStatus::Running {
        return None;
    }
    let now = clock::now();
    if now >= execution.deadline() {
        return Some(Move::Expire);
    }
    let ended = execution
        .steps()
        .find_map(|(node, state)| ended_by_the_clock(node.key(), state, now));
    ended.or_else(|| {
        execution
            .steps()
            .find(|(_, state)| is_due_to_start(state, now))
            .map(|(node, _)| Move::Start(node.key().clone()))
    })
}

/// The change the clock made to the step `key` in `state` by `now`.
fn ended_by_the_clock(key: &NodeKey, state: &StepState, now: OffsetDateTime) -> Option<Move> {
    let StepState::Running { underway, .. } = state else {
        return None;
    };
    match underway {
        Underway::Approval(_) | Underway::Loop(_) => underway
            .decision_wait()
            .filter(|wait| now >= wait.closes_at)
            .map(|_| Move::Lapse(key.clone())),
        Underway::Timer { until } if now >= *until => Some(Move::Elapse(key.clone())),
        Underway::Timer { .. }
        | Underway::AgentRun(_)
        | Underway::Action { .. }
        | Underway::Code(_) => None,
    }
}

/// Whether a step in `state` is ready and due to start by `now`. A call
/// an integration turned away, an agent run put off while the plan was
/// full, or a step waiting for its next round, is due again only from its
/// pause's end.
fn is_due_to_start(state: &StepState, now: OffsetDateTime) -> bool {
    match state {
        StepState::Ready { attempt, .. } => match attempt {
            Attempt::First => true,
            Attempt::Again { due, .. } | Attempt::Deferred { due } | Attempt::NextRound { due } => {
                now >= *due
            }
        },
        StepState::Waiting
        | StepState::Running { .. }
        | StepState::Succeeded { .. }
        | StepState::Failed(_)
        | StepState::Skipped
        | StepState::Stopped
        | StepState::Abandoned { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::execution::HoursBegin;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::workflows::{
        approval_workflow, awaiting_approval, draft_by, loop_asking_for_every_item, next, person,
        published_by, started_by, step, tidy_step, wait_step,
    };

    /// Ann starts a workflow whose first step asks for approval. The
    /// approval is due to be asked for at once.
    #[test]
    fn a_ready_step_is_due_to_start() {
        let ann = person("ann@corp.test");
        let execution = started_by(&ann, &approval_workflow(&ann, ActionClass::Write));

        assert_eq!(next_move(&execution), Some(Move::Start(step("check"))));
    }

    /// Bob is asked to approve Ann's step, and an hour has not passed. The
    /// execution waits on him.
    #[test]
    fn an_open_approval_waits_on_people() {
        let execution = awaiting_approval(
            &person("cid@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Write,
        );

        assert_eq!(next_move(&execution), None);
    }

    /// Nobody decides Ann's approval within its hour. The approval lapses.
    #[test]
    fn a_closed_decision_window_lapses_its_approval() {
        let execution = awaiting_approval(
            &person("cid@corp.test"),
            &person("ann@corp.test"),
            ActionClass::Write,
        );
        let _later = clock::freeze(clock::now() + time::Duration::minutes(61));

        assert_eq!(next_move(&execution), Some(Move::Lapse(step("check"))));
    }

    /// Ann's loop asks one approval for every issue, and nobody decides
    /// within its hour. The loop's approval lapses; before the hour it waits
    /// on people.
    #[test]
    fn a_loop_whose_approval_of_every_item_closed_lapses() {
        let execution =
            loop_asking_for_every_item(&person("ann@corp.test"), &["a", "b"], ActionClass::Write);
        let waiting = next_move(&execution);
        let _later = clock::freeze(clock::now() + time::Duration::minutes(61));

        assert_eq!(waiting, None);
        assert_eq!(next_move(&execution), Some(Move::Lapse(step("each"))));
    }

    /// Ann's workflow waits an hour. After the hour, the wait ends.
    #[test]
    fn a_wait_whose_time_came_ends() {
        let ann = person("ann@corp.test");
        let workflow = published_by(
            &ann,
            draft_by(
                &ann,
                vec![wait_step("pause"), tidy_step("after")],
                vec![next("pause", "after")],
            ),
        );
        let mut execution = started_by(&ann, &workflow);
        execution
            .begin_wait(&step("pause"), HoursBegin::NotAsked)
            .unwrap();
        let _later = clock::freeze(clock::now() + time::Duration::minutes(61));

        assert_eq!(next_move(&execution), Some(Move::Elapse(step("pause"))));
    }

    /// Ann's execution runs past its day. It is expired before anything
    /// else, however much was left to do.
    #[test]
    fn an_execution_past_its_run_limit_is_expired_first() {
        let ann = person("ann@corp.test");
        let execution = started_by(&ann, &approval_workflow(&ann, ActionClass::Write));
        let _tomorrow = clock::freeze(clock::now() + time::Duration::days(2));

        assert_eq!(next_move(&execution), Some(Move::Expire));
    }

    /// Ann's execution only tidied its data and ended. Nothing is due.
    #[test]
    fn an_ended_execution_is_due_nothing() {
        let ann = person("ann@corp.test");
        let workflow = published_by(&ann, draft_by(&ann, vec![tidy_step("tidy")], Vec::new()));

        assert_eq!(next_move(&started_by(&ann, &workflow)), None);
    }
}
