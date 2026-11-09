//! Wait steps: the workflow pauses for a set time, or until working hours
//! begin, then goes on.

use time::OffsetDateTime;

use crate::domains::workflows::design::node::{NodeKey, NodeKind, WaitUntil};
use crate::domains::workflows::design::working_hours::{LONGEST_WAIT_FOR_HOURS, WorkingHours};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::progress::no_output;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::step::{Holding, StepState, Underway};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// When working hours next begin, as the calendar outside the domain read
/// them for a wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoursBegin {
    /// Nobody asked: the wait is for a set time.
    NotAsked,
    /// At this moment, or now when they are on.
    At(OffsetDateTime),
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// The working hours the ready step `key` waits for, when it is a wait
    /// for working hours: the calendar is asked when they next begin, and
    /// the answer handed to [`begin_wait`](Self::begin_wait).
    #[must_use]
    pub fn hours_awaited(&self, key: &NodeKey) -> Option<&WorkingHours> {
        let node = self.graph().node(key)?;
        let NodeKind::Wait(wait) = node.kind() else {
            return None;
        };
        match wait.until() {
            WaitUntil::WorkingHours(hours) => Some(hours),
            WaitUntil::Elapsed(_) => None,
        }
    }

    /// Starts the ready wait step `key`: for its set time, or until working
    /// hours `begin`, at once when they are on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not ready.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    /// - [`DomainError::Validation`] when it is not a wait step, or waits
    ///   for working hours and nobody said when they begin, or said a day
    ///   further off than any week's hours.
    pub fn begin_wait(
        &mut self,
        key: &NodeKey,
        begin: HoursBegin,
    ) -> Result<Vec<ExecutionRecord>, DomainError> {
        let ready = self.ready_step(key)?;
        let NodeKind::Wait(wait) = ready.node.kind() else {
            return Err(DomainError::invalid(message!(
                "workflows-this-step-does-not-wait",
                "this step does not wait"
            )));
        };
        let now = crate::shared::clock::now();
        let until = wait_ends(wait.until(), begin, now)?;
        Ok(self.begin_step(ready, Underway::Timer { until }, now))
    }

    /// Ends the running wait step `key` once its time has come, and the
    /// workflow goes on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not waiting.
    /// - [`DomainError::InvalidTransition`] when the execution has ended.
    /// - [`DomainError::Conflict`] while its time has not come.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    pub fn elapse(&mut self, key: &NodeKey) -> Result<Vec<ExecutionRecord>, DomainError> {
        let running = self.running_step(key)?;
        let Underway::Timer { until } = running.underway else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-this-step-is-not-waiting",
                "this step is not waiting"
            )));
        };
        if crate::shared::clock::now() < until {
            return Err(DomainError::conflict(message!(
                "workflows-the-wait-is-not-over",
                "the wait is not over"
            )));
        }
        Ok(self.succeed(
            running.index,
            no_output(),
            running.exposure,
            Holding::ForGood,
        ))
    }

    /// When the wait step `key` is over. `None` when it is not waiting.
    #[must_use]
    pub fn wait_ends(&self, key: &NodeKey) -> Option<OffsetDateTime> {
        let StepState::Running {
            underway: Underway::Timer { until },
            ..
        } = self.step(key)?
        else {
            return None;
        };
        Some(*until)
    }
}

/// When a wait until `until` started at `now` ends, working hours
/// beginning as `begin` says.
fn wait_ends(
    until: &WaitUntil,
    begin: HoursBegin,
    now: OffsetDateTime,
) -> Result<OffsetDateTime, DomainError> {
    match (until, begin) {
        (WaitUntil::Elapsed(duration), _) => Ok(now.saturating_add(duration.duration())),
        (WaitUntil::WorkingHours(_), HoursBegin::At(at))
            if at <= now.saturating_add(LONGEST_WAIT_FOR_HOURS) =>
        {
            Ok(at.max(now))
        }
        (WaitUntil::WorkingHours(_), HoursBegin::At(_)) => Err(DomainError::invalid(message!(
            "workflows-working-hours-begin-within-a-week",
            "working hours begin within a week"
        ))),
        (WaitUntil::WorkingHours(_), HoursBegin::NotAsked) => Err(DomainError::invalid(message!(
            "workflows-a-wait-for-working-hours-needs-when",
            "a wait for working hours needs to know when they begin"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::FlowData;
    use crate::domains::workflows::design::node::{Join, WaitStep};
    use crate::domains::workflows::design::working_hours::WorkingHoursParams;
    use crate::domains::workflows::execution::tests::fixtures::{
        frozen_at, instant, key, node, started, state, wait,
    };
    use crate::types::Timezone;

    /// A wait for Acme's support hours, Monday to Friday, 9:00 to 17:00 in
    /// Berlin.
    fn support_hours(name: &str) -> crate::domains::workflows::design::node::Node {
        let hours = WorkingHours::new(WorkingHoursParams {
            days: vec![time::Weekday::Monday, time::Weekday::Friday],
            opens: 9 * 60,
            closes: 17 * 60,
            timezone: Timezone::new("Europe/Berlin").unwrap(),
        })
        .unwrap();
        node(
            name,
            NodeKind::Wait(WaitStep::for_working_hours(hours)),
            Join::All,
        )
    }

    /// A page reaches support out of hours. The calendar says the hours
    /// begin in two hours, so the wait ends then; asked when they are on,
    /// it ends at once.
    #[test]
    fn a_wait_for_working_hours_ends_when_they_begin() {
        let _clock = frozen_at(0);
        let mut later = started(vec![support_hours("page")], Vec::new());
        let mut now = started(vec![support_hours("page")], Vec::new());

        later
            .begin_wait(&key("page"), HoursBegin::At(instant(7200)))
            .unwrap();
        now.begin_wait(&key("page"), HoursBegin::At(instant(0)))
            .unwrap();

        assert!(later.hours_awaited(&key("page")).is_some());
        assert_eq!(later.wait_ends(&key("page")), Some(instant(7200)));
        assert_eq!(now.wait_ends(&key("page")), Some(instant(0)));
    }

    /// Working-hours waits reject both a missing calendar answer and a
    /// start one month away as validation errors.
    #[test]
    fn a_wait_for_working_hours_needs_a_believable_beginning() {
        let _clock = frozen_at(0);
        let mut unasked = started(vec![support_hours("page")], Vec::new());
        let mut too_late = started(vec![support_hours("page")], Vec::new());

        let not_asked = unasked.begin_wait(&key("page"), HoursBegin::NotAsked);
        let month = too_late.begin_wait(&key("page"), HoursBegin::At(instant(30 * 86_400)));

        assert!(matches!(not_asked, Err(DomainError::Validation(_))));
        assert!(matches!(month, Err(DomainError::Validation(_))));
    }

    /// A one-hour wait starts at time 0 and says it ends at 3600. Ending it
    /// at once is refused as a conflict. At 3600 it ends, and then reports
    /// no end time.
    #[test]
    fn a_wait_ends_only_once_its_time_has_come() {
        let clock = frozen_at(0);
        let mut execution = started(vec![wait("pause")], Vec::new());
        execution
            .begin_wait(&key("pause"), HoursBegin::NotAsked)
            .unwrap();
        let ends = execution.wait_ends(&key("pause"));
        let early = execution.elapse(&key("pause"));
        drop(clock);
        let _later = frozen_at(3600);

        let on_time = execution.elapse(&key("pause"));

        assert_eq!(ends, Some(instant(3600)));
        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert!(on_time.is_ok());
        assert_eq!(execution.wait_ends(&key("pause")), None);
    }

    /// A one-hour wait ends after its hour. It succeeds with a null output,
    /// so the steps after it see no data from it.
    #[test]
    fn a_wait_produces_nothing_of_its_own() {
        let clock = frozen_at(0);
        let mut execution = started(vec![wait("pause")], Vec::new());
        execution
            .begin_wait(&key("pause"), HoursBegin::NotAsked)
            .unwrap();
        drop(clock);
        let _later = frozen_at(3600);

        execution.elapse(&key("pause")).unwrap();

        let StepState::Succeeded { output, .. } = state(&execution, "pause") else {
            panic!("the wait did not settle");
        };
        assert_eq!(output, FlowData::null());
    }
}
