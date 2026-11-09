//! One approval for every item of a loop, asked before any pass starts.
//!
//! Ann's loop closes each stale issue a search found. Its first step asks
//! one approval for every item, so the loop does not start its passes: it
//! fixes the list and asks. Bob opens the list page by page. His yes counts
//! only once every item was on a page he opened, and the record says who he
//! is, how many items there were and when he had seen the last of them.
//! Each pass then goes through its approval step under Bob's approval.
//!
//! The approval keeps every rule a step's approval keeps: the right to
//! approve and clearance for the data, not the person the run acts for,
//! two different people who are not authors where the action may be high
//! risk, each present with a fresh second factor, and nobody once the
//! window closed. A no fails the loop before any pass runs.
//!
//! The items are fixed when the approval opens. A loop started again opens
//! a new approval over the list it is given then; pages opened of the old
//! list do not count for the new one, so nobody approves items they were
//! not shown.

use time::{Duration, OffsetDateTime};

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::control::StepApprover;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::node::{Covering, NodeKey, NodeKind, WorkflowApprovalStep};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::progress::no_output;
use crate::domains::workflows::execution::record::{ExecutionRecord, ItemsShown, StepRecord};
use crate::domains::workflows::execution::step::{
    ApprovalWait, ApprovedBy, FirstApproval, Holding, ItemsApproved, StepState, Underway,
};
use crate::domains::workflows::execution::steps::approval::ensure_present_when_needed;
use crate::domains::workflows::execution::steps::loops::{LoopMoves, Looping};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// One page of a loop's items a person opened while the loop asked for
/// their approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenPage {
    /// When the approval the page belongs to opened. A page of an earlier
    /// opening showed a list since replaced.
    pub opening: OffsetDateTime,
    /// The position of its first item, counted from zero.
    pub first: u32,
    /// How many items it held.
    pub count: u32,
    /// When the person opened it.
    pub at: OffsetDateTime,
}

/// The pages of a loop's items one person opened, as kept beside the run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemsSeen {
    pages: Vec<SeenPage>,
}

impl ItemsSeen {
    /// The pages `pages` names, in any order.
    #[must_use]
    pub fn new(pages: Vec<SeenPage>) -> Self {
        Self { pages }
    }

    /// How many of `items` items of the approval opened at `opening` were on
    /// some page opened, so an approver sees how far through the list they
    /// are.
    #[must_use]
    pub fn items_shown(&self, opening: OffsetDateTime, items: u32) -> u32 {
        let mut shown = Shown::of(items);
        self.pages
            .iter()
            .filter(|page| page.opening == opening)
            .for_each(|page| {
                shown.mark(page);
            });
        u32::try_from(shown.count()).unwrap_or(u32::MAX)
    }

    /// When every one of `items` items of the approval opened at `opening`
    /// had been on a page, and how many pages of it were opened.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when only pages of an earlier list were
    ///   opened, or some item of this one was on no page opened.
    fn every_item_shown(
        &self,
        opening: OffsetDateTime,
        items: u32,
    ) -> Result<EveryItemShown, DomainError> {
        let mut current: Vec<&SeenPage> = self
            .pages
            .iter()
            .filter(|page| page.opening == opening)
            .collect();
        if current.is_empty() && !self.pages.is_empty() {
            return Err(DomainError::conflict(message!(
                "workflows-the-items-changed-since-they-were-shown",
                "the items changed since they were shown; open every page of the new list before approving"
            )));
        }
        current.sort_by_key(|page| page.at);
        let pages = u32::try_from(current.len()).unwrap_or(u32::MAX);
        let mut shown = Shown::of(items);
        current
            .into_iter()
            .find(|page| shown.mark(page))
            .map(|page| EveryItemShown { at: page.at, pages })
            .ok_or_else(|| not_every_item_shown(&shown, items))
    }
}

/// The items of a loop waiting for its approval of every item, as a person
/// entitled to decide it is shown them.
#[derive(Debug, Clone, PartialEq)]
pub struct ItemsAsked {
    /// When the approval opened. The items were fixed then, and pages
    /// opened count only for this opening.
    pub opening: OffsetDateTime,
    /// What people are asked to approve, its class, window and approvers.
    pub approval: WorkflowApprovalStep,
    /// When it can no longer be approved.
    pub closes_at: OffsetDateTime,
    /// Every item, in the order the passes take them. Pass `n` starts with
    /// item `n`, its position and [`shared`](Self::shared).
    pub items: Vec<FlowData>,
    /// What every pass is given beside its item.
    pub shared: FlowData,
}

/// When the last item not yet seen was shown, and how many pages were
/// opened.
struct EveryItemShown {
    at: OffsetDateTime,
    pages: u32,
}

/// Which items a person was shown so far.
struct Shown {
    items: Vec<bool>,
    left: usize,
}

impl Shown {
    fn of(items: u32) -> Self {
        let count = usize::try_from(items).unwrap_or(usize::MAX);
        Self {
            items: vec![false; count],
            left: count,
        }
    }

    /// Marks the items on `page` as shown. Says whether every item now is.
    fn mark(&mut self, page: &SeenPage) -> bool {
        let first = usize::try_from(page.first).unwrap_or(usize::MAX);
        let count = usize::try_from(page.count).unwrap_or(0);
        for seen in self.items.iter_mut().skip(first).take(count) {
            self.left = self.left.saturating_sub(usize::from(!*seen));
            *seen = true;
        }
        self.left == 0
    }

    fn count(&self) -> usize {
        self.items.len().saturating_sub(self.left)
    }
}

/// A pass's approval of every item, ready since the pass began.
struct ReadyItemsApproval {
    index: usize,
    window: Duration,
    exposure: DataClassLevel,
}

/// A loop asking for its approval of every item, as it stands.
struct AskingForItems {
    looping: Looping,
    approval: WorkflowApprovalStep,
    wait: ApprovalWait,
    opening: OffsetDateTime,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// The items of the loop `key`, waiting for its approval of every item,
    /// shown to `approver`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `approver` may not decide approvals
    ///   or is cleared below the data the loop was handed.
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when it is no loop waiting for
    ///   its approval of every item, or the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    pub fn items_shown_to(
        &self,
        key: &NodeKey,
        approver: &StepApprover<'_>,
    ) -> Result<ItemsAsked, DomainError> {
        let asking = self.asking_for_items(key)?;
        approver.ensure_entitled(asking.looping.exposure)?;
        Ok(ItemsAsked {
            opening: asking.opening,
            closes_at: asking.wait.closes_at,
            approval: asking.approval,
            items: asking.looping.progress.items().to_vec(),
            shared: asking.looping.progress.shared().clone(),
        })
    }

    /// `approver` approves every item of the loop `key`, having opened the
    /// pages `seen` names.
    ///
    /// The yes counts only when every item of the list fixed at the
    /// approval's opening was on a page they opened. When two approvers are
    /// needed and this is the first, the loop keeps waiting for a second,
    /// different person. Otherwise its first passes start.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] for an absent step; [`DomainError::InvalidTransition`]
    /// unless it waits for an open decision, or if the run ended; [`DomainError::Conflict`]
    /// when an item was not shown, the list changed since, or the run timed out.
    /// Returns [`DomainError::Forbidden`] as an approval step's approval is refused:
    /// rights, clearance, presence, the person acted for, the first approver or an author.
    pub fn approve_items(
        &mut self,
        key: &NodeKey,
        approver: &StepApprover<'_>,
        seen: &ItemsSeen,
    ) -> Result<LoopMoves<T>, DomainError> {
        let asking = self.asking_for_items(key)?;
        ensure_window_open(&asking.wait)?;
        approver.ensure_entitled(asking.looping.exposure)?;
        ensure_present_when_needed(&asking.approval, approver)?;
        let by = approver.by();
        self.ensure_may_approve(by, &asking.approval, &asking.wait)?;
        let items = u32::try_from(asking.looping.progress.items().len()).unwrap_or(u32::MAX);
        let shown = seen.every_item_shown(asking.opening, items)?;
        let granted = ExecutionRecord::step(
            key,
            StepRecord::ItemsApprovalGranted(ItemsShown {
                by: by.principal(),
                items,
                pages: shown.pages,
                every_item_at: shown.at,
            }),
        );
        let mut moves = self.decide_items(asking, by);
        moves.records.insert(0, granted);
        Ok(moves)
    }

    /// Records `by`'s approval of every item: the first of two keeps the
    /// loop waiting, the last lets its passes start.
    fn decide_items(&mut self, asking: AskingForItems, by: &Human) -> LoopMoves<T> {
        let AskingForItems {
            mut looping,
            approval,
            wait,
            ..
        } = asking;
        if approval.approvers_needed() == 2 && wait.first == FirstApproval::NotGiven {
            looping.progress.wait_for_approval(ApprovalWait {
                closes_at: wait.closes_at,
                first: FirstApproval::GivenBy(by.clone()),
            });
            self.keep_progress(looping.index, looping.progress);
            return LoopMoves::nothing();
        }
        looping.progress.approve_items(ItemsApproved {
            by: wait.first.completed_by(by),
            at: crate::shared::clock::now(),
        });
        self.go_on(looping)
    }

    /// The approval people are asked under at step `key`: an approval
    /// step's own while it waits for a decision, or the approval of every
    /// item a loop's passes wait for. `None` when nobody is asked there.
    #[must_use]
    pub fn asked_at(&self, key: &NodeKey) -> Option<&WorkflowApprovalStep> {
        let StepState::Running { underway, .. } = self.step(key)? else {
            return None;
        };
        underway.decision_wait()?;
        match self.graph.node(key)?.kind() {
            NodeKind::Approval(step) => Some(step),
            NodeKind::Loop(step) => step.items_approval().map(|(_, approval)| approval),
            NodeKind::AgentRun(_)
            | NodeKind::Action(_)
            | NodeKind::Condition(_)
            | NodeKind::Transform(_)
            | NodeKind::Wait(_)
            | NodeKind::Code(_)
            | NodeKind::Guardrail(_) => None,
        }
    }

    /// Lets this pass through its approval of every item, ready since it
    /// began, under the approval `by` gave its loop.
    ///
    /// It holds from now for its window, as a step approved now would, so
    /// the steps after it act on it while it is current.
    pub(super) fn let_through_items_approval(&mut self, by: &ApprovedBy) -> Vec<ExecutionRecord> {
        let Some(ready) = self.ready_items_approval() else {
            return Vec::new();
        };
        let closes_at = crate::shared::clock::now().saturating_add(ready.window);
        let hold = self.approval_hold(by.clone(), closes_at);
        self.succeed(
            ready.index,
            no_output(),
            ready.exposure,
            Holding::Approved(hold),
        )
    }

    /// This pass's approval of every item, when it stands ready.
    fn ready_items_approval(&self) -> Option<ReadyItemsApproval> {
        self.graph
            .nodes()
            .iter()
            .zip(&self.steps)
            .enumerate()
            .find_map(|(index, (node, state))| {
                let (NodeKind::Approval(step), StepState::Ready { exposure, .. }) =
                    (node.kind(), state)
                else {
                    return None;
                };
                (step.covers_items() == Covering::WholeLoop).then(|| ReadyItemsApproval {
                    index,
                    window: step.window().duration(),
                    exposure: *exposure,
                })
            })
    }

    /// The loop `key`, running and waiting for its approval of every item.
    fn asking_for_items(&self, key: &NodeKey) -> Result<AskingForItems, DomainError> {
        let running = self.running_step(key)?;
        let (NodeKind::Loop(step), Underway::Loop(progress)) =
            (running.node.kind().clone(), running.underway)
        else {
            return Err(not_asking());
        };
        let wait = progress
            .approval()
            .waiting()
            .cloned()
            .ok_or_else(not_asking)?;
        let approval = step
            .items_approval()
            .map(|(_, approval)| approval.clone())
            .ok_or_else(not_asking)?;
        let looping = Looping {
            index: running.index,
            key: key.clone(),
            step,
            exposure: running.exposure,
            progress,
        };
        Ok(AskingForItems {
            looping,
            approval,
            wait,
            opening: running.started_at,
        })
    }
}

/// Why a decision about every item of a loop is refused: the loop does
/// not wait for one.
fn not_asking() -> DomainError {
    DomainError::invalid_transition(message!(
        "workflows-this-loop-is-not-waiting-for-approval",
        "this loop is not waiting for an approval of its items"
    ))
}

/// Refuses a decision once the window closed.
fn ensure_window_open(wait: &ApprovalWait) -> Result<(), DomainError> {
    if crate::shared::clock::now() >= wait.closes_at {
        return Err(DomainError::invalid_transition(message!(
            "workflows-the-approval-s-decision-window-has",
            "the approval's decision window has closed"
        )));
    }
    Ok(())
}

/// The refusal of a yes given before every item was shown.
fn not_every_item_shown(shown: &Shown, items: u32) -> DomainError {
    DomainError::conflict(message!(
        "workflows-open-every-page-before-approving-every-item",
        format!(
            "open every page of the items before approving: {} of {items} items shown so far",
            shown.count()
        )
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::oversight::approval::Presence;
    use crate::domains::workflows::design::graph::{Edge, WorkflowGraph};
    use crate::domains::workflows::design::node::Port;
    use crate::domains::workflows::execution::record::ExecutionEnd;
    use crate::domains::workflows::execution::step::{LoopProgress, Pass, StepFailure};
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, approving_every_item, bob, cid, copy, deciding, each_running, edge, frozen_at,
        instant, key, listing, managing, started, state, stored,
    };
    use crate::domains::workflows::execution::{ExecutionStatus, WorkflowExecutionRow};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{ActionClass, DeclaredAction, WorkflowExecutionId};

    /// Ann's run lists `issues`, then loops over them two at a time: the
    /// loop's first step asks one approval of `class` for every issue, then
    /// a note is written for each.
    fn closing(issues: &[&str], class: DeclaredAction) -> Execution {
        let body = WorkflowGraph::new(
            vec![
                approving_every_item("approve-all", class),
                copy("note", &[("issue", "trigger.item")]),
            ],
            vec![Edge::new(key("approve-all"), Port::Next, key("note"))],
        )
        .unwrap();
        started(
            vec![
                listing("search", issues),
                each_running("each", "search.issues", body, 2),
            ],
            vec![edge("search", Port::Next, "each")],
        )
    }

    fn communicating() -> DeclaredAction {
        DeclaredAction::Declared(ActionClass::Communicate)
    }

    fn asked(issues: &[&str], class: DeclaredAction) -> Execution {
        let mut execution = closing(issues, class);
        execution.begin_loop(&key("each")).unwrap();
        execution
    }

    fn progress(execution: &Execution) -> LoopProgress {
        let StepState::Running {
            underway: Underway::Loop(progress),
            ..
        } = state(execution, "each")
        else {
            panic!("the loop is not running");
        };
        progress
    }

    /// Every page of `execution`'s items, `per_page` at a time, opened at
    /// `at`.
    fn every_page(execution: &Execution, per_page: u32, at: OffsetDateTime) -> ItemsSeen {
        let asked = execution
            .items_shown_to(&key("each"), &deciding(&bob()))
            .unwrap();
        let items = u32::try_from(asked.items.len()).unwrap();
        let pages = (0..items)
            .step_by(usize::try_from(per_page).unwrap())
            .map(|first| SeenPage {
                opening: asked.opening,
                first,
                count: per_page.min(items - first),
                at,
            })
            .collect();
        ItemsSeen::new(pages)
    }

    fn approve_all(
        execution: &mut Execution,
        by: &Human,
    ) -> Result<LoopMoves<ResolvedTenant>, DomainError> {
        let seen = every_page(execution, 2, crate::shared::clock::now());
        execution.approve_items(&key("each"), &deciding(by), &seen)
    }

    /// The loop asks one approval for every issue before anything happens:
    /// no pass starts, and it waits for a decision within the hour.
    #[test]
    fn a_loop_asking_for_every_item_starts_no_pass_until_approved() {
        let _clock = frozen_at(0);
        let mut execution = closing(&["a", "b", "c"], communicating());

        let moves = execution.begin_loop(&key("each")).unwrap();

        assert!(moves.started.is_empty());
        assert!(progress(&execution).passes().is_empty());
        assert_eq!(execution.approval_closes(&key("each")), Some(instant(3600)));
        assert!(execution.asked_at(&key("each")).is_some());
    }

    /// Bob may decide and is shown all three issues, fixed when the loop
    /// asked, in the order the passes take them.
    #[test]
    fn an_approver_is_shown_every_item_in_order() {
        let execution = asked(&["a", "b", "c"], communicating());

        let shown = execution
            .items_shown_to(&key("each"), &deciding(&bob()))
            .unwrap();

        assert_eq!(
            shown.items,
            ["a", "b", "c"].map(|item| FlowData::text(item).unwrap())
        );
    }

    /// Bob, cleared only for public data, cannot see items the loop was
    /// handed at internal.
    #[test]
    fn an_approver_not_cleared_for_the_items_sees_none() {
        let execution = asked(&["a"], communicating());
        let bob = bob();
        let uncleared =
            StepApprover::assumed(managing(&bob), DataClassLevel::Public, Presence::Proven);

        let shown = execution.items_shown_to(&key("each"), &uncleared);

        assert!(matches!(shown, Err(DomainError::Forbidden(_))));
    }

    /// Bob opens the first page of two issues out of three and says yes.
    /// It is refused, and the loop keeps waiting with no pass started.
    #[test]
    fn a_yes_before_every_page_was_opened_is_refused() {
        let mut execution = asked(&["a", "b", "c"], communicating());
        let opening = execution
            .items_shown_to(&key("each"), &deciding(&bob()))
            .unwrap()
            .opening;
        let first_page = ItemsSeen::new(vec![SeenPage {
            opening,
            first: 0,
            count: 2,
            at: crate::shared::clock::now(),
        }]);

        let approved = execution.approve_items(&key("each"), &deciding(&bob()), &first_page);

        assert!(matches!(approved, Err(DomainError::Conflict(_))));
        assert!(progress(&execution).passes().is_empty());
    }

    /// Bob opens both pages and says yes. The record names him, the three
    /// issues and when he saw the last of them. Every pass starts, goes
    /// through its approval step under his approval, and having only a
    /// note to write, ends at once.
    #[test]
    fn a_yes_after_every_page_starts_the_passes_and_records_what_was_shown() {
        let mut execution = asked(&["a", "b", "c"], communicating());
        let at = crate::shared::clock::now();
        let seen = every_page(&execution, 2, at);

        let moves = execution
            .approve_items(&key("each"), &deciding(&bob()), &seen)
            .unwrap();

        assert_eq!(
            moves.records.first(),
            Some(&ExecutionRecord::step(
                &key("each"),
                StepRecord::ItemsApprovalGranted(ItemsShown {
                    by: bob().principal(),
                    items: 3,
                    pages: 2,
                    every_item_at: at,
                })
            ))
        );
        assert_eq!(moves.started.len(), 3);
        let pass = &moves.started[0].execution;
        assert!(matches!(
            state(pass, "approve-all"),
            StepState::Succeeded {
                holds: Holding::Approved(_),
                ..
            }
        ));
    }

    /// The passes through Bob's approval are stored and read back as they
    /// are, as is the run whose loop he approved.
    #[test]
    fn an_approved_loop_and_its_passes_are_read_back() {
        let mut execution = asked(
            &["a", "b", "c"],
            DeclaredAction::Declared(ActionClass::Write),
        );
        let moves = approve_all(&mut execution, &bob()).unwrap();

        assert!(Execution::reconstitute(stored(&execution)).is_ok());
        for start in &moves.started {
            assert!(Execution::reconstitute(stored(&start.execution)).is_ok());
        }
    }

    /// A payment over every item needs two people. Bob's yes is recorded
    /// and the loop keeps waiting; Bob again is refused; Cid's yes starts
    /// the passes.
    #[test]
    fn approving_every_item_of_a_payment_needs_two_different_people() {
        let mut execution = asked(
            &["a", "b"],
            DeclaredAction::Declared(ActionClass::Financial),
        );

        let first = approve_all(&mut execution, &bob()).unwrap();
        let again = approve_all(&mut execution, &bob());
        let second = approve_all(&mut execution, &cid()).unwrap();

        assert!(first.started.is_empty());
        assert_eq!(first.records.len(), 1);
        assert!(matches!(again, Err(DomainError::Forbidden(_))));
        assert_eq!(second.started.len(), 2);
    }

    /// Bob says no. The loop fails before any pass ran, and the run fails.
    #[test]
    fn a_no_stops_the_loop_with_no_pass_run() {
        let mut execution = asked(&["a", "b"], communicating());

        execution.deny(&key("each"), &deciding(&bob())).unwrap();

        assert_eq!(
            state(&execution, "each"),
            StepState::Failed(StepFailure::ApprovalDenied(bob().principal()))
        );
        assert_eq!(
            execution.status(),
            ExecutionStatus::Ended(ExecutionEnd::Failed)
        );
    }

    /// Nobody decides within the hour. A yes at 3600 is refused, and the
    /// loop lapses instead.
    #[test]
    fn an_approval_of_every_item_lapses_when_its_window_closes() {
        let clock = frozen_at(0);
        let mut execution = asked(&["a"], communicating());
        let seen = every_page(&execution, 2, instant(10));
        drop(clock);
        let _later = frozen_at(3600);

        let late = execution.approve_items(&key("each"), &deciding(&bob()), &seen);
        execution.lapse_approval(&key("each")).unwrap();

        assert!(matches!(late, Err(DomainError::InvalidTransition(_))));
        assert_eq!(
            state(&execution, "each"),
            StepState::Failed(StepFailure::ApprovalLapsed)
        );
    }

    /// Bob opened every page of a list since replaced by a loop started
    /// again. His yes is refused: those pages showed other items.
    #[test]
    fn pages_of_an_earlier_list_do_not_count() {
        let mut execution = asked(&["a", "b"], communicating());
        let earlier = ItemsSeen::new(vec![SeenPage {
            opening: instant(-60),
            first: 0,
            count: 2,
            at: instant(-30),
        }]);

        let approved = execution.approve_items(&key("each"), &deciding(&bob()), &earlier);

        assert!(matches!(approved, Err(DomainError::Conflict(_))));
    }

    /// Pages Bob opened out of order, one twice, count once each: the yes
    /// counts from when the last unseen issue was shown.
    #[test]
    fn the_yes_counts_from_when_the_last_unseen_item_was_shown() {
        let seen = ItemsSeen::new(vec![
            SeenPage {
                opening: instant(0),
                first: 2,
                count: 1,
                at: instant(30),
            },
            SeenPage {
                opening: instant(0),
                first: 0,
                count: 2,
                at: instant(10),
            },
            SeenPage {
                opening: instant(0),
                first: 0,
                count: 2,
                at: instant(20),
            },
        ]);

        let shown = seen.every_item_shown(instant(0), 3).unwrap();

        assert_eq!(shown.at, instant(30));
        assert_eq!(shown.pages, 3);
        assert_eq!(seen.items_shown(instant(0), 3), 3);
        assert_eq!(seen.items_shown(instant(0), 5), 3);
    }

    /// A stored loop still asking about every item, yet with a pass started,
    /// is refused as corrupt.
    #[test]
    fn a_stored_loop_asking_with_a_pass_started_is_corrupt() {
        let execution = asked(&["a", "b"], communicating());
        let mut broken = progress(&execution);
        broken
            .passes_mut()
            .push(Pass::Running(WorkflowExecutionId::new()));
        let steps = execution
            .steps()
            .map(|(_, step)| match step {
                StepState::Running {
                    exposure,
                    seen,
                    underway: Underway::Loop(_),
                    started_at,
                } => StepState::Running {
                    exposure: *exposure,
                    seen: seen.clone(),
                    underway: Underway::Loop(broken.clone()),
                    started_at: *started_at,
                },
                other => other.clone(),
            })
            .collect();
        let row = WorkflowExecutionRow {
            steps,
            ..stored(&execution)
        };

        assert!(Execution::reconstitute(stored(&execution)).is_ok());
        assert!(refused_as_corrupt(&Execution::reconstitute(row)));
    }
}
