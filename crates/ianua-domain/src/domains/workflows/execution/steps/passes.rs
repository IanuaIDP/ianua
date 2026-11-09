//! How far a running loop step's passes have got: the items, what every
//! pass is given beside its item, each pass started so far, and whether
//! the passes wait for one approval of every item.

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::execution::step::{ApprovalWait, ApprovedBy};
use crate::types::WorkflowExecutionId;

/// How far a loop step's passes have got.
///
/// Passes start in the order of the items, at most the loop's number at
/// once. Each runs as an execution of its own and reports back here when
/// it ends.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoopProgress {
    items: Vec<FlowData>,
    shared: FlowData,
    passes: Vec<Pass>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "ItemsApproval::is_not_asked")
    )]
    approval: ItemsApproval,
}

impl LoopProgress {
    /// No pass started yet, over `items`, each pass also given `shared`.
    pub(in crate::domains::workflows::execution) fn new(
        items: Vec<FlowData>,
        shared: FlowData,
    ) -> Self {
        Self {
            items,
            shared,
            passes: Vec::new(),
            approval: ItemsApproval::NotAsked,
        }
    }

    /// Whether the passes wait for one approval of every item, and how it
    /// stands.
    #[must_use]
    pub fn approval(&self) -> &ItemsApproval {
        &self.approval
    }

    /// Whether a pass may start as far as the approval of every item goes.
    #[must_use]
    pub fn lets_passes_start(&self) -> bool {
        match self.approval {
            ItemsApproval::NotAsked | ItemsApproval::Given(_) => true,
            ItemsApproval::Waiting(_) => false,
        }
    }

    /// Holds every pass until people approve all the items under `wait`,
    /// or until its window closes.
    pub(in crate::domains::workflows::execution) fn wait_for_approval(
        &mut self,
        wait: ApprovalWait,
    ) {
        self.approval = ItemsApproval::Waiting(wait);
    }

    /// Lets the passes start: `approved` said yes to every item.
    pub(in crate::domains::workflows::execution) fn approve_items(
        &mut self,
        approved: ItemsApproved,
    ) {
        self.approval = ItemsApproval::Given(approved);
    }

    /// The items, one pass each.
    #[must_use]
    pub fn items(&self) -> &[FlowData] {
        &self.items
    }

    /// What every pass is given beside its item: the fields the loop's
    /// inputs mapped from its input.
    #[must_use]
    pub fn shared(&self) -> &FlowData {
        &self.shared
    }

    /// Each pass started so far, in the order of the items.
    #[must_use]
    pub fn passes(&self) -> &[Pass] {
        &self.passes
    }

    /// The executions of the passes still running.
    pub fn running(&self) -> impl Iterator<Item = &WorkflowExecutionId> {
        self.passes.iter().filter_map(|pass| match pass {
            Pass::Running(id) => Some(id),
            Pass::Done { .. } => None,
        })
    }

    /// The execution each pass started so far runs, or ran, as.
    pub fn executions(&self) -> impl Iterator<Item = &WorkflowExecutionId> {
        self.passes.iter().map(|pass| match pass {
            Pass::Running(id) | Pass::Done { execution: id, .. } => id,
        })
    }

    /// How many passes ended and gave back what they made.
    #[must_use]
    pub fn done(&self) -> usize {
        self.passes
            .iter()
            .filter(|pass| matches!(pass, Pass::Done { .. }))
            .count()
    }

    /// How large, together, what the finished passes gave back is.
    #[must_use]
    pub fn output_size(&self) -> usize {
        self.passes
            .iter()
            .filter_map(|pass| match pass {
                Pass::Done { output, .. } => Some(output.size()),
                Pass::Running(_) => None,
            })
            .fold(0, usize::saturating_add)
    }

    pub(in crate::domains::workflows::execution) fn passes_mut(&mut self) -> &mut Vec<Pass> {
        &mut self.passes
    }
}

/// Whether a loop's passes wait for one approval of every item first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ItemsApproval {
    /// Nobody is asked about every item: the loop's steps hold no such
    /// approval, or a test stands in for it. Loops stored before such
    /// approvals existed asked nobody, so it is what a stored loop names by
    /// default.
    #[default]
    NotAsked,
    /// People are asked about every item, and no pass starts until they
    /// approve within the window.
    Waiting(ApprovalWait),
    /// People approved every item, so every pass goes through the loop's
    /// approval step.
    Given(ItemsApproved),
}

impl ItemsApproval {
    /// Whether nobody is asked about every item, which a stored loop leaves
    /// unsaid.
    #[must_use]
    pub fn is_not_asked(&self) -> bool {
        matches!(self, Self::NotAsked)
    }

    /// The decision the passes wait for; `None` once given or when nobody
    /// is asked.
    #[must_use]
    pub fn waiting(&self) -> Option<&ApprovalWait> {
        match self {
            Self::Waiting(wait) => Some(wait),
            Self::NotAsked | Self::Given(_) => None,
        }
    }
}

/// The approval of every item of a loop, once given.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ItemsApproved {
    /// The people who approved, each shown every item first.
    pub by: ApprovedBy,
    /// When the approval that let the passes start was given.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::domains::workflows::stored::instant")
    )]
    pub at: OffsetDateTime,
}

/// One pass of a loop step.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Pass {
    /// It runs as this execution.
    Running(WorkflowExecutionId),
    /// It ended, giving back this.
    Done {
        /// The execution it ran as.
        execution: WorkflowExecutionId,
        /// What its last steps produced, under their keys.
        output: FlowData,
        /// The most sensitive data in it.
        exposure: DataClassLevel,
    },
}
