//! Where each step of a version sits on the builder's canvas, and who is
//! told when one of its runs fails.
//!
//! The layout is a picture only. No run, publish rule or approval ever reads
//! it, so moving a step changes nothing a run does, and the revision a
//! publisher reviewed stays the same.

use crate::domains::workflows::design::graph::{MAX_NODES, WorkflowGraph};
use crate::domains::workflows::design::node::NodeKey;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::{validate_count, validate_range};

/// The farthest a step may sit from the canvas's corner, either way.
pub(crate) const MAX_CANVAS_OFFSET: u32 = 20_000;

/// Where one step sits on the canvas, in points from its top left corner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepPosition {
    x: u32,
    y: u32,
}

impl StepPosition {
    /// A step `x` points from the left and `y` from the top.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when either is past
    ///   `MAX_CANVAS_OFFSET`.
    pub fn new(x: u32, y: u32) -> Result<Self, DomainError> {
        validate_range("step_x", x, 0..=MAX_CANVAS_OFFSET)?;
        validate_range("step_y", y, 0..=MAX_CANVAS_OFFSET)?;
        Ok(Self { x, y })
    }

    /// Points from the left.
    #[must_use]
    pub fn x(self) -> u32 {
        self.x
    }

    /// Points from the top.
    #[must_use]
    pub fn y(self) -> u32 {
        self.y
    }
}

/// Where the steps of one version sit. A step it does not place is put
/// wherever the builder chooses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanvasLayout {
    positions: Vec<(NodeKey, StepPosition)>,
}

impl CanvasLayout {
    /// A layout placing each step once, in the order given.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it places more steps than a graph
    ///   holds.
    /// - [`DomainError::Validation`] when it places one step twice.
    pub fn new(positions: Vec<(NodeKey, StepPosition)>) -> Result<Self, DomainError> {
        validate_count("layout_steps", positions.len(), 0..=MAX_NODES)?;
        if first_repeat(positions.iter().map(|(key, _)| key)).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-a-layout-places-each-step-once",
                "a layout places each step once"
            )));
        }
        Ok(Self { positions })
    }

    /// Refuses this layout unless every step it places is in `graph`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it places a step `graph` does not
    ///   have.
    pub fn ensure_fits(&self, graph: &WorkflowGraph) -> Result<(), DomainError> {
        let Some((stray, _)) = self
            .positions
            .iter()
            .find(|(key, _)| graph.node(key).is_none())
        else {
            return Ok(());
        };
        Err(DomainError::invalid(message!(
            "workflows-the-layout-places-a-step-the",
            format!("the layout places {stray}, which the workflow does not have")
        )))
    }

    /// This layout without the steps `graph` no longer has, so replacing a
    /// draft's steps keeps where the remaining ones sit.
    #[must_use]
    pub fn fitted_to(&self, graph: &WorkflowGraph) -> Self {
        let positions = self
            .positions
            .iter()
            .filter(|(key, _)| graph.node(key).is_some())
            .cloned()
            .collect();
        Self { positions }
    }

    /// Where `key` sits, if this layout places it.
    #[must_use]
    pub fn position_of(&self, key: &NodeKey) -> Option<StepPosition> {
        self.positions
            .iter()
            .find(|(placed, _)| placed == key)
            .map(|(_, position)| *position)
    }

    /// Each step it places and where, in the order given.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeKey, StepPosition)> {
        self.positions
            .iter()
            .map(|(key, position)| (key, *position))
    }
}

/// Who is told when a run of a version fails or runs out of time.
///
/// The tenant's administrators always are, as each of them chose to be
/// reached. A version may tell the people who wrote it too, who may not
/// administer the tenant at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FailureAlert {
    /// The tenant's administrators, as for any failed run.
    #[default]
    Administrators,
    /// Its authors too.
    AlsoAuthors,
}

impl FailureAlert {
    /// The stored name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Administrators => "administrators",
            Self::AlsoAuthors => "also_authors",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] on a name no alert has.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "administrators" => Ok(Self::Administrators),
            "also_authors" => Ok(Self::AlsoAuthors),
            _ => Err(DomainError::corrupt_row(
                "workflow",
                "an unknown failure alert",
            )),
        }
    }

    /// Whether its authors are told too.
    #[must_use]
    pub fn tells_authors(self) -> bool {
        self == Self::AlsoAuthors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::design::node::Port;
    use crate::domains::workflows::execution::tests::fixtures::{edge, wait};

    fn key(value: &str) -> NodeKey {
        NodeKey::new(value).unwrap()
    }

    fn at(x: u32, y: u32) -> StepPosition {
        StepPosition::new(x, y).unwrap()
    }

    fn two_steps() -> WorkflowGraph {
        WorkflowGraph::new(
            vec![wait("first"), wait("second")],
            vec![edge("first", Port::Next, "second")],
        )
        .unwrap()
    }

    /// Ann places both steps of her draft. The layout fits it, and each
    /// step reads back where she put it.
    #[test]
    fn a_layout_of_the_graphs_steps_fits() {
        let layout = CanvasLayout::new(vec![
            (key("first"), at(40, 300)),
            (key("second"), at(340, 300)),
        ])
        .unwrap();

        assert!(layout.ensure_fits(&two_steps()).is_ok());
        assert_eq!(layout.position_of(&key("second")), Some(at(340, 300)));
    }

    /// Layout validation rejects a missing step, a duplicate placement and a
    /// position beyond the canvas limit.
    #[test]
    fn a_layout_that_does_not_fit_is_refused() {
        let stray = CanvasLayout::new(vec![(key("gone"), at(0, 0))]).unwrap();
        let twice = CanvasLayout::new(vec![(key("first"), at(0, 0)), (key("first"), at(10, 10))]);

        assert!(stray.ensure_fits(&two_steps()).is_err());
        assert!(twice.is_err());
        assert!(StepPosition::new(MAX_CANVAS_OFFSET + 1, 0).is_err());
    }

    /// Ann removes a step from her draft. The layout keeps where the other
    /// sits and forgets the removed one.
    #[test]
    fn fitting_to_a_smaller_graph_keeps_the_remaining_steps() {
        let layout =
            CanvasLayout::new(vec![(key("first"), at(40, 300)), (key("gone"), at(9, 9))]).unwrap();

        let fitted = layout.fitted_to(&two_steps());

        assert_eq!(fitted.position_of(&key("first")), Some(at(40, 300)));
        assert_eq!(fitted.position_of(&key("gone")), None);
    }

    /// A stored alert reads back as written, and an unknown one is refused
    /// as a corrupt row.
    #[test]
    fn failure_alerts_read_back_and_refuse_unknown_names() {
        for alert in [FailureAlert::Administrators, FailureAlert::AlsoAuthors] {
            assert_eq!(FailureAlert::from_stored(alert.as_str()).unwrap(), alert);
        }

        assert!(matches!(
            FailureAlert::from_stored("everyone"),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
