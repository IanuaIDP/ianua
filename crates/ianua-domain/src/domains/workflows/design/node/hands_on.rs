//! What each kind of step gives the steps after it, so a builder can be
//! shown what they may read from it.

use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::design::node::NodeKind;

/// What a step gives the steps after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandsOn<'a> {
    /// Nothing: it decides a way on, waits, or waits for a person.
    Nothing,
    /// The agent's answer, under [`ANSWER_FIELD`](crate::domains::workflows::execution::ANSWER_FIELD).
    Answer,
    /// These fields, as a transform builds them.
    Fields(Vec<&'a FieldName>),
    /// Whatever its code or its passes give back, whose shape only a run
    /// shows.
    Whole,
    /// What its operation's guide says it gives back.
    OperationOutputs,
    /// The value a guardrail checked, its findings and how many there
    /// were, under the fields [`guardrail`](crate::domains::workflows::guardrail)
    /// names.
    Guarded,
}

impl<'a> HandsOn<'a> {
    /// What a step of `kind` gives the steps after it.
    #[must_use]
    pub fn of(kind: &'a NodeKind) -> Self {
        match kind {
            NodeKind::AgentRun(_) => Self::Answer,
            NodeKind::Transform(mapping) => {
                Self::Fields(mapping.fields().iter().map(|(name, _)| name).collect())
            }
            NodeKind::Action(_) => Self::OperationOutputs,
            NodeKind::Code(_) | NodeKind::Loop(_) => Self::Whole,
            NodeKind::Guardrail(_) => Self::Guarded,
            NodeKind::Condition(_) | NodeKind::Approval(_) | NodeKind::Wait(_) => Self::Nothing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::{DataPath, FlowData};
    use crate::domains::workflows::design::condition::{Clause, ConditionRule, Matching, Test};
    use crate::domains::workflows::design::node::{Mapping, Source};

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    /// A transform hands on the fields it builds and a condition hands on
    /// nothing, so a builder is offered exactly what each gives.
    #[test]
    fn each_kind_says_what_it_hands_on() {
        let rule = ConditionRule::new(
            Matching::All,
            vec![Clause::new(DataPath::parse("ok").unwrap(), Test::Exists).unwrap()],
        )
        .unwrap();
        let transform = Mapping::new(vec![
            (field("customer"), Source::Literal(FlowData::null())),
            (field("order"), Source::Literal(FlowData::null())),
        ])
        .unwrap();
        let kind = NodeKind::Transform(transform);

        assert_eq!(
            HandsOn::of(&kind),
            HandsOn::Fields(vec![&field("customer"), &field("order")])
        );
        assert_eq!(HandsOn::of(&NodeKind::Condition(rule)), HandsOn::Nothing);
    }
}
