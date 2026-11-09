//! A guardrail step on the wire: which checks it runs, what a finding
//! does, and the words it bans.

use ianua_domain::domains::workflows::data::DataPath;
use ianua_domain::domains::workflows::design::node::{
    GuardrailParams, GuardrailStep, NodeKind, OnFinding,
};
use ianua_domain::domains::workflows::guardrail::banned::{BannedWord, BannedWords};
use ianua_domain::domains::workflows::guardrail::finding::GuardrailCheck;
use serde::{Deserialize, Serialize};

use crate::dto::workflows::data::data_class;
use crate::dto::workflows::graph::StepBody;
use crate::error::ApiError;

/// One check a guardrail runs.
#[derive(Serialize, Deserialize, utoipa::ToSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuardrailCheckBody {
    /// Fields the tenant's classification rules hold at `personal_from` or
    /// above, and email addresses, card numbers and IBANs written in text.
    PersonalData,
    /// Known ways of trying to trick a model, such as "ignore all previous
    /// instructions" or a chat model's speaker marker.
    ModelTricks,
    /// Any word the company banned, listed in `banned_words` on the step.
    BannedWords,
}

impl From<GuardrailCheckBody> for GuardrailCheck {
    fn from(body: GuardrailCheckBody) -> Self {
        match body {
            GuardrailCheckBody::PersonalData => Self::PersonalData,
            GuardrailCheckBody::ModelTricks => Self::ModelTricks,
            GuardrailCheckBody::BannedWords => Self::BannedWords,
        }
    }
}

impl From<GuardrailCheck> for GuardrailCheckBody {
    fn from(check: GuardrailCheck) -> Self {
        match check {
            GuardrailCheck::PersonalData => Self::PersonalData,
            GuardrailCheck::ModelTricks => Self::ModelTricks,
            GuardrailCheck::BannedWords => Self::BannedWords,
        }
    }
}

/// What a guardrail's finding does to the run.
#[derive(Serialize, Deserialize, utoipa::ToSchema, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OnFindingBody {
    /// The step fails, and the run with it.
    #[default]
    Stop,
    /// What was found is taken out and the run goes on: a classified field
    /// as its rule hides it, anything in a text masked as `***`.
    Remove,
    /// The run goes on with the text as it was; the findings are recorded.
    Record,
}

impl From<OnFindingBody> for OnFinding {
    fn from(body: OnFindingBody) -> Self {
        match body {
            OnFindingBody::Stop => Self::Stop,
            OnFindingBody::Remove => Self::Remove,
            OnFindingBody::Record => Self::Record,
        }
    }
}

impl From<OnFinding> for OnFindingBody {
    fn from(on_finding: OnFinding) -> Self {
        match on_finding {
            OnFinding::Stop => Self::Stop,
            OnFinding::Remove => Self::Remove,
            OnFinding::Record => Self::Record,
        }
    }
}

/// The guardrail step a body's fields describe, before they are checked.
pub(crate) struct GuardrailClaim {
    /// Where the text is in the step's input.
    pub(crate) text: String,
    /// The checks it runs.
    pub(crate) checks: Vec<GuardrailCheckBody>,
    /// The least sensitive level a classified field counts as personal
    /// data at.
    pub(crate) personal_from: String,
    /// The words it bans.
    pub(crate) banned_words: Vec<String>,
    /// What a finding does.
    pub(crate) on_finding: OnFindingBody,
}

impl GuardrailClaim {
    /// The step, refused when a field or the combination is not valid.
    pub(crate) fn kind(self) -> Result<NodeKind, ApiError> {
        let banned = self
            .banned_words
            .into_iter()
            .map(BannedWord::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::validation)?;
        GuardrailStep::new(GuardrailParams {
            text: DataPath::parse(&self.text).map_err(ApiError::validation)?,
            checks: self.checks.into_iter().map(GuardrailCheck::from).collect(),
            personal_from: data_class(&self.personal_from)?,
            banned: BannedWords::new(banned).map_err(ApiError::validation)?,
            on_finding: self.on_finding.into(),
        })
        .map(NodeKind::Guardrail)
        .map_err(ApiError::validation)
    }
}

impl From<&GuardrailStep> for StepBody {
    fn from(step: &GuardrailStep) -> Self {
        Self::Guardrail {
            text: step.text().to_string(),
            checks: step
                .checks()
                .iter()
                .copied()
                .map(GuardrailCheckBody::from)
                .collect(),
            personal_from: step.personal_from().as_str().to_owned(),
            banned_words: step
                .banned()
                .words()
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            on_finding: step.on_finding().into(),
        }
    }
}

/// The level a guardrail counts personal data from when the body names
/// none.
pub(crate) fn confidential() -> String {
    "confidential".to_owned()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::design::node::Node;
    use serde_json::json;

    use super::*;
    use crate::dto::workflows::graph::NodeBody;

    /// The step the step body `value` makes, as a saved draft would.
    fn step(value: serde_json::Value) -> Result<Node, ApiError> {
        Node::try_from(serde_json::from_value::<NodeBody>(value).unwrap())
    }

    /// A guardrail sent with only its text and checks stops on a finding
    /// and counts personal data from confidential up, and is read back with
    /// those defaults written out.
    #[test]
    fn a_guardrail_reads_back_with_its_defaults() {
        let node = step(json!({
            "key": "guard",
            "name": "Check the draft",
            "kind": "guardrail",
            "text": "draft.answer",
            "checks": ["personal_data", "model_tricks"],
        }))
        .ok()
        .unwrap();

        let NodeKind::Guardrail(guard) = node.kind() else {
            panic!("a guardrail body made another kind of step");
        };
        assert_eq!(guard.on_finding(), OnFinding::Stop);
        assert_eq!(
            serde_json::to_value(NodeBody::from(&node)).unwrap(),
            json!({
                "key": "guard",
                "name": "Check the draft",
                "join": "all",
                "kind": "guardrail",
                "text": "draft.answer",
                "checks": ["personal_data", "model_tricks"],
                "personal_from": "confidential",
                "banned_words": [],
                "on_finding": "stop",
            })
        );
    }

    /// Banned words sent without the check for them are refused as a bad
    /// request, never stored as a list nothing looks for.
    #[test]
    fn banned_words_without_their_check_are_refused() {
        let sent = step(json!({
            "key": "guard",
            "name": "Check the draft",
            "kind": "guardrail",
            "text": "draft.answer",
            "checks": ["model_tricks"],
            "banned_words": ["guaranteed returns"],
        }));

        assert!(sent.is_err());
    }
}
