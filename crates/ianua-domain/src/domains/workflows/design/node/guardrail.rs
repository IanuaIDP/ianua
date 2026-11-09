//! Guardrail steps: a check of a text from an earlier step before the
//! workflow goes on with it.
//!
//! Pat's workflow has an agent draft a reply to a customer. A guardrail
//! after it checks the draft for personal data, for attempts to trick a
//! model and for the company's banned words. What a finding does is Pat's
//! choice for the step: stop the run (the default), remove what was found
//! and go on, or go on and only record it. A check that cannot run stops
//! the run whatever Pat chose.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::DataPath;
use crate::domains::workflows::guardrail::banned::BannedWords;
use crate::domains::workflows::guardrail::finding::GuardrailCheck;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;

/// What a guardrail's finding does to the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum OnFinding {
    /// The step fails, and with it the run.
    #[default]
    Stop,
    /// What was found is taken out, as the gateway takes a classified field
    /// out of an app's answer, and the run goes on with the rest.
    Remove,
    /// The run goes on with the text as it was, and the findings are
    /// recorded.
    Record,
}

/// The values to make a guardrail step of, before they are checked.
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct GuardrailParams {
    /// Where the text to check is in the step's input, such as
    /// `draft.answer`.
    pub text: DataPath,
    /// The checks it runs, each once.
    pub checks: Vec<GuardrailCheck>,
    /// The least sensitive level a classified field counts as personal
    /// data at.
    pub personal_from: DataClassLevel,
    /// The words it bans, given exactly when it checks for banned words.
    #[cfg_attr(feature = "serde", serde(default))]
    pub banned: BannedWords,
    /// What a finding does.
    #[cfg_attr(feature = "serde", serde(default))]
    pub on_finding: OnFinding,
}

/// A check of one text from an earlier step.
///
/// It runs at least one check, each once. It bans words exactly when it
/// checks for them: a banned-words check with no word would pass every
/// text, and words with no check would read as banned while nothing looks
/// for them. A classified field counts as personal data from the level
/// [`personal_from`](Self::personal_from) up, internal at the lowest, since
/// public data is nobody's personal data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "GuardrailParams"))]
pub struct GuardrailStep {
    text: DataPath,
    checks: Vec<GuardrailCheck>,
    personal_from: DataClassLevel,
    banned: BannedWords,
    on_finding: OnFinding,
}

impl GuardrailStep {
    /// A guardrail step.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for no check, or one named twice.
    /// - [`DomainError::Validation`] for banned words without the check for
    ///   them, or that check without a word.
    /// - [`DomainError::Validation`] when public data counts as personal.
    pub fn new(params: GuardrailParams) -> Result<Self, DomainError> {
        validate_count("checks", params.checks.len(), 1..=GuardrailCheck::ALL.len())?;
        if first_repeat(&params.checks).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-a-guardrail-check-is-named-twice",
                "a guardrail check is named twice"
            )));
        }
        ensure_banned_words_fit(&params)?;
        if params.personal_from == DataClassLevel::Public {
            return Err(DomainError::invalid(message!(
                "workflows-public-data-is-not-personal-data",
                "public data is not personal data: count it from internal up"
            )));
        }
        Ok(Self {
            text: params.text,
            checks: params.checks,
            personal_from: params.personal_from,
            banned: params.banned,
            on_finding: params.on_finding,
        })
    }

    /// Where the text it checks is in its input.
    #[must_use]
    pub fn text(&self) -> &DataPath {
        &self.text
    }

    /// The checks it runs.
    #[must_use]
    pub fn checks(&self) -> &[GuardrailCheck] {
        &self.checks
    }

    /// Whether it runs `check`.
    #[must_use]
    pub fn runs(&self, check: GuardrailCheck) -> bool {
        self.checks.contains(&check)
    }

    /// The least sensitive level a classified field counts as personal
    /// data at.
    #[must_use]
    pub fn personal_from(&self) -> DataClassLevel {
        self.personal_from
    }

    /// The words it bans.
    #[must_use]
    pub fn banned(&self) -> &BannedWords {
        &self.banned
    }

    /// What a finding does.
    #[must_use]
    pub fn on_finding(&self) -> OnFinding {
        self.on_finding
    }
}

impl TryFrom<GuardrailParams> for GuardrailStep {
    type Error = DomainError;

    fn try_from(params: GuardrailParams) -> Result<Self, Self::Error> {
        Self::new(params)
    }
}

/// Refuses banned words without the check for them, and the check without
/// a word.
fn ensure_banned_words_fit(params: &GuardrailParams) -> Result<(), DomainError> {
    let checked = params.checks.contains(&GuardrailCheck::BannedWords);
    match (checked, params.banned.is_empty()) {
        (true, true) => Err(DomainError::invalid(message!(
            "workflows-a-banned-words-check-needs-a-word",
            "a banned-words check needs at least one word to look for"
        ))),
        (false, false) => Err(DomainError::invalid(message!(
            "workflows-banned-words-need-their-check",
            "banned words are given but the step does not check for them"
        ))),
        (true, false) | (false, true) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::guardrail::banned::BannedWord;

    fn params(checks: Vec<GuardrailCheck>, banned: &[&str]) -> GuardrailParams {
        GuardrailParams {
            text: DataPath::parse("draft.answer").unwrap(),
            checks,
            personal_from: DataClassLevel::Confidential,
            banned: BannedWords::new(
                banned
                    .iter()
                    .map(|word| BannedWord::new(*word).unwrap())
                    .collect(),
            )
            .unwrap(),
            on_finding: OnFinding::default(),
        }
    }

    /// Pat's guardrail checks the draft for personal data and model tricks.
    /// It stops the run on a finding unless Pat says otherwise.
    #[test]
    fn a_guardrail_stops_the_run_by_default() {
        let step = GuardrailStep::new(params(
            vec![GuardrailCheck::PersonalData, GuardrailCheck::ModelTricks],
            &[],
        ))
        .unwrap();

        assert_eq!(step.on_finding(), OnFinding::Stop);
        assert!(step.runs(GuardrailCheck::ModelTricks));
        assert!(!step.runs(GuardrailCheck::BannedWords));
    }

    /// A guardrail that checks nothing would pass every text, and is
    /// refused.
    #[test]
    fn a_guardrail_with_no_check_is_refused() {
        assert!(GuardrailStep::new(params(Vec::new(), &[])).is_err());
    }

    /// A banned-words check with no word, and words with no check, are both
    /// refused; the check with "guaranteed returns" is kept.
    #[test]
    fn banned_words_come_exactly_with_their_check() {
        let no_word = GuardrailStep::new(params(vec![GuardrailCheck::BannedWords], &[]));
        let no_check = GuardrailStep::new(params(
            vec![GuardrailCheck::PersonalData],
            &["guaranteed returns"],
        ));
        let both = GuardrailStep::new(params(
            vec![GuardrailCheck::BannedWords],
            &["guaranteed returns"],
        ));

        assert!(matches!(no_word, Err(DomainError::Validation(_))));
        assert!(matches!(no_check, Err(DomainError::Validation(_))));
        assert!(both.is_ok());
    }

    /// Counting public fields as personal data would flag what anyone may
    /// see, so it is refused.
    #[test]
    fn public_data_is_not_counted_as_personal() {
        let mut public = params(vec![GuardrailCheck::PersonalData], &[]);
        public.personal_from = DataClassLevel::Public;

        assert!(GuardrailStep::new(public).is_err());
    }
}
