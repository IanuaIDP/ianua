//! What a guardrail found, and where: never the text it matched.
//!
//! A finding names its kind and its place, the field inside the checked
//! value and the characters inside that field's text. Ann's guardrail finds
//! a card number in an agent's answer: the run records "payment card,
//! characters 40 to 59 of the answer", and the number itself stays out of
//! the record, the audit trail and every message about it.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::DataPath;
use crate::domains::workflows::guardrail::shapes::TextShape;
use crate::domains::workflows::guardrail::tricks::TrickCheck;
use crate::domains::workflows::guardrail::words::Span;

/// The most findings one run of a guardrail records one by one. Past it,
/// only how many there were in all is kept, so a long text full of
/// addresses cannot grow the run's record past what it may hold.
pub(crate) const MAX_RECORDED_FINDINGS: usize = 100;

/// One of the checks a guardrail step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum GuardrailCheck {
    /// Personal data: fields the tenant classifies as sensitive, and the
    /// shapes personal data takes in free text.
    PersonalData,
    /// Known ways of trying to trick a model.
    ModelTricks,
    /// The words the step bans.
    BannedWords,
}

impl GuardrailCheck {
    /// Every check, in the order they run.
    pub const ALL: [Self; 3] = [Self::PersonalData, Self::ModelTricks, Self::BannedWords];

    /// The stable name it is stored and shown by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PersonalData => "personal_data",
            Self::ModelTricks => "model_tricks",
            Self::BannedWords => "banned_words",
        }
    }
}

/// What kind of thing a guardrail found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A field the tenant's classification rules hold at this level, at or
    /// above the one the step counts as personal data.
    ClassifiedField(DataClassLevel),
    /// Personal data of this shape written into a text.
    PersonalText(TextShape),
    /// A known way of trying to trick a model.
    ModelTrick(TrickCheck),
    /// One of the words the step bans.
    BannedWord,
}

impl FindingKind {
    /// The check that finds it.
    #[must_use]
    pub fn check(self) -> GuardrailCheck {
        match self {
            Self::ClassifiedField(_) | Self::PersonalText(_) => GuardrailCheck::PersonalData,
            Self::ModelTrick(_) => GuardrailCheck::ModelTricks,
            Self::BannedWord => GuardrailCheck::BannedWords,
        }
    }

    /// The stable name a record gives it, such as `email_address` or
    /// `pi-ignore-instructions`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClassifiedField(_) => "classified_field",
            Self::PersonalText(shape) => shape.as_str(),
            Self::ModelTrick(trick) => trick.as_str(),
            Self::BannedWord => "banned_word",
        }
    }
}

/// Where a finding stands in the checked value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPlace {
    field: Option<DataPath>,
    span: Option<Span>,
}

impl FindingPlace {
    /// The place `span` of the text at `field`, or of the checked value
    /// itself when `field` is `None`. A whole field has no span.
    pub(crate) fn new(field: Option<DataPath>, span: Option<Span>) -> Self {
        Self { field, span }
    }

    /// The field inside the checked value, counted from its own root, such
    /// as `customer.email` or `items.2.note`. `None` for the checked value
    /// itself.
    #[must_use]
    pub fn field(&self) -> Option<&DataPath> {
        self.field.as_ref()
    }

    /// The characters of the field's text the finding covers. `None` when
    /// the whole field is the finding, as a classified field is.
    #[must_use]
    pub fn span(&self) -> Option<Span> {
        self.span
    }
}

/// One thing a guardrail found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailFinding {
    kind: FindingKind,
    place: FindingPlace,
}

impl GuardrailFinding {
    /// A finding of `kind` at `place`.
    pub(crate) fn new(kind: FindingKind, place: FindingPlace) -> Self {
        Self { kind, place }
    }

    /// What kind of thing was found, and by which check.
    #[must_use]
    pub fn kind(&self) -> FindingKind {
        self.kind
    }

    /// Where in the checked value it was found.
    #[must_use]
    pub fn place(&self) -> &FindingPlace {
        &self.place
    }

    /// How a record names it in one line, such as
    /// `payment_card in answer, characters 40-59`.
    #[must_use]
    pub fn summary(&self) -> String {
        let field = self
            .place
            .field
            .as_ref()
            .map_or_else(|| "the checked value".to_owned(), ToString::to_string);
        match self.place.span {
            Some(span) => format!(
                "{} in {field}, characters {}-{}",
                self.kind.as_str(),
                span.start(),
                span.end()
            ),
            None => format!("{} in {field}", self.kind.as_str()),
        }
    }
}

/// What one run of a guardrail found: the first
/// [`MAX_RECORDED_FINDINGS`] findings, and how many there were in all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailFound {
    findings: Vec<GuardrailFinding>,
    total: usize,
    checks: Vec<GuardrailCheck>,
}

impl GuardrailFound {
    /// What `findings` come to, keeping the first
    /// [`MAX_RECORDED_FINDINGS`] of them.
    pub(crate) fn of(mut findings: Vec<GuardrailFinding>) -> Self {
        let total = findings.len();
        let checks = GuardrailCheck::ALL
            .into_iter()
            .filter(|check| findings.iter().any(|found| found.kind.check() == *check))
            .collect();
        findings.truncate(MAX_RECORDED_FINDINGS);
        Self {
            findings,
            total,
            checks,
        }
    }

    /// The findings recorded one by one, in the order found.
    #[must_use]
    pub fn findings(&self) -> &[GuardrailFinding] {
        &self.findings
    }

    /// How many there were in all.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }

    /// Whether nothing was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The checks that found something, each once, in the order they run,
    /// counting the findings past those recorded one by one too.
    #[must_use]
    pub fn checks(&self) -> &[GuardrailCheck] {
        &self.checks
    }
}

/// Why a guardrail could not check its text. Whatever the step says a
/// finding does, a check that cannot run stops the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Unchecked {
    /// The tenant's classification rules could not be read.
    RulesUnreadable,
    /// Nothing was found where the step reads its text.
    NoText,
}

impl Unchecked {
    /// The stable name it is stored and shown by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RulesUnreadable => "rules_unreadable",
            Self::NoText => "no_text",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card_at(start: usize) -> GuardrailFinding {
        GuardrailFinding::new(
            FindingKind::PersonalText(TextShape::PaymentCard),
            FindingPlace::new(
                Some(DataPath::parse("answer").unwrap()),
                Some(Span::between(start, start + 19)),
            ),
        )
    }

    /// A card number found in the answer is summed up by kind and place,
    /// and the summary holds no digit of the number.
    #[test]
    fn a_summary_names_kind_and_place_only() {
        assert_eq!(
            card_at(40).summary(),
            "payment_card in answer, characters 40-59"
        );
    }

    /// A text with 150 card numbers keeps the first hundred one by one and
    /// counts all 150.
    #[test]
    fn past_the_most_recorded_only_the_count_is_kept() {
        let found = GuardrailFound::of((0..150).map(|at| card_at(at * 20)).collect());

        assert_eq!(found.findings().len(), MAX_RECORDED_FINDINGS);
        assert_eq!(found.total(), 150);
        assert_eq!(found.checks(), [GuardrailCheck::PersonalData]);
    }
}
