//! One sample case: the input a test run starts with, how sensitive it is,
//! and the checks its results must pass.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::evaluation::check::Expectation;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{TextValue, Validator, text_value};

/// The most checks one case may make.
pub(crate) const MAX_CHECKS: usize = 10;

text_value! {
    /// What an author calls a case, such as "late parcel refund", unique
    /// within its set.
    pub struct CaseName;
}

impl TextValue for CaseName {
    const FIELD: &'static str = "case_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.char_length(1..=80).not_blank().no_control_chars()
    }
}

/// One sample case of an evaluation set.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "CaseParams"))]
pub struct EvaluationCase {
    name: CaseName,
    input: FlowData,
    exposure: DataClassLevel,
    checks: Vec<Expectation>,
}

/// The parts of a case, before they are checked.
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct CaseParams {
    /// What the author calls it.
    pub name: CaseName,
    /// The trigger data its test run starts with.
    pub input: FlowData,
    /// The most sensitive data in the input, as the author declared it.
    pub exposure: DataClassLevel,
    /// The checks its results must pass, at least one.
    pub checks: Vec<Expectation>,
}

impl EvaluationCase {
    /// A case of `params`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it makes no check, or more than
    ///   [`MAX_CHECKS`].
    pub fn new(params: CaseParams) -> Result<Self, DomainError> {
        validate_count("checks", params.checks.len(), 1..=MAX_CHECKS)?;
        Ok(Self {
            name: params.name,
            input: params.input,
            exposure: params.exposure,
            checks: params.checks,
        })
    }

    /// What the author calls it.
    #[must_use]
    pub fn name(&self) -> &CaseName {
        &self.name
    }

    /// The trigger data its test run starts with.
    #[must_use]
    pub fn input(&self) -> &FlowData {
        &self.input
    }

    /// The most sensitive data in the input, as the author declared it.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.exposure
    }

    /// The checks its results must pass.
    #[must_use]
    pub fn checks(&self) -> &[Expectation] {
        &self.checks
    }

    /// The data it carries towards its set's size: its input and what its
    /// checks expect.
    pub(super) fn size(&self) -> usize {
        self.checks
            .iter()
            .map(Expectation::size)
            .fold(self.input.size(), usize::saturating_add)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<CaseParams> for EvaluationCase {
    type Error = DomainError;

    fn try_from(params: CaseParams) -> Result<Self, Self::Error> {
        Self::new(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::DataPath;
    use crate::domains::workflows::evaluation::check::ExpectedText;

    fn contains(text: &str) -> Expectation {
        Expectation::Contains {
            at: DataPath::parse("summarise.answer").unwrap(),
            text: ExpectedText::new(text).unwrap(),
        }
    }

    fn params(checks: Vec<Expectation>) -> CaseParams {
        CaseParams {
            name: CaseName::new("late parcel").unwrap(),
            input: FlowData::text("my parcel is late").unwrap(),
            exposure: DataClassLevel::Internal,
            checks,
        }
    }

    /// A case with no check, or with more than the limit, is refused.
    #[test]
    fn a_case_makes_between_one_and_ten_checks() {
        let none = EvaluationCase::new(params(Vec::new()));
        let too_many = EvaluationCase::new(params(vec![contains("refund"); MAX_CHECKS + 1]));
        let enough = EvaluationCase::new(params(vec![contains("refund"); MAX_CHECKS]));

        assert!(matches!(none, Err(DomainError::Validation(_))));
        assert!(matches!(too_many, Err(DomainError::Validation(_))));
        assert!(enough.is_ok());
    }

    /// A blank name is refused.
    #[test]
    fn a_case_is_named() {
        assert!(CaseName::new("   ").is_err());
        assert!(CaseName::new("x".repeat(81)).is_err());
    }
}
