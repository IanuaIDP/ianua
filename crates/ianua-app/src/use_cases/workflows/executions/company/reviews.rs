//! The company step suggesting keep or remove beside a review's holders.
//!
//! Ann's workflow starts when the Finance review opens, asks an agent what
//! each holder really used, and hands its answer to this step: "remove Bob,
//! no Finance app since June; keep Lee, opens payroll weekly". Each
//! suggestion sits beside its holder for Carol, the reviewer, who still
//! decides every one.

use ianua_domain::domains::authorization::access_review::{HolderSuggestion, ReviewChoice};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::company::{REVIEW_INPUT, SUGGESTIONS_INPUT};
use ianua_domain::types::{AccessReviewId, AgentId, PrincipalRef, Text};
use uuid::Uuid;

use crate::ports::workflows::CompanyCall;
use crate::use_case::Command as _;
use crate::use_cases::authorization::access_reviews::SuggestRequest;
use crate::use_cases::workflows::executions::answers::{data, failed};
use crate::use_cases::workflows::executions::company::access::AccessActions;
use crate::use_cases::workflows::executions::company::inputs::{id, value};
use crate::use_cases::workflows::executions::company::people::{PeopleActions, count};
use crate::use_cases::workflows::executions::company::{succeeded, unmade};

/// The field of a suggestion naming a person: their address or user id.
const PERSON_FIELD: &str = "person";
/// The field of a suggestion naming an agent by its id.
const AGENT_FIELD: &str = "agent";
/// The field of a suggestion saying `keep` or `remove`.
const SUGGEST_FIELD: &str = "suggest";
/// The field of a suggestion saying why.
const REASON_FIELD: &str = "reason";

impl AccessActions {
    /// Puts each suggestion the step gives beside its holder in the review
    /// it names; nothing is decided.
    pub(super) async fn suggest(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let review_id = id(step.call, REVIEW_INPUT, AccessReviewId::from_uuid)?;
        let FlowValue::List(listed) = value(step.call, SUGGESTIONS_INPUT)?.value() else {
            return Err(failed("the step's suggestions are not a list"));
        };
        let mut suggestions = Vec::with_capacity(listed.len());
        for listed in listed {
            suggestions.push(suggestion_of(step, people, listed).await?);
        }
        let suggested = suggestions.len();
        let request = SuggestRequest {
            review_id,
            suggestions,
        };
        self.suggest_review
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("suggested", count(suggested))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }
}

/// One suggestion as the step gives it: its holder, keep or remove, and
/// why.
async fn suggestion_of(
    step: &CompanyCall<'_>,
    people: &PeopleActions,
    given: &FlowData,
) -> Result<HolderSuggestion, ActionOutcome> {
    let choice = match field_text(given, SUGGEST_FIELD)? {
        Some("keep") => ReviewChoice::Keep,
        Some("remove") => ReviewChoice::Remove,
        _ => return Err(failed("a suggestion says neither keep nor remove")),
    };
    let reason = field_text(given, REASON_FIELD)?
        .ok_or_else(|| failed("a suggestion gives no reason"))
        .and_then(|reason| {
            Text::new("reason", reason)
                .map_err(|_| failed("a suggestion's reason is not one line of text"))
        })?;
    Ok(HolderSuggestion {
        holder: holder_of(step, people, given).await?,
        choice,
        reason,
    })
}

/// The holder a suggestion names: a person by address or user id, or an
/// agent by its id.
async fn holder_of(
    step: &CompanyCall<'_>,
    people: &PeopleActions,
    given: &FlowData,
) -> Result<PrincipalRef, ActionOutcome> {
    let person = field_text(given, PERSON_FIELD)?;
    let agent = field_text(given, AGENT_FIELD)?;
    match (person, agent) {
        (Some(person), None) => Ok(PrincipalRef::User(people.named(step, person).await?)),
        (None, Some(agent)) => Uuid::parse_str(agent)
            .map(|id| PrincipalRef::Agent(AgentId::from_uuid(id)))
            .map_err(|_| failed("a suggestion's agent is not an id")),
        _ => Err(failed("a suggestion names one person or one agent")),
    }
}

/// The text a suggestion gives in `field`, when it gives one.
fn field_text<'a>(given: &'a FlowData, field: &str) -> Result<Option<&'a str>, ActionOutcome> {
    let name = FieldName::new(field).map_err(|_| failed("a suggestion's field does not read"))?;
    match given.field(&name).map(FlowData::value) {
        None | Some(FlowValue::Null) => Ok(None),
        Some(FlowValue::Text(text)) if !text.trim().is_empty() => Ok(Some(text.trim())),
        Some(_) => Err(failed(&format!("a suggestion's {field} is not text"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A suggestion given as `fields`.
    fn given(fields: &[(&str, &str)]) -> FlowData {
        FlowData::map(
            fields
                .iter()
                .map(|(name, text)| {
                    (
                        FieldName::new(*name).unwrap(),
                        FlowData::text(*text).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    /// A suggestion's fields read as text, trimmed; one it leaves out
    /// reads as none, and one that is not text is refused.
    #[test]
    fn a_suggestions_fields_read_as_text() {
        let suggestion = given(&[("suggest", " remove "), ("reason", "no app since June")]);
        let numbered = FlowData::map(vec![(
            FieldName::new("reason").unwrap(),
            FlowData::number(3.0).unwrap(),
        )])
        .unwrap();

        assert_eq!(
            field_text(&suggestion, "suggest").ok(),
            Some(Some("remove"))
        );
        assert_eq!(field_text(&suggestion, "person").ok(), Some(None));
        assert!(field_text(&numbered, "reason").is_err());
    }
}
