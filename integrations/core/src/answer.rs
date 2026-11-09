//! A service's answer as a step's outcome: its status, its body as text,
//! and the body as values when it is JSON a workflow can hold.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UntrustedText;
use serde_json::Value;

/// The largest answer kept, in bytes: its text and its values both go into
/// the step's output, which workflow data caps at a mebibyte.
pub const LARGEST_ANSWER: usize = 349_000;

/// The outcome of `response`, read to at most `most` bytes, its data
/// counted as sensitive as `exposure`, since it may echo what it was sent.
///
/// An answer saying the service is busy turns the call away; any other
/// refusal fails it, as the service may have acted. A `203` is a sign-in
/// page answering in the API's place, never the API's success, so it
/// fails too.
pub async fn outcome_of(
    response: reqwest::Response,
    most: usize,
    exposure: DataClassLevel,
) -> ActionOutcome {
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
    {
        return ActionOutcome::TurnedAway(answered(status));
    }
    if !status.is_success() || status == reqwest::StatusCode::NON_AUTHORITATIVE_INFORMATION {
        return ActionOutcome::Failed(answered(status));
    }
    let Ok(body) = body_within(response, most.min(LARGEST_ANSWER)).await else {
        return failed("the answer could not be read whole within its limit");
    };
    match output_of(status.as_u16(), &body) {
        Ok(output) => ActionOutcome::Succeeded { output, exposure },
        Err(_) => failed("the answer is larger than workflow data may be"),
    }
}

/// A failed call, for a reason in the integration's own words.
#[must_use]
pub fn failed(reason: &str) -> ActionOutcome {
    ActionOutcome::Failed(UntrustedText::record(reason))
}

/// A call turned away before anything was done, for a reason in the
/// integration's own words.
#[must_use]
pub fn turned_away(reason: &str) -> ActionOutcome {
    ActionOutcome::TurnedAway(UntrustedText::record(reason))
}

/// The answer as the step's output: `status`, `body` and `json`, the last
/// null when the body is not JSON a workflow can hold, such as one with a
/// field name a workflow cannot spell.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the answer is larger than
/// workflow data may be.
pub fn output_of(status: u16, body: &[u8]) -> Result<FlowData, DomainError> {
    let text = String::from_utf8_lossy(body).into_owned();
    let json = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| flow_of(&value).ok())
        .unwrap_or_else(FlowData::null);
    FlowData::map(vec![
        (field("status")?, FlowData::number(f64::from(status))?),
        (field("body")?, FlowData::text(text)?),
        (field("json")?, json),
    ])
}

/// What the reason a refused call is reported under starts with, before
/// the status.
const ANSWERED: &str = "the address answered ";

/// The reason a call answered with `status` is reported under.
fn answered(status: reqwest::StatusCode) -> UntrustedText {
    UntrustedText::record(&format!("{ANSWERED}{}", status.as_u16()))
}

/// The status a refused call answered with, read back from the reason
/// [`outcome_of`] reported it under; none for any other reason, such as a
/// call that never reached the service.
#[must_use]
pub fn refused_status(reason: &UntrustedText) -> Option<u16> {
    reason.as_str().strip_prefix(ANSWERED)?.parse().ok()
}

/// The body of `response`, at most `most` bytes: a longer one is refused
/// before more of it is read.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the body cannot be read or
/// is longer than `most`.
pub async fn body_within(
    mut response: reqwest::Response,
    most: usize,
) -> Result<Vec<u8>, DomainError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(DomainError::infra)? {
        if body.len().saturating_add(chunk.len()) > most {
            return Err(DomainError::infra_msg("the answer was longer than allowed"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// `name` as a field of workflow data.
fn field(name: &str) -> Result<FieldName, DomainError> {
    Ok(FieldName::new(name)?)
}

/// `value`, plain JSON, as workflow data.
///
/// # Errors
///
/// [`DomainError`] when a field name is not one workflow data takes, a
/// number cannot be held, or the data nests too deep or grows too large.
pub fn flow_of(value: &Value) -> Result<FlowData, DomainError> {
    match value {
        Value::Null => Ok(FlowData::null()),
        Value::Bool(flag) => Ok(FlowData::bool(*flag)),
        Value::Number(number) => number_of(number),
        Value::String(text) => FlowData::text(text.as_str()),
        Value::Array(items) => FlowData::list(items.iter().map(flow_of).collect::<Result<_, _>>()?),
        Value::Object(entries) => FlowData::map(
            entries
                .iter()
                .map(|(name, value)| Ok((field(name)?, flow_of(value)?)))
                .collect::<Result<_, DomainError>>()?,
        ),
    }
}

/// A JSON number as workflow data, refused when it has no `f64` reading.
/// The refusal only leaves the answer's values null, so it is worded for
/// the log alone.
fn number_of(number: &serde_json::Number) -> Result<FlowData, DomainError> {
    let Some(value) = number.as_f64() else {
        return Err(DomainError::infra_msg("the number cannot be held"));
    };
    FlowData::number(value)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::FlowValue;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn named<'a>(output: &'a FlowData, name: &str) -> &'a FlowData {
        output.field(&FieldName::new(name).unwrap()).unwrap()
    }

    async fn answering(template: ResponseTemplate) -> reqwest::Response {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(template)
            .mount(&server)
            .await;
        reqwest::get(server.uri()).await.unwrap()
    }

    /// A JSON answer reads back as values, with the status and the text.
    #[test]
    fn a_json_answer_reads_as_values() {
        let output = output_of(200, br#"{"rows": 3, "sheet": "Q1"}"#).unwrap();

        assert_eq!(named(&output, "status").value(), FlowValue::Number(200.0));
        assert_eq!(
            named(named(&output, "json"), "sheet").value(),
            FlowValue::Text("Q1")
        );
        assert_eq!(
            named(&output, "body").value(),
            FlowValue::Text(r#"{"rows": 3, "sheet": "Q1"}"#)
        );
    }

    /// A body that is not JSON keeps its text, and its values are null.
    #[test]
    fn a_plain_answer_keeps_its_text() {
        let output = output_of(200, b"accepted").unwrap();

        assert!(named(&output, "json").is_null());
        assert_eq!(named(&output, "body").value(), FlowValue::Text("accepted"));
    }

    /// A JSON field a workflow cannot name leaves the values null rather
    /// than failing the step; the text is still there.
    #[test]
    fn a_field_a_workflow_cannot_name_leaves_the_values_null() {
        let output = output_of(200, br#"{"two words": 1}"#).unwrap();

        assert!(named(&output, "json").is_null());
    }

    /// An answer nested beyond workflow data's depth limit produces null
    /// JSON values without failing output conversion.
    #[test]
    fn an_answer_nested_too_deep_has_no_values() {
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));

        let output = output_of(200, deep.as_bytes()).unwrap();

        assert!(named(&output, "json").is_null());
    }

    /// A busy service turns the call away, so it may be tried again; a
    /// refusal fails it.
    #[tokio::test]
    async fn a_busy_service_turns_away_and_a_refusal_fails() {
        let busy = answering(ResponseTemplate::new(429)).await;
        let refused = answering(ResponseTemplate::new(403)).await;

        let busy = outcome_of(busy, 1024, DataClassLevel::Internal).await;
        let refused = outcome_of(refused, 1024, DataClassLevel::Internal).await;

        assert!(matches!(busy, ActionOutcome::TurnedAway(_)));
        assert!(matches!(refused, ActionOutcome::Failed(_)));
    }

    /// A file that is not there fails with its status, which reads back as
    /// 404; a reason of the integration's own names none.
    #[tokio::test]
    async fn a_refusal_names_the_status_it_answered_with() {
        let missing = answering(ResponseTemplate::new(404)).await;

        let ActionOutcome::Failed(reason) =
            outcome_of(missing, 1024, DataClassLevel::Internal).await
        else {
            panic!("a 404 fails the call");
        };

        assert_eq!(refused_status(&reason), Some(404));
        assert_eq!(
            refused_status(&UntrustedText::record("no token was handed over")),
            None
        );
    }

    /// A response body larger than the configured byte limit fails the step.
    #[tokio::test]
    async fn an_answer_past_its_limit_fails() {
        let long = answering(ResponseTemplate::new(200).set_body_string("x".repeat(2048))).await;

        let outcome = outcome_of(long, 1024, DataClassLevel::Internal).await;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }
}
