//! What a service's answer says: of a credential, by a probe's status or
//! the body it answered with, and of a call, by an `"ok"` flag or a
//! GraphQL `"errors"` list in an answer sent with success.

use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::types::UntrustedText;

use crate::answer::{failed, turned_away};

/// What reaching the service through a credential said of it: refused for
/// the reason a failure gives, and unknown when it was turned away, such as
/// by a busy token address.
pub(super) fn refused(outcome: ActionOutcome) -> AccountCheck {
    match outcome {
        ActionOutcome::Failed(why) => AccountCheck::Refused(why),
        ActionOutcome::TurnedAway(_) => AccountCheck::Unreachable,
        ActionOutcome::Succeeded { .. } | ActionOutcome::NotYet { .. } => {
            AccountCheck::Refused(UntrustedText::record("the credential was not taken"))
        }
    }
}

/// What a service answering a probe with `status` says of the credential:
/// taken on success, refused when it does not know or allow it, and
/// unknown otherwise, such as when it is down or limiting the rate. A
/// `203` is a sign-in page answering in the API's place, as Azure DevOps
/// answers a token it does not know, so it is a refusal.
pub(super) fn by_status(status: reqwest::StatusCode) -> AccountCheck {
    if status.is_success() && status != reqwest::StatusCode::NON_AUTHORITATIVE_INFORMATION {
        return AccountCheck::Accepted;
    }
    match status {
        reqwest::StatusCode::UNAUTHORIZED
        | reqwest::StatusCode::FORBIDDEN
        | reqwest::StatusCode::NON_AUTHORITATIVE_INFORMATION => AccountCheck::Refused(
            UntrustedText::record("the service does not accept the token"),
        ),
        _ => AccountCheck::Unreachable,
    }
}

/// What a service answering a limited credential's probe with `status`
/// says of it: taken when it answers `taken`, the status it gives a
/// request it took the credential for, refused when it does not know or
/// allow it, and unknown otherwise.
pub(super) fn by_limited_status(status: reqwest::StatusCode, taken: u16) -> AccountCheck {
    if status.as_u16() == taken {
        return AccountCheck::Accepted;
    }
    match status {
        reqwest::StatusCode::UNAUTHORIZED
        | reqwest::StatusCode::FORBIDDEN
        | reqwest::StatusCode::NOT_FOUND => AccountCheck::Refused(UntrustedText::record(
            "the service does not accept the credential for its place",
        )),
        _ => AccountCheck::Unreachable,
    }
}

/// What a service answering with success said in its body, by an `"ok"`
/// flag or a GraphQL `"errors"` list.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict<'a> {
    /// Done: `"ok": true`, or data with no errors.
    Done,
    /// Refused, for the error named.
    Refused(&'a str),
    /// Refused because the token sent too much too fast.
    Limited,
    /// No verdict: the call failed, was turned away, or the answer did not
    /// say.
    Unclear,
}

/// The error a service names when a token sent too much too fast.
const RATE_LIMITED: &str = "ratelimited";

/// The code a GraphQL error carries when a token sent too much too fast.
const GRAPHQL_RATE_LIMITED: &str = "RATELIMITED";

/// What a GraphQL refusal is called when its first error has no message.
const UNNAMED_ERROR: &str = "an error it did not name";

/// The verdict of the `"ok"` flag in `outcome`.
pub(super) fn verdict(outcome: &ActionOutcome) -> Verdict<'_> {
    let ActionOutcome::Succeeded { output, .. } = outcome else {
        return Verdict::Unclear;
    };
    let Some(json) = named(output, "json").filter(|json| !json.is_null()) else {
        return Verdict::Unclear;
    };
    if named(json, "ok").map(FlowData::value) == Some(FlowValue::Bool(true)) {
        return Verdict::Done;
    }
    match named(json, "error").map(FlowData::value) {
        Some(FlowValue::Text(RATE_LIMITED)) => Verdict::Limited,
        Some(FlowValue::Text(error)) => Verdict::Refused(error),
        _ => Verdict::Unclear,
    }
}

/// The verdict of a GraphQL answer in `outcome`: the first of a non-empty
/// `"errors"` list refuses it, `data` with no errors is done.
pub(super) fn graphql_verdict(outcome: &ActionOutcome) -> Verdict<'_> {
    let ActionOutcome::Succeeded { output, .. } = outcome else {
        return Verdict::Unclear;
    };
    let Some(json) = named(output, "json").filter(|json| !json.is_null()) else {
        return Verdict::Unclear;
    };
    if let Some(FlowValue::List([first, ..])) = named(json, "errors").map(FlowData::value) {
        return graphql_error(first);
    }
    match named(json, "data").filter(|data| !data.is_null()) {
        Some(_) => Verdict::Done,
        None => Verdict::Unclear,
    }
}

/// The verdict `error`, a GraphQL error, gives: busy for the rate-limit
/// code, otherwise a refusal naming its message.
fn graphql_error(error: &FlowData) -> Verdict<'_> {
    let code = named(error, "extensions")
        .and_then(|extensions| named(extensions, "code"))
        .map(FlowData::value);
    if code == Some(FlowValue::Text(GRAPHQL_RATE_LIMITED)) {
        return Verdict::Limited;
    }
    match named(error, "message").map(FlowData::value) {
        Some(FlowValue::Text(message)) => Verdict::Refused(message),
        _ => Verdict::Refused(UNNAMED_ERROR),
    }
}

/// What a probe's `verdict` says of the credential.
pub(super) fn checked_by(verdict: &Verdict<'_>) -> AccountCheck {
    match verdict {
        Verdict::Done => AccountCheck::Accepted,
        Verdict::Refused(error) => AccountCheck::Refused(UntrustedText::record(&format!(
            "the service refused the token: {error}"
        ))),
        Verdict::Limited | Verdict::Unclear => AccountCheck::Unreachable,
    }
}

/// `outcome` once `read` gives its verdict: a refusal fails it however it
/// was sent, rate limiting turns the call away, and a success that does
/// not say is a failure.
pub(super) fn judged(
    outcome: ActionOutcome,
    read: fn(&ActionOutcome) -> Verdict<'_>,
) -> ActionOutcome {
    let replaced = match read(&outcome) {
        Verdict::Done => None,
        Verdict::Limited => Some(turned_away("the service rate limited the token")),
        Verdict::Refused(error) => Some(failed(&format!("the service refused it: {error}"))),
        Verdict::Unclear => match &outcome {
            ActionOutcome::Succeeded { .. } => {
                Some(failed("the service's answer did not say it was done"))
            }
            ActionOutcome::Failed(_)
            | ActionOutcome::TurnedAway(_)
            | ActionOutcome::NotYet { .. } => None,
        },
    };
    replaced.unwrap_or(outcome)
}

/// The field `name` of `data`, when it has one.
fn named<'a>(data: &'a FlowData, name: &str) -> Option<&'a FlowData> {
    data.field(&FieldName::new(name).ok()?)
}
