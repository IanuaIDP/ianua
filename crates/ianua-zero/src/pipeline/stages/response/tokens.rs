//! `TokenRateLimit`, its response side: what an exchange with a language
//! model cost, read from the answer and settled against what admitting the
//! request reserved.
//!
//! The provider says the cost only once it has answered, in a `usage`
//! object, whole or spread across a stream's events. An answer that does
//! not say, or that the gateway did not read whole, is settled as
//! unreported, which the domain charges at least the reservation: a caller
//! can always stream or leave usage out, so silence never costs less.
//!
//! The charge never withholds the answer. The request was allowed and the
//! provider has answered; an overspend lands on the caller's next request.

use async_trait::async_trait;
use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::token_budget::{
    LlmDialect, Reservation, TokenCharge, TokenRateLimitConfig, TokenUsage,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, StageId};
use serde_json::Value;

use super::body::{Encoding, encoding};
use super::{ResponseRead, ResponseStages, unchanged};

/// The stage and configuration that identify a token counter.
#[derive(Clone, Copy)]
pub(crate) struct TokenLimit<'a> {
    /// The stage that reserved the tokens.
    pub(crate) stage: &'a StageId,
    /// The rules used both to reserve and settle its counter.
    pub(crate) config: &'a TokenRateLimitConfig,
}

/// The shared counters a token limit spends from.
///
/// Keyed as admitting the request keyed its reservation, from the caller in
/// the context, the stage and its `key_by`, so a charge lands on the
/// counter it was reserved from.
#[async_trait]
pub(crate) trait TokenLedger: Send + Sync {
    /// Adds `charge`'s adjustment, which may be negative, to its window of
    /// the counter `limit` keeps for the caller in `ctx`.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the counter cannot be reached.
    async fn settle(
        &self,
        ctx: &PipelineContext,
        limit: TokenLimit<'_>,
        charge: TokenCharge,
    ) -> Result<(), DomainError>;
}

impl ResponseStages {
    /// Settles what the exchange cost against `reservation`, the tokens set
    /// aside when the request was admitted. The answer always passes.
    ///
    /// # Errors
    ///
    /// Never: a charge that cannot be applied is logged, and the answer
    /// passes.
    pub(crate) async fn token_charge(
        &self,
        limit: TokenLimit<'_>,
        reservation: Reservation,
        answer: ResponseRead<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        let config = limit.config;
        let reported = reported_usage(config.dialect(), answer.meta, answer.body);
        let charge = config.settle(reservation, reported, clock::now());
        if charge.adjustment() == 0 {
            return Ok(unchanged("the exchange cost what it reserved"));
        }
        let settled = self
            .within(self.tokens.settle(answer.context, limit, charge))
            .await;
        if let Err(error) = settled {
            tracing::warn!(%error, "a token charge could not be settled");
            return Ok(unchanged("the token charge could not be settled"));
        }
        Ok(unchanged(format!(
            "token charge settled by {}",
            charge.adjustment()
        )))
    }

    /// Gives back `reservation` for an exchange that never reached the
    /// provider: the request was refused after its tokens were set aside,
    /// or answered without forwarding. A release that cannot be applied is
    /// logged; the caller's window keeps the tokens until it rolls over.
    pub(crate) async fn token_release(
        &self,
        limit: TokenLimit<'_>,
        ctx: &PipelineContext,
        reservation: Reservation,
    ) {
        let charge = limit.config.release(reservation, clock::now());
        if charge.adjustment() == 0 {
            return;
        }
        let released = self.within(self.tokens.settle(ctx, limit, charge)).await;
        if let Err(error) = released {
            tracing::warn!(%error, "a token reservation could not be released");
        }
    }
}

/// What the answer says the exchange cost: known only from a body read
/// whole and as written.
fn reported_usage(
    dialect: LlmDialect,
    response: &ResponseMeta,
    body: CapturedBody<'_>,
) -> Fact<TokenUsage> {
    if !body.is_whole() || encoding(response) == Encoding::Encoded {
        return Fact::Unknown;
    }
    usage_in(dialect, body.bytes).map_or(Fact::Unknown, Fact::Known)
}

/// The token counts in an answer, a JSON document or a stream of events.
///
/// `None` when the answer does not say: not text, not JSON, or no `usage`.
fn usage_in(dialect: LlmDialect, body: &[u8]) -> Option<TokenUsage> {
    let text = std::str::from_utf8(body).ok()?;
    if is_event_stream(text) {
        return usage_in_events(dialect, text);
    }
    usage_of(dialect, &serde_json::from_str(text).ok()?)
}

/// Whether the answer is a server-sent event stream, not one document.
fn is_event_stream(text: &str) -> bool {
    text.lines()
        .any(|line| line.starts_with("data:") || line.starts_with("event:"))
}

/// The counts spread across a stream's events.
///
/// The largest of each, not the sum: Anthropic reports the output so far on
/// every `message_delta`, so summing would charge each running total.
fn usage_in_events(dialect: LlmDialect, text: &str) -> Option<TokenUsage> {
    text.lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim))
        .filter(|payload| !payload.is_empty() && *payload != "[DONE]")
        .filter_map(|payload| serde_json::from_str::<Value>(payload).ok())
        .filter_map(|event| usage_of(dialect, &event))
        .reduce(|merged, usage| {
            TokenUsage::new(
                merged.input.max(usage.input),
                merged.output.max(usage.output),
            )
        })
}

/// The counts in one document or event's `usage` object, in the dialect's
/// field names. Reading one dialect as the other reports nothing.
fn usage_of(dialect: LlmDialect, value: &Value) -> Option<TokenUsage> {
    let usage = value.get("usage")?;
    let (input_field, output_field) = match dialect {
        LlmDialect::OpenAi => ("prompt_tokens", "completion_tokens"),
        LlmDialect::Anthropic => ("input_tokens", "output_tokens"),
    };
    let input = count(usage, input_field);
    let output = count(usage, output_field);
    if input.is_none() && output.is_none() {
        return None;
    }
    Some(TokenUsage::new(input.unwrap_or(0), output.unwrap_or(0)))
}

/// One count, when it is a number that fits. A number too large for a
/// count is not reported, rather than clamped to a charge of everything.
fn count(usage: &Value, field: &str) -> Option<u32> {
    u32::try_from(usage.get(field)?.as_u64()?).ok()
}

#[cfg(test)]
pub(crate) mod fakes {
    use std::sync::Mutex;

    use super::*;

    /// A ledger that remembers each adjustment it was given.
    #[derive(Default)]
    pub(crate) struct FakeLedger {
        settled: Mutex<Vec<i64>>,
    }

    impl FakeLedger {
        /// The adjustments settled so far.
        pub(crate) fn settled(&self) -> Vec<i64> {
            self.settled.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TokenLedger for FakeLedger {
        async fn settle(
            &self,
            _: &PipelineContext,
            _: TokenLimit<'_>,
            charge: TokenCharge,
        ) -> Result<(), DomainError> {
            self.settled.lock().unwrap().push(charge.adjustment());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::body::BodyExtent;
    use ianua_domain::domains::proxy::stages::stage::RateLimitKey;
    use ianua_domain::domains::proxy::stages::token_budget::{TokenRateLimitParams, UnknownUsage};
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::pipeline::stages::response::fixtures::{Fakes, context, is_unchanged, json};

    fn config(dialect: LlmDialect) -> TokenRateLimitConfig {
        TokenRateLimitConfig::new(TokenRateLimitParams {
            max_tokens: 10_000,
            window_seconds: Seconds::new(3600),
            key_by: RateLimitKey::UserId,
            dialect,
            on_unknown: UnknownUsage::default(),
        })
        .unwrap()
    }

    async fn charge(
        fakes: &Fakes,
        config: &TokenRateLimitConfig,
        body: CapturedBody<'_>,
    ) -> ResponseStageOutcome {
        let reservation = config.admit(0, clock::now()).unwrap();
        fakes
            .stages()
            .token_charge(
                TokenLimit {
                    stage: &StageId::new(),
                    config,
                },
                reservation,
                ResponseRead {
                    context: &context(),
                    meta: &json(),
                    body,
                },
            )
            .await
            .unwrap()
    }

    /// An OpenAI answer reporting 120 prompt and 380 answer tokens is
    /// charged 500, settled against what was reserved, and passed on.
    #[tokio::test]
    async fn a_reported_cost_is_settled_against_the_reservation() {
        let fakes = Fakes::default();
        let config = config(LlmDialect::OpenAi);
        let body = br#"{"usage":{"prompt_tokens":120,"completion_tokens":380}}"#;

        let outcome = charge(&fakes, &config, CapturedBody::new(body, BodyExtent::Whole)).await;

        assert!(is_unchanged(&outcome));
        let reserved = i64::from(config.reservation());
        assert_eq!(fakes.ledger.settled(), [500 - reserved]);
    }

    /// An answer captured as a prefix passes unchanged and produces no
    /// negative settlement, even when its bytes report a small token cost.
    #[tokio::test]
    async fn an_answer_read_in_part_is_never_charged_less_than_reserved() {
        let fakes = Fakes::default();
        let config = config(LlmDialect::OpenAi);
        let body = br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;

        let outcome = charge(&fakes, &config, CapturedBody::new(body, BodyExtent::Prefix)).await;

        assert!(is_unchanged(&outcome));
        assert!(
            fakes
                .ledger
                .settled()
                .iter()
                .all(|adjustment| *adjustment >= 0)
        );
    }

    /// Eve's request set its tokens aside, then a later stage refused it.
    /// All of them go back to her window.
    #[tokio::test]
    async fn a_refused_exchange_gives_its_reservation_back() {
        let fakes = Fakes::default();
        let config = config(LlmDialect::OpenAi);
        let reservation = config.admit(0, clock::now()).unwrap();

        fakes
            .stages()
            .token_release(
                TokenLimit {
                    stage: &StageId::new(),
                    config: &config,
                },
                &context(),
                reservation,
            )
            .await;

        assert_eq!(fakes.ledger.settled(), [-i64::from(reservation.tokens())]);
    }

    /// Anthropic's stream reports the input when the message opens and the
    /// output so far on every delta: the largest of each is the cost.
    #[test]
    fn a_stream_is_charged_its_final_counts() {
        let stream = "event: message_start\n\
            data: {\"usage\":{\"input_tokens\":95,\"output_tokens\":1}}\n\n\
            event: message_delta\n\
            data: {\"usage\":{\"output_tokens\":100}}\n\n\
            event: message_delta\n\
            data: {\"usage\":{\"output_tokens\":210}}\n\n";

        assert_eq!(
            usage_in(LlmDialect::Anthropic, stream.as_bytes()),
            Some(TokenUsage::new(95, 210))
        );
    }

    /// One dialect read as the other reports nothing, not a plausible wrong
    /// number.
    #[test]
    fn the_dialects_are_not_read_as_each_other() {
        let openai = br#"{"usage":{"prompt_tokens":120,"completion_tokens":380}}"#;

        assert_eq!(usage_in(LlmDialect::Anthropic, openai), None);
        assert_eq!(
            usage_in(LlmDialect::OpenAi, openai),
            Some(TokenUsage::new(120, 380))
        );
    }

    /// A count too large for a number of tokens is not reported.
    #[test]
    fn an_absurd_count_is_not_reported() {
        let body = br#"{"usage":{"prompt_tokens":99999999999,"completion_tokens":null}}"#;

        assert_eq!(usage_in(LlmDialect::OpenAi, body), None);
    }
}
