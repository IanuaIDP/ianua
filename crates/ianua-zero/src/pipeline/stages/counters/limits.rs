//! The RateLimit stage, the request side of the TokenRateLimit stage, and
//! the headers every refusal for being over a limit carries.

use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use ianua_domain::domains::proxy::stages::stage::RateLimitConfig;
use ianua_domain::domains::proxy::stages::token_budget::{
    Reservation, TokenRateLimitConfig, TokenWindow,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DenialStatus, HeaderName, HeaderValue, StageId};

use super::keys::{CounterScope, FixedWindow, counter_key, subject};
use super::{CounterStages, passed, refused, unavailable};

/// What the request side of a token limit decided, and what it set aside.
#[derive(Debug, Clone)]
pub(crate) struct TokenAdmission {
    /// Whether the request goes on.
    pub decision: StageDecision,
    /// The tokens set aside for the exchange, which the response side
    /// settles once the provider says what it cost. `None` when the request
    /// was refused.
    pub reservation: Option<Reservation>,
}

impl TokenAdmission {
    fn refused(decision: StageDecision) -> Self {
        Self {
            decision,
            reservation: None,
        }
    }
}

impl CounterStages {
    /// Counts the request against the rate limit of the stage `stage`, and
    /// refuses it with a 429 once its window holds more than the limit.
    ///
    /// The count is the fleet's. Two limits in one pipeline, or the same
    /// limit in two pipelines, count apart.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the refusal's headers cannot be written.
    pub(crate) async fn rate_limit(
        &self,
        stage: &StageId,
        config: &RateLimitConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let Some(subject) = subject(ctx, &config.key_by) else {
            return Ok(nothing_to_count());
        };
        let window = FixedWindow::at(config.window_seconds, clock::now());
        let key = counter_key(
            "rate",
            CounterScope {
                tenant: ctx.tenant_id,
                stage,
            },
            &subject,
            window.index(),
        );
        let Some(used) = self
            .within(self.fleet.count(&key, config.window_seconds))
            .await
        else {
            return Ok(unavailable());
        };
        if used <= config.max_requests {
            return Ok(passed("within the rate limit"));
        }
        let over = Exhausted {
            limit: config.max_requests,
            resets_in: window.resets_in(),
        };
        refuse_over(ctx, &over, "rate limit exceeded")
    }

    /// Sets aside a typical exchange's tokens against the token limit of
    /// the stage `stage`, and refuses the request with a 429 when that would
    /// not fit in its window.
    ///
    /// The reservation is added in the same step as the spend is read, so
    /// two requests racing for the last of a budget cannot both be admitted.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the refusal's headers cannot be written.
    pub(crate) async fn token_rate_limit(
        &self,
        stage: &StageId,
        config: &TokenRateLimitConfig,
        ctx: &mut PipelineContext,
    ) -> Result<TokenAdmission, DomainError> {
        let now = clock::now();
        let Some(key) = token_counter_key(ctx, stage, config, config.window_at(now)) else {
            return Ok(TokenAdmission::refused(nothing_to_count()));
        };
        let reservation = config.reservation();
        let Some(held) = self
            .within(self.fleet.add(&key, reservation, config.window_seconds()))
            .await
        else {
            return Ok(TokenAdmission::refused(unavailable()));
        };
        if let Some(admitted) = config.admit(held.saturating_sub(reservation), now) {
            return Ok(TokenAdmission {
                decision: passed("within the token limit"),
                reservation: Some(admitted),
            });
        }
        self.give_back(&key, reservation, config).await;
        let over = Exhausted {
            limit: config.max_tokens(),
            resets_in: FixedWindow::at(config.window_seconds(), now).resets_in(),
        };
        let decision = refuse_over(ctx, &over, "token limit exceeded")?;
        Ok(TokenAdmission::refused(decision))
    }

    /// Takes back the `reservation` set aside under `key` for a request the
    /// limit then refused, so a refused request spends nothing. A take-back
    /// that does not land is logged: the window keeps the tokens until it
    /// rolls over, which refuses more, never less.
    async fn give_back(&self, key: &str, reservation: u32, config: &TokenRateLimitConfig) {
        let given = self
            .within(
                self.fleet
                    .adjust(key, -i64::from(reservation), config.window_seconds()),
            )
            .await;
        if given.is_none() {
            tracing::warn!("a refused request's token reservation could not be given back");
        }
    }
}

/// The shared counter a token limit of the stage `stage` keeps this
/// request's spend in, for `window`: where the request side sets a
/// reservation aside and the response side settles it.
///
/// `None` when the request has neither what the limit is keyed by nor a
/// known address.
#[must_use]
pub(crate) fn token_counter_key(
    ctx: &PipelineContext,
    stage: &StageId,
    config: &TokenRateLimitConfig,
    window: TokenWindow,
) -> Option<String> {
    let subject = subject(ctx, config.key_by())?;
    Some(counter_key(
        "tokens",
        CounterScope {
            tenant: ctx.tenant_id,
            stage,
        },
        &subject,
        window.index(),
    ))
}

/// A limit that is used up, and when its window resets.
pub(super) struct Exhausted {
    pub(super) limit: u32,
    pub(super) resets_in: u32,
}

impl Exhausted {
    /// `Retry-After` and the `RateLimit-*` headers saying so.
    fn headers(&self) -> Result<Vec<HeaderEntry>, DomainError> {
        [
            ("retry-after", self.resets_in),
            ("ratelimit-limit", self.limit),
            ("ratelimit-remaining", 0),
            ("ratelimit-reset", self.resets_in),
        ]
        .into_iter()
        .map(|(name, value)| header(name, value))
        .collect()
    }
}

/// Refuses the request with a 429, its response carrying when to retry.
pub(super) fn refuse_over(
    ctx: &mut PipelineContext,
    over: &Exhausted,
    reason: &str,
) -> Result<StageDecision, DomainError> {
    ctx.response_headers.extend(over.headers()?);
    Ok(refused(DenialStatus::TOO_MANY_REQUESTS, reason))
}

fn header(name: &str, value: u32) -> Result<HeaderEntry, DomainError> {
    Ok(HeaderEntry::new(
        HeaderName::new(name)?,
        HeaderValue::new(value.to_string())?,
    ))
}

/// The request has nothing a limit could count it by, so it is refused
/// rather than let through uncounted.
fn nothing_to_count() -> StageDecision {
    refused(
        DenialStatus::FORBIDDEN,
        "the request has nothing to be counted by",
    )
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::stages::stage::RateLimitKey;
    use ianua_domain::domains::proxy::stages::token_budget::{
        LlmDialect, TokenRateLimitParams, UnknownUsage,
    };
    use ianua_domain::types::{Fact, IpAddress, Seconds};

    use super::super::fakes::{Rig, context, denial_status, header_value, signed_in_user};
    use super::*;

    fn per_caller(max_requests: u32) -> RateLimitConfig {
        RateLimitConfig {
            max_requests,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
        }
    }

    fn per_address(max_requests: u32) -> RateLimitConfig {
        RateLimitConfig {
            key_by: RateLimitKey::IpAddress,
            ..per_caller(max_requests)
        }
    }

    fn tokens(max_tokens: u32, charge: u32) -> TokenRateLimitConfig {
        TokenRateLimitConfig::new(TokenRateLimitParams {
            max_tokens,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
            dialect: LlmDialect::OpenAi,
            on_unknown: UnknownUsage::Charge(charge),
        })
        .unwrap()
    }

    /// Ann's two requests fit a limit of two a minute.
    #[tokio::test]
    async fn requests_within_the_limit_pass() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let (stage, mut ctx) = (StageId::new(), signed_in_user());

        for _ in 0..2 {
            let decision = stages
                .rate_limit(&stage, &per_caller(2), &mut ctx)
                .await
                .unwrap();
            assert!(!decision.is_terminal());
        }
        assert!(ctx.response_headers.is_empty());
    }

    /// Ann's third request in the minute is refused with a 429 that says
    /// when to come back and that nothing is left.
    #[tokio::test]
    async fn a_request_over_the_limit_is_refused_with_its_headers() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let (stage, mut ctx) = (StageId::new(), signed_in_user());
        for _ in 0..2 {
            stages
                .rate_limit(&stage, &per_caller(2), &mut ctx)
                .await
                .unwrap();
        }

        let decision = stages
            .rate_limit(&stage, &per_caller(2), &mut ctx)
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(429));
        assert_eq!(header_value(&ctx, "ratelimit-limit").as_deref(), Some("2"));
        assert_eq!(
            header_value(&ctx, "ratelimit-remaining").as_deref(),
            Some("0")
        );
        let retry = header_value(&ctx, "retry-after").unwrap();
        assert!((1..=60).contains(&retry.parse::<u32>().unwrap()));
        assert_eq!(header_value(&ctx, "ratelimit-reset"), Some(retry));
    }

    /// One address spending its limit leaves another address's untouched.
    #[tokio::test]
    async fn a_per_address_limit_counts_each_address_apart() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let stage = StageId::new();
        let mut first = context();
        let mut second = context();
        second.tenant_id = first.tenant_id;
        second.ip_address = Fact::Known(IpAddress::new("198.51.100.9").unwrap());
        stages
            .rate_limit(&stage, &per_address(1), &mut first)
            .await
            .unwrap();

        let decision = stages
            .rate_limit(&stage, &per_address(1), &mut second)
            .await
            .unwrap();

        assert!(!decision.is_terminal());
    }

    /// An anonymous caller's second request exceeds a per-caller limit of
    /// one and receives 429 using its address for counting.
    #[tokio::test]
    async fn an_anonymous_request_is_still_limited() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let (stage, mut ctx) = (StageId::new(), context());
        stages
            .rate_limit(&stage, &per_caller(1), &mut ctx)
            .await
            .unwrap();

        let decision = stages
            .rate_limit(&stage, &per_caller(1), &mut ctx)
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(429));
    }

    /// An unavailable rate-limit counter returns a 503 denial.
    #[tokio::test]
    async fn an_unreachable_counter_refuses() {
        let rig = Rig::unreachable();

        let decision = rig
            .stages()
            .rate_limit(&StageId::new(), &per_caller(100), &mut signed_in_user())
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(503));
    }

    /// A counter that never answers reaches its timeout and returns a 503 denial.
    #[tokio::test(start_paused = true)]
    async fn a_counter_that_hangs_refuses() {
        let rig = Rig::hanging();

        let decision = rig
            .stages()
            .rate_limit(&StageId::new(), &per_caller(100), &mut signed_in_user())
            .await
            .unwrap();

        assert_eq!(denial_status(&decision), Some(503));
    }

    /// A request that fits sets aside a typical exchange's tokens, for the
    /// response side to settle.
    #[tokio::test]
    async fn a_token_request_that_fits_sets_tokens_aside() {
        let rig = Rig::counting();

        let admission = rig
            .stages()
            .token_rate_limit(
                &StageId::new(),
                &tokens(3_000, 1_000),
                &mut signed_in_user(),
            )
            .await
            .unwrap();

        let reserved = admission.reservation.map(Reservation::tokens);
        assert!(!admission.decision.is_terminal());
        assert_eq!(reserved, Some(1_000));
    }

    /// Ann's fourth request would set aside more than her 3,000 tokens a
    /// minute, so it is refused with a 429 naming the token limit.
    #[tokio::test]
    async fn a_token_request_that_does_not_fit_is_refused() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let (stage, mut ctx) = (StageId::new(), signed_in_user());
        for _ in 0..3 {
            stages
                .token_rate_limit(&stage, &tokens(3_000, 1_000), &mut ctx)
                .await
                .unwrap();
        }

        let admission = stages
            .token_rate_limit(&stage, &tokens(3_000, 1_000), &mut ctx)
            .await
            .unwrap();

        assert_eq!(denial_status(&admission.decision), Some(429));
        assert!(admission.reservation.is_none());
        let limit = header_value(&ctx, "ratelimit-limit");
        assert_eq!(limit.as_deref(), Some("3000"));
    }

    /// Four attempts to reserve 1,000 tokens against a 3,000-token cap leave
    /// only 3,000 counted after the excess reservation is returned.
    #[tokio::test]
    async fn a_refused_token_request_gives_its_reservation_back() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let (stage, mut ctx) = (StageId::new(), signed_in_user());
        for _ in 0..4 {
            stages
                .token_rate_limit(&stage, &tokens(3_000, 1_000), &mut ctx)
                .await
                .unwrap();
        }

        let counted = rig.fleet.total_under("");

        assert_eq!(counted, 3_000);
    }

    /// A token counter that cannot answer refuses the request.
    #[tokio::test]
    async fn an_unreachable_token_counter_refuses() {
        let rig = Rig::unreachable();

        let admission = rig
            .stages()
            .token_rate_limit(
                &StageId::new(),
                &tokens(3_000, 1_000),
                &mut signed_in_user(),
            )
            .await
            .unwrap();

        assert_eq!(denial_status(&admission.decision), Some(503));
    }
}
