//! Limiting what a caller may spend on a language model, not how often it
//! asks.
//!
//! A request count says little about cost here. One request can cost a
//! thousand times another, and the bill follows tokens. So this counts tokens.
//!
//! The hard part is when the count is known. A request limit is decided before
//! forwarding, from the request alone. The provider reports tokens only once it
//! has answered. So admitting a request sets aside a reservation, the
//! configured cost of a typical exchange. The request is refused when that
//! would not fit. Once the answer reports its cost, the reservation is settled
//! against it.
//!
//! Requests in flight together each hold their own reservation, so running
//! them at once cannot spend the same budget twice. One exchange can still cost
//! more than it reserved, since its price is learned last. That is why the
//! window matters more than the precision.

use time::OffsetDateTime;

use crate::domains::proxy::stages::stage::RateLimitKey;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{Fact, Seconds};

/// The most tokens a single window may allow.
///
/// High enough for any real deployment. Low enough that a typo setting four
/// billion is refused, instead of acting as no limit.
pub(crate) const MAX_TOKENS_PER_WINDOW: u32 = 100_000_000;

/// The shortest window worth counting over.
pub(crate) const MIN_WINDOW_SECS: u32 = 1;

/// The longest window, one day.
///
/// A longer window is a quota, not a rate limit. A quota needs a counter that
/// survives a restart and reports how much is left, which this is not.
pub(crate) const MAX_WINDOW_SECS: u32 = 86_400;

/// Which provider's response format says what an exchange cost.
///
/// The two put the numbers in different places and count different things.
/// Reading one as the other gives a number that looks right and is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LlmDialect {
    /// OpenAI and the APIs that copy it, such as Azure OpenAI, Together,
    /// Groq, vLLM and Ollama's compatible endpoint.
    ///
    /// Counts are under `usage` as `prompt_tokens` and `completion_tokens`.
    OpenAi,
    /// Anthropic's Messages API.
    ///
    /// Counts are under `usage` as `input_tokens` and `output_tokens`. A
    /// streamed exchange reports them in two separate events.
    Anthropic,
}

impl LlmDialect {
    /// The name it is stored under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "open_ai",
            Self::Anthropic => "anthropic",
        }
    }
}

/// What one exchange cost.
///
/// Input and output are kept apart because they are priced differently.
/// Output costs several times more everywhere. So a deployment that wants to
/// weight them has both numbers, not only a total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenUsage {
    /// Tokens the prompt consumed.
    pub input: u32,
    /// Tokens the answer consumed.
    pub output: u32,
}

impl TokenUsage {
    /// A usage of `input` prompt tokens and `output` answer tokens.
    #[must_use]
    pub fn new(input: u32, output: u32) -> Self {
        Self { input, output }
    }

    /// What to charge for this exchange.
    ///
    /// The sum stops at `u32::MAX`. A provider reporting nonsense costs the
    /// caller its whole window, instead of wrapping round to almost nothing.
    #[must_use]
    pub fn total(self) -> u32 {
        self.input.saturating_add(self.output)
    }

    /// Whether anything was reported at all.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.input == 0 && self.output == 0
    }
}

/// What to charge when the response never said what it cost.
///
/// A caller chooses whether to stream and whether to ask for usage. So a
/// response that does not say its cost is something the caller can cause at
/// will. Charging nothing for it would let any caller opt out of the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum UnknownUsage {
    /// Charge a fixed number of tokens.
    ///
    /// The default, and the only setting that keeps the limit binding.
    ///
    /// The number is a deployment's guess at a typical exchange. Roughly right
    /// is enough. Its job is to make skipping the report pointless, not to
    /// bill exactly.
    Charge(u32),
    /// Charge only the smallest reservation, one token.
    ///
    /// A caller can then mostly avoid the limit. Use it only where every
    /// caller is trusted and an uncounted exchange is better than an
    /// overcharged one.
    Ignore,
}

impl Default for UnknownUsage {
    /// A thousand tokens, the cost of a short exchange. It is small enough
    /// not to punish a response that truly could not report its cost.
    fn default() -> Self {
        Self::Charge(1_000)
    }
}

impl UnknownUsage {
    /// What this setting charges. `Ignore` charges zero here, and the
    /// one-token reservation still applies.
    #[must_use]
    pub fn charge(self) -> u32 {
        match self {
            Self::Charge(tokens) => tokens,
            Self::Ignore => 0,
        }
    }
}

/// Settings for the TokenRateLimit stage: a limit on what a caller spends.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TokenRateLimitConfig {
    max_tokens: u32,
    window_seconds: Seconds,
    key_by: RateLimitKey,
    dialect: LlmDialect,
    on_unknown: UnknownUsage,
}

/// What a caller supplies to configure a token limit.
pub struct TokenRateLimitParams {
    /// The most tokens one key may spend per window.
    pub max_tokens: u32,
    /// How long the window lasts.
    pub window_seconds: Seconds,
    /// What counts as one caller.
    pub key_by: RateLimitKey,
    /// Whose response shape to read the cost from.
    pub dialect: LlmDialect,
    /// What to charge when the response did not say.
    pub on_unknown: UnknownUsage,
}

impl TokenRateLimitConfig {
    /// A token limit, once its settings pass.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `max_tokens` is zero or above
    ///   `MAX_TOKENS_PER_WINDOW`.
    /// - [`ValidationError`] if the window is outside
    ///   `MIN_WINDOW_SECS..=MAX_WINDOW_SECS`.
    /// - [`ValidationError`] if the fallback charge is larger than
    ///   `max_tokens`. One unreported exchange would then spend the whole
    ///   window, and the gateway would look broken.
    pub fn new(params: TokenRateLimitParams) -> Result<Self, ValidationError> {
        validate_range("max_tokens", params.max_tokens, 1..=MAX_TOKENS_PER_WINDOW)?;
        validate_range(
            "window_seconds",
            params.window_seconds.get(),
            MIN_WINDOW_SECS..=MAX_WINDOW_SECS,
        )?;
        validate_range(
            "unknown_charge",
            params.on_unknown.charge(),
            0..=params.max_tokens,
        )?;

        Ok(Self {
            max_tokens: params.max_tokens,
            window_seconds: params.window_seconds,
            key_by: params.key_by,
            dialect: params.dialect,
            on_unknown: params.on_unknown,
        })
    }

    /// The most tokens one key may spend per window.
    #[must_use]
    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }

    /// How long the window lasts.
    #[must_use]
    pub fn window_seconds(&self) -> Seconds {
        self.window_seconds
    }

    /// What counts as one caller.
    #[must_use]
    pub fn key_by(&self) -> &RateLimitKey {
        &self.key_by
    }

    /// Whose response shape to read the cost from.
    #[must_use]
    pub fn dialect(&self) -> LlmDialect {
        self.dialect
    }

    /// What to charge when the response did not say.
    #[must_use]
    pub fn on_unknown(&self) -> UnknownUsage {
        self.on_unknown
    }

    /// What admitting one request sets aside before its cost is known.
    ///
    /// It is the fallback charge, the deployment's guess at a typical
    /// exchange, and never less than one token.
    #[must_use]
    pub fn reservation(&self) -> u32 {
        self.on_unknown.charge().max(1)
    }

    /// The fixed window `at` falls in.
    ///
    /// Windows are counted from the Unix epoch, so every proxy instance
    /// agrees on where one ends.
    #[must_use]
    pub fn window_at(&self, at: OffsetDateTime) -> TokenWindow {
        TokenWindow(
            at.unix_timestamp()
                .div_euclid(i64::from(self.window_seconds.get())),
        )
    }

    /// A reservation for one more request, when it still fits under the
    /// limit.
    ///
    /// `spent` is what the key's window at `now` already holds, with the
    /// reservations of requests still in flight. The caller adds the
    /// reservation to that window in the same step as it asks. So two
    /// requests racing for the last of a budget cannot both be admitted. The
    /// reservation remembers its window, so settling it later never moves
    /// budget between windows.
    #[must_use]
    pub fn admit(&self, spent: u32, now: OffsetDateTime) -> Option<Reservation> {
        let tokens = self.reservation();
        if spent.saturating_add(tokens) > self.max_tokens {
            return None;
        }
        Some(Reservation {
            tokens,
            window: self.window_at(now),
        })
    }

    /// Settles an exchange admitted with `reservation`, given what the
    /// response reported, at `now`.
    ///
    /// This is the one place the fallback is applied, so no code path can
    /// charge nothing by forgetting it. An exchange that reported nothing is
    /// charged at least what it reserved. The caller decides whether usage is
    /// reported, so silence never costs less.
    ///
    /// Inside the reservation's own window, the difference is settled there.
    /// Once that window has passed, a refund is dropped. Crediting the current
    /// window would give it budget spent in the old one. An overrun is
    /// charged to the current window, where the cost landed.
    #[must_use]
    pub fn settle(
        &self,
        reservation: Reservation,
        reported: Fact<TokenUsage>,
        now: OffsetDateTime,
    ) -> TokenCharge {
        let charged = match reported {
            Fact::Known(usage) if !usage.is_empty() => usage.total(),
            Fact::Known(_) | Fact::Unknown => self.on_unknown.charge().max(reservation.tokens),
        };
        let difference = i64::from(charged).saturating_sub(i64::from(reservation.tokens));
        let current = self.window_at(now);
        if current == reservation.window {
            return TokenCharge {
                window: current,
                adjustment: difference,
            };
        }
        TokenCharge {
            window: current,
            adjustment: difference.max(0),
        }
    }

    /// Gives back `reservation` for an exchange that never reached the
    /// provider, such as a request a later stage refused, at `now`.
    ///
    /// Inside the reservation's own window the whole of it comes back.
    /// Once that window has passed nothing does, as with any refund
    /// [`settle`](Self::settle) drops.
    #[must_use]
    pub fn release(&self, reservation: Reservation, now: OffsetDateTime) -> TokenCharge {
        let current = self.window_at(now);
        if current != reservation.window {
            return TokenCharge {
                window: current,
                adjustment: 0,
            };
        }
        TokenCharge {
            window: current,
            adjustment: i64::from(reservation.tokens).saturating_neg(),
        }
    }
}

/// One fixed counting window, numbered from the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenWindow(i64);

impl TokenWindow {
    /// The window's number, which counters are keyed by.
    #[must_use]
    pub fn index(self) -> i64 {
        self.0
    }
}

/// Tokens set aside for one request when it was admitted, in the window it
/// was admitted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Reservation {
    tokens: u32,
    window: TokenWindow,
}

impl Reservation {
    /// The tokens set aside.
    #[must_use]
    pub fn tokens(self) -> u32 {
        self.tokens
    }

    /// The window they were set aside in.
    #[must_use]
    pub fn window(self) -> TokenWindow {
        self.window
    }
}

/// What settling an exchange changes, and in which window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCharge {
    window: TokenWindow,
    adjustment: i64,
}

impl TokenCharge {
    /// The window to apply the adjustment to.
    #[must_use]
    pub fn window(self) -> TokenWindow {
        self.window
    }

    /// What to add to that window.
    ///
    /// Positive when the exchange cost more than it reserved, negative when
    /// it cost less.
    #[must_use]
    pub fn adjustment(self) -> i64 {
        self.adjustment
    }
}

/// Reads a token limit through [`TokenRateLimitConfig::new`], so a stored
/// limit is checked the same way as a new one.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TokenRateLimitConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            max_tokens: u32,
            window_seconds: Seconds,
            key_by: RateLimitKey,
            dialect: LlmDialect,
            #[serde(default)]
            on_unknown: UnknownUsage,
        }

        let wire = Wire::deserialize(deserializer)?;

        Self::new(TokenRateLimitParams {
            max_tokens: wire.max_tokens,
            window_seconds: wire.window_seconds,
            key_by: wire.key_by,
            dialect: wire.dialect,
            on_unknown: wire.on_unknown,
        })
        .map_err(<D::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Seconds;

    fn params() -> TokenRateLimitParams {
        TokenRateLimitParams {
            max_tokens: 10_000,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::ConsumerId,
            dialect: LlmDialect::OpenAi,
            on_unknown: UnknownUsage::default(),
        }
    }

    fn config() -> TokenRateLimitConfig {
        TokenRateLimitConfig::new(params()).unwrap()
    }

    /// `seconds` into a sixty-second window.
    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_040 + seconds).unwrap()
    }

    /// What an exchange admitted and settled in one window adds to it.
    fn settled(config: &TokenRateLimitConfig, reported: Fact<TokenUsage>) -> i64 {
        let reservation = config.admit(0, at(0)).unwrap();
        config.settle(reservation, reported, at(1)).adjustment()
    }

    /// An exchange reserved 1,000 tokens and reported 120 in and 380 out.
    /// Settling charges 500, so 500 comes back to the window.
    #[test]
    fn a_reported_exchange_is_charged_what_it_cost() {
        assert_eq!(
            settled(&config(), Fact::Known(TokenUsage::new(120, 380))),
            500 - 1_000
        );
    }

    /// Unknown usage keeps the 1,000-token reservation as the fallback
    /// charge, producing no settlement adjustment.
    #[test]
    fn an_unreported_exchange_is_charged_the_fallback() {
        assert_eq!(settled(&config(), Fact::Unknown), 0);
    }

    /// Reporting zero input and output tokens keeps the fallback charge,
    /// producing no adjustment to the reservation.
    #[test]
    fn an_exchange_reporting_nothing_is_charged_the_fallback() {
        assert_eq!(settled(&config(), Fact::Known(TokenUsage::default())), 0);
    }

    /// With `Ignore`, a request reserves one token, and an unreported
    /// exchange keeps that one token as its charge.
    #[test]
    fn ignoring_unknown_usage_charges_only_the_smallest_reservation() {
        let config = TokenRateLimitConfig::new(TokenRateLimitParams {
            on_unknown: UnknownUsage::Ignore,
            ..params()
        })
        .unwrap();

        assert_eq!(config.admit(0, at(0)).unwrap().tokens(), 1);
        assert_eq!(settled(&config, Fact::Unknown), 0);
    }

    /// Eve's request set 1,000 tokens aside, then a later stage refused it
    /// before it reached the provider. All 1,000 come back to the window.
    #[test]
    fn a_refused_exchange_gives_its_reservation_back() {
        let config = config();
        let reservation = config.admit(0, at(0)).unwrap();

        let charge = config.release(reservation, at(1));

        assert_eq!(charge.window(), reservation.window());
        assert_eq!(charge.adjustment(), -1_000);
    }

    /// Releasing a reservation after its window ends produces no refund.
    #[test]
    fn a_release_after_the_window_rolled_over_gives_nothing_back() {
        let config = config();
        let reservation = config.admit(0, at(59)).unwrap();

        let charge = config.release(reservation, at(61));

        assert_eq!(charge.adjustment(), 0);
    }

    /// Settling an exchange below its reservation after the window ends
    /// targets the current window with a zero adjustment.
    #[test]
    fn a_refund_after_the_window_rolled_over_is_dropped() {
        let config = config();
        let reservation = config.admit(9_000, at(59)).unwrap();

        let charge = config.settle(reservation, Fact::Known(TokenUsage::new(5, 6)), at(61));

        assert_eq!(charge.window(), config.window_at(at(61)));
        assert_eq!(charge.adjustment(), 0);
    }

    /// An exchange reserved 1,000 tokens at second 59 and reported 1,500 at
    /// second 61. The extra 500 is charged to the new window.
    #[test]
    fn an_overrun_after_the_window_rolled_over_is_charged_to_the_current_window() {
        let config = config();
        let reservation = config.admit(0, at(59)).unwrap();

        let charge = config.settle(
            reservation,
            Fact::Known(TokenUsage::new(1_000, 500)),
            at(61),
        );

        assert_eq!(charge.window(), config.window_at(at(61)));
        assert_eq!(charge.adjustment(), 500);
    }

    /// A reservation taken at second 10 belongs to the window that runs to
    /// second 59, not the one starting at 60.
    #[test]
    fn a_reservation_remembers_the_window_it_was_taken_in() {
        let config = config();

        let reservation = config.admit(0, at(10)).unwrap();

        assert_eq!(reservation.window(), config.window_at(at(59)));
        assert_ne!(reservation.window(), config.window_at(at(60)));
    }

    /// Summing maximum input and output counts saturates at `u32::MAX`
    /// instead of overflowing.
    #[test]
    fn an_absurd_report_saturates_rather_than_wrapping() {
        let usage = TokenUsage::new(u32::MAX, u32::MAX);

        assert_eq!(usage.total(), u32::MAX);
    }

    /// Under a 10,000-token limit, a key that spent nothing, or 9,000, still
    /// has room for a 1,000-token reservation.
    #[test]
    fn a_key_with_room_for_a_reservation_may_ask_again() {
        let config = config();

        assert!(config.admit(0, at(0)).is_some());
        assert!(config.admit(9_000, at(0)).is_some());
    }

    /// A 1,000-token reservation is refused when spending reaches 9,001,
    /// 10,000 or `u32::MAX` under a 10,000-token limit.
    #[test]
    fn a_key_without_room_for_a_reservation_may_not() {
        let config = config();

        assert!(config.admit(9_001, at(0)).is_none());
        assert!(config.admit(10_000, at(0)).is_none());
        assert!(config.admit(u32::MAX, at(0)).is_none());
    }

    /// Adding each admitted reservation to the running total permits ten
    /// requests under the 10,000-token limit and refuses the eleventh.
    #[test]
    fn concurrent_requests_cannot_spend_the_same_budget_twice() {
        let config = config();
        let mut window = 0u32;

        let admitted = (0..10)
            .filter_map(|_| {
                let reservation = config.admit(window, at(0))?;
                window += reservation.tokens();
                Some(reservation)
            })
            .count();

        assert_eq!(admitted, 10);
        assert!(config.admit(window, at(0)).is_none());
    }

    /// An exchange that cost 300 of its 1,000 reserved gets 700 back. One
    /// that reported nothing keeps its whole reservation.
    #[test]
    fn settling_refunds_the_unused_reservation_but_never_below_it_when_unreported() {
        let config = config();

        assert_eq!(
            settled(&config, Fact::Known(TokenUsage::new(100, 200))),
            -700
        );
        assert_eq!(settled(&config, Fact::Unknown), 0);
    }

    /// A limit of zero tokens would refuse every request, so it is refused.
    #[test]
    fn a_zero_limit_is_refused() {
        assert!(
            TokenRateLimitConfig::new(TokenRateLimitParams {
                max_tokens: 0,
                ..params()
            })
            .is_err()
        );
    }

    /// A zero-second window and one a second past a day are refused.
    #[test]
    fn a_window_outside_the_bounds_is_refused() {
        assert!(
            TokenRateLimitConfig::new(TokenRateLimitParams {
                window_seconds: Seconds::new(0),
                ..params()
            })
            .is_err()
        );
        assert!(
            TokenRateLimitConfig::new(TokenRateLimitParams {
                window_seconds: Seconds::new(MAX_WINDOW_SECS + 1),
                ..params()
            })
            .is_err()
        );
    }

    /// A fallback of 501 tokens under a 500-token limit is refused. One
    /// unreported exchange would spend the whole window.
    #[test]
    fn a_fallback_that_would_exhaust_the_window_is_refused() {
        assert!(
            TokenRateLimitConfig::new(TokenRateLimitParams {
                max_tokens: 500,
                on_unknown: UnknownUsage::Charge(501),
                ..params()
            })
            .is_err()
        );
    }

    /// A fallback of exactly 500 tokens under a 500-token limit is allowed.
    #[test]
    fn a_fallback_equal_to_the_window_is_allowed() {
        assert!(
            TokenRateLimitConfig::new(TokenRateLimitParams {
                max_tokens: 500,
                on_unknown: UnknownUsage::Charge(500),
                ..params()
            })
            .is_ok()
        );
    }

    /// The dialects are stored as `open_ai` and `anthropic`. Renaming one
    /// fails here instead of changing stored data.
    #[test]
    fn every_dialect_has_a_stable_discriminant() {
        assert_eq!(LlmDialect::OpenAi.as_str(), "open_ai");
        assert_eq!(LlmDialect::Anthropic.as_str(), "anthropic");
    }

    /// A limit built with 10,000 tokens per 60 seconds reports exactly those
    /// two numbers back.
    #[test]
    fn the_budget_and_the_window_read_back_as_configured() {
        let config = config();

        assert_eq!(config.max_tokens(), 10_000);
        assert_eq!(config.window_seconds(), Seconds::new(60));
    }

    /// A limit built with a 500-token fallback reports 500, not the default
    /// of 1,000.
    #[test]
    fn the_configured_fallback_is_the_one_reported_back() {
        let config = TokenRateLimitConfig::new(TokenRateLimitParams {
            on_unknown: UnknownUsage::Charge(500),
            ..params()
        })
        .unwrap();

        assert_eq!(config.on_unknown(), UnknownUsage::Charge(500));
        assert_ne!(config.on_unknown(), UnknownUsage::default());
    }

    /// Usage of zero in and zero out is empty, and so gets the fallback. One
    /// token on either side is not empty. A streamed answer often reports
    /// only output.
    #[test]
    fn usage_is_empty_only_when_neither_side_reported_anything() {
        assert!(TokenUsage::new(0, 0).is_empty());
        assert!(!TokenUsage::new(1, 0).is_empty());
        assert!(!TokenUsage::new(0, 1).is_empty());
        assert!(!TokenUsage::new(120, 380).is_empty());
    }
}
