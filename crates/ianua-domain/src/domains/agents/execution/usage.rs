//! What a model call uses and what it costs.
//!
//! A provider reports the tokens each reply took. The price a tenant sets
//! on its provider turns them into spend, in millionths of the tenant's
//! billing currency, so a run can be held to a spend budget.

/// Tokens per million, the unit prices are quoted in.
const PER_MILLION: u128 = 1_000_000;

/// The tokens one model call, or a whole run, used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelTokens {
    input: u64,
    output: u64,
}

impl ModelTokens {
    /// `input` tokens sent to the model and `output` tokens it wrote.
    #[must_use]
    pub fn new(input: u64, output: u64) -> Self {
        Self { input, output }
    }

    /// Tokens sent to the model.
    #[must_use]
    pub fn input(self) -> u64 {
        self.input
    }

    /// Tokens the model wrote.
    #[must_use]
    pub fn output(self) -> u64 {
        self.output
    }

    /// Both counts added to `other`'s. A count past `u64::MAX` stays there.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        Self {
            input: self.input.saturating_add(other.input),
            output: self.output.saturating_add(other.output),
        }
    }
}

/// What a provider said one call used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelUsage {
    /// The provider reported no usage.
    Unreported,
    /// The provider reported these tokens.
    Reported(ModelTokens),
}

/// An amount of money in millionths of the tenant's billing currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Spend(u64);

impl Spend {
    /// `micros` millionths of the currency.
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// The amount in millionths of the currency.
    #[must_use]
    pub fn micros(self) -> u64 {
        self.0
    }

    /// This amount and `other` together. A sum past `u64::MAX` stays there.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

/// What a model provider charges, or that its price is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ModelPricing {
    /// Nobody set a price, so what it costs is unknown.
    Unpriced,
    /// The price per million tokens sent and written.
    PerMillionTokens {
        /// The price of a million tokens sent to the model.
        input: Spend,
        /// The price of a million tokens the model wrote.
        output: Spend,
    },
}

impl ModelPricing {
    /// What `usage` costs at this price, rounded up to the next millionth so
    /// a run is never under-counted. `None` when the price is unknown.
    #[must_use]
    pub fn cost_of(self, usage: ModelTokens) -> Option<Spend> {
        let Self::PerMillionTokens { input, output } = self else {
            return None;
        };
        Some(priced(usage.input, input).plus(priced(usage.output, output)))
    }
}

/// What `tokens` cost at `per_million`, rounded up. A cost past `u64::MAX`
/// stays there.
fn priced(tokens: u64, per_million: Spend) -> Spend {
    let total = u128::from(tokens)
        .saturating_mul(u128::from(per_million.micros()))
        .div_ceil(PER_MILLION);
    Spend::from_micros(u64::try_from(total).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A million tokens in at 3,000,000 millionths and half a million out at
    /// 15,000,000 cost 3 and 7.5 currency units, 10.5 together.
    #[test]
    fn a_price_per_million_tokens_gives_the_cost_of_a_call() {
        let pricing = ModelPricing::PerMillionTokens {
            input: Spend::from_micros(3_000_000),
            output: Spend::from_micros(15_000_000),
        };

        let cost = pricing.cost_of(ModelTokens::new(1_000_000, 500_000));

        assert_eq!(cost, Some(Spend::from_micros(10_500_000)));
    }

    /// A one-token call costing less than one millionth rounds up to one,
    /// preventing fractional usage from being counted as free.
    #[test]
    fn a_fraction_of_a_millionth_is_rounded_up() {
        let pricing = ModelPricing::PerMillionTokens {
            input: Spend::from_micros(1),
            output: Spend::from_micros(1),
        };

        assert_eq!(
            pricing.cost_of(ModelTokens::new(1, 0)),
            Some(Spend::from_micros(1))
        );
    }

    /// A provider with no price set gives no cost.
    #[test]
    fn an_unpriced_provider_has_no_cost() {
        assert_eq!(
            ModelPricing::Unpriced.cost_of(ModelTokens::new(10, 10)),
            None
        );
    }

    /// Counts and amounts near the top add up to the top, never wrap round
    /// to a small number that would slip under a budget.
    #[test]
    fn sums_stop_at_the_top_instead_of_wrapping() {
        let near_top = ModelTokens::new(u64::MAX, 1);

        assert_eq!(near_top.plus(ModelTokens::new(5, 5)).input(), u64::MAX);
        assert_eq!(
            Spend::from_micros(u64::MAX).plus(Spend::from_micros(1)),
            Spend::from_micros(u64::MAX)
        );
        let dear = ModelPricing::PerMillionTokens {
            input: Spend::from_micros(u64::MAX),
            output: Spend::from_micros(0),
        };
        assert_eq!(
            dear.cost_of(ModelTokens::new(u64::MAX, 0)),
            Some(Spend::from_micros(u64::MAX))
        );
    }
}
