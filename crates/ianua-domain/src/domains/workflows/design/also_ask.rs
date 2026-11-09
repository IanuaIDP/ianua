//! Where else an approval step asks, beside the platform's own inbox.
//!
//! Bob approves payments from Slack. The workflow's approval step also
//! posts to the finance channel, with Approve and Deny buttons. The buttons
//! only open the approval in ianua: a press counts once Bob has signed in
//! there and decided, with every rule an approval keeps. Slack carries the
//! question, never the answer, so whoever reads the channel decides
//! nothing by pressing.

use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::IntegrationAccountId;

text_value! {
    /// A Slack channel a message may be posted to: its id, such as
    /// `C0123ABCD`, or its name with `#`.
    pub struct SlackChannel;
}

impl TextValue for SlackChannel {
    const FIELD: &'static str = "channel";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=80).charset(
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }

    fn normalized(value: String) -> String {
        value.strip_prefix('#').map(str::to_owned).unwrap_or(value)
    }
}

/// An approval also asked in a Slack channel, through one of the tenant's
/// connected Slack accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlackAsk {
    account: IntegrationAccountId,
    channel: SlackChannel,
}

impl SlackAsk {
    /// Asks in `channel` through the Slack account `account`.
    #[must_use]
    pub fn new(account: IntegrationAccountId, channel: SlackChannel) -> Self {
        Self { account, channel }
    }

    /// The connected Slack account the message is posted through.
    #[must_use]
    pub fn account(&self) -> IntegrationAccountId {
        self.account
    }

    /// The channel the message is posted to.
    #[must_use]
    pub fn channel(&self) -> &SlackChannel {
        &self.channel
    }
}

/// Where an approval step also asks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AlsoAsk {
    /// Only in the platform's inbox.
    #[default]
    Nowhere,
    /// In a Slack channel too.
    Slack(SlackAsk),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel named `#finance` is kept as `finance`; an id is kept as
    /// given; a lone `#` or a name with a space is no channel.
    #[test]
    fn a_channel_is_named_by_id_or_name() {
        assert_eq!(SlackChannel::new("#finance").unwrap().as_str(), "finance");
        assert_eq!(
            SlackChannel::new("C0123ABCD").unwrap().as_str(),
            "C0123ABCD"
        );
        assert!(SlackChannel::new("#").is_err());
        assert!(SlackChannel::new("my channel").is_err());
    }
}
