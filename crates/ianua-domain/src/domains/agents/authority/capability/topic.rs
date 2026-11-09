//! The messaging topic patterns a delegation may publish or subscribe on.

use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

/// Whether a holder may publish, subscribe, or both on a messaging topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PubSub {
    /// May publish only.
    Publish,
    /// May subscribe only.
    Subscribe,
    /// May both publish and subscribe.
    Both,
}

impl PubSub {
    /// The stored and wire form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
            Self::Both => "both",
        }
    }

    /// Whether these rights include `other`. [`PubSub::Both`] includes
    /// everything, and the others include only themselves.
    #[must_use]
    pub fn covers(self, other: Self) -> bool {
        matches!(self, Self::Both) || self == other
    }
}

text_value! {
    /// A messaging topic pattern in NATS form.
    ///
    /// Tokens are separated by `.`. A `*` token matches exactly one token. A
    /// `>` as the last token matches one or more remaining tokens.
    pub struct TopicPattern;
}

impl TextValue for TopicPattern {
    const FIELD: &'static str = "topic_pattern";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(512)
            .no_control_chars()
            .no_whitespace()
            .rule(&WholeTokens)
    }
}

impl TopicPattern {
    /// Whether this pattern matches every topic `other` matches.
    ///
    /// When in doubt the answer is no. A `*` here does not cover a `>` in
    /// `other`, since `>` can match more tokens than `*` does.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        let mut these = self.0.split('.');
        let mut those = other.0.split('.');
        loop {
            match (these.next(), those.next()) {
                (Some(">"), next) => return next.is_some(),
                (Some("*"), Some(">") | None) => return false,
                (Some("*"), Some(_)) => {}
                (Some(token), Some(other_token)) if token == other_token => {}
                (Some(_), _) => return false,
                (None, next) => return next.is_none(),
            }
        }
    }
}

/// A topic pattern with the publish and subscribe rights held on it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TopicCapability {
    pattern: TopicPattern,
    rights: PubSub,
}

impl TopicCapability {
    /// Pairs a topic pattern with the rights held on it.
    #[must_use]
    pub fn new(pattern: TopicPattern, rights: PubSub) -> Self {
        Self { pattern, rights }
    }

    /// The topic pattern.
    #[must_use]
    pub fn pattern(&self) -> &TopicPattern {
        &self.pattern
    }

    /// The publish and subscribe rights.
    #[must_use]
    pub fn rights(&self) -> PubSub {
        self.rights
    }

    /// Whether this covers `other`. The pattern must cover `other`'s pattern,
    /// and the rights must include `other`'s rights.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        self.pattern.covers(&other.pattern) && self.rights.covers(other.rights)
    }
}

/// Allows only subjects the message broker reads. Tokens are split by `.`,
/// none is empty, `*` and `>` stand only as whole tokens, and `>` comes last.
struct WholeTokens;

impl Rule for WholeTokens {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let tokens: Vec<&str> = value.split('.').collect();
        let last = tokens.len().saturating_sub(1);
        let problem = tokens.iter().enumerate().find_map(|(index, token)| {
            let wildcard_inside = token.len() > 1 && token.contains(['*', '>']);
            match *token {
                "" => Some("topic pattern must not contain empty tokens"),
                ">" if index != last => Some("`>` may only appear as the final token"),
                _ if wildcard_inside => Some("`*` and `>` may only stand as a whole token"),
                _ => None,
            }
        })?;
        Some(ValidationError::Custom {
            field,
            code: "invalid_topic_pattern".to_owned(),
            message: problem.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty pattern, one with a space, one with an empty token and one
    /// with `>` in the middle are all refused. `ianua.msg.t1.agents.>` is
    /// accepted.
    #[test]
    fn topic_pattern_rejects_bad_input() {
        assert!(TopicPattern::new("").is_err());
        assert!(TopicPattern::new("a b").is_err());
        assert!(TopicPattern::new("a..b").is_err());
        assert!(TopicPattern::new("a.>.b").is_err());
        assert!(TopicPattern::new("ianua.msg.t1.agents.>").is_ok());
    }

    /// A trailing wildcard covers a concrete agent topic, while that
    /// concrete topic does not cover the broader wildcard pattern.
    #[test]
    fn wildcard_topic_covers_concrete() {
        let broad = TopicPattern::new("ianua.msg.t1.agents.>").unwrap();
        let narrow = TopicPattern::new("ianua.msg.t1.agents.a2.tasks").unwrap();
        assert!(broad.covers(&narrow));
        assert!(!narrow.covers(&broad));
    }

    /// `ianua.msg.t1.*` covers `ianua.msg.t1.agents`. It does not cover
    /// `ianua.msg.t1.agents.a2`, which has one token more.
    #[test]
    fn star_matches_single_token_only() {
        let star = TopicPattern::new("ianua.msg.t1.*").unwrap();
        assert!(star.covers(&TopicPattern::new("ianua.msg.t1.agents").unwrap()));
        assert!(!star.covers(&TopicPattern::new("ianua.msg.t1.agents.a2").unwrap()));
    }

    /// Holding both rights includes publishing and subscribing. Holding only
    /// publish does not include subscribe.
    #[test]
    fn pubsub_both_covers_all() {
        assert!(PubSub::Both.covers(PubSub::Publish));
        assert!(PubSub::Both.covers(PubSub::Subscribe));
        assert!(!PubSub::Publish.covers(PubSub::Subscribe));
    }

    /// Deserialization refuses an empty topic pattern and a wildcard
    /// followed by another token, while accepting a concrete two-token topic.
    #[cfg(feature = "serde")]
    #[test]
    fn a_malformed_topic_pattern_is_refused() {
        assert!(serde_json::from_str::<TopicPattern>(r#""a.>.b""#).is_err());
        assert!(serde_json::from_str::<TopicPattern>(r#""""#).is_err());
        assert!(serde_json::from_str::<TopicPattern>(r#""a.b""#).is_ok());
    }
}
