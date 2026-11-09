//! The namespace every name on the bus server and the cache server sits
//! under, so two deployments, such as staging and production, can share
//! one bus server and one cache server and never see each other's events,
//! broadcasts, consumers or keys.
//!
//! The rest of the crate builds its names relative to the namespace:
//! `tenant.<tenant>.<event type>` for an event, `realtime.operator.<id>`
//! for a broadcast, `rate:tenant:<tenant>` for a key. The bus server's and
//! the cache server's adapters put every one of them under the namespace
//! here on the way out, and take it off again on the way in, so no name
//! reaches either server without it. The default, `ianua`, gives the names
//! the platform has always kept its records under:
//! `ianua.tenant.<tenant>.<event type>`, the `ianua-events` stream,
//! `ianua:rate:tenant:<tenant>`. A durable consumer is kept inside its
//! stream, so its name is the namespace's through the stream's.
//!
//! A bus and state in this process hold one deployment's names only, so
//! they take no namespace.

use std::fmt;

use ianua_domain::shared::validation::{Boundary, Charset, ValidationError, Validator};

/// The namespace a deployment that names none runs under.
const DEFAULT: &str = "ianua";

/// The longest namespace, short enough to leave a stream's and a key's
/// own name room.
const MOST_BYTES: usize = 32;

/// What every bus subject, stream name and cache key of one deployment
/// sits under: 1 to 32 lower-case letters, digits and dashes, starting and
/// ending with a letter or a digit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace(String);

impl Namespace {
    /// The namespace `value` names.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `value` is not 1 to 32 lower-case
    /// letters, digits and dashes, or starts or ends with a dash.
    pub fn new(value: &str) -> Result<Self, ValidationError> {
        Validator::new("namespace", value)
            .max_bytes(MOST_BYTES)
            .ascii_only()
            .not_empty()
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
            .boundaries(Boundary::LowercaseAlphanumeric)
            .validate_first()?;
        Ok(Self(value.to_owned()))
    }

    /// The namespace as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The bus subject, or the pattern of subjects, `relative` names under
    /// the namespace: `<namespace>.<relative>`.
    pub(crate) fn subject(&self, relative: &str) -> String {
        format!("{}.{relative}", self.0)
    }

    /// What `subject` names under the namespace, or `None` when it is not
    /// under it.
    pub(crate) fn relative<'s>(&self, subject: &'s str) -> Option<&'s str> {
        subject.strip_prefix(self.0.as_str())?.strip_prefix('.')
    }

    /// The name of the stream `role` is kept in: `<namespace>-<role>`.
    pub(crate) fn stream(&self, role: &str) -> String {
        format!("{}-{role}", self.0)
    }

    /// The cache key `relative` names under the namespace:
    /// `<namespace>:<relative>`.
    pub(crate) fn key(&self, relative: &str) -> String {
        format!("{}:{relative}", self.0)
    }
}

impl Default for Namespace {
    /// `ianua`, the names the platform has always used.
    fn default() -> Self {
        Self(DEFAULT.to_owned())
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The default namespace gives today's names exactly: the event
    /// subjects, the streams and the cache keys.
    #[test]
    fn the_default_namespace_gives_the_names_used_before() {
        let namespace = Namespace::default();

        assert_eq!(namespace.as_str(), "ianua");
        assert_eq!(
            namespace.subject("tenant.0190aa.identity.user_registered"),
            "ianua.tenant.0190aa.identity.user_registered"
        );
        assert_eq!(namespace.subject("tenant.>"), "ianua.tenant.>");
        assert_eq!(namespace.stream("events"), "ianua-events");
        assert_eq!(namespace.stream("messages"), "ianua-messages");
        assert_eq!(namespace.stream("dead-letters"), "ianua-dead-letters");
        assert_eq!(namespace.key("rate:tenant:t1"), "ianua:rate:tenant:t1");
    }

    /// A subject read back loses its namespace, and one under another
    /// namespace, even one that starts with the same letters, is not read
    /// as this one's.
    #[test]
    fn only_a_subject_under_the_namespace_reads_back() {
        let namespace = Namespace::new("staging").unwrap();

        assert_eq!(
            namespace.relative("staging.tenant.0190aa.tenant.deleted"),
            Some("tenant.0190aa.tenant.deleted")
        );
        assert_eq!(namespace.relative("staging-2.tenant.0190aa.x"), None);
        assert_eq!(namespace.relative("ianua.tenant.0190aa.x"), None);
        assert_eq!(namespace.relative("staging"), None);
    }

    /// Namespace validation rejects separators, wildcards, invalid characters,
    /// misplaced dashes and values outside the length bounds.
    #[test]
    fn a_namespace_that_breaks_a_name_is_refused() {
        for refused in [
            "",
            "Ianua",
            "ianua.prod",
            "ianua:prod",
            "ianua>",
            "ianua*",
            "ianua prod",
            "-ianua",
            "ianua-",
            "ianuä",
            "a234567890123456789012345678901234",
        ] {
            assert!(Namespace::new(refused).is_err(), "{refused:?}");
        }
    }

    /// A short token of letters, digits and dashes is taken as written.
    #[test]
    fn a_short_token_is_taken() {
        for taken in ["ianua", "staging", "s1a2b3c4", "eu-west-1", "a"] {
            assert_eq!(Namespace::new(taken).unwrap().as_str(), taken);
        }
    }

    proptest! {
        /// Every namespace taken is one subject segment, one stream name
        /// part and one key part: it never holds a separator or a wildcard
        /// of either server.
        #[test]
        fn a_taken_namespace_holds_no_separator(value in "\\PC{0,40}") {
            if let Ok(namespace) = Namespace::new(&value) {
                prop_assert!(!namespace.as_str().contains(['.', ':', '*', '>', ' ']));
                let subject = namespace.subject("x");
                prop_assert_eq!(namespace.relative(&subject), Some("x"));
            }
        }
    }
}
