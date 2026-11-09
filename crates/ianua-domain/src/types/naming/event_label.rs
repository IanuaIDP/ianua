//! What an event calls the thing it is about.

use std::fmt;

use crate::types::naming::untrusted_text::made_safe;

/// The name a person, role, client or other thing had when an event was
/// recorded, such as an email, a display name or a role's name.
///
/// It is kept as it was, because the name may change later and the event
/// records that moment. It is never refused, since an event must be
/// recorded whatever the name held. It is made safe like
/// [`UntrustedText`](crate::types::UntrustedText). It is cut to 512
/// characters and its control characters are replaced, so a name cannot
/// forge a line in a log or bloat the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "String", into = "String"))]
pub struct EventLabel(String);

impl From<String> for EventLabel {
    /// A label read back is made safe the same way as one recorded.
    fn from(name: String) -> Self {
        Self::of(&name)
    }
}

impl From<EventLabel> for String {
    fn from(label: EventLabel) -> Self {
        label.0
    }
}

impl EventLabel {
    /// The label for something named `name`.
    #[must_use]
    pub fn of(name: &str) -> Self {
        Self(made_safe(name))
    }

    /// The label as recorded.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `alice@acme.com` is recorded exactly as it was.
    #[test]
    fn an_ordinary_name_is_kept_as_it_was() {
        assert_eq!(EventLabel::of("alice@acme.com").as_str(), "alice@acme.com");
    }

    /// Recording a name containing a newline removes that line break so it
    /// cannot introduce a second log entry.
    #[test]
    fn a_name_with_a_line_break_cannot_forge_a_log_line() {
        assert!(
            !EventLabel::of("eve\nadmin logged in")
                .as_str()
                .contains('\n')
        );
    }

    /// A 2000-character name is recorded, cut to 512 characters, so it does
    /// not bloat the audit trail.
    #[test]
    fn a_very_long_name_is_cut() {
        assert_eq!(
            EventLabel::of(&"a".repeat(2000)).as_str().chars().count(),
            512
        );
    }
}
