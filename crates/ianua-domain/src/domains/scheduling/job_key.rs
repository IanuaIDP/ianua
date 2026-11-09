//! The key that keeps the same work from being queued twice.

use std::fmt::Display;

use crate::shared::validation::{Charset, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// What a job does, said once: while a job with this key waits or runs,
    /// queueing another with the same key adds nothing.
    ///
    /// Made of what names the work, such as an event and the target it goes
    /// to, joined by a colon. Lowercase letters, digits, `-`, `_`, `.` and
    /// `:`, at most 200 characters.
    pub struct JobKey;
}

impl TextValue for JobKey {
    const FIELD: &'static str = "job_key";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=200,
            Charset::LOWERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::DOT
                | Charset::COLON,
        )
    }
}

impl JobKey {
    /// The key naming the work by `what` and `target`, joined by a colon,
    /// such as an event and the subscription it is sent to.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when either part writes a character a key may
    ///   not hold, or the two are too long together.
    pub fn of(what: impl Display, target: impl Display) -> Result<Self, ValidationError> {
        Self::new(format!("{what}:{target}"))
    }
}

/// How long a job's key keeps another job with the same key from being
/// queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyHold {
    /// While the job waits or runs. Once it has ended, the same work may be
    /// queued again, as a run woken again after its last drive.
    WhileLive,
    /// For as long as the job is kept, whatever became of it, so the work
    /// is done once: Acme's event handed to one webhook, delivered again
    /// by the bus after the first delivery went out, sends nothing more.
    WhileKept,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An event id and a subscription id make one key, joined by a colon.
    #[test]
    fn two_ids_make_one_key() {
        let event = uuid::Uuid::now_v7();
        let target = uuid::Uuid::now_v7();

        let key = JobKey::of(event, target).unwrap();

        assert_eq!(key.as_str(), format!("{event}:{target}"));
    }

    /// A key with a space or a capital letter is refused, so two spellings
    /// of the same work cannot slip past each other.
    #[test]
    fn a_key_with_a_space_or_a_capital_is_refused() {
        assert!(JobKey::new("event 1").is_err());
        assert!(JobKey::new("Event:1").is_err());
    }

    /// An empty key names no work, and is refused.
    #[test]
    fn an_empty_key_is_refused() {
        assert!(JobKey::new("").is_err());
    }
}
