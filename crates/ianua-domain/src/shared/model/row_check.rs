//! The check every stored row passes before an aggregate is rebuilt from it.
//!
//! The aggregate's own methods write its rows. A row that breaks one of
//! their rules was not written by them. Either the store is damaged or
//! something wrote to it around the domain. Rebuilding from it would give
//! callers an aggregate no code path allows. So the row is refused as
//! [`DomainError::Infrastructure`].

use time::OffsetDateTime;

use crate::shared::errors::DomainError;

/// The rules one stored row is checked against, refused at the first one it
/// breaks.
///
/// ```ignore
/// RowCheck::of("session")
///     .in_order(row.created_at, row.last_active_at, "used before it was created")
///     .holds(row.parent_id.parent() != Some(&row.id), "rotated from itself")
///     .finish()?;
/// ```
#[must_use]
pub(crate) struct RowCheck {
    entity: &'static str,
    verdict: Verdict,
}

/// What a row check has found so far.
enum Verdict {
    /// Every rule checked so far holds.
    Kept,
    /// The first rule found broken, by the reason that names it.
    Broken(&'static str),
}

impl RowCheck {
    /// Starts the check of a row meant to rebuild `entity`.
    pub(crate) fn of(entity: &'static str) -> Self {
        Self {
            entity,
            verdict: Verdict::Kept,
        }
    }

    /// Requires `rule` to hold. `reason` says what the row claims if not.
    pub(crate) fn holds(mut self, rule: bool, reason: &'static str) -> Self {
        if matches!(self.verdict, Verdict::Kept) && !rule {
            self.verdict = Verdict::Broken(reason);
        }
        self
    }

    /// Requires `earlier` not to come after `later`.
    pub(crate) fn in_order(
        self,
        earlier: OffsetDateTime,
        later: OffsetDateTime,
        reason: &'static str,
    ) -> Self {
        self.holds(earlier <= later, reason)
    }

    /// Requires `earlier` not to come after `later`, when `later` happened.
    pub(crate) fn in_order_if(
        self,
        earlier: OffsetDateTime,
        later: Option<OffsetDateTime>,
        reason: &'static str,
    ) -> Self {
        self.holds(later.is_none_or(|later| earlier <= later), reason)
    }

    /// The row as checked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] holding a
    ///   `CorruptRow` when a rule is
    ///   broken. It names the first rule the row broke.
    pub(crate) fn finish(self) -> Result<(), DomainError> {
        match self.verdict {
            Verdict::Kept => Ok(()),
            Verdict::Broken(reason) => Err(DomainError::corrupt_row(self.entity, reason)),
        }
    }
}

/// Whether `result` is a stored row refused as corrupt.
#[cfg(test)]
pub(crate) fn refused_as_corrupt<T>(result: &Result<T, DomainError>) -> bool {
    let Err(DomainError::Infrastructure(source)) = result else {
        return false;
    };
    source.is::<crate::shared::errors::CorruptRow>()
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::shared::errors::CorruptRow;

    /// A row check that failed counts as corrupt. A database that is down
    /// and a success do not, so tests cannot pass on the wrong error.
    #[test]
    fn only_a_corrupt_row_counts_as_one() {
        assert!(refused_as_corrupt(
            &RowCheck::of("session").holds(false, "x").finish()
        ));
        assert!(!refused_as_corrupt(&Err::<(), _>(DomainError::infra_msg(
            "down"
        ))));
        assert!(!refused_as_corrupt(&Ok::<(), DomainError>(())));
    }

    fn corrupt(result: Result<(), DomainError>) -> Option<&'static str> {
        let Err(DomainError::Infrastructure(source)) = result else {
            return None;
        };
        source.downcast_ref::<CorruptRow>().map(CorruptRow::entity)
    }

    /// A session row with a true rule, times in order, and no end time yet
    /// passes every check.
    #[test]
    fn a_row_that_keeps_every_rule_passes() {
        let now = OffsetDateTime::UNIX_EPOCH;

        let checked = RowCheck::of("session")
            .holds(true, "never")
            .in_order(now, now + Duration::SECOND, "never")
            .in_order_if(now, None, "never")
            .finish();

        assert!(checked.is_ok());
    }

    /// A session row that breaks one rule is refused as a corrupt row, and
    /// the error names `session`.
    #[test]
    fn a_broken_rule_is_a_corrupt_row_of_that_entity() {
        assert_eq!(
            corrupt(RowCheck::of("session").holds(false, "broken").finish()),
            Some("session")
        );
    }

    /// A session row that ended one second before it began is refused as
    /// corrupt.
    #[test]
    fn times_out_of_order_are_refused() {
        let now = OffsetDateTime::UNIX_EPOCH;

        let checked = RowCheck::of("session")
            .in_order_if(now, Some(now - Duration::SECOND), "ended before it began")
            .finish();

        assert!(corrupt(checked).is_some());
    }

    /// A row breaks two rules, "first" and then "second". The error gives
    /// "first", the rule checked earlier.
    #[test]
    fn the_first_broken_rule_is_the_one_reported() {
        let checked = RowCheck::of("session")
            .holds(false, "first")
            .holds(false, "second")
            .finish();

        let Err(error) = checked else {
            panic!("a broken rule must refuse the row");
        };
        assert!(crate::shared::errors::causes(&error).ends_with("first"));
    }
}
