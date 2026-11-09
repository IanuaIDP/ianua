//! A change to some values of one record set, worked out against the set a
//! zone holds, so two writers sharing a set each keep their own values.

use ianua_domain::domains::tenant::custom_domains::dns_zone::RecordSet;
use ianua_domain::shared::errors::DomainError;

/// Values added to, or taken out of, the set answering one name and type.
#[derive(Debug, Clone, Copy)]
pub(super) enum ValueChange<'a> {
    /// These values are added beside the ones held.
    Add(&'a RecordSet),
    /// These values are taken out, the others kept.
    Remove(&'a RecordSet),
}

/// What the set a zone holds becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NextSet {
    /// It stays as it is.
    Unchanged,
    /// It is written as this set.
    Written(RecordSet),
    /// It is removed, no value being left.
    Removed,
}

impl<'a> ValueChange<'a> {
    /// The set whose values change, which names the question it answers.
    pub(super) fn set(self) -> &'a RecordSet {
        match self {
            Self::Add(set) | Self::Remove(set) => set,
        }
    }

    /// What `held`, the set the zone holds for this question if any,
    /// becomes.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the merged set breaks a rule
    /// a set keeps.
    pub(super) fn applied_to(self, held: Option<RecordSet>) -> Result<NextSet, DomainError> {
        match (self, held) {
            (Self::Add(addition), None) => Ok(NextSet::Written(addition.clone())),
            (Self::Add(addition), Some(set)) => Ok(compared(set.merged_with(addition)?, &set)),
            (Self::Remove(_), None) => Ok(NextSet::Unchanged),
            (Self::Remove(removal), Some(set)) => Ok(set
                .without_values_of(removal)
                .map_or(NextSet::Removed, |rest| compared(rest, &set))),
        }
    }
}

/// `next` to be written, unless it is the set `held` already.
fn compared(next: RecordSet, held: &RecordSet) -> NextSet {
    if next == *held {
        return NextSet::Unchanged;
    }
    NextSet::Written(next)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{
        RecordName, RecordValue, Ttl, TxtValue,
    };

    use super::*;

    fn proofs(values: &[&str]) -> RecordSet {
        RecordSet::new(
            RecordName::new("_acme-challenge.auth.acme.example").unwrap(),
            Ttl::shortest(),
            values
                .iter()
                .map(|value| RecordValue::Text(TxtValue::new(*value).unwrap()))
                .collect(),
        )
        .unwrap()
    }

    /// A value added to a set that holds it already writes nothing, and one
    /// taken out of a set that never held it writes nothing either.
    #[test]
    fn a_change_that_changes_nothing_writes_nothing() {
        let held = proofs(&["one"]);

        let added = ValueChange::Add(&proofs(&["one"])).applied_to(Some(held.clone()));
        let taken = ValueChange::Remove(&proofs(&["two"])).applied_to(Some(held));

        assert_eq!(added.unwrap(), NextSet::Unchanged);
        assert_eq!(taken.unwrap(), NextSet::Unchanged);
    }

    /// Taking out the last value removes the set, and taking one out of a
    /// zone without the set changes nothing.
    #[test]
    fn the_last_value_taken_out_removes_the_set() {
        let removal = proofs(&["one"]);

        let last = ValueChange::Remove(&removal).applied_to(Some(proofs(&["one"])));
        let absent = ValueChange::Remove(&removal).applied_to(None);

        assert_eq!(last.unwrap(), NextSet::Removed);
        assert_eq!(absent.unwrap(), NextSet::Unchanged);
    }
}
