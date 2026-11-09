//! One chosen channel as a preference row holds it, the same for a tenant
//! user, an organization member and an operator: read back into the
//! domain's row, and written out as the two arrays a save binds.

use std::collections::BTreeMap;

use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::preference::{
    NotificationPreference, NotificationPreferenceRow,
};
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CHOICE: Stored = Stored("notification preference");

/// One person's channel for one category, as it is read.
pub(super) struct ChoiceRecord {
    pub(super) category: String,
    pub(super) channel: String,
}

impl ChoiceRecord {
    /// The domain's row for the choice.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown.
    pub(super) fn into_row(self) -> Result<NotificationPreferenceRow, DomainError> {
        Ok(NotificationPreferenceRow {
            category: CHOICE.choice(&self.category)?,
            channel: CHOICE.choice(&self.channel)?,
        })
    }
}

/// The rows `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when any word is unknown.
pub(super) fn rows_of(
    records: Vec<ChoiceRecord>,
) -> Result<Vec<NotificationPreferenceRow>, DomainError> {
    records.into_iter().map(ChoiceRecord::into_row).collect()
}

/// Who chose a channel for one category, and which, as the fan-out reads
/// them.
pub(super) struct HolderRecord {
    pub(super) holder: Uuid,
    pub(super) channel: String,
}

impl HolderRecord {
    /// The holder, named by `named`, with the channel they chose.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the channel's word is
    /// unknown.
    pub(super) fn into_choice<I>(
        self,
        named: fn(Uuid) -> I,
    ) -> Result<(I, NotificationChannel), DomainError> {
        Ok((named(self.holder), CHOICE.choice(&self.channel)?))
    }
}

/// Every holder `records` name with their channel.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when any word is unknown.
pub(super) fn choices_of<I>(
    records: Vec<HolderRecord>,
    named: fn(Uuid) -> I,
) -> Result<Vec<(I, NotificationChannel)>, DomainError> {
    records
        .into_iter()
        .map(|record| record.into_choice(named))
        .collect()
}

/// A person's choices as a save writes them: the categories and, in the
/// same places, their channels. A category given twice keeps the later
/// channel, as the domain's set does.
pub(super) struct ChoiceColumns {
    pub(super) categories: Vec<String>,
    pub(super) channels: Vec<String>,
}

impl ChoiceColumns {
    /// The columns `preferences` are written to.
    pub(super) fn of(preferences: &[NotificationPreference]) -> Self {
        let chosen: BTreeMap<&'static str, &'static str> = preferences
            .iter()
            .map(|preference| (preference.category().word(), preference.channel().word()))
            .collect();
        Self {
            categories: chosen.keys().map(|word| (*word).to_owned()).collect(),
            channels: chosen.values().map(|word| (*word).to_owned()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;

    use super::*;

    /// A category chosen twice is written once, with the later channel, so
    /// the save neither fails nor keeps the earlier choice.
    #[test]
    fn a_category_chosen_twice_keeps_the_later_channel() {
        let preferences = [
            NotificationPreference::new(NotificationCategory::Crypto, NotificationChannel::InApp),
            NotificationPreference::new(
                NotificationCategory::Identity,
                NotificationChannel::Disabled,
            ),
            NotificationPreference::new(
                NotificationCategory::Crypto,
                NotificationChannel::InAppAndEmail,
            ),
        ];

        let columns = ChoiceColumns::of(&preferences);

        assert_eq!(columns.categories, ["crypto", "identity"]);
        assert_eq!(columns.channels, ["in_app_and_email", "disabled"]);
    }
}
