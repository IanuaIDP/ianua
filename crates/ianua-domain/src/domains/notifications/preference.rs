//! A user's choice of delivery channel for each notification category.

use std::collections::HashMap;

use crate::domains::notifications::category::NotificationCategory;
use crate::domains::notifications::channel::NotificationChannel;
use crate::domains::notifications::events::NotificationPreferencesUpdated;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};

/// The channel a user picked for one notification category.
///
/// A [`NotificationChannel::Disabled`] channel means the user gets nothing
/// for that category.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NotificationPreference {
    category: NotificationCategory,
    channel: NotificationChannel,
}

/// A notification preference as storage holds it.
#[derive(Clone, Copy)]
pub struct NotificationPreferenceRow {
    /// The notification category.
    pub category: NotificationCategory,
    /// The delivery channel.
    pub channel: NotificationChannel,
}

impl NotificationPreference {
    /// Creates a new preference.
    #[must_use]
    pub fn new(category: NotificationCategory, channel: NotificationChannel) -> Self {
        Self { category, channel }
    }

    /// Rebuilds a notification preference from storage.
    ///
    /// # Errors
    ///
    /// - None. No part of the row can contradict another, and each part
    ///   was read through its own checked type.
    pub fn reconstitute(row: NotificationPreferenceRow) -> Result<Self, DomainError> {
        Ok(Self {
            category: row.category,
            channel: row.channel,
        })
    }

    /// The notification category this preference controls.
    #[must_use]
    pub fn category(&self) -> NotificationCategory {
        self.category
    }

    /// The delivery channel.
    #[must_use]
    pub fn channel(&self) -> NotificationChannel {
        self.channel
    }

    /// Whether this category has any delivery enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.channel.is_disabled()
    }

    /// Whether this category includes email delivery.
    #[must_use]
    pub fn includes_email(&self) -> bool {
        self.channel.includes_email()
    }
}

/// All of one user's notification preferences.
///
/// It holds exactly one channel per category. A category the user never
/// set is `InApp`.
///
/// This set is a tenant user's, so changing one is a change in that tenant
/// and is recorded there. Organization members and operators keep their
/// own sets, recorded on their own plane.
#[derive(Debug, Clone)]
pub struct NotificationPreferenceSet<T: TenantScope> {
    prefs: HashMap<NotificationCategory, NotificationChannel>,
    raised: Raised<T>,
}

impl<T: TenantScope> NotificationPreferenceSet<T> {
    /// Builds a set from a list of preferences.
    ///
    /// A category missing from the list gets `InApp`. When a category
    /// appears twice, the later entry wins.
    #[must_use]
    pub fn from_preferences(prefs: Vec<NotificationPreference>) -> Self {
        let mut map: HashMap<NotificationCategory, NotificationChannel> =
            NotificationCategory::all()
                .iter()
                .map(|&cat| (cat, NotificationChannel::default()))
                .collect();

        for p in prefs {
            map.insert(p.category, p.channel);
        }

        Self {
            prefs: map,
            raised: Raised::default(),
        }
    }

    /// The channel for a category.
    #[must_use]
    pub fn channel_for(&self, category: NotificationCategory) -> NotificationChannel {
        self.prefs.get(&category).copied().unwrap_or_default()
    }

    /// Whether the category's channel delivers anything.
    #[must_use]
    pub fn is_enabled(&self, category: NotificationCategory) -> bool {
        !self.channel_for(category).is_disabled()
    }

    /// Every preference, sorted by category name, for storage.
    #[must_use]
    pub fn to_vec(&self) -> Vec<NotificationPreference> {
        let mut result: Vec<_> = self
            .prefs
            .iter()
            .map(|(&cat, &ch)| NotificationPreference::new(cat, ch))
            .collect();
        result.sort_by_key(|p| p.category().as_str());
        result
    }

    /// Changes a single category's channel. Raises
    /// `notifications.preferences_updated` every time, even when the
    /// category already had that channel, so each choice the user made is
    /// on record.
    pub fn change_channel(&mut self, category: NotificationCategory, channel: NotificationChannel) {
        self.prefs.insert(category, channel);
        self.raised.raise(NotificationPreferencesUpdated {
            category,
            new_channel: channel,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for NotificationPreferenceSet<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::{raised, raised_names};

    type Set = NotificationPreferenceSet<ResolvedTenant>;

    /// A user who never set a preference.
    fn defaults() -> Set {
        Set::from_preferences(Vec::new())
    }

    /// A user picks in-app and email for crypto notifications. The
    /// preference keeps both and reports email as included.
    #[test]
    fn new_creates_with_given_channel() {
        let p = NotificationPreference::new(
            NotificationCategory::Crypto,
            NotificationChannel::InAppAndEmail,
        );
        assert_eq!(p.category(), NotificationCategory::Crypto);
        assert_eq!(p.channel(), NotificationChannel::InAppAndEmail);
        assert!(p.is_enabled());
        assert!(p.includes_email());
    }

    /// A user turns off branding notifications. The preference reports
    /// nothing enabled and no email.
    #[test]
    fn a_disabled_channel_sends_nothing() {
        let p = NotificationPreference::new(
            NotificationCategory::Branding,
            NotificationChannel::Disabled,
        );
        assert!(!p.is_enabled());
        assert!(!p.includes_email());
    }

    /// A user who never set a preference gets every category, each on
    /// in-app.
    #[test]
    fn defaults_enables_all_as_in_app() {
        let set = defaults();
        for cat in NotificationCategory::all() {
            assert!(set.is_enabled(*cat));
            assert_eq!(set.channel_for(*cat), NotificationChannel::InApp);
        }
    }

    /// A user saved only "crypto off". Crypto is off and identity, which
    /// was never set, stays on.
    #[test]
    fn from_preferences_fills_missing_with_defaults() {
        let prefs = vec![NotificationPreference::new(
            NotificationCategory::Crypto,
            NotificationChannel::Disabled,
        )];
        let set = Set::from_preferences(prefs);

        assert!(!set.is_enabled(NotificationCategory::Crypto));
        assert!(set.is_enabled(NotificationCategory::Identity));
    }

    /// The default set lists one preference for every category, so storage
    /// gets a full row set.
    #[test]
    fn to_vec_has_all_categories() {
        let set = defaults();
        assert_eq!(set.to_vec().len(), NotificationCategory::all().len());
    }

    /// The listed preferences come in alphabetical order of category name,
    /// whatever order the set holds them in.
    #[test]
    fn to_vec_is_sorted_by_category_name() {
        let set = defaults();
        let v = set.to_vec();
        let names: Vec<&str> = v.iter().map(|p| p.category().as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    /// A user turns off webhook notifications. Webhooks are off and
    /// identity stays on.
    #[test]
    fn a_changed_category_channel_overrides_only_that_category() {
        let mut set = defaults();
        set.change_channel(
            NotificationCategory::Webhooks,
            NotificationChannel::Disabled,
        );
        assert!(!set.is_enabled(NotificationCategory::Webhooks));
        assert!(set.is_enabled(NotificationCategory::Identity));
    }

    /// The list holds crypto twice, first in-app and then disabled. The
    /// later entry wins, so crypto is off.
    #[test]
    fn duplicate_categories_last_write_wins() {
        let prefs = vec![
            NotificationPreference::new(NotificationCategory::Crypto, NotificationChannel::InApp),
            NotificationPreference::new(
                NotificationCategory::Crypto,
                NotificationChannel::Disabled,
            ),
        ];
        let set = Set::from_preferences(prefs);
        assert!(!set.is_enabled(NotificationCategory::Crypto));
    }

    /// Ann turns off webhook notifications, then picks in-app for identity,
    /// which it already was. Each choice is raised, in order, naming the
    /// category and the channel.
    #[test]
    fn changing_a_channel_raises_notifications_preferences_updated() {
        let mut set = defaults();

        set.change_channel(
            NotificationCategory::Webhooks,
            NotificationChannel::Disabled,
        );
        set.change_channel(NotificationCategory::Identity, NotificationChannel::InApp);

        let events = raised(&mut set);
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "notifications.preferences_updated",
                "notifications.preferences_updated"
            ]
        );
        assert_eq!(events[0].payload().get("category"), Some("webhooks"));
        assert_eq!(events[0].payload().get("channel"), Some("disabled"));
    }

    /// Ann's preferences are read back from storage. Loading them is no
    /// change, so they have raised nothing.
    #[test]
    fn preferences_read_back_from_storage_have_raised_nothing() {
        let mut set = Set::from_preferences(vec![NotificationPreference::new(
            NotificationCategory::Crypto,
            NotificationChannel::Disabled,
        )]);

        assert!(raised_names(&mut set).is_empty());
    }

    /// Ann's preferences are copied after she changed one. The copy has
    /// raised nothing, so the change is never recorded twice.
    #[test]
    fn a_copy_of_changed_preferences_has_raised_nothing() {
        let mut set = defaults();
        set.change_channel(NotificationCategory::Crypto, NotificationChannel::Disabled);

        let mut copy = set.clone();

        assert!(raised_names(&mut copy).is_empty());
        assert_eq!(
            raised_names(&mut set),
            ["notifications.preferences_updated"]
        );
    }
}
