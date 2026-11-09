//! How notifications reach an organization member or an operator: one
//! channel per category, chosen by that person alone.
//!
//! A tenant user's choices are [`NotificationPreferenceSet`], recorded in
//! their tenant. Organization members and operators sit above any tenant,
//! so theirs are kept here and recorded on their own plane.
//!
//! Only the person whose choices they are changes them. Sam turning off
//! Ann's security alerts would keep her from hearing of an attack on her
//! own account.
//!
//! [`NotificationPreferenceSet`]: crate::domains::notifications::preference::NotificationPreferenceSet

use std::collections::HashMap;

use crate::domains::notifications::category::NotificationCategory;
use crate::domains::notifications::channel::NotificationChannel;
use crate::domains::notifications::events::{MemberPreferencesUpdated, OperatorPreferencesUpdated};
use crate::domains::notifications::preference::{
    NotificationPreference, NotificationPreferenceRow,
};
use crate::domains::operator::control::OperatorAuthority;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgNotificationAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{OperatorId, OrgUserId, OrganizationId};

/// The right a member needs to change their own choices.
const UPDATES_NOTIFICATIONS: OrgPermission =
    OrgPermission::Notifications(OrgNotificationAction::Update);

/// One channel per category. A category never chosen is in-app.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelChoices(HashMap<NotificationCategory, NotificationChannel>);

impl ChannelChoices {
    /// The choices stored as `rows`, each category not among them in-app.
    fn from_rows(rows: Vec<NotificationPreferenceRow>) -> Self {
        Self(
            rows.into_iter()
                .map(|row| (row.category, row.channel))
                .collect(),
        )
    }

    /// The channel `category` goes to.
    fn channel_for(&self, category: NotificationCategory) -> NotificationChannel {
        self.0.get(&category).copied().unwrap_or_default()
    }

    /// Sends `category` to `channel`.
    fn choose(&mut self, category: NotificationCategory, channel: NotificationChannel) {
        self.0.insert(category, channel);
    }

    /// Every category's channel, sorted by category name, for storage.
    fn listed(&self) -> Vec<NotificationPreference> {
        let mut listed: Vec<NotificationPreference> = NotificationCategory::all()
            .iter()
            .map(|&category| NotificationPreference::new(category, self.channel_for(category)))
            .collect();
        listed.sort_by_key(|preference| preference.category().as_str());
        listed
    }
}

/// An organization member's notification choices, as storage holds them.
pub struct MemberNotificationPreferencesRow {
    /// The organization the member belongs to.
    pub organization_id: OrganizationId,
    /// The member.
    pub org_user_id: OrgUserId,
    /// The categories they chose a channel for.
    pub preferences: Vec<NotificationPreferenceRow>,
}

/// How notifications reach one organization member.
#[derive(Debug, Clone)]
pub struct MemberNotificationPreferences {
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    choices: ChannelChoices,
    raised: RaisedEvents,
}

impl MemberNotificationPreferences {
    /// The member acting through `by`, with every category in-app, before
    /// they chose anything.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the member's
    ///   own notifications.
    pub fn for_member(by: &OrgControl<'_>) -> Result<Self, DomainError> {
        let member = by.by();
        by.ensure_may(member.organization_id(), UPDATES_NOTIFICATIONS)?;
        Ok(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            choices: ChannelChoices::from_rows(Vec::new()),
            raised: RaisedEvents::default(),
        })
    }

    /// Rebuilds a member's choices from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row chooses for one
    ///   category twice.
    pub fn reconstitute(row: MemberNotificationPreferencesRow) -> Result<Self, DomainError> {
        ensure_each_category_once(&row.preferences)?;
        Ok(Self {
            organization_id: row.organization_id,
            org_user_id: row.org_user_id,
            choices: ChannelChoices::from_rows(row.preferences),
            raised: RaisedEvents::default(),
        })
    }

    /// The organization the member belongs to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The member.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// The channel `category` reaches the member through.
    #[must_use]
    pub fn channel_for(&self, category: NotificationCategory) -> NotificationChannel {
        self.choices.channel_for(category)
    }

    /// Every category's channel, sorted by category name, for storage.
    #[must_use]
    pub fn preferences(&self) -> Vec<NotificationPreference> {
        self.choices.listed()
    }

    /// Sends `category` to `channel`, as the member acting through `by`
    /// chooses. Raises `notifications.member_preferences_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is another member, or may not
    ///   change their own notifications here.
    pub fn change_channel(
        &mut self,
        category: NotificationCategory,
        channel: NotificationChannel,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        if !by.is_member(&self.org_user_id) {
            return Err(DomainError::forbidden(message!(
                "notifications-only-the-member-changes-how-notifications",
                "only the member changes how notifications reach them"
            )));
        }
        by.ensure_may(&self.organization_id, UPDATES_NOTIFICATIONS)?;
        self.choices.choose(category, channel);
        self.raised.raise_organization(MemberPreferencesUpdated {
            organization_id: self.organization_id,
            category,
            channel,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }
}

impl RaisesComplete for MemberNotificationPreferences {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// An operator's notification choices, as storage holds them.
pub struct OperatorNotificationPreferencesRow {
    /// The staff identity whose category and channel choices are stored.
    pub operator_id: OperatorId,
    /// The categories they chose a channel for.
    pub preferences: Vec<NotificationPreferenceRow>,
}

/// How notifications reach one platform operator.
#[derive(Debug, Clone)]
pub struct OperatorNotificationPreferences {
    operator_id: OperatorId,
    choices: ChannelChoices,
    raised: RaisedEvents,
}

impl OperatorNotificationPreferences {
    /// The operator acting as `by`, with every category in-app, before they
    /// chose anything.
    #[must_use]
    pub fn for_operator(by: &OperatorAuthority) -> Self {
        Self {
            operator_id: *by.operator(),
            choices: ChannelChoices::from_rows(Vec::new()),
            raised: RaisedEvents::default(),
        }
    }

    /// Rebuilds an operator's choices from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row chooses for one
    ///   category twice.
    pub fn reconstitute(row: OperatorNotificationPreferencesRow) -> Result<Self, DomainError> {
        ensure_each_category_once(&row.preferences)?;
        Ok(Self {
            operator_id: row.operator_id,
            choices: ChannelChoices::from_rows(row.preferences),
            raised: RaisedEvents::default(),
        })
    }

    /// The staff identity whose notices these choices govern.
    #[must_use]
    pub fn operator_id(&self) -> &OperatorId {
        &self.operator_id
    }

    /// The channel `category` reaches the operator through.
    #[must_use]
    pub fn channel_for(&self, category: NotificationCategory) -> NotificationChannel {
        self.choices.channel_for(category)
    }

    /// Every category's channel, sorted by category name, for storage.
    #[must_use]
    pub fn preferences(&self) -> Vec<NotificationPreference> {
        self.choices.listed()
    }

    /// Sends `category` to `channel`, as the operator acting as `by`
    /// chooses. Raises `notifications.operator_preferences_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is another operator.
    pub fn change_channel(
        &mut self,
        category: NotificationCategory,
        channel: NotificationChannel,
        by: &OperatorAuthority,
    ) -> Result<(), DomainError> {
        if by.operator() != &self.operator_id {
            return Err(DomainError::forbidden(message!(
                "notifications-only-the-operator-changes-how-notifications",
                "only the operator changes how notifications reach them"
            )));
        }
        self.choices.choose(category, channel);
        self.raised.raise_platform(OperatorPreferencesUpdated {
            category,
            channel,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }
}

impl RaisesComplete for OperatorNotificationPreferences {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses stored choices that name one category twice.
fn ensure_each_category_once(rows: &[NotificationPreferenceRow]) -> Result<(), DomainError> {
    RowCheck::of("notification preferences")
        .holds(
            first_repeat(rows.iter().map(|row| row.category)).is_none(),
            "a category chosen twice",
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::members::control::tests::{
        acting, founder, member_of, session_of,
    };
    use crate::domains::organization::members::org_user::OrgUser;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;

    /// What `f` gives back when `member` acts through a fresh session of
    /// their own.
    fn by<R>(member: &OrgUser, f: impl FnOnce(&OrgControl<'_>) -> R) -> R {
        let session = session_of(member);
        f(&acting(member, &session))
    }

    /// Ann's choices before she made any.
    fn anns(ann: &OrgUser) -> MemberNotificationPreferences {
        by(ann, MemberNotificationPreferences::for_member).unwrap()
    }

    /// Ann has chosen nothing yet. Every category reaches her in-app, and
    /// every category is listed for storage.
    #[test]
    fn a_member_starts_with_every_category_in_app() {
        let ann = founder();

        let preferences = anns(&ann);

        assert_eq!(preferences.org_user_id(), ann.id());
        assert_eq!(
            preferences.channel_for(NotificationCategory::Crypto),
            NotificationChannel::InApp
        );
        assert_eq!(
            preferences.preferences().len(),
            NotificationCategory::all().len()
        );
    }

    /// Ann sends crypto notifications to her mail as well. The choice is
    /// kept and recorded.
    #[test]
    fn a_member_changes_their_own_channel() {
        let ann = founder();
        let mut preferences = anns(&ann);

        by(&ann, |c| {
            preferences.change_channel(
                NotificationCategory::Crypto,
                NotificationChannel::InAppAndEmail,
                c,
            )
        })
        .unwrap();

        assert_eq!(
            preferences.channel_for(NotificationCategory::Crypto),
            NotificationChannel::InAppAndEmail
        );
        assert_eq!(
            raised_complete_names(&mut preferences),
            ["notifications.member_preferences_updated"]
        );
    }

    /// Sam, a plain member, keeps his own notifications and changes them.
    #[test]
    fn a_plain_member_changes_their_own_too() {
        let ann = founder();
        let sam = member_of(&ann);
        let mut preferences = by(&sam, MemberNotificationPreferences::for_member).unwrap();

        let changed = by(&sam, |c| {
            preferences.change_channel(
                NotificationCategory::Authentication,
                NotificationChannel::Disabled,
                c,
            )
        });

        assert!(changed.is_ok());
    }

    /// Sam cannot disable Ann's alerts, nor can Ann change Sam's choices
    /// as an owner. Ann's authentication alerts remain in-app.
    #[test]
    fn nobody_changes_another_members_choices() {
        let ann = founder();
        let sam = member_of(&ann);
        let mut ann_choices = anns(&ann);
        let mut sam_choices = by(&sam, MemberNotificationPreferences::for_member).unwrap();

        let by_sam = by(&sam, |c| {
            ann_choices.change_channel(
                NotificationCategory::Authentication,
                NotificationChannel::Disabled,
                c,
            )
        });
        let by_ann = by(&ann, |c| {
            sam_choices.change_channel(
                NotificationCategory::Authentication,
                NotificationChannel::Disabled,
                c,
            )
        });

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert_eq!(
            ann_choices.channel_for(NotificationCategory::Authentication),
            NotificationChannel::InApp
        );
    }

    /// A member's stored choices that name one category twice are refused
    /// as corrupt, never repaired by keeping one.
    #[test]
    fn a_member_row_choosing_twice_is_refused() {
        let ann = founder();
        let row = MemberNotificationPreferencesRow {
            organization_id: *ann.organization_id(),
            org_user_id: *ann.id(),
            preferences: vec![
                NotificationPreferenceRow {
                    category: NotificationCategory::Crypto,
                    channel: NotificationChannel::InApp,
                },
                NotificationPreferenceRow {
                    category: NotificationCategory::Crypto,
                    channel: NotificationChannel::Disabled,
                },
            ],
        };

        assert!(refused_as_corrupt(
            &MemberNotificationPreferences::reconstitute(row)
        ));
    }

    /// Ann's stored choice of mail for crypto reads back as it was.
    #[test]
    fn a_member_row_reads_back_as_it_was() {
        let ann = founder();
        let row = MemberNotificationPreferencesRow {
            organization_id: *ann.organization_id(),
            org_user_id: *ann.id(),
            preferences: vec![NotificationPreferenceRow {
                category: NotificationCategory::Crypto,
                channel: NotificationChannel::InAppAndEmail,
            }],
        };

        let preferences = MemberNotificationPreferences::reconstitute(row).unwrap();

        assert_eq!(
            preferences.channel_for(NotificationCategory::Crypto),
            NotificationChannel::InAppAndEmail
        );
    }

    /// Olivia, an operator, turns off branding notifications. The choice is
    /// kept and recorded as a platform event.
    #[test]
    fn an_operator_changes_their_own_channel() {
        let olivia = OperatorAuthority::assumed(OperatorId::new());
        let mut preferences = OperatorNotificationPreferences::for_operator(&olivia);

        preferences
            .change_channel(
                NotificationCategory::Branding,
                NotificationChannel::Disabled,
                &olivia,
            )
            .unwrap();

        assert_eq!(
            preferences.channel_for(NotificationCategory::Branding),
            NotificationChannel::Disabled
        );
        assert_eq!(
            raised_complete_names(&mut preferences),
            ["notifications.operator_preferences_updated"]
        );
    }

    /// Another operator cannot disable Olivia's authentication alerts;
    /// her channel remains in-app.
    #[test]
    fn no_operator_changes_anothers_choices() {
        let olivia = OperatorAuthority::assumed(OperatorId::new());
        let mallory = OperatorAuthority::assumed(OperatorId::new());
        let mut preferences = OperatorNotificationPreferences::for_operator(&olivia);

        let result = preferences.change_channel(
            NotificationCategory::Authentication,
            NotificationChannel::Disabled,
            &mallory,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(
            preferences.channel_for(NotificationCategory::Authentication),
            NotificationChannel::InApp
        );
    }

    /// An operator's stored choices that name one category twice are
    /// refused as corrupt.
    #[test]
    fn an_operator_row_choosing_twice_is_refused() {
        let row = OperatorNotificationPreferencesRow {
            operator_id: OperatorId::new(),
            preferences: vec![
                NotificationPreferenceRow {
                    category: NotificationCategory::Tenant,
                    channel: NotificationChannel::InApp,
                },
                NotificationPreferenceRow {
                    category: NotificationCategory::Tenant,
                    channel: NotificationChannel::Disabled,
                },
            ],
        };

        assert!(refused_as_corrupt(
            &OperatorNotificationPreferences::reconstitute(row)
        ));
    }
}
