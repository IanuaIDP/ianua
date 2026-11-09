//! Update preferences: changes the caller's own notification preferences.

use std::sync::Arc;

use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::preference::NotificationPreferenceSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::NotificationPreferenceStore;
use crate::use_case::Command;
use crate::use_cases::notifications::lookup::current_preferences;

/// A single preference update.
pub struct PreferenceUpdate {
    /// The category to update.
    pub category: NotificationCategory,
    /// The new channel setting.
    pub channel: NotificationChannel,
}

/// How the caller's preferences change.
pub struct UpdatePreferencesRequest {
    /// The categories to change; the rest keep their setting.
    pub updates: Vec<PreferenceUpdate>,
}

/// Ports needed by the update preferences use case.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePreferencesPorts {
    /// Port for loading and saving preferences.
    pub preference_store: Arc<dyn NotificationPreferenceStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes the signed-in person's delivery choices for selected categories.
pub struct UpdatePreferencesUseCase {
    ports: UpdatePreferencesPorts,
}

impl UpdatePreferencesUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: UpdatePreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdatePreferencesUseCase {
    type Caller = CallerContext;
    type Input = UpdatePreferencesRequest;
    type Output = Result<NotificationPreferenceSet<ResolvedTenant>, AppError>;

    /// Applies the updates to the preferences of the person signed in to
    /// `ctx`, saves them, and records one
    /// `notifications.preferences_updated` per update requested, whether or
    /// not it changed the setting.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not signed in to a
    ///   session of their own that still counts.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdatePreferencesRequest,
    ) -> Result<NotificationPreferenceSet<ResolvedTenant>, AppError> {
        let signed_in = self.ports.tenant_authorities.signed_in(ctx).await?;
        let user_id = *signed_in.account.id();
        let store = self.ports.preference_store.as_ref();
        let mut set = current_preferences(store, &ctx.tenant(), &user_id).await?;
        for update in &request.updates {
            set.change_channel(update.category, update.channel);
        }

        store
            .save(&ctx.tenant(), &user_id, &set.to_vec())
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ActorRef::User(user_id), set.take_events(&ctx.tenant()))
            .await
            .or_internal()?;

        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::preference::NotificationPreference;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{FakeNotificationPreferenceStore, test_ctx_user};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn update(
        use_case: &UpdatePreferencesUseCase,
        updates: Vec<PreferenceUpdate>,
    ) -> (
        Result<NotificationPreferenceSet<ResolvedTenant>, AppError>,
        Arc<FakeEventDispatcher>,
    ) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            UpdatePreferencesRequest { updates },
        ));
        (result, audit)
    }

    fn over(store: Arc<FakeNotificationPreferenceStore>) -> UpdatePreferencesUseCase {
        UpdatePreferencesUseCase::new(UpdatePreferencesPorts {
            preference_store: store,
            ..UpdatePreferencesPorts::fakes()
        })
    }

    fn turning(category: NotificationCategory, channel: NotificationChannel) -> PreferenceUpdate {
        PreferenceUpdate { category, channel }
    }

    /// Ann turns crypto notifications off. They are off, and the rest keep
    /// their setting.
    #[test]
    fn one_category_changes_and_the_rest_stay() {
        let use_case = over(Arc::new(FakeNotificationPreferenceStore::empty()));

        let (result, _) = update(
            &use_case,
            vec![turning(
                NotificationCategory::Crypto,
                NotificationChannel::Disabled,
            )],
        );

        let set = result.unwrap();
        assert!(!set.is_enabled(NotificationCategory::Crypto));
        assert!(set.is_enabled(NotificationCategory::Identity));
    }

    /// Ann asks for webhook notifications by mail too. That is what is kept
    /// for her.
    #[test]
    fn the_change_is_kept_for_the_person_signed_in() {
        let store = Arc::new(FakeNotificationPreferenceStore::empty());

        let (result, _) = update(
            &over(store.clone()),
            vec![turning(
                NotificationCategory::Webhooks,
                NotificationChannel::InAppAndEmail,
            )],
        );

        result.unwrap();
        let saved = block_on(store.get(&test_ctx().tenant(), &test_ctx_user())).unwrap();
        let webhooks = saved
            .iter()
            .find(|pref| pref.category() == NotificationCategory::Webhooks)
            .map(NotificationPreference::channel);
        assert_eq!(webhooks, Some(NotificationChannel::InAppAndEmail));
    }

    /// Ann changes two categories at once. Both change and a third keeps its
    /// setting.
    #[test]
    fn several_categories_change_in_one_call() {
        let use_case = over(Arc::new(FakeNotificationPreferenceStore::empty()));

        let (result, _) = update(
            &use_case,
            vec![
                turning(
                    NotificationCategory::Identity,
                    NotificationChannel::Disabled,
                ),
                turning(
                    NotificationCategory::Branding,
                    NotificationChannel::InAppAndEmail,
                ),
            ],
        );

        let set = result.unwrap();
        assert!(!set.is_enabled(NotificationCategory::Identity));
        assert_eq!(
            set.channel_for(NotificationCategory::Branding),
            NotificationChannel::InAppAndEmail
        );
        assert!(set.is_enabled(NotificationCategory::Crypto));
    }

    /// Each category Ann changes is recorded on its own.
    #[test]
    fn every_category_changed_is_recorded() {
        let use_case = over(Arc::new(FakeNotificationPreferenceStore::empty()));

        let (_, audit) = update(
            &use_case,
            vec![
                turning(
                    NotificationCategory::Identity,
                    NotificationChannel::Disabled,
                ),
                turning(
                    NotificationCategory::Branding,
                    NotificationChannel::InAppAndEmail,
                ),
            ],
        );

        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            [
                "notifications.preferences_updated",
                "notifications.preferences_updated"
            ]
        );
    }

    /// Updating notification preferences with a signed-out session returns
    /// an unauthenticated error without saving preferences or recording an event.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeNotificationPreferenceStore::empty());
        let use_case = UpdatePreferencesUseCase::new(UpdatePreferencesPorts {
            preference_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        });

        let (result, audit) = update(
            &use_case,
            vec![turning(
                NotificationCategory::Crypto,
                NotificationChannel::Disabled,
            )],
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(store.prefs.lock().unwrap().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }
}
