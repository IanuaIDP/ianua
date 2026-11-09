//! Update operator preferences: an operator chooses how notifications
//! reach them, one channel per category.
//!
//! A request never names an operator, so it always changes the caller's
//! own choices.

use std::sync::Arc;

use ianua_domain::domains::notifications::personal::OperatorNotificationPreferences;
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::OperatorPreferenceStore;
use crate::use_case::Command;
use crate::use_cases::notifications::PreferenceUpdate;
use crate::use_cases::notifications::personal::lookup::operator_choices;

/// The ports [`UpdateOperatorPreferencesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateOperatorPreferencesPorts {
    /// Operators' notification choices.
    pub preferences: Arc<dyn OperatorPreferenceStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Changes the calling operator's notification choices.
pub struct UpdateOperatorPreferencesUseCase {
    ports: UpdateOperatorPreferencesPorts,
}

impl UpdateOperatorPreferencesUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateOperatorPreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateOperatorPreferencesUseCase {
    type Caller = OperatorCaller;
    type Input = Vec<PreferenceUpdate>;
    type Output = Result<OperatorNotificationPreferences, AppError>;

    /// Sends each category `updates` names to its channel for the operator
    /// `caller` came as, the rest keeping theirs, saves the choices and
    /// records one `notifications.operator_preferences_updated` per update.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or the key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key no longer works or its operator
    ///   is disabled.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        updates: Vec<PreferenceUpdate>,
    ) -> Result<OperatorNotificationPreferences, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let store = self.ports.preferences.as_ref();
        let mut choices = operator_choices(store, &authority).await?;
        for update in &updates {
            choices
                .change_channel(update.category, update.channel, &authority)
                .map_err(AppError::from_domain)?;
        }
        store.save(&choices).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), choices.take_events())
            .await
            .or_internal()?;
        Ok(choices)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::notification_delivery::FakeOperatorPreferenceStore;
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: UpdateOperatorPreferencesUseCase,
        preferences: Arc<FakeOperatorPreferenceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(authorities: FakeOperatorAuthorities) -> Self {
            let preferences = Arc::new(FakeOperatorPreferenceStore::empty());
            Self {
                uc: UpdateOperatorPreferencesUseCase::new(UpdateOperatorPreferencesPorts {
                    preferences: preferences.clone(),
                    operator_authorities: Arc::new(authorities),
                }),
                preferences,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn mute_messaging(&self) -> Result<OperatorNotificationPreferences, AppError> {
            let updates = vec![PreferenceUpdate {
                category: NotificationCategory::Messaging,
                channel: NotificationChannel::Disabled,
            }];
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                updates,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olga turns messaging notifications off. Her choice is kept and
    /// recorded.
    #[test]
    fn an_operator_turns_a_category_off() {
        let setup = Setup::with(FakeOperatorAuthorities::admitting());

        let choices = setup.mute_messaging().unwrap();

        let stored = setup.preferences.stored(choices.operator_id()).unwrap();
        assert_eq!(
            stored.channel_for(NotificationCategory::Messaging),
            NotificationChannel::Disabled
        );
        assert_eq!(
            setup.recorded(),
            vec!["notifications.operator_preferences_updated"]
        );
    }

    /// Forbidden operator authority prevents muting messaging alerts and
    /// records no preference update.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        let result = setup.mute_messaging();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Updating preferences after operator authentication fails returns an
    /// unauthenticated error.
    #[test]
    fn a_removed_key_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::SignedOut));

        let result = setup.mute_messaging();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
