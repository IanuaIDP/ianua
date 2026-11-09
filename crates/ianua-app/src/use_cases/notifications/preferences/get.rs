//! Get preferences: the caller's own notification preferences.

use std::sync::Arc;

use ianua_domain::domains::notifications::preference::NotificationPreferenceSet;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::notifications::NotificationPreferenceStore;
use crate::use_case::Query;
use crate::use_cases::notifications::lookup::current_preferences;

/// Ports needed by the get preferences use case.
#[derive(ianua_macros::Fakes)]
pub struct GetPreferencesPorts {
    /// Port for loading preferences.
    pub preference_store: Arc<dyn NotificationPreferenceStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the signed-in person's delivery choices, including unset defaults.
pub struct GetPreferencesUseCase {
    ports: GetPreferencesPorts,
}

impl GetPreferencesUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: GetPreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetPreferencesUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<NotificationPreferenceSet<ResolvedTenant>, AppError>;

    /// The preferences of the person signed in to `ctx`, with every
    /// category they never set filled in with its default.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not signed in to a
    ///   session of their own that still counts.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<NotificationPreferenceSet<ResolvedTenant>, AppError> {
        let signed_in = self.ports.tenant_authorities.signed_in(ctx).await?;
        current_preferences(
            self.ports.preference_store.as_ref(),
            &ctx.tenant(),
            signed_in.account.id(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;
    use ianua_domain::domains::notifications::preference::NotificationPreference;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{FakeNotificationPreferenceStore, test_ctx_user};
    use crate::test_support::{block_on, test_ctx};

    /// Ann never set a preference. Every category is on.
    #[test]
    fn no_stored_preference_leaves_every_category_on() {
        let use_case = GetPreferencesUseCase::new(GetPreferencesPorts::fakes());

        let set = block_on(use_case.execute(&test_ctx(), ())).unwrap();

        assert!(
            NotificationCategory::all()
                .iter()
                .all(|cat| set.is_enabled(*cat))
        );
    }

    /// Ann turned crypto notifications off. They stay off, and the rest
    /// keep their default.
    #[test]
    fn stored_preferences_override_the_defaults() {
        let prefs = vec![NotificationPreference::new(
            NotificationCategory::Crypto,
            NotificationChannel::Disabled,
        )];
        let store = FakeNotificationPreferenceStore::with_prefs(
            test_ctx().tenant_id(),
            test_ctx_user(),
            prefs,
        );
        let use_case = GetPreferencesUseCase::new(GetPreferencesPorts {
            preference_store: Arc::new(store),
            ..GetPreferencesPorts::fakes()
        });

        let set = block_on(use_case.execute(&test_ctx(), ())).unwrap();

        assert!(!set.is_enabled(NotificationCategory::Crypto));
        assert!(set.is_enabled(NotificationCategory::Identity));
    }

    /// Reading notification preferences with a signed-out session returns
    /// an unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetPreferencesUseCase::new(GetPreferencesPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetPreferencesPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
