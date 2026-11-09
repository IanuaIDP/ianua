//! Update user preferences: the signed-in person sets their own locale and
//! timezone.

use std::sync::Arc;

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Locale, Preference, Timezone};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::use_case::Command;

/// The ports [`UpdatePreferencesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePreferencesPorts {
    /// Saves the person's account.
    pub user_store: Arc<dyn UserStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A requested change to the caller's locale and timezone.
///
/// Each field is optional: `Some` sets the preference, `None` leaves the
/// current value untouched.
pub struct Preferences {
    /// The locale to set, if changing.
    pub locale: Option<Locale>,
    /// The timezone to set, if changing.
    pub timezone: Option<Timezone>,
}

/// Sets the signed-in person's own locale and timezone.
pub struct UpdatePreferencesUseCase {
    ports: UpdatePreferencesPorts,
}

impl UpdatePreferencesUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdatePreferencesUseCase {
    type Caller = CallerContext;
    type Input = Preferences;
    type Output = Result<(), AppError>;

    /// Applies `preferences` to the account of the person signed in to the
    /// caller's session. Their own choice overrides the tenant's default.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        preferences: Preferences,
    ) -> Result<(), AppError> {
        let mut person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let tenant = ctx.tenant();
        person
            .account
            .change_preferences(
                preferences.locale.map(Preference::Own),
                preferences.timezone.map(Preference::Own),
                &person.signed_in,
            )
            .map_err(AppError::from_domain)?;

        self.ports
            .user_store
            .save(&tenant, &person.account)
            .await
            .or_internal()?;
        let actor = ActorRef::User(*person.account.id());
        auditor
            .dispatch_by(&actor, person.account.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    fn german() -> Preferences {
        Preferences {
            locale: Some(Locale::new("de-DE").unwrap()),
            timezone: Some(Timezone::new("Europe/Berlin").unwrap()),
        }
    }

    fn signed_in_as(user_id: UserId) -> CallerContext {
        let seeded = test_ctx();
        test_ctx_with(seeded.organization_id(), seeded.tenant_id(), user_id)
    }

    /// Ann sets German and Berlin time for herself. Her account carries both
    /// and the change is recorded.
    #[test]
    fn the_person_sets_their_own_preferences() {
        let ann = UserId::new();
        let users = Arc::new(FakeUserStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = UpdatePreferencesUseCase::new(UpdatePreferencesPorts {
            user_store: users.clone(),
            ..UpdatePreferencesPorts::fakes()
        });
        let ctx = signed_in_as(ann);

        block_on(use_case.execute(&ctx, &test_auditor(sink.clone()), german())).unwrap();

        let ann = block_on(users.find_by_id(&ctx.tenant(), &ann))
            .unwrap()
            .unwrap();
        assert_eq!(
            ann.locale(),
            &Preference::Own(Locale::new("de-DE").unwrap())
        );
        assert_eq!(
            sink.records.lock().unwrap()[0],
            "identity.user_preferences_updated"
        );
    }

    /// A signed-out person cannot change their locale and timezone.
    /// No account is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let users = Arc::new(FakeUserStore::empty());
        let use_case = UpdatePreferencesUseCase::new(UpdatePreferencesPorts {
            user_store: users.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        });

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            german(),
        ));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(users.count(), 0);
    }
}
