//! Get operator preferences: how notifications reach the operator asking,
//! one channel per category.

use std::sync::Arc;

use ianua_domain::domains::notifications::personal::OperatorNotificationPreferences;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::ports::notifications::OperatorPreferenceStore;
use crate::use_case::Query;
use crate::use_cases::notifications::personal::lookup::operator_choices;

/// The ports [`GetOperatorPreferencesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOperatorPreferencesPorts {
    /// Operators' notification choices.
    pub preferences: Arc<dyn OperatorPreferenceStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Reads the calling operator's notification choices.
pub struct GetOperatorPreferencesUseCase {
    ports: GetOperatorPreferencesPorts,
}

impl GetOperatorPreferencesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOperatorPreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOperatorPreferencesUseCase {
    type Caller = OperatorCaller;
    type Input = ();
    type Output = Result<OperatorNotificationPreferences, AppError>;

    /// The choices of the operator `caller` came as, every category they
    /// never chose for in-app.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or the key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key no longer works or its operator
    ///   is disabled.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        (): (),
    ) -> Result<OperatorNotificationPreferences, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        operator_choices(self.ports.preferences.as_ref(), &authority).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::block_on;
    use crate::test_support::operator::test_operator_caller;

    fn read(
        authorities: FakeOperatorAuthorities,
    ) -> Result<OperatorNotificationPreferences, AppError> {
        let uc = GetOperatorPreferencesUseCase::new(GetOperatorPreferencesPorts {
            operator_authorities: Arc::new(authorities),
            ..GetOperatorPreferencesPorts::fakes()
        });
        block_on(uc.execute(&test_operator_caller(), ()))
    }

    /// Olga never chose anything. Every category reaches her in the app.
    #[test]
    fn an_operator_who_chose_nothing_gets_everything_in_the_app() {
        let preferences = read(FakeOperatorAuthorities::admitting()).unwrap();

        assert_eq!(
            preferences.channel_for(NotificationCategory::Authentication),
            NotificationChannel::InApp
        );
    }

    /// Reading preferences when operator authority is forbidden returns
    /// that refusal to the caller.
    #[test]
    fn a_disabled_operator_is_refused() {
        let result = read(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
