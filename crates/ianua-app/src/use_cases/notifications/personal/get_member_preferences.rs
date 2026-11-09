//! Get member preferences: how notifications reach the organization member
//! asking, one channel per category.

use std::sync::Arc;

use ianua_domain::domains::notifications::personal::MemberNotificationPreferences;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::notifications::MemberPreferenceStore;
use crate::use_case::Query;
use crate::use_cases::notifications::personal::lookup::member_choices;

/// The ports [`GetMemberPreferencesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetMemberPreferencesPorts {
    /// Members' notification choices.
    pub preferences: Arc<dyn MemberPreferenceStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reads the calling member's notification choices.
pub struct GetMemberPreferencesUseCase {
    ports: GetMemberPreferencesPorts,
}

impl GetMemberPreferencesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetMemberPreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetMemberPreferencesUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<MemberNotificationPreferences, AppError>;

    /// The choices of the member `caller` came as, every category they never
    /// chose for in-app. Only their own: a request never names a member.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not change their own
    ///   notifications.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        (): (),
    ) -> Result<MemberNotificationPreferences, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        member_choices(self.ports.preferences.as_ref(), &actor.control()?).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::{block_on, test_org_caller};

    fn read(actors: FakeOrgActors) -> Result<MemberNotificationPreferences, AppError> {
        let uc = GetMemberPreferencesUseCase::new(GetMemberPreferencesPorts {
            org_actors: Arc::new(actors),
            ..GetMemberPreferencesPorts::fakes()
        });
        block_on(uc.execute(&test_org_caller(), ()))
    }

    /// Ann, a member of Acme, never chose anything. Every category reaches
    /// her in the app.
    #[test]
    fn a_member_who_chose_nothing_gets_everything_in_the_app() {
        let preferences = read(FakeOrgActors::in_role(OrgRole::Member)).unwrap();

        assert_eq!(
            preferences.channel_for(NotificationCategory::Authentication),
            NotificationChannel::InApp
        );
        assert_eq!(preferences.org_user_id(), test_org_caller().member());
    }

    /// An owner's key without notification management scope cannot read
    /// the member's preferences.
    #[test]
    fn a_key_that_may_only_read_notifications_is_refused() {
        let result = read(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading member preferences with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
