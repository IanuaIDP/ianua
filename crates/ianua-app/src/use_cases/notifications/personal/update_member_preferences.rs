//! Update member preferences: an organization member chooses how
//! notifications reach them, one channel per category.
//!
//! Only the member changes their own choices: Sam turning off Ann's
//! security alerts would keep her from hearing of an attack on her account.
//! A request never names a member, so it always changes the caller's own.

use std::sync::Arc;

use ianua_domain::domains::notifications::personal::MemberNotificationPreferences;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::MemberPreferenceStore;
use crate::use_case::Command;
use crate::use_cases::notifications::PreferenceUpdate;
use crate::use_cases::notifications::personal::lookup::member_choices;

/// The ports [`UpdateMemberPreferencesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateMemberPreferencesPorts {
    /// Members' notification choices.
    pub preferences: Arc<dyn MemberPreferenceStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Changes the calling member's notification choices.
pub struct UpdateMemberPreferencesUseCase {
    ports: UpdateMemberPreferencesPorts,
}

impl UpdateMemberPreferencesUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateMemberPreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateMemberPreferencesUseCase {
    type Caller = OrgCaller;
    type Input = Vec<PreferenceUpdate>;
    type Output = Result<MemberNotificationPreferences, AppError>;

    /// Sends each category `updates` names to its channel for the member
    /// `caller` came as, the rest keeping theirs, saves the choices and
    /// records one `notifications.member_preferences_updated` per update.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member may not change their own
    ///   notifications.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        updates: Vec<PreferenceUpdate>,
    ) -> Result<MemberNotificationPreferences, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let store = self.ports.preferences.as_ref();
        let mut choices = member_choices(store, &control).await?;
        for update in &updates {
            choices
                .change_channel(update.category, update.channel, &control)
                .map_err(AppError::from_domain)?;
        }
        store.save(&choices).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*actor.member().id()),
                choices.take_events(),
            )
            .await
            .or_internal()?;
        Ok(choices)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::notification_delivery::FakeMemberPreferenceStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: UpdateMemberPreferencesUseCase,
        preferences: Arc<FakeMemberPreferenceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn acting_as(actors: FakeOrgActors) -> Self {
            let preferences = Arc::new(FakeMemberPreferenceStore::empty());
            Self {
                uc: UpdateMemberPreferencesUseCase::new(UpdateMemberPreferencesPorts {
                    preferences: preferences.clone(),
                    org_actors: Arc::new(actors),
                }),
                preferences,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn mail_sign_ins(&self) -> Result<MemberNotificationPreferences, AppError> {
            let updates = vec![PreferenceUpdate {
                category: NotificationCategory::Authentication,
                channel: NotificationChannel::InAppAndEmail,
            }];
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                updates,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann, a member of Acme, has sign-in alerts mailed to her too. Her
    /// choice is kept and recorded.
    #[test]
    fn a_member_chooses_mail_for_a_category() {
        let setup = Setup::acting_as(FakeOrgActors::in_role(OrgRole::Member));

        setup.mail_sign_ins().unwrap();

        let stored = setup
            .preferences
            .stored(test_org_caller().member())
            .unwrap();
        assert_eq!(
            stored.channel_for(NotificationCategory::Authentication),
            NotificationChannel::InAppAndEmail
        );
        assert_eq!(
            setup.recorded(),
            vec!["notifications.member_preferences_updated"]
        );
    }

    /// An owner's key without notification management scope cannot enable
    /// mailed sign-in alerts; no preferences or audit events are saved.
    #[test]
    fn a_key_that_may_only_read_notifications_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        let result = setup.mail_sign_ins();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            setup
                .preferences
                .stored(test_org_caller().member())
                .is_none()
        );
        assert!(setup.recorded().is_empty());
    }

    /// Updating member preferences with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::acting_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.mail_sign_ins();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
