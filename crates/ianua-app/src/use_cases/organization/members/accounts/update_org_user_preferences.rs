//! Changing a member's language and timezone: their own, or another
//! member's for an owner.

use std::sync::Arc;

use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, Locale, OrgUserId, Preference, Timezone};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgUserStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;

/// Whose preferences change, and how. A preference left out stays as it
/// is.
pub struct UpdateOrgUserPreferencesRequest {
    /// The member: the caller themselves, or another member.
    pub member: OrgUserId,
    /// Their own locale, or back to the organization's, if changing.
    pub locale: Option<Preference<Locale>>,
    /// Their own timezone, or back to the organization's, if changing.
    pub timezone: Option<Preference<Timezone>>,
}

/// The ports [`UpdateOrgUserPreferencesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateOrgUserPreferencesPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
}

/// Changes a member's language and timezone.
pub struct UpdateOrgUserPreferencesUseCase {
    ports: UpdateOrgUserPreferencesPorts,
}

impl UpdateOrgUserPreferencesUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateOrgUserPreferencesPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateOrgUserPreferencesUseCase {
    type Caller = OrgCaller;
    type Input = UpdateOrgUserPreferencesRequest;
    type Output = Result<(), AppError>;

    /// Applies the preferences `request` names and records
    /// `organization.org_user_preferences_updated`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller changes someone else's
    ///   preferences without the right to update members, or an owner's
    ///   without being one.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: UpdateOrgUserPreferencesRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let mut member = existing_member(users, organization.id(), &request.member).await?;
        apply_preferences(&mut member, request, &control).map_err(AppError::from_domain)?;
        users.save(&member).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), member.take_events())
            .await
            .or_internal()
    }
}

/// Sets the preferences `request` names on `member`, as `control` decides.
/// A preference left out stays as it is.
fn apply_preferences(
    member: &mut OrgUser,
    request: UpdateOrgUserPreferencesRequest,
    control: &OrgControl<'_>,
) -> Result<(), DomainError> {
    let locale = request.locale.unwrap_or_else(|| member.locale().clone());
    let timezone = request
        .timezone
        .unwrap_or_else(|| member.timezone().clone());
    member.change_preferences(locale, timezone, control)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgUserStore, org_user_store_with, stored_caller, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: UpdateOrgUserPreferencesUseCase,
        users: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
        owner: OrgUserId,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            let organization_id = test_org_caller().organization_id();
            let owner = test_org_user(organization_id, "olivia@acme.test", OrgRole::Owner);
            let owner_id = *owner.id();
            let users = Arc::new(org_user_store_with([
                stored_caller(OrgRole::Member, "pw"),
                owner,
            ]));
            Self {
                uc: UpdateOrgUserPreferencesUseCase::new(UpdateOrgUserPreferencesPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                }),
                users,
                audit: Arc::new(FakeEventDispatcher::new()),
                owner: owner_id,
            }
        }

        fn set_german(&self, member: OrgUserId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                UpdateOrgUserPreferencesRequest {
                    member,
                    locale: Some(Preference::Own(Locale::new("de-DE").unwrap())),
                    timezone: Some(Preference::Own(Timezone::new("Europe/Berlin").unwrap())),
                },
            ))
        }

        fn stored(&self, member: OrgUserId) -> OrgUser {
            block_on(self.users.find_by_id(&member)).unwrap().unwrap()
        }
    }

    /// Sam, a plain member, switches himself to German and Berlin time.
    /// Both are saved and the change recorded.
    #[test]
    fn a_member_sets_their_own_preferences_and_it_is_recorded() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));
        let sam = *test_org_caller().member();

        setup.set_german(sam).unwrap();

        let stored = setup.stored(sam);
        assert_eq!(
            *stored.locale(),
            Preference::Own(Locale::new("de-DE").unwrap())
        );
        assert_eq!(
            *stored.timezone(),
            Preference::Own(Timezone::new("Europe/Berlin").unwrap())
        );
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_preferences_updated"]
        );
    }

    /// A plain member cannot change an owner's preferences; her locale
    /// remains inherited from the organization.
    #[test]
    fn a_member_changing_an_owners_preferences_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.set_german(setup.owner);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(*setup.stored(setup.owner).locale(), Preference::Inherited);
    }

    /// A member id the organization does not have is not found.
    #[test]
    fn an_unknown_member_is_not_found() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.set_german(OrgUserId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller must authenticate before updating preferences.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.set_german(*test_org_caller().member());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents updating member preferences.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.set_german(*test_org_caller().member());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
