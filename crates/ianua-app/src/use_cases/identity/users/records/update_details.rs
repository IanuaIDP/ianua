//! Update user details: the person's own given and family name, the name
//! they go by, their picture and their phone number, changed by the person
//! themselves or by someone who may edit their profile.
//!
//! A phone number here is the person's word. Nothing proves it reaches
//! them, so no sign-in or recovery step trusts it; a number texted codes
//! go to is set up and proved as a second factor instead.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_profile::PersonalDetails;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::whose::Whose;

/// Whose details change, and to what.
pub struct UpdateDetailsRequest {
    /// The signed-in person's own, or another user's.
    pub whose: Whose,
    /// The details as they should read; a detail left unset is cleared.
    pub details: PersonalDetails,
}

/// The ports [`UpdateDetailsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateDetailsPorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces a user's personal details.
pub struct UpdateDetailsUseCase {
    ports: UpdateDetailsPorts,
}

impl UpdateDetailsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateDetailsPorts) -> Self {
        Self { ports }
    }

    /// The account with `details` in place, and who changed them.
    async fn changed(
        &self,
        ctx: &CallerContext,
        whose: Whose,
        details: PersonalDetails,
    ) -> Result<(User<ResolvedTenant>, ActorRef), AppError> {
        match whose {
            Whose::Own => self.own(ctx, details).await,
            Whose::OnBehalfOf(user_id) => self.on_behalf_of(ctx, user_id, details).await,
        }
    }

    /// The signed-in person's own account with `details` in place.
    async fn own(
        &self,
        ctx: &CallerContext,
        details: PersonalDetails,
    ) -> Result<(User<ResolvedTenant>, ActorRef), AppError> {
        let mut person = self.ports.tenant_authorities.signed_in(ctx).await?;
        person
            .account
            .update_details(details, &person.signed_in)
            .map_err(AppError::from_domain)?;
        let actor = ActorRef::User(*person.account.id());
        Ok((person.account, actor))
    }

    /// `user_id`'s account with `details` in place, for a caller who may
    /// edit their profile.
    async fn on_behalf_of(
        &self,
        ctx: &CallerContext,
        user_id: UserId,
        details: PersonalDetails,
    ) -> Result<(User<ResolvedTenant>, ActorRef), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let editing = AccountAction::EditProfile;
        let control = account_control(records, &tenant, &authority, &user_id, editing).await?;
        let mut user = existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        user.update_details(details, &control)
            .map_err(AppError::from_domain)?;
        Ok((user, ctx.actor()))
    }
}

impl Command for UpdateDetailsUseCase {
    type Caller = CallerContext;
    type Input = UpdateDetailsRequest;
    type Output = Result<(), AppError>;

    /// Replaces the personal details of `request.whose` with
    /// `request.details`, and records `identity.user_profile_updated` naming
    /// the fields that changed, never what they say. Saving the details a
    /// user already has records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person changing their own came with no session.
    /// - `AppError::Forbidden` when the caller may not edit the user's
    ///   profile, or the user holds more than the caller.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateDetailsRequest,
    ) -> Result<(), AppError> {
        let UpdateDetailsRequest { whose, details } = request;
        let tenant = ctx.tenant();
        let (mut user, actor) = self.changed(ctx, whose, details).await?;

        self.ports
            .user_store
            .save(&tenant, &user)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&actor, user.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::profile_values::{GivenName, PhoneNumber};
    use ianua_domain::types::Setting;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{FakeUserStore, access_where_holds};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn anns_details() -> PersonalDetails {
        PersonalDetails {
            given_name: Setting::Set(GivenName::new("Ann").unwrap()),
            phone_number: Setting::Set(PhoneNumber::new("+4930123456").unwrap()),
            ..PersonalDetails::default()
        }
    }

    fn update(
        ports: UpdateDetailsPorts,
        whose: Whose,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = UpdateDetailsRequest {
            whose,
            details: anns_details(),
        };
        let result = block_on(UpdateDetailsUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ));
        (result, sink)
    }

    fn over(users: &Arc<FakeUserStore>) -> UpdateDetailsPorts {
        UpdateDetailsPorts {
            user_store: users.clone(),
            ..UpdateDetailsPorts::fakes()
        }
    }

    fn details_of(users: &FakeUserStore, id: UserId) -> PersonalDetails {
        block_on(users.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap()
            .profile()
            .details
            .clone()
    }

    /// Ann adds her given name and phone number from her own sign-in. Her
    /// profile holds them, and the change is recorded.
    #[test]
    fn a_person_fills_in_their_own_details() {
        let ann = test_caller_id();
        let users = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));

        let (result, sink) = update(over(&users), Whose::Own);

        result.unwrap();
        assert_eq!(details_of(&users, ann), anns_details());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.user_profile_updated"]
        );
    }

    /// Ann, an admin, fills in Bob's details for him.
    #[test]
    fn an_admin_fills_in_someones_details() {
        let bob = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(bob, "bob@acme.test"));

        let (result, _) = update(over(&users), Whose::OnBehalfOf(bob));

        result.unwrap();
        assert_eq!(details_of(&users, bob), anns_details());
    }

    /// User-viewing rights do not permit changing Bob's personal details.
    /// His details stay unchanged, and no update event is recorded.
    #[test]
    fn a_caller_who_may_not_edit_users_is_refused() {
        let bob = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(bob, "bob@acme.test"));
        let ports = UpdateDetailsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..over(&users)
        };

        let (result, sink) = update(ports, Whose::OnBehalfOf(bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(details_of(&users, bob), PersonalDetails::default());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// User-update rights do not permit changing Bob's personal details
    /// while he holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_is_not_edited() {
        let bob = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(bob, "bob@acme.test"));
        let ports = UpdateDetailsPorts {
            access_records: access_where_holds(bob, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..over(&users)
        };

        let (result, _) = update(ports, Whose::OnBehalfOf(bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann names someone the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let users = Arc::new(FakeUserStore::empty());

        let (result, _) = update(over(&users), Whose::OnBehalfOf(UserId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out person cannot change their own personal details.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let users = Arc::new(FakeUserStore::empty());
        let ports = UpdateDetailsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..over(&users)
        };

        let (result, _) = update(ports, Whose::Own);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
