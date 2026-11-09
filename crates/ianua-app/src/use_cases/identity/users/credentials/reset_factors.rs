//! Reset user factors: an admin clears every second factor of a tenant
//! user's account at once, the factor in force and every passkey, for
//! someone who lost their device and their recovery codes.
//!
//! The account keeps its password. Every session it held ends, since one of
//! them may be the thief's, and its next sign-in sets up a new factor when
//! the tenant asks for one.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::operations::factor_reset::{
    EnrollmentHeld, FactorReset, HeldByAccount,
};
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, PasskeyStore};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;

/// The ports [`ResetFactorsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetFactorsPorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The account's second factor.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// The account's passkeys.
    pub passkey_store: Arc<dyn PasskeyStore>,
}

/// How many factors a reset cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorsCleared {
    /// Whether a factor in force was turned off: 0 or 1.
    pub enrollments_turned_off: usize,
    /// How many passkeys were removed.
    pub passkeys_removed: usize,
}

/// Clears every second factor of a user of the caller's tenant.
pub struct ResetFactorsUseCase {
    ports: ResetFactorsPorts,
}

/// What the account holds, loaded for the reset.
struct Held {
    /// Its enrollment, if it ever set one up.
    enrollment: Option<MfaEnrollment<ResolvedTenant>>,
    /// Registered credentials that must be removed by the reset.
    passkeys: Vec<PasskeyCredential<ResolvedTenant>>,
}

impl ResetFactorsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResetFactorsPorts) -> Self {
        Self { ports }
    }

    /// The account's enrollment, held until the unit of work ends, and its
    /// passkeys.
    async fn held(&self, tenant: &ScopedTenant, user_id: &UserId) -> Result<Held, AppError> {
        let enrollment = self
            .ports
            .enrollment_store
            .hold_by_user(tenant, user_id)
            .await
            .or_internal()?;
        let passkeys = self
            .ports
            .passkey_store
            .list_by_user(tenant, user_id)
            .await
            .or_internal()?;
        Ok(Held {
            enrollment,
            passkeys,
        })
    }

    /// Keeps the turned-off factor, deletes every passkey, and records the
    /// account's change of how it signs in, which ends its sessions.
    async fn store(
        &self,
        tenant: &ScopedTenant,
        account: &mut User<ResolvedTenant>,
        held: &Held,
    ) -> Result<(), AppError> {
        if let Some(enrollment) = &held.enrollment {
            self.ports
                .enrollment_store
                .save(tenant, enrollment)
                .await
                .or_internal()?;
        }
        for passkey in &held.passkeys {
            self.ports
                .passkey_store
                .delete(tenant, passkey.id())
                .await
                .or_internal()?;
        }
        account.record_credential_change();
        self.ports
            .user_store
            .save(tenant, account)
            .await
            .or_internal()
    }
}

impl Command for ResetFactorsUseCase {
    type Caller = CallerContext;
    type Input = UserId;
    type Output = Result<FactorsCleared, AppError>;

    /// Turns off `user_id`'s factor in force and removes each of their
    /// passkeys, and records `authentication.factors_reset` with
    /// `authentication.mfa_unenrolled` and `authentication.passkey_removed`
    /// for each one. Every session the account held ends.
    ///
    /// Whoever clears a factor can sign in in its place. Sam may edit users.
    /// Without the domain's check he clears the factors of Ann, an admin,
    /// and signs in as her with a password he set. So the caller must hold
    /// all the account holds, and nothing changes when they do not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Forbidden` when the caller may not change the user's
    ///   sign-in, or the user holds more than the caller.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<FactorsCleared, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let signing_in = AccountAction::ChangeSignIn;
        let control = account_control(records, &tenant, &authority, &user_id, signing_in).await?;
        let mut account = existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        let mut held = self.held(&tenant, &user_id).await?;
        let cleared = clearing(&held);
        let enrollment = match held.enrollment.as_mut() {
            Some(enrollment) => EnrollmentHeld::Enrolled(enrollment),
            None => EnrollmentHeld::NoneSetUp,
        };
        let held_by = HeldByAccount {
            enrollment,
            passkeys: &mut held.passkeys,
        };
        let mut reset =
            FactorReset::by_admin(&account, held_by, &control).map_err(AppError::from_domain)?;

        self.store(&tenant, &mut account, &held).await?;
        let events = raised(&tenant, &mut reset, &mut held, &mut account);
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()?;
        Ok(cleared)
    }
}

/// How many factors a reset of `held` clears: the factor when it is in
/// force, and every passkey.
fn clearing(held: &Held) -> FactorsCleared {
    let in_force = held
        .enrollment
        .as_ref()
        .is_some_and(MfaEnrollment::is_active);
    FactorsCleared {
        enrollments_turned_off: usize::from(in_force),
        passkeys_removed: held.passkeys.len(),
    }
}

/// What the reset, the factor, the passkeys and the account raised, the
/// reset first.
fn raised(
    tenant: &ScopedTenant,
    reset: &mut FactorReset<ResolvedTenant>,
    held: &mut Held,
    account: &mut User<ResolvedTenant>,
) -> Vec<DomainEvent> {
    let mut events = reset.take_events(tenant);
    if let Some(enrollment) = held.enrollment.as_mut() {
        events.extend(enrollment.take_events(tenant));
    }
    for passkey in &mut held.passkeys {
        events.extend(passkey.take_events(tenant));
    }
    events.extend(account.take_events(tenant));
    events
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, FakePasskeyStore};
    use crate::test_support::identity::{FakeUserStore, access_where_holds};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        bob: UserId,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        passkeys: Arc<FakePasskeyStore>,
        audit: Arc<FakeEventDispatcher>,
        ports: ResetFactorsPorts,
    }

    impl Fixture {
        fn new() -> Self {
            let bob = UserId::new();
            let enrollments = Arc::new(FakeMfaEnrollmentStore::active_for(bob));
            let passkeys = Arc::new(FakePasskeyStore::with_passkey(bob));
            Self {
                ports: ResetFactorsPorts {
                    user_store: Arc::new(FakeUserStore::with_user(bob, "bob@acme.test")),
                    enrollment_store: enrollments.clone(),
                    passkey_store: passkeys.clone(),
                    ..ResetFactorsPorts::fakes()
                },
                bob,
                enrollments,
                passkeys,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn reset(self) -> (Result<FactorsCleared, AppError>, Self) {
            let use_case = ResetFactorsUseCase::new(self.ports);
            let result = block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.audit.clone()),
                self.bob,
            ));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn factor_in_force(&self) -> bool {
            self.enrollments
                .enrollment_of(self.bob)
                .is_some_and(|enrollment| enrollment.is_active())
        }

        fn passkey_count(&self) -> usize {
            block_on(self.passkeys.list_by_user(&test_ctx().tenant(), &self.bob))
                .unwrap()
                .len()
        }
    }

    /// Bob lost his phone and his recovery codes. Ann, an admin, clears his
    /// factors: his authenticator is off, his passkey is gone, and the reset
    /// is recorded first among what it raised.
    #[test]
    fn an_admin_clears_every_factor() {
        let (result, fixture) = Fixture::new().reset();

        let cleared = result.unwrap();

        assert_eq!(cleared.enrollments_turned_off, 1);
        assert_eq!(cleared.passkeys_removed, 1);
        assert!(!fixture.factor_in_force());
        assert_eq!(fixture.passkey_count(), 0);
        assert_eq!(fixture.recorded()[0], "authentication.factors_reset");
        assert!(
            fixture
                .recorded()
                .contains(&"authentication.mfa_unenrolled".to_owned())
        );
    }

    /// Bob never set a factor up. Nothing is cleared, and the reset is still
    /// recorded.
    #[test]
    fn an_account_without_factors_clears_nothing() {
        let mut fixture = Fixture::new();
        fixture.ports.enrollment_store = Arc::new(FakeMfaEnrollmentStore::empty());
        fixture.ports.passkey_store = Arc::new(FakePasskeyStore::empty());

        let (result, fixture) = fixture.reset();

        let cleared = result.unwrap();
        assert_eq!(cleared.enrollments_turned_off, 0);
        assert_eq!(cleared.passkeys_removed, 0);
        assert_eq!(fixture.recorded()[0], "authentication.factors_reset");
    }

    /// A caller with user-viewing rights cannot reset Bob's factors. His
    /// enrollment and passkey remain, and no audit event is recorded.
    #[test]
    fn a_caller_who_may_not_edit_users_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::View,
            )]));

        let (result, fixture) = fixture.reset();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.factor_in_force());
        assert_eq!(fixture.passkey_count(), 1);
        assert!(fixture.recorded().is_empty());
    }

    /// A caller with user-updating rights cannot reset Bob's factors when
    /// Bob holds broader user-management rights. His enrollment and passkey
    /// remain intact.
    #[test]
    fn an_account_holding_more_than_the_caller_keeps_its_factors() {
        let mut fixture = Fixture::new();
        fixture.ports.access_records =
            access_where_holds(fixture.bob, &[SystemPermission::ManageUsers]);
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::holding(&[SystemPermission::Users(
                UserAction::Update,
            )]));

        let (result, fixture) = fixture.reset();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.factor_in_force());
        assert_eq!(fixture.passkey_count(), 1);
    }

    /// Ann names someone the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let mut fixture = Fixture::new();
        fixture.ports.user_store = Arc::new(FakeUserStore::empty());

        let (result, _) = fixture.reset();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot reset Bob's factors and is refused as
    /// unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.reset();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
