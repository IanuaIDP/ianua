//! Deactivate user: switch off a user's account, ending their sessions and
//! the delegations they granted.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control_to_shut_out;
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;

/// The ports [`DeactivateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeactivatePorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Ends the user's sessions and the delegations they granted.
    pub removal: StandingRemoval,
}

/// Switches off a user of the caller's tenant.
pub struct DeactivateUseCase {
    ports: DeactivatePorts,
}

impl DeactivateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeactivatePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeactivateUseCase {
    type Caller = CallerContext;
    type Input = UserId;
    type Output = Result<(), AppError>;

    /// Deactivates `user_id`: revokes every delegation they granted and ends
    /// their sessions, then saves them deactivated. A failure to revoke the
    /// grants leaves the user unchanged, so the call can be retried.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without deactivation rights, before reading any user.
    /// - `AppError::NotFound` for a missing user; `Forbidden` when the user holds more rights.
    /// - `AppError::Conflict` for the last administrator; `Domain` for an already deactivated user.
    /// - `AppError::Internal` on persistence failure, including delegation revocation.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let (users, records) = (
            self.ports.user_store.as_ref(),
            self.ports.access_records.as_ref(),
        );
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let shutting_out = AccountAction::ShutOut;
        let control =
            account_control_to_shut_out(records, &tenant, &authority, &user_id, shutting_out)
                .await?;
        let mut user = existing_user(users, &tenant, &user_id).await?;
        user.deactivate(&control).map_err(AppError::from_domain)?;

        let removal = &self.ports.removal;
        let revoked = removal.cut_off(&tenant, &user, &ctx.actor()).await?;
        users.save(&tenant, &user).await.or_internal()?;
        let mut events = user.take_events(&tenant);
        events.extend(revoked);
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::SessionId;

    use super::*;
    use crate::ports::agents::DelegationStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeDelegationStore, grant_from_user};
    use crate::test_support::authentication::{FakeSessionStore, password_session};
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::identity::{FakeUserStore, access_where_holds, removal_over};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Alice, an active user signed in on her laptop, and the stores that
    /// watch what happens to her.
    struct Tenant {
        alice: UserId,
        laptop: SessionId,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        delegations: Arc<FakeDelegationStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn with_alice() -> Self {
            let alice = UserId::new();
            let laptop = password_session(alice, "alices-laptop", SecondFactor::NotOwed);
            let laptop_id = *laptop.id();
            Self {
                alice,
                laptop: laptop_id,
                users: Arc::new(FakeUserStore::with_user(alice, "alice@acme.com")),
                sessions: Arc::new(FakeSessionStore::with_session(laptop)),
                delegations: Arc::new(FakeDelegationStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn laptop_status(&self) -> Option<SessionStatus> {
            self.sessions.get_status(&self.laptop)
        }

        fn ports(&self) -> DeactivatePorts {
            DeactivatePorts {
                user_store: self.users.clone(),
                removal: removal_over(&self.sessions, &self.delegations),
                ..DeactivatePorts::fakes()
            }
        }

        fn deactivate(&self, ports: DeactivatePorts) -> Result<(), AppError> {
            block_on(DeactivateUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                self.alice,
            ))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann deactivates Alice. Alice is switched off and her laptop session
    /// ends, and both are recorded once.
    #[test]
    fn a_deactivated_user_is_signed_out_and_recorded() {
        let tenant = Tenant::with_alice();

        tenant.deactivate(tenant.ports()).unwrap();

        assert_eq!(
            tenant.users.get_status(&tenant.alice),
            Some(UserStatus::Deactivated)
        );
        assert_eq!(tenant.laptop_status(), Some(SessionStatus::Revoked));
        assert_eq!(
            tenant.records(),
            [
                "identity.user_status_changed",
                "authentication.session_revoked"
            ]
        );
    }

    /// Ann deactivates Alice. The delegation Alice gave her agent is
    /// revoked.
    #[test]
    fn deactivating_revokes_the_delegations_the_user_granted() {
        let tenant = Tenant::with_alice();
        let grant = grant_from_user(tenant.alice);
        let grant_id = *grant.id();
        block_on(tenant.delegations.save(&test_ctx().tenant(), &grant)).unwrap();

        tenant.deactivate(tenant.ports()).unwrap();

        let stored = block_on(
            tenant
                .delegations
                .find_by_id(&test_ctx().tenant(), &grant_id),
        )
        .unwrap()
        .unwrap();
        assert!(stored.is_revoked());
    }

    /// Alice's delegations cannot be revoked. She stays active, and nothing
    /// is recorded, so Ann can try again.
    #[test]
    fn a_failed_revocation_leaves_the_user_active() {
        let tenant = Tenant::with_alice();
        block_on(
            tenant
                .delegations
                .save(&test_ctx().tenant(), &grant_from_user(tenant.alice)),
        )
        .unwrap();
        tenant.delegations.fail_revocations();

        let result = tenant.deactivate(tenant.ports());

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(
            tenant.users.get_status(&tenant.alice),
            Some(UserStatus::Active)
        );
        assert!(tenant.records().is_empty());
    }

    /// Ann deactivates Alice twice. The second time the status rules refuse
    /// it and nothing more is recorded.
    #[test]
    fn deactivating_twice_is_refused() {
        let tenant = Tenant::with_alice();
        tenant.deactivate(tenant.ports()).unwrap();

        let again = tenant.deactivate(tenant.ports());

        assert!(matches!(again, Err(AppError::Domain(_))));
        assert_eq!(tenant.records().len(), 2);
    }

    /// Deactivating Alice checks the administrator count while holding the
    /// tenant's grants. No count is read without that hold.
    #[test]
    fn the_last_administrator_is_counted_under_the_hold() {
        let tenant = Tenant::with_alice();
        let records = Arc::new(FakeAccessRecordStore::empty());

        tenant
            .deactivate(DeactivatePorts {
                access_records: records.clone(),
                ..tenant.ports()
            })
            .unwrap();

        assert_eq!(records.counted_without_a_hold(), 0);
    }

    /// Ann deactivates a user the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let tenant = Tenant::with_alice();
        let ports = DeactivatePorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..tenant.ports()
        };

        let result = tenant.deactivate(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with user-viewing rights cannot deactivate Alice. Her
    /// laptop session remains active after the refusal.
    #[test]
    fn a_caller_who_may_not_shut_users_out_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = DeactivatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.deactivate(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.laptop_status(), Some(SessionStatus::Active));
    }

    /// A caller with user-deactivation rights cannot deactivate Alice when
    /// she holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_is_not_deactivated() {
        let tenant = Tenant::with_alice();
        let ports = DeactivatePorts {
            access_records: access_where_holds(tenant.alice, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Deactivate),
            ])),
            ..tenant.ports()
        };

        let result = tenant.deactivate(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot deactivate Alice and is refused as
    /// unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = DeactivatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.deactivate(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
