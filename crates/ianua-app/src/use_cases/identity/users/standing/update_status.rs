//! Update user status: lock, unlock, activate or deactivate a user of the
//! tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::granter::AccountControl;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
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

/// The ports [`UpdateStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateStatusPorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Ends the sessions and delegations of a user who is shut out.
    pub removal: StandingRemoval,
}

/// Which user moves to which status.
pub struct UpdateStatusRequest {
    /// The user whose status changes.
    pub user_id: UserId,
    /// The status they move to.
    pub target: UserStatus,
}

/// Moves a user of the caller's tenant to another status.
pub struct UpdateStatusUseCase {
    ports: UpdateStatusPorts,
}

impl UpdateStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateStatusPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateStatusUseCase {
    type Caller = CallerContext;
    type Input = UpdateStatusRequest;
    type Output = Result<(), AppError>;

    /// Moves `request.user_id` to `request.target`.
    ///
    /// `Active` unlocks a locked account and lets any other one in. Locking
    /// or deactivating first revokes every delegation the user granted and
    /// ends their sessions, then saves the user, so a failure never leaves
    /// them shut out while their agents still act for them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a target of Invited/PendingVerification/Closing or missing activation/deactivation rights, before lookup.
    /// - `AppError::NotFound` for a missing user; `Forbidden` when the user holds more rights.
    /// - `AppError::Conflict` for shutting out the last administrator; `Domain` for a refused status transition.
    /// - `AppError::Internal` on persistence failure, including delegation revocation.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateStatusRequest,
    ) -> Result<(), AppError> {
        let UpdateStatusRequest { user_id, target } = request;
        let tenant = ctx.tenant();
        let (users, records) = (
            self.ports.user_store.as_ref(),
            self.ports.access_records.as_ref(),
        );
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let step = StatusMove::to(target)?;
        let control =
            account_control_to_shut_out(records, &tenant, &authority, &user_id, step.action())
                .await?;
        let mut user = existing_user(users, &tenant, &user_id).await?;
        set_status(&mut user, step, &control)?;

        let mut revoked = Vec::new();
        if step.action() == AccountAction::ShutOut {
            let removal = &self.ports.removal;
            revoked = removal.cut_off(&tenant, &user, &ctx.actor()).await?;
        }
        users.save(&tenant, &user).await.or_internal()?;
        let mut events = user.take_events(&tenant);
        events.extend(revoked);
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()
    }
}

/// The move a request for a status asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusMove {
    /// Unlocking a locked account, or letting any other one in.
    LetIn,
    /// Locking the account.
    Lock,
    /// Switching the account off.
    Deactivate,
}

impl StatusMove {
    /// The move to `target`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when `target` is `Invited`,
    ///   `PendingVerification` or `Closing`, which no admin moves a user
    ///   into.
    fn to(target: UserStatus) -> Result<Self, AppError> {
        match target {
            UserStatus::Active => Ok(Self::LetIn),
            UserStatus::Locked => Ok(Self::Lock),
            UserStatus::Deactivated => Ok(Self::Deactivate),
            UserStatus::Invited | UserStatus::PendingVerification | UserStatus::Closing => {
                Err(AppError::Forbidden(message!(
                    "identity-no-one-moves-a-user-to",
                    format!("no one moves a user to {target:?}")
                )))
            }
        }
    }

    /// What the move does to the account, whose right it needs.
    fn action(self) -> AccountAction {
        match self {
            Self::LetIn => AccountAction::LetIn,
            Self::Lock | Self::Deactivate => AccountAction::ShutOut,
        }
    }
}

/// Makes `step` on `user`, as `control` allows.
fn set_status(
    user: &mut User<ResolvedTenant>,
    step: StatusMove,
    control: &AccountControl<'_>,
) -> Result<(), AppError> {
    let moved = match (step, user.status()) {
        (StatusMove::LetIn, UserStatus::Locked) => user.unlock(control),
        (StatusMove::LetIn, _) => user.activate(control),
        (StatusMove::Lock, _) => user.lock(control),
        (StatusMove::Deactivate, _) => user.deactivate(control),
    };
    moved.map(|_| ()).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::SessionId;

    use super::*;
    use crate::ports::agents::DelegationStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeDelegationStore, grant_from_user};
    use crate::test_support::authentication::{FakeSessionStore, password_session};
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

        fn ports(&self) -> UpdateStatusPorts {
            UpdateStatusPorts {
                user_store: self.users.clone(),
                removal: removal_over(&self.sessions, &self.delegations),
                ..UpdateStatusPorts::fakes()
            }
        }

        fn move_alice(&self, target: UserStatus) -> Result<(), AppError> {
            self.move_with(self.ports(), target)
        }

        fn move_with(&self, ports: UpdateStatusPorts, target: UserStatus) -> Result<(), AppError> {
            block_on(UpdateStatusUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                UpdateStatusRequest {
                    user_id: self.alice,
                    target,
                },
            ))
        }

        fn alices_grant(&self) -> ianua_domain::types::DelegationId {
            let grant = grant_from_user(self.alice);
            let id = *grant.id();
            block_on(self.delegations.save(&test_ctx().tenant(), &grant)).unwrap();
            id
        }

        fn is_revoked(&self, grant: ianua_domain::types::DelegationId) -> bool {
            block_on(self.delegations.find_by_id(&test_ctx().tenant(), &grant))
                .unwrap()
                .unwrap()
                .is_revoked()
        }

        fn laptop_status(&self) -> Option<SessionStatus> {
            self.sessions.get_status(&self.laptop)
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann locks Alice. Alice is locked and her laptop session ends, and
    /// both are recorded once: the lock, then the session it ended.
    #[test]
    fn locking_signs_the_user_out_on_the_record() {
        let tenant = Tenant::with_alice();

        tenant.move_alice(UserStatus::Locked).unwrap();

        assert_eq!(
            tenant.users.get_status(&tenant.alice),
            Some(UserStatus::Locked)
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

    /// Ann unlocks Alice after locking her. She is active again, and
    /// unlocking ends no session and records only the unlock.
    #[test]
    fn unlocking_lets_the_user_back_in() {
        let tenant = Tenant::with_alice();
        tenant.move_alice(UserStatus::Locked).unwrap();

        tenant.move_alice(UserStatus::Active).unwrap();

        assert_eq!(
            tenant.users.get_status(&tenant.alice),
            Some(UserStatus::Active)
        );
        assert_eq!(
            tenant.records(),
            [
                "identity.user_status_changed",
                "authentication.session_revoked",
                "identity.user_status_changed"
            ]
        );
    }

    /// Alice registered and waits to confirm her address, on a deployment
    /// where no link can reach her. Ann lets her in by hand: she is active,
    /// her address stays unconfirmed, and the change is recorded. Nothing
    /// here asks for mail, so it works the same with a mail server or
    /// without one.
    #[test]
    fn an_admin_lets_a_waiting_account_in_and_its_address_stays_unconfirmed() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            user_store: Arc::new(FakeUserStore::with_unverified_user(
                tenant.alice,
                "alice@acme.com",
            )),
            ..tenant.ports()
        };
        let users = ports.user_store.clone();

        tenant.move_with(ports, UserStatus::Active).unwrap();

        let alice = block_on(users.find_by_id(&test_ctx().tenant(), &tenant.alice))
            .unwrap()
            .unwrap();
        assert_eq!(alice.status(), UserStatus::Active);
        assert!(!alice.email_verified());
        assert_eq!(tenant.records(), ["identity.user_status_changed"]);
    }

    /// A caller with user-viewing rights cannot activate an account awaiting
    /// verification. Its pending status remains and no event is recorded.
    #[test]
    fn a_caller_who_may_not_let_users_in_leaves_a_waiting_account_waiting() {
        let tenant = Tenant::with_alice();
        let waiting = Arc::new(FakeUserStore::with_unverified_user(
            tenant.alice,
            "alice@acme.com",
        ));
        let ports = UpdateStatusPorts {
            user_store: waiting.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Active);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            waiting.get_status(&tenant.alice),
            Some(UserStatus::PendingVerification)
        );
        assert!(tenant.records().is_empty());
    }

    /// Ann activates Alice, who is already active. The status rules refuse
    /// it.
    #[test]
    fn activating_an_active_user_is_refused() {
        let tenant = Tenant::with_alice();

        let result = tenant.move_alice(UserStatus::Active);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann tries to move Alice back to invited. No one moves a user there.
    #[test]
    fn moving_to_invited_is_refused() {
        let tenant = Tenant::with_alice();

        let result = tenant.move_alice(UserStatus::Invited);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.records().is_empty());
    }

    /// Ann locks a user the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Locked);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann deactivates Alice. The delegation Alice gave her agent is revoked
    /// and the revocation recorded.
    #[test]
    fn deactivating_revokes_the_delegations_the_user_granted() {
        let tenant = Tenant::with_alice();
        let grant = tenant.alices_grant();

        tenant.move_alice(UserStatus::Deactivated).unwrap();

        assert!(tenant.is_revoked(grant));
        assert!(
            tenant
                .records()
                .contains(&"agents.delegation_revoked".to_owned())
        );
    }

    /// Ann locks Alice. The delegation Alice gave her agent is revoked.
    #[test]
    fn locking_revokes_the_delegations_the_user_granted() {
        let tenant = Tenant::with_alice();
        let grant = tenant.alices_grant();

        tenant.move_alice(UserStatus::Locked).unwrap();

        assert!(tenant.is_revoked(grant));
    }

    /// Ann unlocks Alice after Alice delegated again. Letting her in leaves
    /// that delegation alone.
    #[test]
    fn letting_a_user_in_leaves_their_delegations_alone() {
        let tenant = Tenant::with_alice();
        tenant.move_alice(UserStatus::Locked).unwrap();
        let grant = tenant.alices_grant();

        tenant.move_alice(UserStatus::Active).unwrap();

        assert!(!tenant.is_revoked(grant));
    }

    /// Ann deactivates Alice. Bob's delegation is untouched.
    #[test]
    fn deactivating_leaves_other_users_delegations_alone() {
        let tenant = Tenant::with_alice();
        let bobs = grant_from_user(UserId::new());
        let bobs_id = *bobs.id();
        block_on(tenant.delegations.save(&test_ctx().tenant(), &bobs)).unwrap();

        tenant.move_alice(UserStatus::Deactivated).unwrap();

        assert!(!tenant.is_revoked(bobs_id));
    }

    /// Alice's delegations cannot be revoked. Nothing changes: she stays
    /// active and signed in, and nothing is recorded, so Ann can try again.
    #[test]
    fn a_failed_revocation_leaves_the_user_unchanged() {
        let tenant = Tenant::with_alice();
        tenant.alices_grant();
        tenant.delegations.fail_revocations();

        let result = tenant.move_alice(UserStatus::Deactivated);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(
            tenant.users.get_status(&tenant.alice),
            Some(UserStatus::Active)
        );
        assert_eq!(tenant.laptop_status(), Some(SessionStatus::Active));
        assert!(tenant.records().is_empty());
    }

    /// User-updating rights do not permit locking Alice. The request is
    /// refused and her account stays active.
    #[test]
    fn a_caller_who_may_not_shut_users_out_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Locked);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            tenant.users.get_status(&tenant.alice),
            Some(UserStatus::Active)
        );
    }

    /// A caller without user rights receives a forbidden response when
    /// requesting a lock for an unknown user.
    #[test]
    fn a_caller_without_a_user_right_is_refused_for_an_unknown_user_too() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            user_store: Arc::new(FakeUserStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Locked);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller with user-deactivation rights cannot lock Alice when she
    /// holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_is_not_locked() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            access_records: access_where_holds(tenant.alice, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Deactivate),
            ])),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Locked);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Locking Alice is refused with a conflict when she is the tenant's
    /// only administrator.
    #[test]
    fn the_last_administrator_is_not_locked() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            access_records: access_where_holds(tenant.alice, SystemPermission::all()),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Locked);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A signed-out caller cannot lock Alice and is refused as
    /// unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = UpdateStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.move_with(ports, UserStatus::Locked);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
