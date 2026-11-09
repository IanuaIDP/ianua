//! Revoke invitation: an admin withdraws a pending invitation, and the
//! account waiting on it is closed.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{InvitationStore, UserStore};
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::lookup::existing_invitation;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Loads and saves the invited account.
    pub user_store: Arc<dyn UserStore>,
    /// Loads and saves invitations.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Withdraws a pending invitation of the caller's tenant.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = UserId;
    type Output = Result<(), AppError>;

    /// Withdraws the pending invitation of `user_id`. Its link stops working
    /// at once, and the account that waited on it is closed rather than
    /// deleted, so its history stays and an admin may still let it in.
    ///
    /// Withdrawing shuts the invited account out, so it needs what shutting
    /// out an account needs.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the user or a pending invitation doesn't
    ///   exist.
    /// - `AppError::Forbidden` when the caller may not shut users out.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let (users, invitations) = (
            self.ports.user_store.as_ref(),
            self.ports.invitation_store.as_ref(),
        );
        let records = self.ports.access_records.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let shutting_out = AccountAction::ShutOut;
        let control = account_control(records, &tenant, &authority, &user_id, shutting_out).await?;
        let mut user = existing_user(users, &tenant, &user_id).await?;
        let mut invitation = existing_invitation(invitations, &tenant, &user_id).await?;
        invitation
            .revoke(&user, &control)
            .map_err(AppError::from_domain)?;
        let closed = invitation.close_unanswered(&mut user);
        closed.map_err(AppError::from_domain)?;

        invitations.save(&tenant, &invitation).await.or_internal()?;
        users.save(&tenant, &user).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), invitation.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeInvitationStore, FakeUserStore, InvitationSeed};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Bob, invited and waiting, and the stores that watch his invitation.
    struct Invited {
        bob: UserId,
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Invited {
        fn new() -> Self {
            let bob = UserId::new();
            let invitation = InvitationSeed::for_user(bob, "bob@acme.com", RoleId::new(), "bob");
            Self {
                bob,
                users: Arc::new(FakeUserStore::with_invited_user(bob, "bob@acme.com")),
                invitations: Arc::new(FakeInvitationStore::holding(invitation.stored())),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> RevokePorts {
            RevokePorts {
                user_store: self.users.clone(),
                invitation_store: self.invitations.clone(),
                ..RevokePorts::fakes()
            }
        }

        fn revoke(&self, ports: RevokePorts) -> Result<(), AppError> {
            block_on(RevokeUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                self.bob,
            ))
        }

        fn still_waiting(&self) -> bool {
            block_on(
                self.invitations
                    .find_pending_by_user_id(&test_ctx().tenant(), &self.bob),
            )
            .unwrap()
            .is_some()
        }
    }

    /// Ann withdraws Bob's invitation. His link stops working, his waiting
    /// account is closed rather than deleted, and it is recorded.
    #[test]
    fn a_revoked_invitation_closes_the_waiting_account() {
        let invited = Invited::new();

        invited.revoke(invited.ports()).unwrap();

        assert!(!invited.still_waiting());
        assert_eq!(
            invited.users.get_status(&invited.bob),
            Some(UserStatus::Deactivated)
        );
        assert_eq!(
            invited.sink.records.lock().unwrap().as_slice(),
            ["identity.invitation_revoked"]
        );
    }

    /// Bob has no invitation waiting. There is nothing to withdraw.
    #[test]
    fn a_user_without_an_invitation_is_not_found() {
        let invited = Invited::new();
        let ports = RevokePorts {
            invitation_store: Arc::new(FakeInvitationStore::empty()),
            ..invited.ports()
        };

        let result = invited.revoke(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// User-viewing rights do not permit withdrawing Bob's invitation.
    /// The invitation remains pending after the refusal.
    #[test]
    fn a_caller_who_may_not_shut_users_out_is_refused() {
        let invited = Invited::new();
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..invited.ports()
        };

        let result = invited.revoke(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(invited.still_waiting());
    }

    /// A signed-out caller cannot revoke Bob's invitation, which remains
    /// pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let invited = Invited::new();
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..invited.ports()
        };

        let result = invited.revoke(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(invited.still_waiting());
    }
}
