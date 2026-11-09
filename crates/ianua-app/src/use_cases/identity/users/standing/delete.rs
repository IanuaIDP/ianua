//! Delete user: remove a user of the tenant for good, after handing on the
//! agents they own and ending their sessions and the delegations they
//! granted.
//!
//! An agent always has a person answerable for it, so the person deleting
//! the account takes over each agent it owned. They must be allowed to
//! manage and create agents; otherwise the account stays until someone who
//! is deletes it.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, HumanAccount, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::agents::handover::agents_handed_on;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control_to_shut_out;
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The agents the user owns, handed on to the caller.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Ends the user's sessions and the delegations they granted. They must
    /// go before the user row: delegations name their delegator, they do
    /// not cascade from it.
    pub removal: StandingRemoval,
}

/// Deletes a user of the caller's tenant for good.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }

    /// `user_id`, marked deleted by `authority` but not yet removed.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Forbidden` when `authority` may not delete users, or the
    ///   user holds more than it.
    /// - `AppError::Conflict` when the user is the tenant's last
    ///   administrator.
    /// - `AppError::Internal` on persistence failure.
    async fn deleted_user(
        &self,
        tenant: &ScopedTenant,
        authority: &TenantAuthority,
        user_id: &UserId,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let records = self.ports.access_records.as_ref();
        let erasing = AccountAction::Erase;
        let control =
            account_control_to_shut_out(records, tenant, authority, user_id, erasing).await?;
        let mut user = existing_user(self.ports.user_store.as_ref(), tenant, user_id).await?;
        user.delete(&control).map_err(AppError::from_domain)?;
        Ok(user)
    }

    /// Hands the agents `user_id` owns to `authority`, with what records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when `authority` may not take them over.
    /// - `AppError::Internal` on persistence failure.
    async fn agents_handed_over(
        &self,
        tenant: &ScopedTenant,
        authority: &TenantAuthority,
        user_id: UserId,
    ) -> Result<Vec<DomainEvent>, AppError> {
        agents_handed_on(
            self.ports.agent_store.as_ref(),
            tenant,
            &AgentControl::new(authority),
            HumanAccount::User(user_id),
        )
        .await
    }

    /// Ends the sessions of `user_id` and the delegations they granted, then
    /// removes them, with what records it.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` on persistence failure, including a failure to
    /// revoke the user's delegations.
    async fn removed(
        &self,
        tenant: &ScopedTenant,
        user_id: UserId,
        actor: &ActorRef,
    ) -> Result<Vec<DomainEvent>, AppError> {
        self.ports
            .removal
            .remove(self.ports.user_store.as_ref(), tenant, user_id, actor)
            .await
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = UserId;
    type Output = Result<(), AppError>;

    /// Deletes `user_id`, handing the agents they own to the caller and
    /// revoking every delegation they granted and all their sessions first.
    /// A failure to revoke leaves the user in place to try again.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without deletion rights, before reading any user.
    /// - `AppError::NotFound` for a missing user; `Forbidden` for superior user rights or agents the caller cannot take over.
    /// - `AppError::Conflict` for the last administrator; `Internal` on persistence failure, including delegation revocation.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut user = self.deleted_user(&tenant, &authority, &user_id).await?;
        let handed_on = self
            .agents_handed_over(&tenant, &authority, user_id)
            .await?;
        let revoked = self.removed(&tenant, user_id, &ctx.actor()).await?;

        let mut events = user.take_events(&tenant);
        events.extend(handed_on);
        events.extend(revoked);
        auditor
            .dispatch_by(&ctx.actor(), events)
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::{AgentId, Human, PersonKey};

    use super::*;
    use crate::ports::agents::DelegationStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, caller_person, grant_from_user,
    };
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::identity::{
        FakeDataExportFiles, FakeDataExportStore, FakeUserStore, access_where_holds,
        ready_export_of, removal_over,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Alice, a user, and the stores that watch what happens to her.
    struct Tenant {
        alice: UserId,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        delegations: Arc<FakeDelegationStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn with_alice() -> Self {
            let alice = UserId::new();
            Self {
                alice,
                users: Arc::new(FakeUserStore::with_user(alice, "alice@acme.com")),
                sessions: Arc::new(FakeSessionStore::empty()),
                delegations: Arc::new(FakeDelegationStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> DeletePorts {
            DeletePorts {
                user_store: self.users.clone(),
                removal: removal_over(&self.sessions, &self.delegations),
                ..DeletePorts::fakes()
            }
        }

        fn delete(&self, ports: DeletePorts) -> Result<(), AppError> {
            block_on(DeleteUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                self.alice,
            ))
        }
    }

    /// Ann deletes Alice. Alice is gone, signed out first, and the deletion
    /// is recorded.
    #[test]
    fn a_deleted_user_is_gone_and_recorded() {
        let tenant = Tenant::with_alice();

        tenant.delete(tenant.ports()).unwrap();

        assert_eq!(tenant.users.count(), 0);
        assert_eq!(*tenant.sessions.revoke_all_count.lock().unwrap(), 1);
        assert_eq!(
            tenant.sink.records.lock().unwrap()[0],
            "identity.user_deleted"
        );
    }

    /// Alice has a ready data export. Deleting her account also deletes
    /// that export's file.
    #[test]
    fn deleting_removes_the_files_of_the_users_exports() {
        let tenant = Tenant::with_alice();
        let export = ready_export_of(tenant.alice);
        let files = Arc::new(FakeDataExportFiles::default());
        let mut removal = removal_over(&tenant.sessions, &tenant.delegations);
        removal.exports = Arc::new(FakeDataExportStore::holding(&export));
        removal.export_files = files.clone();

        tenant
            .delete(DeletePorts {
                removal,
                ..tenant.ports()
            })
            .unwrap();

        assert_eq!(files.deleted(), [*export.id()]);
    }

    /// Alice, owner of the agent `id`.
    fn alices_agent(tenant: &Tenant, id: AgentId) -> Arc<FakeAgentStore> {
        let agents = Arc::new(FakeAgentStore::empty());
        let alice = Human::new(
            HumanAccount::User(tenant.alice),
            PersonKey::new("alice@acme.com").unwrap(),
        );
        agents.add_owned_by(id, alice);
        agents
    }

    /// Ann deletes Alice, who owns an agent. Ann takes the agent over, so
    /// it is never left with nobody to answer for it, and the hand-over is
    /// recorded with the deletion.
    #[test]
    fn deleting_hands_the_users_agents_to_the_caller() {
        let tenant = Tenant::with_alice();
        let agent = AgentId::new();
        let agents = alices_agent(&tenant, agent);
        let ports = DeletePorts {
            agent_store: agents.clone(),
            ..tenant.ports()
        };

        tenant.delete(ports).unwrap();

        let owner = agents.find_by_id_direct(&agent).unwrap().owner().account();
        assert_eq!(owner, caller_person().account());
        assert!(
            tenant
                .sink
                .records
                .lock()
                .unwrap()
                .contains(&"agents.agent_ownership_transferred".to_owned())
        );
    }

    /// A caller who may delete users but cannot take over their agents is
    /// refused when deleting Alice. Her account remains and she still
    /// owns her agent.
    #[test]
    fn a_caller_who_may_not_take_over_the_users_agents_is_refused() {
        let tenant = Tenant::with_alice();
        let agent = AgentId::new();
        let agents = alices_agent(&tenant, agent);
        let ports = DeletePorts {
            agent_store: agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Delete),
            ])),
            ..tenant.ports()
        };

        let result = tenant.delete(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(tenant.users.count(), 1);
        let owner = agents.find_by_id_direct(&agent).unwrap().owner().account();
        assert_eq!(owner, HumanAccount::User(tenant.alice));
    }

    /// Ann deletes Alice. The delegation Alice gave her agent is revoked
    /// before her account goes.
    #[test]
    fn deleting_revokes_the_delegations_the_user_granted() {
        let tenant = Tenant::with_alice();
        let grant = grant_from_user(tenant.alice);
        let grant_id = *grant.id();
        block_on(tenant.delegations.save(&test_ctx().tenant(), &grant)).unwrap();

        tenant.delete(tenant.ports()).unwrap();

        let stored = block_on(
            tenant
                .delegations
                .find_by_id(&test_ctx().tenant(), &grant_id),
        )
        .unwrap()
        .unwrap();
        assert!(stored.is_revoked());
    }

    /// Alice's delegations cannot be revoked. Her account stays, so Ann can
    /// try again.
    #[test]
    fn a_failed_revocation_keeps_the_user() {
        let tenant = Tenant::with_alice();
        block_on(
            tenant
                .delegations
                .save(&test_ctx().tenant(), &grant_from_user(tenant.alice)),
        )
        .unwrap();
        tenant.delegations.fail_revocations();

        let result = tenant.delete(tenant.ports());

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(tenant.users.count(), 1);
        assert!(tenant.sink.records.lock().unwrap().is_empty());
    }

    /// Ann deletes a user the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let tenant = Tenant::with_alice();
        let ports = DeletePorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..tenant.ports()
        };

        let result = tenant.delete(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// User-updating rights do not permit deleting Alice. The request is
    /// refused and her account remains.
    #[test]
    fn a_caller_who_may_not_delete_users_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = tenant.delete(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 1);
    }

    /// A caller with user-deletion rights cannot delete Alice when she
    /// holds broader user-management rights. Her account remains.
    #[test]
    fn a_user_holding_more_than_the_caller_is_not_deleted() {
        let tenant = Tenant::with_alice();
        let ports = DeletePorts {
            access_records: access_where_holds(tenant.alice, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Delete),
            ])),
            ..tenant.ports()
        };

        let result = tenant.delete(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.users.count(), 1);
    }

    /// A signed-out caller cannot delete Alice and is refused as
    /// unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_alice();
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.delete(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
