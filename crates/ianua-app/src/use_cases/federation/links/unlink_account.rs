//! Unlink account: remove the link from a local account to who its owner
//! is at a connection's provider, so the provider no longer signs it in.
//!
//! The account's holder removes their own from any finished sign-in: it
//! only takes a way in away. An admin removes someone else's when they may
//! change that account's sign-in. Each removal is recorded, so the person
//! can be told.

use std::sync::Arc;

use ianua_domain::domains::federation::link::{FederatedLink, UnlinkGrounds};
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConnectionId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::federation::{ConnectionStore, FederatedLinkStore};
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::federation::lookup::{existing_connection, existing_link};
use crate::use_cases::identity::account_control::account_control;

/// Whose link is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkFrom {
    /// The caller's own account, from their own sign-in.
    OwnAccount,
    /// Another user's account, by an admin.
    User(UserId),
}

/// Which connection's link to remove, from whose account.
pub struct UnlinkAccountRequest {
    /// The connection whose provider no longer signs the account in.
    pub connection_id: ConnectionId,
    /// Whose link it is.
    pub from: UnlinkFrom,
}

/// The ports [`UnlinkAccountUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UnlinkAccountPorts {
    /// The links between accounts and providers.
    pub links: Arc<dyn FederatedLinkStore>,
    /// The tenant's connections, for the provider's name on the record.
    pub connections: Arc<dyn ConnectionStore>,
    /// The tenant's users, for the account an admin names.
    pub users: Arc<dyn UserStore>,
    /// Who holds what, for what an admin may do to the account.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is, and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes an account's link to a connection's provider.
pub struct UnlinkAccountUseCase {
    ports: UnlinkAccountPorts,
}

impl UnlinkAccountUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UnlinkAccountPorts) -> Self {
        Self { ports }
    }

    /// The caller's own link at `connection_id`'s provider, removed by
    /// them.
    async fn by_holder(
        &self,
        ctx: &CallerContext,
        connection_id: &ConnectionId,
    ) -> Result<FederatedLink<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let links = self.ports.links.as_ref();
        let mut link = existing_link(links, &tenant, connection_id, person.account.id()).await?;
        let connections = self.ports.connections.as_ref();
        let connection = existing_connection(connections, &tenant, connection_id).await?;
        link.remove(
            &UnlinkGrounds::Holder(&person.signed_in),
            &person.account,
            &connection,
        )
        .map_err(AppError::from_domain)?;
        Ok(link)
    }

    /// `user_id`'s link at `connection_id`'s provider, removed by the
    /// caller as an admin, if they may change the account's sign-in.
    async fn by_admin(
        &self,
        ctx: &CallerContext,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<FederatedLink<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let signing_in = AccountAction::ChangeSignIn;
        let control = account_control(records, &tenant, &authority, user_id, signing_in).await?;
        control
            .ensure_allowed(user_id, signing_in)
            .map_err(AppError::from_domain)?;
        let mut link =
            existing_link(self.ports.links.as_ref(), &tenant, connection_id, user_id).await?;
        let account = existing_user(self.ports.users.as_ref(), &tenant, user_id).await?;
        let connections = self.ports.connections.as_ref();
        let connection = existing_connection(connections, &tenant, connection_id).await?;
        link.remove(&UnlinkGrounds::Control(&control), &account, &connection)
            .map_err(AppError::from_domain)?;
        Ok(link)
    }
}

impl Command for UnlinkAccountUseCase {
    type Caller = CallerContext;
    type Input = UnlinkAccountRequest;
    type Output = Result<(), AppError>;

    /// Removes the link `request` names, for the caller, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or they remove their own link without a tenant
    ///   session.
    /// - `AppError::NotFound` when the connection does not exist, the
    ///   account is not linked through it, or the user does not exist.
    /// - `AppError::Forbidden` when an admin may not change the account's
    ///   sign-in.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UnlinkAccountRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let mut link = match request.from {
            UnlinkFrom::OwnAccount => self.by_holder(ctx, &request.connection_id).await?,
            UnlinkFrom::User(user_id) => {
                self.by_admin(ctx, &request.connection_id, &user_id).await?
            }
        };

        self.ports
            .links
            .delete(&tenant, &request.connection_id, link.user_id())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), link.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::PrincipalRef;

    use super::*;
    use crate::context::CallerIdentity;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeRoleAssignmentStore, FakeRoleStore,
        stored_assignment, stored_role,
    };
    use crate::test_support::federation::{
        FakeConnectionStore, FakeFederatedLinkStore, test_connection, test_link,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The caller, Ann.
    fn ann() -> UserId {
        match test_ctx().identity() {
            CallerIdentity::TenantUser(id) => *id,
            _ => unreachable!("the test caller is a tenant user"),
        }
    }

    /// A tenant with one Okta connection, Bob among its users, and the
    /// links kept.
    struct Tenant {
        connection_id: ConnectionId,
        bob: UserId,
        links: Arc<FakeFederatedLinkStore>,
        connections: Arc<FakeConnectionStore>,
        users: Arc<FakeUserStore>,
    }

    impl Tenant {
        fn new() -> Self {
            let connection_id = ConnectionId::new();
            let connection = test_connection(connection_id, ConnectionStatus::Active);
            let bob = UserId::new();
            Self {
                connection_id,
                bob,
                links: Arc::new(FakeFederatedLinkStore::empty()),
                connections: Arc::new(FakeConnectionStore::holding(
                    &test_ctx().tenant(),
                    [connection],
                )),
                users: Arc::new(FakeUserStore::with_user(bob, "bob@acme.test")),
            }
        }

        fn linking(self, user_id: UserId) -> Self {
            let link = test_link(self.connection_id, user_id, clock::now());
            block_on(self.links.save(&test_ctx().tenant(), &link)).unwrap();
            self
        }

        fn ports(&self) -> UnlinkAccountPorts {
            UnlinkAccountPorts {
                links: self.links.clone(),
                connections: self.connections.clone(),
                users: self.users.clone(),
                ..UnlinkAccountPorts::fakes()
            }
        }

        fn request(&self, from: UnlinkFrom) -> UnlinkAccountRequest {
            UnlinkAccountRequest {
                connection_id: self.connection_id,
                from,
            }
        }

        fn is_linked(&self, user_id: UserId) -> bool {
            let tenant = test_ctx().tenant();
            let found = self
                .links
                .find_by_user(&tenant, &self.connection_id, &user_id);
            block_on(found).unwrap().is_some()
        }
    }

    fn unlink(
        ports: UnlinkAccountPorts,
        sink: &Arc<FakeEventDispatcher>,
        request: UnlinkAccountRequest,
    ) -> Result<(), AppError> {
        block_on(UnlinkAccountUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn quietly(ports: UnlinkAccountPorts, request: UnlinkAccountRequest) -> Result<(), AppError> {
        unlink(ports, &Arc::new(FakeEventDispatcher::new()), request)
    }

    /// Records where `admin` holds the admin role.
    fn admin_records(admin: UserId) -> AccessSources {
        let tenant = test_ctx().tenant_id();
        let role: Role<ResolvedTenant> = stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        );
        let assignment = stored_assignment(PrincipalRef::User(admin), *role.id());
        AccessSources {
            roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, [assignment])),
            ..AccessSources::default()
        }
    }

    /// Ann removes her own Okta link. Okta no longer signs her in, and the
    /// removal is recorded.
    #[test]
    fn the_holder_removes_her_own_link_and_it_is_recorded() {
        let tenant = Tenant::new().linking(ann());
        let sink = Arc::new(FakeEventDispatcher::new());

        unlink(
            tenant.ports(),
            &sink,
            tenant.request(UnlinkFrom::OwnAccount),
        )
        .unwrap();

        assert!(!tenant.is_linked(ann()));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["federation.account_unlinked"]
        );
    }

    /// Ann, an admin, removes Bob's Okta link. It is gone and the removal
    /// is recorded.
    #[test]
    fn an_admin_removes_another_users_link() {
        let tenant = Tenant::new();
        let bob = tenant.bob;
        let tenant = tenant.linking(bob);
        let sink = Arc::new(FakeEventDispatcher::new());

        unlink(tenant.ports(), &sink, tenant.request(UnlinkFrom::User(bob))).unwrap();

        assert!(!tenant.is_linked(bob));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["federation.account_unlinked"]
        );
    }

    /// Ann removes an Okta link she does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn a_link_that_is_not_there_is_not_found() {
        let tenant = Tenant::new();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = unlink(
            tenant.ports(),
            &sink,
            tenant.request(UnlinkFrom::OwnAccount),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann removes her link to a connection the tenant does not have. It is
    /// not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let tenant = Tenant::new().linking(ann());
        let request = UnlinkAccountRequest {
            connection_id: ConnectionId::new(),
            from: UnlinkFrom::OwnAccount,
        };

        let result = quietly(tenant.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(tenant.is_linked(ann()));
    }

    /// Without user-update rights, a caller cannot remove Bob's Okta link,
    /// which remains stored.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused() {
        let tenant = Tenant::new();
        let bob = tenant.bob;
        let tenant = tenant.linking(bob);
        let ports = UnlinkAccountPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request(UnlinkFrom::User(bob)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.is_linked(bob));
    }

    /// User-update rights cannot unlink an administrator with stronger
    /// authority; Bob keeps his provider link.
    #[test]
    fn an_account_holding_more_than_the_caller_keeps_its_link() {
        let tenant = Tenant::new();
        let bob = tenant.bob;
        let tenant = tenant.linking(bob);
        let ports = UnlinkAccountPorts {
            access_records: Arc::new(FakeAccessRecordStore::reading(admin_records(bob))),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request(UnlinkFrom::User(bob)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.is_linked(bob));
    }

    /// An unauthorized unlink request returns forbidden even for an unknown
    /// user and connection, without revealing their absence.
    #[test]
    fn a_caller_who_may_not_update_users_learns_nothing_of_an_unknown_link() {
        let ports = UnlinkAccountPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..UnlinkAccountPorts::fakes()
        };
        let request = UnlinkAccountRequest {
            connection_id: ConnectionId::new(),
            from: UnlinkFrom::User(UserId::new()),
        };

        let result = quietly(ports, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot remove Ann's own link, which stays stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::new().linking(ann());
        let ports = UnlinkAccountPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.request(UnlinkFrom::OwnAccount));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(tenant.is_linked(ann()));
    }
}
