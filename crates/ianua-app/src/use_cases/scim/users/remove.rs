//! Remove SCIM user: the directory takes someone out of the tenant, by
//! switching their account off or deleting it, as the endpoint says.
//!
//! An account holding built-in permissions is only ever switched off,
//! whatever the setting, so a leaked token cannot delete every admin.
//! Either way the person's sessions and the delegations they gave end.

use std::sync::Arc;

use ianua_domain::domains::federation::scim::{DirectoryControl, ScimRemoval};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user::directory::DirectorySwitch;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, UserId};

use crate::acting::ScimAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::federation::ScimStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;
use crate::use_cases::scim::sync::record_synced;
use crate::use_cases::scim::users::directory_account::directory_reach;

/// The ports [`RemoveScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Records when the directory last synced.
    pub scim_store: Arc<dyn ScimStore>,
    /// Loads, saves and deletes users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Ends the user's sessions and the delegations they gave. They go
    /// before the user row: delegations name their delegator, they do not
    /// cascade from it.
    pub removal: StandingRemoval,
}

/// Removes users from a tenant for its directory.
pub struct RemoveScimUseCase {
    ports: RemoveScimPorts,
}

impl RemoveScimUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveScimPorts) -> Self {
        Self { ports }
    }

    /// Switches `user` off for good and ends their access, returning what
    /// to record. An account already switched off only loses its access.
    async fn switched_off(
        &self,
        tenant: &ScopedTenant,
        mut user: User<ResolvedTenant>,
        control: &DirectoryControl,
    ) -> Result<Vec<DomainEvent>, AppError> {
        user.switch_by_directory(DirectorySwitch::SwitchOff, control)
            .map_err(AppError::from_domain)?;
        let removal = &self.ports.removal;
        let revoked = removal.cut_off(tenant, &user, &ActorRef::System).await?;
        self.ports
            .user_store
            .save(tenant, &user)
            .await
            .or_internal()?;
        user.close_directory_change();
        let mut events = user.take_events(tenant);
        events.extend(revoked);
        Ok(events)
    }

    /// Deletes `user` and everything that hangs off them, returning what to
    /// record.
    async fn deleted(
        &self,
        tenant: &ScopedTenant,
        mut user: User<ResolvedTenant>,
        control: &DirectoryControl,
    ) -> Result<Vec<DomainEvent>, AppError> {
        user.delete_by_directory(control)
            .map_err(AppError::from_domain)?;
        let users = self.ports.user_store.as_ref();
        let revoked = self
            .ports
            .removal
            .remove(users, tenant, *user.id(), &ActorRef::System)
            .await?;
        let mut events = user.take_events(tenant);
        events.extend(revoked);
        Ok(events)
    }
}

impl Command for RemoveScimUseCase {
    type Caller = ScimCaller;
    type Input = UserId;
    type Output = Result<(), AppError>;

    /// Removes `user_id` as the endpoint says, records the removal by the
    /// system, and the sync.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::NotFound` when the tenant has no such user.
    /// - `AppError::Conflict` when the user is the tenant's last
    ///   administrator.
    /// - `AppError::Domain` when the account cannot be switched off from its
    ///   status.
    /// - `AppError::Internal` on persistence or audit failure, including a
    ///   failure to revoke the user's delegations.
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let endpoint = self.ports.scim_authorities.endpoint(caller).await?;
        let user = existing_user(self.ports.user_store.as_ref(), tenant, &user_id).await?;
        let records = self.ports.access_records.as_ref();
        let reach = directory_reach(records, tenant, &endpoint, &user_id).await?;

        let events = match endpoint.removal_for(reach.privilege) {
            ScimRemoval::Deactivate => self.switched_off(tenant, user, &reach.control).await?,
            ScimRemoval::Delete => self.deleted(tenant, user, &reach.control).await?,
        };
        record_synced(
            self.ports.scim_store.as_ref(),
            tenant,
            endpoint,
            auditor,
            events,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::federation::scim::ScimEndpointRow;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{PrincipalRef, SessionId, TenantId};

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::agents::FakeDelegationStore;
    use crate::test_support::authentication::{FakeSessionStore, password_session};
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{FakeUserStore, removal_over, stored_user};
    use crate::test_support::scim::{
        SignInRefusal, directory_row, refused_sign_in, scim_caller, scim_sign_in_with,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Acme {
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        ada: UserId,
        laptop: SessionId,
    }

    fn acme() -> Acme {
        let ada = UserId::new();
        let laptop = password_session(ada, "adas-laptop", SecondFactor::NotOwed);
        Acme {
            users: Arc::new(FakeUserStore::with_user(ada, "ada@acme.com")),
            laptop: *laptop.id(),
            sessions: Arc::new(FakeSessionStore::with_session(laptop)),
            ada,
        }
    }

    impl Acme {
        fn ports(&self, removal: ScimRemoval) -> RemoveScimPorts {
            RemoveScimPorts {
                scim_authorities: scim_sign_in_with(ScimEndpointRow {
                    deactivate_on_remove: removal,
                    ..directory_row()
                }),
                user_store: self.users.clone(),
                removal: removal_over(&self.sessions, &Arc::new(FakeDelegationStore::empty())),
                ..RemoveScimPorts::fakes()
            }
        }

        fn remove_with(
            &self,
            ports: RemoveScimPorts,
            caller: &ScimCaller,
            user_id: UserId,
        ) -> Result<(), AppError> {
            let use_case = RemoveScimUseCase::new(ports);
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            block_on(use_case.execute(caller, &auditor, user_id))
        }

        fn remove(&self, ports: RemoveScimPorts) -> Result<(), AppError> {
            self.remove_with(ports, &scim_caller(), self.ada)
        }
    }

    fn owners(people: &[UserId]) -> Arc<FakeAccessRecordStore> {
        let owner = stored_role("Owner", SystemPermission::all().to_vec(), Vec::new());
        let held = people
            .iter()
            .map(|person| stored_assignment(PrincipalRef::User(*person), *owner.id()))
            .collect();
        Arc::new(FakeAccessRecordStore::holding(
            test_ctx().tenant_id(),
            AccessRecords {
                roles: vec![owner],
                assignments: held,
                groups: Vec::new(),
                memberships: Vec::new(),
                catalogue: Vec::new(),
                break_glass: Vec::new(),
            },
        ))
    }

    /// Okta removes Ada, and Acme keeps removed accounts. Hers is switched
    /// off, and her sessions end.
    #[test]
    fn removing_a_user_switches_them_off_by_default() {
        let acme = acme();

        acme.remove(acme.ports(ScimRemoval::Deactivate)).unwrap();

        assert_eq!(
            acme.users.get_status(&acme.ada),
            Some(UserStatus::Deactivated)
        );
        assert_eq!(
            acme.sessions.get_status(&acme.laptop),
            Some(SessionStatus::Revoked)
        );
    }

    /// Okta removes Ada, and Acme deletes removed accounts. Hers is gone.
    #[test]
    fn removing_a_user_deletes_them_when_the_tenant_says_so() {
        let acme = acme();

        acme.remove(acme.ports(ScimRemoval::Delete)).unwrap();

        assert_eq!(acme.users.count(), 0);
    }

    /// Okta removes Ada a second time. Her account stays switched off, and
    /// the call goes through.
    #[test]
    fn removing_a_switched_off_user_again_goes_through() {
        let acme = acme();
        acme.remove(acme.ports(ScimRemoval::Deactivate)).unwrap();

        let result = acme.remove(acme.ports(ScimRemoval::Deactivate));

        assert!(result.is_ok());
        assert_eq!(
            acme.users.get_status(&acme.ada),
            Some(UserStatus::Deactivated)
        );
    }

    /// With another owner still present, removing an owner through SCIM
    /// deactivates their account even when ordinary accounts are deleted.
    #[test]
    fn the_directory_never_deletes_an_account_holding_built_in_permissions() {
        let acme = acme();
        let ports = RemoveScimPorts {
            access_records: owners(&[acme.ada, UserId::new()]),
            ..acme.ports(ScimRemoval::Delete)
        };

        acme.remove(ports).unwrap();

        assert_eq!(
            acme.users.get_status(&acme.ada),
            Some(UserStatus::Deactivated)
        );
    }

    /// Removing the last administrator returns a conflict and leaves
    /// their account active.
    #[test]
    fn the_directory_never_removes_the_last_administrator() {
        let acme = acme();
        let ports = RemoveScimPorts {
            access_records: owners(&[acme.ada]),
            ..acme.ports(ScimRemoval::Delete)
        };

        let result = acme.remove(ports);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(acme.users.get_status(&acme.ada), Some(UserStatus::Active));
    }

    /// Okta removes Ada while she and Grace own Acme. What the directory
    /// may do to her is worked out from her own records and the tenant's
    /// count of administrators; the rest of the tenant's records are never
    /// read.
    #[test]
    fn removing_a_user_reads_only_their_records() {
        let acme = acme();
        let records = owners(&[acme.ada, UserId::new()]);
        let ports = RemoveScimPorts {
            access_records: records.clone(),
            ..acme.ports(ScimRemoval::Deactivate)
        };

        acme.remove(ports).unwrap();

        assert_eq!(records.whole_reads(), 0);
    }

    /// Removing another tenant's user returns not found and leaves both
    /// accounts stored.
    #[test]
    fn a_user_of_another_tenant_is_not_found() {
        let acme = acme();
        let alan = UserId::new();
        acme.users.add_in(
            TenantId::new(),
            stored_user(alan, "alan@globex.com", UserStatus::Active),
        );

        let result = acme.remove_with(acme.ports(ScimRemoval::Delete), &scim_caller(), alan);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(acme.users.count(), 2);
    }

    /// Missing, invalid or rotated tokens and disabled SCIM each return an
    /// unauthenticated error without deleting the account.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let acme = acme();
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let ports = RemoveScimPorts {
                scim_authorities,
                ..acme.ports(ScimRemoval::Delete)
            };

            let result = acme.remove_with(ports, &caller, acme.ada);

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(acme.users.count(), 1);
        }
    }
}
