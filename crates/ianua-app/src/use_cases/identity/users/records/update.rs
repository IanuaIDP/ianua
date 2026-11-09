//! Update user records: what the company's directory records about a user,
//! its id for the account, their department, manager and employee number,
//! changed by someone who may act on the account.
//!
//! These are the company's records, not the person's word: a manager
//! decides who approves for whom, so the person alone never changes them.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::account::user_profile::DirectoryRecords;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;

/// Whose records change, and to what.
pub struct UpdateRecordsRequest {
    /// The user the records are about.
    pub user_id: UserId,
    /// The records as they should read; a record left unset is cleared.
    pub records: DirectoryRecords,
}

/// The ports [`UpdateRecordsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateRecordsPorts {
    /// Loads and saves users, and finds the manager named.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces what the company's directory records about a user.
pub struct UpdateRecordsUseCase {
    ports: UpdateRecordsPorts,
}

impl UpdateRecordsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateRecordsPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateRecordsUseCase {
    type Caller = CallerContext;
    type Input = UpdateRecordsRequest;
    type Output = Result<(), AppError>;

    /// Replaces the directory records of `request.user_id`, and records
    /// `identity.user_profile_updated` naming the fields that changed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update users, or the
    ///   user holds more than the caller.
    /// - `AppError::NotFound` if the user, or the manager named, is not in
    ///   the tenant.
    /// - `AppError::Domain` when the records name the user as their own
    ///   manager.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRecordsRequest,
    ) -> Result<(), AppError> {
        let UpdateRecordsRequest { user_id, records } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let access = self.ports.access_records.as_ref();
        let editing = AccountAction::EditRecords;
        let control = account_control(access, &tenant, &authority, &user_id, editing).await?;
        let users = self.ports.user_store.as_ref();
        let mut user = existing_user(users, &tenant, &user_id).await?;
        ensure_manager_known(users, &tenant, &records).await?;
        user.update_records(records, &control)
            .map_err(AppError::from_domain)?;

        users.save(&tenant, &user).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Refuses records naming a manager the tenant does not have.
///
/// # Errors
///
/// - `AppError::NotFound` when the manager is not a user of the tenant.
/// - `AppError::Internal` on storage failure.
async fn ensure_manager_known(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    records: &DirectoryRecords,
) -> Result<(), AppError> {
    let Some(manager) = records.manager.value() else {
        return Ok(());
    };
    existing_user(users, tenant, manager).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::profile_values::Department;
    use ianua_domain::types::Setting;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserStore, access_where_holds};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Acme {
        ann: UserId,
        bob: UserId,
        users: Arc<FakeUserStore>,
    }

    fn acme() -> Acme {
        let ann = UserId::new();
        let bob = UserId::new();
        let users = FakeUserStore::with_user(ann, "ann@acme.test");
        users.add_active_user(bob, "bob@acme.test");
        Acme {
            ann,
            bob,
            users: Arc::new(users),
        }
    }

    fn under(manager: UserId) -> DirectoryRecords {
        DirectoryRecords {
            department: Setting::Set(Department::new("Finance").unwrap()),
            manager: Setting::Set(manager),
            ..DirectoryRecords::default()
        }
    }

    fn update(
        ports: UpdateRecordsPorts,
        user_id: UserId,
        records: DirectoryRecords,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = UpdateRecordsRequest { user_id, records };
        let result = block_on(UpdateRecordsUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ));
        (result, sink)
    }

    fn over(acme: &Acme) -> UpdateRecordsPorts {
        UpdateRecordsPorts {
            user_store: acme.users.clone(),
            ..UpdateRecordsPorts::fakes()
        }
    }

    fn records_of(acme: &Acme, id: UserId) -> DirectoryRecords {
        block_on(acme.users.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap()
            .profile()
            .records
            .clone()
    }

    /// An admin puts Bob in Finance under Ann. His records hold both and
    /// the change is recorded.
    #[test]
    fn an_admin_keeps_the_directory_records() {
        let acme = acme();

        let (result, sink) = update(over(&acme), acme.bob, under(acme.ann));

        result.unwrap();
        assert_eq!(records_of(&acme, acme.bob), under(acme.ann));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.user_profile_updated"]
        );
    }

    /// An admin names a manager the tenant does not have. It is not found
    /// and Bob's records stay as they were.
    #[test]
    fn an_unknown_manager_is_not_found() {
        let acme = acme();

        let (result, _) = update(over(&acme), acme.bob, under(UserId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(records_of(&acme, acme.bob), DirectoryRecords::default());
    }

    /// Directory records naming Bob as his own manager are refused.
    #[test]
    fn nobody_is_their_own_manager() {
        let acme = acme();

        let (result, _) = update(over(&acme), acme.bob, under(acme.bob));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// User-viewing rights do not permit changing Ann's directory records.
    /// Her records stay unchanged, and no update event is recorded.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused() {
        let acme = acme();
        let ports = UpdateRecordsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..over(&acme)
        };

        let (result, sink) = update(ports, acme.ann, under(acme.bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(records_of(&acme, acme.ann), DirectoryRecords::default());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// User-update rights do not permit changing Ann's directory records
    /// while she holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_keeps_their_records() {
        let acme = acme();
        let ports = UpdateRecordsPorts {
            access_records: access_where_holds(acme.ann, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..over(&acme)
        };

        let (result, _) = update(ports, acme.ann, under(acme.bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot change Bob's directory records.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let acme = acme();
        let ports = UpdateRecordsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..over(&acme)
        };

        let (result, _) = update(ports, acme.bob, under(acme.ann));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
