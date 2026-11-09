//! Rename user: change the display name of a user of the tenant.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{DisplayName, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;

/// The ports [`RenameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenamePorts {
    /// Loads and saves users.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which user to rename, and to what.
pub struct RenameRequest {
    /// The user being renamed.
    pub user_id: UserId,
    /// The display name they get.
    pub new_name: DisplayName,
}

/// Renames a user of the caller's tenant.
pub struct RenameUseCase {
    ports: RenamePorts,
}

impl RenameUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenamePorts) -> Self {
        Self { ports }
    }
}

impl Command for RenameUseCase {
    type Caller = CallerContext;
    type Input = RenameRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.user_id` the display name `request.new_name`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not edit users' profiles,
    ///   checked before the user is looked up so a made-up id is refused the
    ///   same as a real one.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Forbidden` when the user holds more than the caller.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RenameRequest,
    ) -> Result<(), AppError> {
        let RenameRequest { user_id, new_name } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = account_control(
            self.ports.access_records.as_ref(),
            &tenant,
            &authority,
            &user_id,
            AccountAction::EditProfile,
        )
        .await?;
        let mut user = existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        user.rename(new_name, &control)
            .map_err(AppError::from_domain)?;

        self.ports
            .user_store
            .save(&tenant, &user)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), user.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserStore, access_where_holds};
    use crate::test_support::tenant::cfg;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn name(text: &str) -> DisplayName {
        DisplayName::new(text, &cfg().display_name).unwrap()
    }

    fn rename(
        ports: RenamePorts,
        user_id: UserId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let result = block_on(RenameUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            RenameRequest {
                user_id,
                new_name: name("Alice Johnson"),
            },
        ));
        (result, sink)
    }

    fn ports_over(users: &Arc<FakeUserStore>) -> RenamePorts {
        RenamePorts {
            user_store: users.clone(),
            ..RenamePorts::fakes()
        }
    }

    /// Ann, an admin, renames Alice. Alice carries the new name and the
    /// rename is recorded, naming Ann as the one who made it.
    #[test]
    fn a_rename_changes_the_name_and_is_recorded() {
        let alice = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(alice, "alice@acme.com"));

        let (result, sink) = rename(ports_over(&users), alice);

        assert!(result.is_ok());
        assert_eq!(
            users.get_display_name(&alice).unwrap().as_str(),
            "Alice Johnson"
        );
        assert_eq!(sink.records.lock().unwrap()[0], "identity.user_renamed");
    }

    /// Ann renames someone the tenant does not have. It is not found.
    #[test]
    fn renaming_an_unknown_user_is_not_found() {
        let users = Arc::new(FakeUserStore::empty());

        let (result, _) = rename(ports_over(&users), UserId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// User-viewing rights do not permit renaming Alice. Her stored name
    /// stays unchanged, and no rename event is recorded.
    #[test]
    fn a_caller_who_may_not_edit_users_is_refused() {
        let alice = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(alice, "alice@acme.com"));
        let ports = RenamePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..ports_over(&users)
        };

        let (result, sink) = rename(ports, alice);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            users.get_display_name(&alice).unwrap().as_str(),
            "Test User"
        );
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// An unauthorized rename returns forbidden even for an unknown user,
    /// without revealing that the account is missing.
    #[test]
    fn a_caller_without_a_user_right_is_refused_for_an_unknown_user_too() {
        let users = Arc::new(FakeUserStore::empty());
        let ports = RenamePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&users)
        };

        let (result, _) = rename(ports, UserId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// User-update rights do not permit renaming Ann while she holds broader
    /// user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_is_not_renamed() {
        let ann = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(ann, "ann@acme.com"));
        let ports = RenamePorts {
            access_records: access_where_holds(ann, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..ports_over(&users)
        };

        let (result, _) = rename(ports, ann);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot rename Alice.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let alice = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(alice, "alice@acme.com"));
        let ports = RenamePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&users)
        };

        let (result, _) = rename(ports, alice);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
