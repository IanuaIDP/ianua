//! The devices a person has remembered: the caller's own, or another
//! user's for a caller who may view users.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TrustedDeviceStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Query;
use crate::use_cases::identity::whose::{Whose, readable_account};

/// The ports [`ListDevicesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListDevicesPorts {
    /// Where remembered devices are kept.
    pub device_store: Arc<dyn TrustedDeviceStore>,
    /// The tenant's users, so a user it does not hold is not found.
    pub user_store: Arc<dyn UserStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists a user's remembered devices.
pub struct ListDevicesUseCase {
    ports: ListDevicesPorts,
}

impl ListDevicesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListDevicesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListDevicesUseCase {
    type Caller = CallerContext;
    type Input = Whose;
    type Output = Result<Vec<TrustedDevice<ResolvedTenant>>, AppError>;

    /// Every device `whose` remembered, forgotten ones included.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person listing their own came with no session.
    /// - `AppError::Forbidden` when the caller lists another user's without
    ///   the right to view users.
    /// - `AppError::NotFound` when the tenant holds no such other user.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<Vec<TrustedDevice<ResolvedTenant>>, AppError> {
        let authorities = self.ports.tenant_authorities.as_ref();
        let user_id = readable_account(authorities, ctx, whose).await?;
        let tenant = ctx.tenant();
        if let Whose::OnBehalfOf(_) = whose {
            existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        }
        self.ports
            .device_store
            .list_by_user(&tenant, &user_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeTrustedDeviceStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{block_on, test_ctx, test_ctx_with};

    fn listed_for(
        ann: UserId,
        devices: FakeTrustedDeviceStore,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<TrustedDevice<ResolvedTenant>>, AppError> {
        let use_case = ListDevicesUseCase::new(ListDevicesPorts {
            device_store: Arc::new(devices),
            user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
            tenant_authorities: Arc::new(authorities),
        });
        let ctx = test_ctx_with(test_ctx().organization_id(), test_ctx().tenant_id(), ann);
        block_on(use_case.execute(&ctx, Whose::Own))
    }

    /// Ann remembered three devices. She sees all three.
    #[test]
    fn the_callers_devices_are_listed() {
        let ann = UserId::new();

        let listed = listed_for(
            ann,
            FakeTrustedDeviceStore::with_devices(ann, 3),
            FakeTenantAuthorities::holding(&[]),
        )
        .unwrap();

        assert_eq!(listed.len(), 3);
    }

    /// Ann never remembered a device. Her list is empty.
    #[test]
    fn someone_without_devices_sees_none() {
        let listed = listed_for(
            UserId::new(),
            FakeTrustedDeviceStore::empty(),
            FakeTenantAuthorities::holding(&[]),
        )
        .unwrap();

        assert!(listed.is_empty());
    }

    /// Listing one's own devices returns none when the stored devices all
    /// belong to another user.
    #[test]
    fn another_users_devices_are_not_listed() {
        let ann = UserId::new();

        let listed = listed_for(
            UserId::new(),
            FakeTrustedDeviceStore::with_devices(ann, 2),
            FakeTenantAuthorities::holding(&[]),
        )
        .unwrap();

        assert!(listed.is_empty());
    }

    /// A signed-out caller is unauthenticated when listing devices.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ann = UserId::new();

        let result = listed_for(
            ann,
            FakeTrustedDeviceStore::with_devices(ann, 1),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The devices `bob` remembered, as read by a caller holding `held`.
    fn bobs_as(
        bob: UserId,
        held: &[SystemPermission],
    ) -> Result<Vec<TrustedDevice<ResolvedTenant>>, AppError> {
        let use_case = ListDevicesUseCase::new(ListDevicesPorts {
            device_store: Arc::new(FakeTrustedDeviceStore::with_devices(bob, 2)),
            user_store: Arc::new(FakeUserStore::with_user(bob, "bob@acme.test")),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
        });
        block_on(use_case.execute(&test_ctx(), Whose::OnBehalfOf(bob)))
    }

    /// Ann may view users and reads the two devices Bob remembered.
    #[test]
    fn a_caller_who_may_view_users_reads_someones_devices() {
        let listed = bobs_as(UserId::new(), &[SystemPermission::Users(UserAction::View)]).unwrap();

        assert_eq!(listed.len(), 2);
    }

    /// Reading another user's devices without user-view permission is forbidden.
    #[test]
    fn a_caller_who_may_not_view_users_reads_no_ones_devices() {
        let result = bobs_as(UserId::new(), &[]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
