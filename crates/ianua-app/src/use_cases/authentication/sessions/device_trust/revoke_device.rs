//! Forgetting a remembered device, so sign-ins from it ask for the second
//! factor again: the person's own, or someone else's by a caller who may
//! change how they sign in, as when Bob's laptop is stolen and Ann, an
//! admin, forgets it for him.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_change::DeviceChange;
use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, TrustedDeviceId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TrustedDeviceStore;
use crate::ports::authorization::AccessRecordStore;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::lookup::owned_device;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::whose::Whose;

/// Whose device to forget, and which.
pub struct RevokeDeviceRequest {
    /// The signed-in person's own, or another user's.
    pub whose: Whose,
    /// The device to forget.
    pub device_id: TrustedDeviceId,
}

/// The ports [`RevokeDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeDevicePorts {
    /// Where remembered devices are kept.
    pub device_store: Arc<dyn TrustedDeviceStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Forgets one of a user's remembered devices.
pub struct RevokeDeviceUseCase {
    ports: RevokeDevicePorts,
}

impl RevokeDeviceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeDevicePorts) -> Self {
        Self { ports }
    }

    /// The device `request` names, forgotten as the caller may, and who
    /// forgot it.
    async fn forgotten(
        &self,
        ctx: &CallerContext,
        request: RevokeDeviceRequest,
    ) -> Result<
        (
            TrustedDevice<ResolvedTenant>,
            DeviceChange<ResolvedTenant>,
            ActorRef,
        ),
        AppError,
    > {
        let RevokeDeviceRequest { whose, device_id } = request;
        let Whose::OnBehalfOf(user_id) = whose else {
            let person = self.ports.tenant_authorities.signed_in(ctx).await?;
            let holder = *person.account.id();
            let mut device = self.device_of(ctx, &device_id, &holder).await?;
            let change =
                DeviceChange::revoke(&mut device, &person.signed_in).map_err(revoke_error)?;
            return Ok((device, change, ActorRef::User(holder)));
        };
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let changing = AccountAction::ChangeSignIn;
        let control =
            account_control(records, &ctx.tenant(), &authority, &user_id, changing).await?;
        let mut device = self.device_of(ctx, &device_id, &user_id).await?;
        let change = DeviceChange::revoke(&mut device, &control).map_err(revoke_error)?;
        Ok((device, change, ctx.actor()))
    }

    /// `user_id`'s device `device_id`.
    async fn device_of(
        &self,
        ctx: &CallerContext,
        device_id: &TrustedDeviceId,
        user_id: &UserId,
    ) -> Result<TrustedDevice<ResolvedTenant>, AppError> {
        let store = self.ports.device_store.as_ref();
        owned_device(store, &ctx.tenant(), device_id, user_id).await
    }
}

impl Command for RevokeDeviceUseCase {
    type Caller = CallerContext;
    type Input = RevokeDeviceRequest;
    type Output = Result<(), AppError>;

    /// Forgets the device `request` names and records
    /// `authentication.device_revoked`: the person's own, or another
    /// user's when the caller may change how that user signs in.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person forgetting their own came with no
    ///   session.
    /// - `AppError::Forbidden` when the caller may not change how the user
    ///   signs in, checked before the device is read, or the user holds
    ///   more than the caller.
    /// - `AppError::NotFound` when the user has no such device.
    /// - `AppError::Conflict` when the device was already forgotten.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RevokeDeviceRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let (device, mut change, actor) = self.forgotten(ctx, request).await?;
        self.ports
            .device_store
            .save(&tenant, &device)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&actor, change.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The error a device that cannot be forgotten answers with: one already
/// forgotten is a conflict.
fn revoke_error(error: DomainError) -> AppError {
    match error {
        DomainError::InvalidTransition(_) => AppError::Conflict(message!(
            "authentication-device-already-revoked",
            "device already revoked"
        )),
        other => AppError::from_domain(other),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeTrustedDeviceStore, known_device};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    struct Fixture {
        ann: UserId,
        device_id: TrustedDeviceId,
        devices: Arc<FakeTrustedDeviceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn with_device_of(owner: UserId, ann: UserId, status: DeviceStatus) -> Self {
            let device = known_device(owner, status);
            Self {
                ann,
                device_id: *device.id(),
                devices: Arc::new(FakeTrustedDeviceStore::holding([device])),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn anns_device() -> Self {
            let ann = UserId::new();
            Self::with_device_of(ann, ann, DeviceStatus::Trusted)
        }

        fn revoke_as(
            &self,
            authorities: FakeTenantAuthorities,
            device_id: TrustedDeviceId,
        ) -> Result<(), AppError> {
            let use_case = RevokeDeviceUseCase::new(RevokeDevicePorts {
                device_store: self.devices.clone(),
                tenant_authorities: Arc::new(authorities),
                ..RevokeDevicePorts::fakes()
            });
            let ctx = test_ctx_with(
                test_ctx().organization_id(),
                test_ctx().tenant_id(),
                self.ann,
            );
            let request = RevokeDeviceRequest {
                whose: Whose::Own,
                device_id,
            };
            block_on(use_case.execute(&ctx, &test_auditor(self.audit.clone()), request))
        }

        fn forget_for(
            &self,
            owner: UserId,
            authorities: FakeTenantAuthorities,
        ) -> Result<(), AppError> {
            let use_case = RevokeDeviceUseCase::new(RevokeDevicePorts {
                device_store: self.devices.clone(),
                tenant_authorities: Arc::new(authorities),
                ..RevokeDevicePorts::fakes()
            });
            let request = RevokeDeviceRequest {
                whose: Whose::OnBehalfOf(owner),
                device_id: self.device_id,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request))
        }

        fn revoke(&self) -> Result<(), AppError> {
            self.revoke_as(FakeTenantAuthorities::holding(&[]), self.device_id)
        }

        fn status(&self) -> DeviceStatus {
            block_on(
                self.devices
                    .find_by_id(&test_ctx().tenant(), &self.device_id),
            )
            .unwrap()
            .unwrap()
            .status()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann forgets her old laptop. It stops counting and the change is
    /// recorded.
    #[test]
    fn a_device_is_forgotten_and_audited() {
        let fixture = Fixture::anns_device();

        fixture.revoke().unwrap();

        assert_eq!(fixture.status(), DeviceStatus::Revoked);
        assert_eq!(fixture.recorded(), ["authentication.device_revoked"]);
    }

    /// Revoking an unknown device returns NotFound and records no event.
    #[test]
    fn an_unknown_device_is_not_found() {
        let fixture = Fixture::anns_device();

        let result = fixture.revoke_as(FakeTenantAuthorities::holding(&[]), TrustedDeviceId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Another user's device returns NotFound and remains trusted.
    #[test]
    fn another_users_device_is_not_found() {
        let fixture = Fixture::with_device_of(UserId::new(), UserId::new(), DeviceStatus::Trusted);

        let result = fixture.revoke();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.status(), DeviceStatus::Trusted);
    }

    /// Ann forgets a device she already forgot. It is a conflict and nothing
    /// more is recorded.
    #[test]
    fn a_device_already_forgotten_is_a_conflict() {
        let ann = UserId::new();
        let fixture = Fixture::with_device_of(ann, ann, DeviceStatus::Revoked);

        let result = fixture.revoke();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller is unauthenticated and leaves the device trusted.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::anns_device();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.device_id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.status(), DeviceStatus::Trusted);
    }

    /// Bob's laptop was stolen. Ann, who may update users, forgets it for
    /// him, so the next sign-in from it asks for his second factor.
    #[test]
    fn an_admin_forgets_someones_device() {
        let bob = UserId::new();
        let fixture = Fixture::with_device_of(bob, UserId::new(), DeviceStatus::Trusted);

        fixture
            .forget_for(
                bob,
                FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::Update)]),
            )
            .unwrap();

        assert_eq!(fixture.status(), DeviceStatus::Revoked);
        assert_eq!(fixture.recorded(), ["authentication.device_revoked"]);
    }

    /// View-only authority cannot revoke another user's device; it remains
    /// trusted and no event is recorded.
    #[test]
    fn a_caller_who_may_not_update_users_forgets_nothing() {
        let bob = UserId::new();
        let fixture = Fixture::with_device_of(bob, UserId::new(), DeviceStatus::Trusted);

        let result = fixture.forget_for(
            bob,
            FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.status(), DeviceStatus::Trusted);
        assert!(fixture.recorded().is_empty());
    }
}
