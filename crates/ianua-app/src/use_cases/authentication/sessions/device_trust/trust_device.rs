//! Remembering a device, so later sign-ins from it may skip the second
//! factor.
//!
//! Only a sign-in that proved a second factor may remember a device, and
//! the device belongs to whoever signed in. The secret the browser presents
//! is never kept: the server stores its digest only.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_change::DeviceChange;
use ianua_domain::domains::authentication::device_trust::{
    DeviceSecret, PresentedSecret, TrustDeviceParams,
};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, IpAddress, Label, TrustedDeviceId, UserAgent};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TrustedDeviceStore;
use crate::ports::oauth::CodeHasher;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::device_trust::remembering::{
    digest_of, ensure_room_for_another, refused,
};

/// The device to remember, as the browser and the request describe it.
pub struct TrustDeviceRequest {
    /// The secret the browser made for itself and presents at sign-in.
    pub secret: DeviceSecret,
    /// The name shown in the person's device list.
    pub device_name: Label,
    /// The User-Agent of the current request.
    pub user_agent: UserAgent,
    /// The address of the current request.
    pub ip: IpAddress,
}

/// How many devices one person may have remembered at a time.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// The most trusted devices one person holds.
    pub max_devices_per_user: usize,
}

/// The ports [`TrustDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TrustDevicePorts {
    /// Where remembered devices are kept.
    pub device_store: Arc<dyn TrustedDeviceStore>,
    /// Hashes the presented secret into the digest that is stored.
    pub secret_hasher: Arc<dyn CodeHasher>,
    /// Who is signed in to the caller's session, and how.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Remembers the device the caller signed in from.
pub struct TrustDeviceUseCase {
    policy: Policy,
    ports: TrustDevicePorts,
}

impl TrustDeviceUseCase {
    /// A use case keeping to `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: Policy, ports: TrustDevicePorts) -> Self {
        Self { policy, ports }
    }
}

impl Command for TrustDeviceUseCase {
    type Caller = CallerContext;
    type Input = TrustDeviceRequest;
    type Output = Result<TrustedDeviceId, AppError>;

    /// Remembers the device for the person signed in to `ctx`'s session and
    /// records `authentication.device_trusted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Forbidden` when the sign-in proved no second factor.
    /// - `AppError::Conflict` when the person already holds as many devices
    ///   as the policy allows.
    /// - `AppError::Internal` on hashing or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: TrustDeviceRequest,
    ) -> Result<TrustedDeviceId, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let store = self.ports.device_store.as_ref();
        ensure_room_for_another(store, &ctx.tenant(), person.account.id(), self.policy).await?;
        let secret = PresentedSecret::on_dashboard(req.secret);
        let params = TrustDeviceParams {
            secret_hash: digest_of(self.ports.secret_hasher.as_ref(), &secret).await?,
            device_name: req.device_name,
            user_agent: req.user_agent,
            ip: req.ip,
        };
        let holder = ActorRef::User(*person.account.id());
        let (device, mut change) =
            DeviceChange::trust(params, &person.signed_in).map_err(refused)?;
        self.ports
            .device_store
            .save(&ctx.tenant(), &device)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&holder, change.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(*device.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::types::{PrincipalId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeTrustedDeviceStore, known_device};
    use crate::test_support::oauth::hash_of;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn totp_sign_in() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::Proved(MfaFactor::Totp),
            owed: SecondFactor::NotOwed,
        }
    }

    struct Fixture {
        ann: UserId,
        devices: Arc<FakeTrustedDeviceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn holding(devices: FakeTrustedDeviceStore) -> Self {
            Self {
                ann: UserId::new(),
                devices: Arc::new(devices),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::holding(FakeTrustedDeviceStore::empty())
        }

        fn trust(&self, authorities: FakeTenantAuthorities) -> Result<TrustedDeviceId, AppError> {
            let use_case = TrustDeviceUseCase::new(
                Policy {
                    max_devices_per_user: 2,
                },
                TrustDevicePorts {
                    device_store: self.devices.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..TrustDevicePorts::fakes()
                },
            );
            let ctx = test_ctx_with(
                test_ctx().organization_id(),
                test_ctx().tenant_id(),
                self.ann,
            );
            block_on(use_case.execute(&ctx, &test_auditor(self.audit.clone()), request()))
        }

        fn trust_after_a_code(&self) -> Result<TrustedDeviceId, AppError> {
            self.trust(FakeTenantAuthorities::holding(&[]).signed_in_by(totp_sign_in()))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn request() -> TrustDeviceRequest {
        TrustDeviceRequest {
            secret: DeviceSecret::new(SECRET).unwrap(),
            device_name: Label::new("device_name", "Ann's laptop").unwrap(),
            user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            ip: IpAddress::new("203.0.113.7").unwrap(),
        }
    }

    /// Ann signed in with her password and a code, and remembers her laptop.
    /// It is hers, stored by the digest of its secret, and recorded.
    #[test]
    fn a_device_is_remembered_after_a_second_factor() {
        let fixture = Fixture::new();

        let id = fixture.trust_after_a_code().unwrap();

        let stored = block_on(fixture.devices.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.subject_id(), PrincipalId::from(fixture.ann));
        assert_eq!(stored.secret_hash(), &hash_of(SECRET));
        assert_eq!(fixture.recorded(), ["authentication.device_trusted"]);
    }

    /// A password-only session is forbidden from trusting a device, with
    /// no device stored and no trust event recorded.
    #[test]
    fn a_password_only_sign_in_may_not_remember_a_device() {
        let fixture = Fixture::new();

        let result = fixture.trust(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.devices.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Trusting a third device conflicts with the two-device policy and
    /// records no event.
    #[test]
    fn a_device_past_the_most_allowed_is_refused() {
        let ann = UserId::new();
        let fixture = Fixture {
            ann,
            ..Fixture::holding(FakeTrustedDeviceStore::with_devices(ann, 2))
        };

        let result = fixture.trust_after_a_code();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Ann forgot one of her two devices. That frees its place, so she may
    /// remember another.
    #[test]
    fn a_revoked_device_frees_its_place() {
        let ann = UserId::new();
        let devices = FakeTrustedDeviceStore::holding([
            known_device(ann, DeviceStatus::Trusted),
            known_device(ann, DeviceStatus::Revoked),
        ]);
        let fixture = Fixture {
            ann,
            ..Fixture::holding(devices)
        };

        let result = fixture.trust_after_a_code();

        assert!(result.is_ok());
    }

    /// A signed-out caller is unauthenticated and stores no trusted device.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.trust(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.devices.count(), 0);
    }
}
