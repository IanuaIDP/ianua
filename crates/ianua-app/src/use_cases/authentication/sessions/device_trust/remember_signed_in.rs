//! Remembering the device a sign-in that just finished came from, on an
//! app's host, where no dashboard session asks for it.
//!
//! The gateway's second-factor page offers "remember this device". The
//! sign-in it finishes is held to what remembering from the dashboard is:
//! only a finished sign-in that proved a second factor remembers a device,
//! the device is the signed-in person's, and they hold no more than the
//! policy allows. The device counts only where it was remembered: its
//! digest is of the secret bound to the app's host. The session names the
//! device it now comes from, so its tokens carry it to a device posture
//! check.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_change::DeviceChange;
use ianua_domain::domains::authentication::device_trust::{
    PresentedSecret, TrustDeviceParams, TrustedDevice,
};
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    ActorRef, Fact, IpAddress, Label, SessionId, TrustedDeviceId, UserAgent,
};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TrustedDeviceStore;
use crate::ports::oauth::CodeHasher;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::device_trust::remembering::{
    digest_of, ensure_room_for_another, refused,
};
use crate::use_cases::authentication::sessions::device_trust::trust_device::Policy;

/// The device to remember, for the sign-in that just finished on it.
pub struct RememberSignedInRequest {
    /// The session the sign-in opened.
    pub session_id: SessionId,
    /// The secret the browser keeps for the device, with where it was
    /// presented.
    pub secret: PresentedSecret,
    /// The name shown in the person's device list.
    pub device_name: Label,
    /// The User-Agent of the current request.
    pub user_agent: UserAgent,
    /// The address of the current request.
    pub ip: IpAddress,
}

/// The ports [`RememberSignedInDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RememberSignedInPorts {
    /// Where remembered devices are kept.
    pub device_store: Arc<dyn TrustedDeviceStore>,
    /// Hashes the presented secret into the digest that is stored.
    pub secret_hasher: Arc<dyn CodeHasher>,
    /// Saves the session the sign-in opened, which then names the device.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in on the session the sign-in opened, and how.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Remembers the device a finished sign-in came from.
pub struct RememberSignedInDeviceUseCase {
    policy: Policy,
    ports: RememberSignedInPorts,
}

impl RememberSignedInDeviceUseCase {
    /// A use case keeping to `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: Policy, ports: RememberSignedInPorts) -> Self {
        Self { policy, ports }
    }

    /// Keeps `device` and the session now naming it.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        device: &TrustedDevice<ResolvedTenant>,
        session: &mut Session<ResolvedTenant>,
    ) -> Result<(), AppError> {
        session
            .record_signed_in_from(device)
            .map_err(AppError::from_domain)?;
        self.ports
            .device_store
            .save(tenant, device)
            .await
            .or_internal()?;
        self.ports
            .session_store
            .save(tenant, session)
            .await
            .or_internal()
    }
}

impl Command for RememberSignedInDeviceUseCase {
    type Caller = ScopedTenant;
    type Input = RememberSignedInRequest;
    type Output = Result<TrustedDeviceId, AppError>;

    /// Remembers the device for the person whose sign-in `request` names,
    /// names it on that session, and records
    /// `authentication.device_trusted`. A sign-in that came from a device
    /// already remembered remembers nothing more and answers that device.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or its account is
    ///   gone, or the sign-in is not finished or no longer counts.
    /// - `AppError::TenantUnavailable` when the tenant is not open.
    /// - `AppError::Forbidden` when the sign-in proved no second factor.
    /// - `AppError::Conflict` when the person already holds as many devices
    ///   as the policy allows.
    /// - `AppError::Internal` on hashing or persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RememberSignedInRequest,
    ) -> Result<TrustedDeviceId, AppError> {
        let SignedInAccount {
            account,
            signed_in,
            mut session,
            ..
        } = self
            .ports
            .tenant_authorities
            .signed_in_on(tenant, &request.session_id)
            .await?;
        if let Fact::Known(device) = session.signed_in_from() {
            return Ok(device);
        }
        let store = self.ports.device_store.as_ref();
        ensure_room_for_another(store, tenant, account.id(), self.policy).await?;
        let params = trust_params(self.ports.secret_hasher.as_ref(), request).await?;
        let holder = ActorRef::User(*account.id());
        let (device, mut change) = DeviceChange::trust(params, &signed_in).map_err(refused)?;
        self.keep(tenant, &device, &mut session).await?;
        auditor
            .dispatch_by(&holder, change.take_events(tenant))
            .await
            .or_internal()?;
        Ok(*device.id())
    }
}

/// What the device is remembered by: the digest of the secret it will
/// present, hashed by `hasher`, and what `request` says of it.
async fn trust_params(
    hasher: &dyn CodeHasher,
    request: RememberSignedInRequest,
) -> Result<TrustDeviceParams, AppError> {
    Ok(TrustDeviceParams {
        secret_hash: digest_of(hasher, &request.secret).await?,
        device_name: request.device_name,
        user_agent: request.user_agent,
        ip: request.ip,
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::{DeviceSecret, SignInPlace};
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::types::{DomainName, PrincipalId, UserId};

    use super::*;
    use crate::acting::tenant::{TenantActing, TenantActingPorts, TenantCredentialPorts};
    use crate::test_support::authentication::{
        FakeSessionStore, FakeTrustedDeviceStore, session_signed_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::oauth::hash_of;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SHOP: &str = "shop.acme.example";

    fn progress(factor: FactorProved) -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor,
            owed: SecondFactor::NotOwed,
        }
    }

    fn on_shop() -> PresentedSecret {
        PresentedSecret::new(
            DeviceSecret::new(SECRET).unwrap(),
            SignInPlace::AppHost(DomainName::new(SHOP).unwrap()),
        )
    }

    struct Fixture {
        ann: UserId,
        session_id: SessionId,
        sessions: Arc<FakeSessionStore>,
        devices: Arc<FakeTrustedDeviceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// Ann's finished sign-in that proved `factor`, her devices `held`.
        fn signed_in(factor: FactorProved, held: FakeTrustedDeviceStore) -> Self {
            let ann = UserId::new();
            let session = session_signed_in(ann, progress(factor));
            Self {
                ann,
                session_id: *session.id(),
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                devices: Arc::new(held),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn after_a_code() -> Self {
            Self::signed_in(
                FactorProved::Proved(MfaFactor::Totp),
                FakeTrustedDeviceStore::empty(),
            )
        }

        fn remember(&self) -> Result<TrustedDeviceId, AppError> {
            let use_case = RememberSignedInDeviceUseCase::new(
                Policy {
                    max_devices_per_user: 2,
                },
                RememberSignedInPorts {
                    device_store: self.devices.clone(),
                    session_store: self.sessions.clone(),
                    tenant_authorities: Arc::new(TenantActing::new(TenantActingPorts {
                        tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                        tenant: TenantCredentialPorts {
                            users: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                            sessions: self.sessions.clone(),
                            ..TenantCredentialPorts::fakes()
                        },
                        ..TenantActingPorts::fakes()
                    })),
                    ..RememberSignedInPorts::fakes()
                },
            );
            let request = RememberSignedInRequest {
                session_id: self.session_id,
                secret: on_shop(),
                device_name: Label::new("device_name", "Browser on shop.acme.example").unwrap(),
                user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
                ip: IpAddress::new("203.0.113.7").unwrap(),
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, request))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann proved a code on the shop's sign-in and asked to remember her
    /// laptop. It is hers, kept by the digest of its secret bound to the
    /// shop's host, her session names it, and it is recorded.
    #[test]
    fn a_device_is_remembered_on_the_apps_host_after_a_second_factor() {
        let f = Fixture::after_a_code();

        let id = f.remember().unwrap();

        let stored = block_on(f.devices.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.subject_id(), PrincipalId::from(f.ann));
        assert_eq!(stored.secret_hash(), &hash_of(on_shop().bound().expose()));
        assert_ne!(stored.secret_hash(), &hash_of(SECRET));
        let session = f.sessions.get_session(&f.session_id).unwrap();
        assert_eq!(session.signed_in_from(), Fact::Known(id));
        assert_eq!(f.recorded(), ["authentication.device_trusted"]);
    }

    /// A password-only sign-in cannot remember a device; it is forbidden,
    /// with no device stored and no event recorded.
    #[test]
    fn a_password_only_sign_in_remembers_nothing() {
        let f = Fixture::signed_in(FactorProved::NoneYet, FakeTrustedDeviceStore::empty());

        let refused = f.remember();

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert_eq!(f.devices.count(), 0);
        assert!(f.recorded().is_empty());
    }

    /// Remembering a device at the policy limit conflicts and records no event.
    #[test]
    fn a_device_past_the_most_allowed_is_refused() {
        let ann = UserId::new();
        let session = session_signed_in(ann, progress(FactorProved::Proved(MfaFactor::Totp)));
        let f = Fixture {
            ann,
            session_id: *session.id(),
            sessions: Arc::new(FakeSessionStore::with_session(session)),
            devices: Arc::new(FakeTrustedDeviceStore::with_devices(ann, 2)),
            audit: Arc::new(FakeEventDispatcher::new()),
        };

        let refused = f.remember();

        assert!(matches!(refused, Err(AppError::Conflict(_))));
        assert!(f.recorded().is_empty());
    }

    /// Ann's sign-in already came from a laptop she remembered. Nothing
    /// more is remembered, and the answer is that laptop.
    #[test]
    fn a_sign_in_from_a_remembered_device_remembers_nothing_more() {
        let ann = UserId::new();
        let laptop = crate::test_support::authentication::known_device(ann, DeviceStatus::Trusted);
        let laptop_id = *laptop.id();
        let mut session = session_signed_in(ann, progress(FactorProved::Proved(MfaFactor::Totp)));
        session.record_signed_in_from(&laptop).unwrap();
        let f = Fixture {
            ann,
            session_id: *session.id(),
            sessions: Arc::new(FakeSessionStore::with_session(session)),
            devices: Arc::new(FakeTrustedDeviceStore::holding([laptop])),
            audit: Arc::new(FakeEventDispatcher::new()),
        };

        let id = f.remember().unwrap();

        assert_eq!(id, laptop_id);
        assert_eq!(f.devices.count(), 1);
        assert!(f.recorded().is_empty());
    }

    /// A missing session is unauthenticated and leaves the device store empty.
    #[test]
    fn a_gone_session_remembers_nothing() {
        let f = Fixture {
            sessions: Arc::new(FakeSessionStore::empty()),
            ..Fixture::after_a_code()
        };

        let refused = f.remember();

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
        assert_eq!(f.devices.count(), 0);
    }
}
