//! A member remembering the device they signed in from, so later sign-ins
//! from it may skip the second factor.
//!
//! The management-plane twin of the tenant's device trust. Only a sign-in
//! that proved a second factor may remember a device, and the device is
//! the member's who signed in. The secret the browser presents is never
//! kept: the server stores its digest only.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::{
    DeviceSecret, TrustDeviceParams, TrustedDevice,
};
use ianua_domain::domains::organization::events::access::OrgDeviceTrusted;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, IpAddress, Label, TokenHash, TrustedDeviceId, UserAgent};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::CodeHasher;
use crate::ports::organization::OrgTrustedDeviceStore;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::device_trust::Policy;

/// The device to remember, as the browser and the request describe it.
pub struct TrustOrgDeviceRequest {
    /// The secret the browser made for itself and presents at sign-in.
    pub secret: DeviceSecret,
    /// The name shown in the member's device list.
    pub device_name: Label,
    /// The User-Agent of the current request.
    pub user_agent: UserAgent,
    /// The address of the current request.
    pub ip: IpAddress,
}

/// The ports [`TrustOrgDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TrustOrgDevicePorts {
    /// Where members' remembered devices are kept.
    pub devices: Arc<dyn OrgTrustedDeviceStore>,
    /// Hashes the presented secret into the digest that is stored.
    pub device_secret_hasher: Arc<dyn CodeHasher>,
    /// Who acts on an organization, and how they signed in.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Remembers the device the caller signed in from.
pub struct TrustOrgDeviceUseCase {
    policy: Policy,
    ports: TrustOrgDevicePorts,
}

impl TrustOrgDeviceUseCase {
    /// A use case keeping to `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: Policy, ports: TrustOrgDevicePorts) -> Self {
        Self { policy, ports }
    }

    /// Refuses another device once the member holds as many as the policy
    /// allows. Every remembered device is a place a second factor is not
    /// asked for, so the count stays one the member can keep track of.
    async fn ensure_member_has_room(&self, member: &OrgUser) -> Result<(), AppError> {
        let held = self
            .ports
            .devices
            .list_by_user(member.id())
            .await
            .or_internal()?;
        let remembered = held
            .iter()
            .filter(|device| device.status().is_trusted())
            .count();
        if remembered >= self.policy.max_devices_per_user {
            return Err(AppError::Conflict(message!(
                "authentication-maximum-trusted-devices-reached",
                "maximum trusted devices reached"
            )));
        }
        Ok(())
    }

    async fn secret_digest(&self, secret: &DeviceSecret) -> Result<TokenHash, AppError> {
        self.ports
            .device_secret_hasher
            .hash_code(&Secret::new(secret.as_str()))
            .await
            .or_internal()
    }
}

impl Command for TrustOrgDeviceUseCase {
    type Caller = OrgCaller;
    type Input = TrustOrgDeviceRequest;
    type Output = Result<TrustedDeviceId, AppError>;

    /// Remembers the device for the member signed in to the caller's
    /// session and records `organization.org_device_trusted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with a key rather
    ///   than a session, or the session no longer counts.
    /// - `AppError::Forbidden` when the organization turns the caller away,
    ///   or the sign-in proved no second factor.
    /// - `AppError::Conflict` when the member already holds as many devices
    ///   as the policy allows.
    /// - `AppError::Internal` on hashing, storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: TrustOrgDeviceRequest,
    ) -> Result<TrustedDeviceId, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let signed_in = actor.signed_in()?;
        let member = actor.member();
        self.ensure_member_has_room(member).await?;
        let params = TrustDeviceParams {
            secret_hash: self.secret_digest(&request.secret).await?,
            device_name: request.device_name,
            user_agent: request.user_agent,
            ip: request.ip,
        };
        let device = TrustedDevice::<ResolvedOrganization>::trust(params, &signed_in)
            .map_err(|refusal| AppError::Forbidden(refusal.to_string().into()))?;
        self.ports
            .devices
            .save(member.id(), &device)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*member.id()),
                vec![OrgDeviceTrusted::observed(member)],
            )
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
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::PrincipalId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{FakeTrustedDeviceStore, known_device};
    use crate::test_support::oauth::hash_of;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn totp_sign_in() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::Proved(MfaFactor::Totp),
            owed: SecondFactor::NotOwed,
        }
    }

    struct Fixture {
        devices: Arc<FakeTrustedDeviceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn holding(devices: FakeTrustedDeviceStore) -> Self {
            Self {
                devices: Arc::new(devices),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::holding(FakeTrustedDeviceStore::empty())
        }

        fn trust(&self, actors: FakeOrgActors) -> Result<TrustedDeviceId, AppError> {
            let use_case = TrustOrgDeviceUseCase::new(
                Policy {
                    max_devices_per_user: 2,
                },
                TrustOrgDevicePorts {
                    devices: self.devices.clone(),
                    org_actors: Arc::new(actors),
                    ..TrustOrgDevicePorts::fakes()
                },
            );
            block_on(use_case.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request(),
            ))
        }

        fn trust_after_a_code(&self) -> Result<TrustedDeviceId, AppError> {
            self.trust(FakeOrgActors::in_role(OrgRole::Member).signed_in_by(totp_sign_in()))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn request() -> TrustOrgDeviceRequest {
        TrustOrgDeviceRequest {
            secret: DeviceSecret::new(SECRET).unwrap(),
            device_name: Label::new("device_name", "Olivia's laptop").unwrap(),
            user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            ip: IpAddress::new("203.0.113.7").unwrap(),
        }
    }

    /// Olivia signed in with her password and a code, and remembers her
    /// laptop. It is hers, stored by the digest of its secret, and
    /// recorded.
    #[test]
    fn a_device_is_remembered_after_a_second_factor() {
        let fixture = Fixture::new();

        let id = fixture.trust_after_a_code().unwrap();

        let olivia = *test_org_caller().member();
        let stored = block_on(fixture.devices.find_by_id(&olivia, &id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.subject_id(), PrincipalId::from(olivia));
        assert_eq!(stored.secret_hash(), &hash_of(SECRET));
        assert_eq!(fixture.recorded(), ["organization.org_device_trusted"]);
    }

    /// A password-only sign-in cannot remember a device, and no device or
    /// audit event is stored.
    #[test]
    fn a_password_only_sign_in_may_not_remember_a_device() {
        let fixture = Fixture::new();

        let result = fixture.trust(FakeOrgActors::in_role(OrgRole::Member));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.devices.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Remembering another device at the configured limit conflicts and
    /// produces no audit event.
    #[test]
    fn a_device_past_the_most_allowed_is_refused() {
        let olivia = *test_org_caller().member();
        let fixture = Fixture::holding(FakeTrustedDeviceStore::with_devices(olivia, 2));

        let result = fixture.trust_after_a_code();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Olivia forgot one of her two devices. That frees its place, so she
    /// may remember another.
    #[test]
    fn a_forgotten_device_frees_its_place() {
        let olivia = *test_org_caller().member();
        let fixture = Fixture::holding(FakeTrustedDeviceStore::holding_members([
            known_device(olivia, DeviceStatus::Trusted),
            known_device(olivia, DeviceStatus::Revoked),
        ]));

        assert!(fixture.trust_after_a_code().is_ok());
    }

    /// A signed-out session cannot remember a device, and none is stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.trust(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.devices.count(), 0);
    }

    /// An API key cannot remember a device, even for an owner, and none is stored.
    #[test]
    fn a_key_may_not_remember_a_device() {
        let fixture = Fixture::new();

        let result = fixture.trust(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.devices.count(), 0);
    }
}
