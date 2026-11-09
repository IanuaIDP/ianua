//! A member forgetting a device they remembered, so sign-ins from it ask
//! for the second factor again.

use std::sync::Arc;

use ianua_domain::domains::organization::events::access::OrgDeviceRevoked;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, TrustedDeviceId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgTrustedDeviceStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::owned_trusted_device;

/// The ports [`RevokeOrgDeviceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeOrgDevicePorts {
    /// Where members' remembered devices are kept.
    pub devices: Arc<dyn OrgTrustedDeviceStore>,
    /// Who acts on an organization, and how they signed in.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Forgets one of the caller's own remembered devices.
pub struct RevokeOrgDeviceUseCase {
    ports: RevokeOrgDevicePorts,
}

impl RevokeOrgDeviceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeOrgDevicePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeOrgDeviceUseCase {
    type Caller = OrgCaller;
    type Input = TrustedDeviceId;
    type Output = Result<(), AppError>;

    /// Forgets the device `device_id` of the member signed in to the
    /// caller's session and records `organization.org_device_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with a key rather
    ///   than a session, or the session no longer counts.
    /// - `AppError::Forbidden` when the organization turns the caller away.
    /// - `AppError::NotFound` when the member has no such device. Someone
    ///   else's device reads as absent.
    /// - `AppError::Conflict` when the device was already forgotten.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        device_id: TrustedDeviceId,
    ) -> Result<(), AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let signed_in = actor.signed_in()?;
        let member = actor.member();
        let store = self.ports.devices.as_ref();
        let mut device = owned_trusted_device(store, member.id(), &device_id).await?;
        device.revoke(&signed_in).map_err(forget_error)?;
        store.save(member.id(), &device).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*member.id()),
                vec![OrgDeviceRevoked::observed(member)],
            )
            .await
            .or_internal()
    }
}

/// The error a device that cannot be forgotten answers with: one forgotten
/// before is a conflict.
fn forget_error(error: DomainError) -> AppError {
    match error {
        DomainError::InvalidTransition(_) => AppError::Conflict(message!(
            "organization-this-device-was-already-forgotten",
            "this device was already forgotten"
        )),
        other => AppError::from_domain(other),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::TrustedDevice;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::isolation::organization::scope::ResolvedOrganization;
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{FakeTrustedDeviceStore, known_device};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        device_id: TrustedDeviceId,
        devices: Arc<FakeTrustedDeviceStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// One device of `owner`, in `status`.
        fn device_of(owner: OrgUserId, status: DeviceStatus) -> Self {
            let device: TrustedDevice<ResolvedOrganization> = known_device(owner, status);
            Self {
                device_id: *device.id(),
                devices: Arc::new(FakeTrustedDeviceStore::holding_members([device])),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn callers(status: DeviceStatus) -> Self {
            Self::device_of(*test_org_caller().member(), status)
        }

        fn forget(&self, actors: FakeOrgActors) -> Result<(), AppError> {
            let use_case = RevokeOrgDeviceUseCase::new(RevokeOrgDevicePorts {
                devices: self.devices.clone(),
                org_actors: Arc::new(actors),
            });
            block_on(use_case.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                self.device_id,
            ))
        }

        fn status(&self, owner: &OrgUserId) -> Option<DeviceStatus> {
            block_on(self.devices.find_by_id(owner, &self.device_id))
                .unwrap()
                .map(|device| device.status())
        }
    }

    fn olivia() -> FakeOrgActors {
        FakeOrgActors::in_role(OrgRole::Member)
    }

    /// Olivia forgets her laptop. It stays listed as forgotten, and the
    /// change is recorded.
    #[test]
    fn forgetting_leaves_the_device_listed_as_forgotten() {
        let fixture = Fixture::callers(DeviceStatus::Trusted);

        fixture.forget(olivia()).unwrap();

        let owner = *test_org_caller().member();
        assert_eq!(fixture.status(&owner), Some(DeviceStatus::Revoked));
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            ["organization.org_device_revoked"]
        );
    }

    /// Forgetting an already revoked device returns a conflict.
    #[test]
    fn a_forgotten_device_cannot_be_forgotten_again() {
        let fixture = Fixture::callers(DeviceStatus::Revoked);

        let result = fixture.forget(olivia());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Another member's device is treated as not found and remains trusted.
    #[test]
    fn someone_elses_device_reads_as_absent() {
        let sam = OrgUserId::new();
        let fixture = Fixture::device_of(sam, DeviceStatus::Trusted);

        let result = fixture.forget(olivia());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.status(&sam), Some(DeviceStatus::Trusted));
    }

    /// A signed-out session cannot revoke a remembered device.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::callers(DeviceStatus::Trusted);

        let result = fixture.forget(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
