//! The devices a member remembered, forgotten ones included, for their own
//! device list.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgTrustedDeviceStore;
use crate::use_case::Query;

/// The ports [`ListOrgDevicesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOrgDevicesPorts {
    /// Where members' remembered devices are kept.
    pub devices: Arc<dyn OrgTrustedDeviceStore>,
    /// Who acts on an organization, and how they signed in.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the caller's own remembered devices.
pub struct ListOrgDevicesUseCase {
    ports: ListOrgDevicesPorts,
}

impl ListOrgDevicesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOrgDevicesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListOrgDevicesUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<Vec<TrustedDevice<ResolvedOrganization>>, AppError>;

    /// Every device the member signed in to the caller's session
    /// remembered, forgotten ones included.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with a key rather
    ///   than a session, or the session no longer counts.
    /// - `AppError::Forbidden` when the organization turns the caller away.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        (): (),
    ) -> Result<Vec<TrustedDevice<ResolvedOrganization>>, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        actor.signed_in().map(drop)?;
        self.ports
            .devices
            .list_by_user(actor.member().id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::FakeTrustedDeviceStore;
    use crate::test_support::{block_on, test_org_caller};

    fn list(
        devices: FakeTrustedDeviceStore,
        actors: FakeOrgActors,
    ) -> Result<Vec<TrustedDevice<ResolvedOrganization>>, AppError> {
        let use_case = ListOrgDevicesUseCase::new(ListOrgDevicesPorts {
            devices: Arc::new(devices),
            org_actors: Arc::new(actors),
        });
        block_on(use_case.execute(&test_org_caller(), ()))
    }

    /// Olivia remembered three devices. All three are listed.
    #[test]
    fn every_remembered_device_is_listed() {
        let olivia = *test_org_caller().member();

        let devices = list(
            FakeTrustedDeviceStore::with_devices(olivia, 3),
            FakeOrgActors::in_role(OrgRole::Member),
        )
        .unwrap();

        assert_eq!(devices.len(), 3);
    }

    /// Sam remembered two devices. Olivia's list shows none of them.
    #[test]
    fn someone_elses_devices_are_not_listed() {
        let devices = list(
            FakeTrustedDeviceStore::with_devices(OrgUserId::new(), 2),
            FakeOrgActors::in_role(OrgRole::Owner),
        )
        .unwrap();

        assert!(devices.is_empty());
    }

    /// A signed-out session cannot list the member's remembered devices.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let olivia = *test_org_caller().member();

        let result = list(
            FakeTrustedDeviceStore::with_devices(olivia, 1),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
