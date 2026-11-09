//! Reading back the external id a cloud connection was begun with, so the
//! customer's console can be filled in again.

use std::sync::Arc;

use ianua_domain::domains::organization::cloud::credential::ExternalId;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::cloud::CloudAccountStore;
use crate::use_case::Query;
use crate::use_cases::organization::cloud_accounts::rights::ensure_may_connect;

/// The ports [`GetCloudExternalIdUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetCloudExternalIdPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reads the external id generated for a connection.
pub struct GetCloudExternalIdUseCase {
    ports: GetCloudExternalIdPorts,
}

impl GetCloudExternalIdUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetCloudExternalIdPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetCloudExternalIdUseCase {
    type Caller = OrgCaller;
    type Input = CloudProvider;
    type Output = Result<Option<ExternalId>, AppError>;

    /// The external id the connection of `caller`'s organization to
    /// `provider` was begun with, or `None` when it never was.
    ///
    /// It is shown only to whoever may connect the cloud, as when it was
    /// first handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization.
    /// - `AppError::Internal` on a storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        provider: CloudProvider,
    ) -> Result<Option<ExternalId>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        ensure_may_connect(&actor.control()?, organization.id())?;
        self.ports
            .store
            .external_id(organization.id(), provider)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::ConnectionState;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeCloudAccountStore, seeded_aws_connection, seeded_external_id,
    };
    use crate::test_support::{block_on, test_org_caller};

    fn read_with(
        store: FakeCloudAccountStore,
        actors: FakeOrgActors,
    ) -> Result<Option<ExternalId>, AppError> {
        let uc = GetCloudExternalIdUseCase::new(GetCloudExternalIdPorts {
            store: Arc::new(store),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), CloudProvider::Aws))
    }

    fn begun() -> FakeCloudAccountStore {
        FakeCloudAccountStore::holding(seeded_aws_connection(
            test_org_caller().organization_id(),
            ConnectionState::AwaitingCredential,
        ))
    }

    /// Olivia, an owner, reads back the external id of Acme's AWS
    /// connection. It is the one the connection was begun with.
    #[test]
    fn the_external_id_read_back_is_the_one_begin_handed_out() {
        let stored = read_with(begun(), FakeOrgActors::in_role(OrgRole::Owner)).unwrap();

        assert_eq!(
            stored.as_ref().map(ExternalId::as_str),
            Some(seeded_external_id().as_str())
        );
    }

    /// Olivia reads the external id of a cloud she never began connecting.
    /// There is none.
    #[test]
    fn a_cloud_never_begun_has_no_external_id() {
        let stored = read_with(
            FakeCloudAccountStore::default(),
            FakeOrgActors::in_role(OrgRole::Owner),
        )
        .unwrap();

        assert!(stored.is_none());
    }

    /// A plain member cannot read the external id of a begun connection.
    #[test]
    fn a_plain_member_is_refused() {
        let result = read_with(begun(), FakeOrgActors::in_role(OrgRole::Member));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before reading the external id.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read_with(begun(), FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents reading the external id.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = read_with(begun(), FakeOrgActors::refusing(Refusal::Forbidden));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
