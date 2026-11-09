//! Listing the networks of a connected cloud a tenant's database could be
//! placed in.

use std::sync::Arc;

use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::message;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::cloud::{CloudAccountStore, CloudProviderRegistry};
use crate::use_case::Query;
use crate::use_cases::organization::cloud_accounts::lookup::existing_cloud_account;
use crate::use_cases::organization::cloud_accounts::rights::ensure_may_connect;

/// Which cloud and region to list networks in.
pub struct ListCloudNetworksRequest {
    /// The connected cloud.
    pub provider: CloudProvider,
    /// The region whose networks are listed.
    pub region: DeploymentRegion,
}

/// The ports [`ListCloudNetworksUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListCloudNetworksPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// Reaches each cloud this deployment can drive.
    pub registry: Arc<dyn CloudProviderRegistry>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the networks a database could be placed in.
pub struct ListCloudNetworksUseCase {
    ports: ListCloudNetworksPorts,
}

impl ListCloudNetworksUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListCloudNetworksPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListCloudNetworksUseCase {
    type Caller = OrgCaller;
    type Input = ListCloudNetworksRequest;
    type Output = Result<Vec<CloudNetwork>, AppError>;

    /// The networks in `request.region` of the cloud `caller`'s
    /// organization connected.
    ///
    /// Listing someone's networks is reading their infrastructure, so only
    /// a proved connection is used, as at provisioning.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization, the connection is not verified, or the cloud refused
    ///   the credential.
    /// - `AppError::NotFound` if no connection exists.
    /// - `AppError::Domain` if this deployment has no adapter for that
    ///   cloud.
    /// - `AppError::Internal` if the cloud could not be reached, or on a
    ///   storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        request: ListCloudNetworksRequest,
    ) -> Result<Vec<CloudNetwork>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        ensure_may_connect(&actor.control()?, organization.id())?;
        let account = existing_cloud_account(
            self.ports.store.as_ref(),
            organization.id(),
            request.provider,
        )
        .await?;
        let credential = account.usable_credential().ok_or_else(|| {
            AppError::Forbidden(message!(
                "organization-this-cloud-connection-has-not-been",
                "this cloud connection has not been verified"
            ))
        })?;
        self.ports
            .registry
            .factory(request.provider)
            .map_err(AppError::from_domain)?
            .network_discovery()
            .networks(credential, request.region)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::ConnectionState;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeCloudAccountStore, seeded_aws_connection, seeded_aws_credential, seeded_cloud_identity,
    };
    use crate::test_support::{block_on, test_org_caller};

    fn networks_with(
        state: ConnectionState,
        actors: FakeOrgActors,
    ) -> Result<Vec<CloudNetwork>, AppError> {
        let account = seeded_aws_connection(test_org_caller().organization_id(), state);
        let uc = ListCloudNetworksUseCase::new(ListCloudNetworksPorts {
            store: Arc::new(FakeCloudAccountStore::holding(account)),
            org_actors: Arc::new(actors),
            ..ListCloudNetworksPorts::fakes()
        });
        block_on(uc.execute(
            &test_org_caller(),
            ListCloudNetworksRequest {
                provider: CloudProvider::Aws,
                region: DeploymentRegion::EuCentral1,
            },
        ))
    }

    fn verified() -> ConnectionState {
        ConnectionState::Verified {
            credential: seeded_aws_credential(),
            at: clock::now(),
            identity: seeded_cloud_identity(),
        }
    }

    fn owner() -> FakeOrgActors {
        FakeOrgActors::in_role(OrgRole::Owner)
    }

    /// Olivia, an owner, lists the networks of Acme's proved AWS
    /// connection. The account has none, and that is the answer.
    #[test]
    fn a_verified_connection_lists_its_networks() {
        let networks = networks_with(verified(), owner()).unwrap();

        assert!(networks.is_empty());
    }

    /// An attached but unverified credential cannot be used to list networks,
    /// even by the organization's owner.
    #[test]
    fn networks_are_refused_for_an_unverified_connection() {
        let attached = ConnectionState::AwaitingVerification {
            credential: seeded_aws_credential(),
        };

        let result = networks_with(attached, owner());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A plain member cannot list networks through a verified connection.
    #[test]
    fn a_plain_member_is_refused() {
        let result = networks_with(verified(), FakeOrgActors::in_role(OrgRole::Member));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before listing cloud networks.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = networks_with(verified(), FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents listing cloud networks.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = networks_with(verified(), FakeOrgActors::refusing(Refusal::Forbidden));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
