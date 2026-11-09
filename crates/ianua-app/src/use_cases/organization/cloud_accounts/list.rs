//! Listing every cloud an organization has connected.

use std::sync::Arc;

use ianua_domain::domains::organization::cloud::account::CloudAccount;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::cloud::CloudAccountStore;
use crate::use_case::Query;
use crate::use_cases::organization::cloud_accounts::rights::ensure_may_see_connections;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the cloud connections of the caller's organization.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<Vec<CloudAccount>, AppError>;

    /// Every cloud `caller`'s organization has connected.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the
    ///   organization.
    /// - `AppError::Internal` on a storage failure.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<Vec<CloudAccount>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        ensure_may_see_connections(&actor.control()?, organization.id())?;
        self.ports
            .store
            .list_for_organization(organization.id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::ConnectionState;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OrganizationId, Scope};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeCloudAccountStore, seeded_aws_connection, seeded_external_id,
    };
    use crate::test_support::{block_on, test_org_caller};

    fn list_with(
        store: FakeCloudAccountStore,
        actors: FakeOrgActors,
    ) -> Result<Vec<CloudAccount>, AppError> {
        let uc = ListUseCase::new(ListPorts {
            store: Arc::new(store),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), ()))
    }

    fn ours_and_theirs() -> FakeCloudAccountStore {
        let ours = test_org_caller().organization_id();
        let store = FakeCloudAccountStore::holding(seeded_aws_connection(
            ours,
            ConnectionState::AwaitingCredential,
        ));
        let theirs =
            seeded_aws_connection(OrganizationId::new(), ConnectionState::AwaitingCredential);
        block_on(store.save(&theirs, &seeded_external_id())).unwrap();
        store
    }

    /// Sam, a plain member of Acme, looks at the connected clouds. He sees
    /// Acme's only, never another organization's.
    #[test]
    fn listing_shows_only_this_organizations_connections() {
        let listed = list_with(ours_and_theirs(), FakeOrgActors::in_role(OrgRole::Member)).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].organization_id(),
            &test_org_caller().organization_id()
        );
    }

    /// A signed-out caller must authenticate before listing cloud connections.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_with(
            ours_and_theirs(),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents reading the connection list.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = list_with(
            ours_and_theirs(),
            FakeOrgActors::refusing(Refusal::Forbidden),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner's key scoped only to viewing tenants cannot list the
    /// organization's cloud connections.
    #[test]
    fn a_key_without_the_view_right_is_refused() {
        let scopes = vec![Scope::new("org:tenants:view").unwrap()];

        let result = list_with(
            ours_and_theirs(),
            FakeOrgActors::through_key(OrgRole::Owner, scopes),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
