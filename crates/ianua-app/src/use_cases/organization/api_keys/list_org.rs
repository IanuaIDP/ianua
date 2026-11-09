//! Listing the organization's API keys, revoked ones included.

use std::sync::Arc;

use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::domains::organization::members::permission::{OrgApiKeyAction, OrgPermission};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::organization::{OrgApiKeySortField, OrgApiKeyStore};
use crate::use_case::Query;

/// Which page of the organization's API keys to return, in what order.
pub struct ListOrgRequest {
    /// The fields and directions to order by.
    pub sort: SortOrder<OrgApiKeySortField>,
    /// Which page of the ordered keys to return.
    pub page: PageRequest,
}

/// The ports [`ListOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOrgPorts {
    /// Where the organization's keys are kept.
    pub key_store: Arc<dyn OrgApiKeyStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the API keys of the caller's organization.
pub struct ListOrgUseCase {
    ports: ListOrgPorts,
}

impl ListOrgUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOrgPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListOrgUseCase {
    type Caller = OrgCaller;
    type Input = ListOrgRequest;
    type Output = Result<Page<OrgApiKey>, AppError>;

    /// The page of the keys of `caller`'s organization `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the
    ///   organization's keys.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        caller: &OrgCaller,
        request: ListOrgRequest,
    ) -> Result<Page<OrgApiKey>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::ApiKeys(OrgApiKeyAction::View),
            )
            .map_err(AppError::from_domain)?;
        self.ports
            .key_store
            .list_by_org(organization.id(), &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::api_key::MintedThrough;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OrgUserId, OrganizationId};

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{FakeOrgApiKeyStore, stored_org_api_key};
    use crate::test_support::{block_on, test_org_caller};

    fn keys_named(organization_id: OrganizationId, names: &[&str]) -> Arc<FakeOrgApiKeyStore> {
        Arc::new(FakeOrgApiKeyStore::holding(names.iter().map(|name| {
            stored_org_api_key(
                organization_id,
                OrgUserId::new(),
                name,
                MintedThrough::Session,
            )
        })))
    }

    fn list_with(
        keys: Arc<FakeOrgApiKeyStore>,
        actors: FakeOrgActors,
        sort: SortOrder<OrgApiKeySortField>,
    ) -> Result<Page<OrgApiKey>, AppError> {
        let uc = ListOrgUseCase::new(ListOrgPorts {
            key_store: keys,
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(
            &test_org_caller(),
            ListOrgRequest {
                sort,
                page: PageRequest::default(),
            },
        ))
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    /// Olivia, an owner, lists Acme's keys. She sees all three.
    #[test]
    fn lists_all_keys_for_org() {
        let keys = keys_named(acme(), &["alpha", "bravo", "charlie"]);

        let page = list_with(
            keys,
            FakeOrgActors::in_role(OrgRole::Owner),
            SortOrder::default(),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
    }

    /// Olivia lists the keys by name, last first. Charlie leads and alpha
    /// trails.
    #[test]
    fn sorts_by_name_descending() {
        let keys = keys_named(acme(), &["alpha", "bravo", "charlie"]);
        let sort = SortOrder::single(Sort::descending(OrgApiKeySortField::Name));

        let page = list_with(keys, FakeOrgActors::in_role(OrgRole::Owner), sort).unwrap();

        assert_eq!(page.items[0].name().as_str(), "charlie");
        assert_eq!(page.items[2].name().as_str(), "alpha");
    }

    /// Another organization's keys never show in Acme's list.
    #[test]
    fn another_organizations_keys_are_not_listed() {
        let keys = keys_named(OrganizationId::new(), &["foreign"]);

        let page = list_with(
            keys,
            FakeOrgActors::in_role(OrgRole::Owner),
            SortOrder::default(),
        )
        .unwrap();

        assert_eq!(page.items.len(), 0);
    }

    /// A plain member cannot list the organization's stored keys.
    #[test]
    fn a_plain_member_is_refused() {
        let keys = keys_named(acme(), &["alpha"]);

        let result = list_with(
            keys,
            FakeOrgActors::in_role(OrgRole::Member),
            SortOrder::default(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before listing keys.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_with(
            keys_named(acme(), &["alpha"]),
            FakeOrgActors::refusing(Refusal::SignedOut),
            SortOrder::default(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents reading the key list.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = list_with(
            keys_named(acme(), &["alpha"]),
            FakeOrgActors::refusing(Refusal::Forbidden),
            SortOrder::default(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
