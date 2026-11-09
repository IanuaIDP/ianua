//! Listing every organization on the platform, for its operators.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::status::OrganizationStatus;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::organization::{OrganizationSortField, OrganizationStore};
use crate::use_case::Query;

/// Which organizations to list.
pub struct OrganizationFilter {
    /// Only organizations of this status, or every status.
    pub status: Option<OrganizationStatus>,
}

impl OrganizationFilter {
    /// Organizations of every status.
    #[must_use]
    pub fn all() -> Self {
        Self { status: None }
    }
}

/// Which organizations to list, in what order, and which page of them.
pub struct ListOrganizationsRequest {
    /// Which organizations to include.
    pub filter: OrganizationFilter,
    /// The fields and directions to order by.
    pub sort: SortOrder<OrganizationSortField>,
    /// Which page of the ordered organizations to return.
    pub page: PageRequest,
}

/// The ports [`ListOrganizationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOrganizationsPorts {
    /// Reads the platform's organization directory a page at a time.
    pub organizations: Arc<dyn OrganizationStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Lists the platform's organizations.
pub struct ListOrganizationsUseCase {
    ports: ListOrganizationsPorts,
}

impl ListOrganizationsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOrganizationsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListOrganizationsUseCase {
    type Caller = OperatorCaller;
    type Input = ListOrganizationsRequest;
    type Output = Result<Page<Organization>, AppError>;

    /// The page of organizations `request` asks for, for an operator.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or their key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the operator may not act now.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        operator: &OperatorCaller,
        request: ListOrganizationsRequest,
    ) -> Result<Page<Organization>, AppError> {
        self.ports.operator_authorities.authority(operator).await?;
        let ListOrganizationsRequest { filter, sort, page } = request;
        self.ports
            .organizations
            .list_all(filter.status, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{ActedBy, OperatorId, OrganizationId};

    use super::*;
    use crate::listing::{Limit, Sort};
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::block_on;
    use crate::test_support::notifications::operator_caller;
    use crate::test_support::organization::{org_store_with, test_org};

    fn every(page: PageRequest) -> ListOrganizationsRequest {
        ListOrganizationsRequest {
            filter: OrganizationFilter::all(),
            sort: SortOrder::default(),
            page,
        }
    }

    fn list(
        orgs: impl IntoIterator<Item = Organization>,
        request: ListOrganizationsRequest,
    ) -> Result<Page<Organization>, AppError> {
        let use_case = ListOrganizationsUseCase::new(ListOrganizationsPorts {
            organizations: org_store_with(orgs),
            ..ListOrganizationsPorts::fakes()
        });
        block_on(use_case.execute(&operator_caller(OperatorId::new()), request))
    }

    fn named(slugs: &[&str]) -> Vec<Organization> {
        slugs
            .iter()
            .map(|slug| test_org(OrganizationId::new(), slug))
            .collect()
    }

    /// Bob, an operator, lists five organizations three at a time. He gets
    /// the first three, told there are five and more to come.
    #[test]
    fn list_with_pagination() {
        let page = list(
            named(&["org0", "org1", "org2", "org3", "org4"]),
            every(PageRequest::first(Limit::new(3).unwrap())),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
        assert!(page.has_next());
    }

    /// Bob lists only active organizations, where one of two was
    /// suspended. He gets the active one.
    #[test]
    fn filter_by_active() {
        let mut orgs = named(&["active", "suspended"]);
        orgs[1]
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let request = ListOrganizationsRequest {
            filter: OrganizationFilter {
                status: Some(OrganizationStatus::Active),
            },
            ..every(PageRequest::default())
        };

        let page = list(orgs, request).unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Bob lists a platform with no organizations. The page is empty.
    #[test]
    fn no_organizations_returns_an_empty_page() {
        let page = list(Vec::new(), every(PageRequest::default())).unwrap();

        assert!(page.is_empty());
    }

    /// Bob orders the organizations by name. They come back alphabetical.
    #[test]
    fn sort_by_name_ascending_orders_results() {
        let request = ListOrganizationsRequest {
            sort: SortOrder::single(Sort::ascending(OrganizationSortField::Slug)),
            ..every(PageRequest::default())
        };

        let page = list(named(&["charlie", "alpha", "bravo"]), request).unwrap();

        let slugs: Vec<_> = page.items.iter().map(|o| o.slug().as_str()).collect();
        assert_eq!(slugs, vec!["alpha", "bravo", "charlie"]);
    }

    /// Refused operator authority prevents listing the platform's organizations.
    #[test]
    fn an_operator_turned_away_is_refused() {
        let use_case = ListOrganizationsUseCase::new(ListOrganizationsPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::Forbidden)),
            ..ListOrganizationsPorts::fakes()
        });

        let result = block_on(use_case.execute(
            &operator_caller(OperatorId::new()),
            every(PageRequest::default()),
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
