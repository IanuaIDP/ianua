//! List operators: platform operators, filtered, ordered and paged.

use std::sync::Arc;

use ianua_domain::domains::operator::identity::Operator;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::operator::{OperatorFilter, OperatorSortField, OperatorStore};
use crate::use_case::Query;

/// The ports [`ListOperatorsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOperatorsPorts {
    /// Platform operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Which operators to list, in what order, and which page.
pub struct ListOperatorsRequest {
    /// Which operators to include.
    pub filter: OperatorFilter,
    /// The field and direction to order by.
    pub sort: SortOrder<OperatorSortField>,
    /// Which page of the ordered operators to return.
    pub page: PageRequest,
}

/// Lists platform operators.
pub struct ListOperatorsUseCase {
    ports: ListOperatorsPorts,
}

impl ListOperatorsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOperatorsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListOperatorsUseCase {
    type Caller = OperatorCaller;
    type Input = ListOperatorsRequest;
    type Output = Result<Page<Operator>, AppError>;

    /// One page of the operators the filter admits, in the order asked, for
    /// an operator acting now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works or
    ///   their account is disabled.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        request: ListOperatorsRequest,
    ) -> Result<Page<Operator>, AppError> {
        self.ports.operator_authorities.authority(caller).await?;
        let ListOperatorsRequest { filter, sort, page } = request;
        self.ports
            .operator_store
            .list(&filter, &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::types::OperatorId;

    use super::*;
    use crate::listing::{Limit, Sort};
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::block_on;
    use crate::test_support::operator::{FakeOperatorStore, stored_operator, test_operator_caller};

    fn active(email: &str) -> Operator {
        stored_operator(OperatorId::new(), email, OperatorStatus::Active)
    }

    fn listing(operators: impl IntoIterator<Item = Operator>) -> ListOperatorsUseCase {
        ListOperatorsUseCase::new(ListOperatorsPorts {
            operator_store: Arc::new(FakeOperatorStore::holding(operators)),
            ..ListOperatorsPorts::fakes()
        })
    }

    fn refusing(refusal: Refusal) -> ListOperatorsUseCase {
        ListOperatorsUseCase::new(ListOperatorsPorts {
            operator_store: Arc::new(FakeOperatorStore::holding([active("a@ianua.dev")])),
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(refusal)),
        })
    }

    fn request(filter: OperatorFilter, page: PageRequest) -> ListOperatorsRequest {
        ListOperatorsRequest {
            filter,
            sort: SortOrder::default(),
            page,
        }
    }

    fn list(
        uc: &ListOperatorsUseCase,
        request: ListOperatorsRequest,
    ) -> Result<Page<Operator>, AppError> {
        block_on(uc.execute(&test_operator_caller(), request))
    }

    /// The platform has five operators. Bob asks for three; he gets three
    /// and is told there are more.
    #[test]
    fn list_with_pagination() {
        let uc = listing((0..5).map(|i| active(&format!("op{i}@ianua.dev"))));

        let page = list(
            &uc,
            request(
                OperatorFilter::all(),
                PageRequest::first(Limit::new(3).unwrap()),
            ),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
        assert!(page.has_next());
    }

    /// One operator is active, one disabled. Asking for active ones lists
    /// only the first.
    #[test]
    fn filter_by_active() {
        let disabled = stored_operator(
            OperatorId::new(),
            "disabled@ianua.dev",
            OperatorStatus::Disabled,
        );
        let uc = listing([active("active@ianua.dev"), disabled]);
        let only_active = OperatorFilter {
            status: Some(OperatorStatus::Active),
        };

        let page = list(&uc, request(only_active, PageRequest::default())).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].email().as_str(), "active@ianua.dev");
    }

    /// With no operators stored, the list is empty.
    #[test]
    fn no_operators_returns_an_empty_page() {
        let uc = listing([]);

        let page = list(&uc, request(OperatorFilter::all(), PageRequest::default())).unwrap();

        assert!(page.is_empty());
    }

    /// Bob orders the operators by address. They come back alphabetically.
    #[test]
    fn sort_by_email_ascending_orders_results() {
        let uc = listing(["c@ianua.dev", "a@ianua.dev", "b@ianua.dev"].map(active));
        let sorted = ListOperatorsRequest {
            sort: SortOrder::single(Sort::ascending(OperatorSortField::Email)),
            ..request(OperatorFilter::all(), PageRequest::default())
        };

        let page = list(&uc, sorted).unwrap();

        let emails: Vec<_> = page.items.iter().map(|o| o.email().as_str()).collect();
        assert_eq!(emails, vec!["a@ianua.dev", "b@ianua.dev", "c@ianua.dev"]);
    }

    /// A disabled operator's authority refusal prevents listing platform
    /// operators.
    #[test]
    fn a_disabled_operator_is_refused() {
        let uc = refusing(Refusal::Forbidden);

        let result = list(&uc, request(OperatorFilter::all(), PageRequest::default()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An unauthenticated operator cannot list platform operators.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let uc = refusing(Refusal::SignedOut);

        let result = list(&uc, request(OperatorFilter::all(), PageRequest::default()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
