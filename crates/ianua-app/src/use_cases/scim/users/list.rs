//! List SCIM users: the tenant's users as the directory pages through them,
//! picks them by a filter, and orders them.
//!
//! A filter compares `userName`, `displayName`, `externalId`, the name's
//! parts or the enterprise fields with `eq`, `co` or `sw`, joined by `and`
//! and `or`, as RFC 7644 3.4.2.2 describes them.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::ScimAuthorities;
use crate::context::ScimCaller;
use crate::error::AppError;
use crate::ports::federation::{
    ScimPage, ScimQuery, ScimUserAttribute, ScimUserQueries, ScimUserSort, ScimWindow,
};
use crate::use_case::Query;

/// Which users to list, in which order, and which page of them.
pub struct ListScimRequest {
    /// Picks the users returned.
    pub filter: ScimQuery<ScimUserAttribute>,
    /// Orders them.
    pub sort: ScimUserSort,
    /// The page to return.
    pub page: ScimWindow,
}

/// The ports [`ListScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Finds the users a filter picks.
    pub user_queries: Arc<dyn ScimUserQueries>,
}

/// Lists a tenant's users for its directory.
pub struct ListScimUseCase {
    ports: ListScimPorts,
}

impl ListScimUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListScimPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListScimUseCase {
    type Caller = ScimCaller;
    type Input = ListScimRequest;
    type Output = Result<ScimPage<User<ResolvedTenant>>, AppError>;

    /// One page of the tenant's users the filter picks, in the order asked
    /// for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        request: ListScimRequest,
    ) -> Result<ScimPage<User<ResolvedTenant>>, AppError> {
        let ListScimRequest { filter, sort, page } = request;
        self.ports.scim_authorities.endpoint(caller).await?;
        self.ports
            .user_queries
            .find(caller.tenant(), &filter, sort, page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{TenantId, UserId};

    use super::*;
    use crate::listing::SortDirection;
    use crate::ports::federation::{ScimFilterValue, ScimOperator};
    use crate::tenancy::ScopedTenant;
    use crate::test_support::federation::FakeScimUserQueries;
    use crate::test_support::identity::stored_user;
    use crate::test_support::scim::{SignInRefusal, refused_sign_in, scim_caller, signed_in};
    use crate::test_support::{block_on, test_ctx};

    fn acme_users() -> FakeScimUserQueries {
        FakeScimUserQueries::holding(
            &test_ctx().tenant(),
            [
                stored_user(UserId::new(), "grace@acme.com", UserStatus::Active),
                stored_user(UserId::new(), "ada@acme.com", UserStatus::Active),
            ],
        )
    }

    fn use_case(
        scim_authorities: Arc<dyn ScimAuthorities>,
        users: FakeScimUserQueries,
    ) -> ListScimUseCase {
        ListScimUseCase::new(ListScimPorts {
            scim_authorities,
            user_queries: Arc::new(users),
        })
    }

    fn user_name(operator: ScimOperator, value: &str) -> ScimQuery<ScimUserAttribute> {
        ScimQuery::Compare {
            attribute: ScimUserAttribute::UserName,
            operator,
            value: ScimFilterValue::new(value).unwrap(),
        }
    }

    fn request(filter: ScimQuery<ScimUserAttribute>) -> ListScimRequest {
        ListScimRequest {
            filter,
            sort: ScimUserSort::Default,
            page: ScimWindow::new(1, 100),
        }
    }

    fn list(
        users: FakeScimUserQueries,
        request: ListScimRequest,
    ) -> ScimPage<User<ResolvedTenant>> {
        block_on(use_case(signed_in(), users).execute(&scim_caller(), request)).unwrap()
    }

    /// Okta pages through Acme's users. It sees both of them.
    #[test]
    fn every_user_is_listed() {
        let page = list(acme_users(), request(ScimQuery::All));

        assert_eq!(page.total, 2);
        assert_eq!(page.items.len(), 2);
    }

    /// Okta looks Grace up by her address before it creates her, in any
    /// case. It finds her and only her.
    #[test]
    fn a_user_is_looked_up_by_user_name() {
        let filter = user_name(ScimOperator::Equals, "Grace@Acme.com");

        let page = list(acme_users(), request(filter));

        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].email().as_str(), "grace@acme.com");
    }

    /// Entra looks for addresses starting with `ada` or containing
    /// `grace`. It finds both people, ordered by address.
    #[test]
    fn filters_join_with_or_and_order_by_an_attribute() {
        let filter = ScimQuery::Or(
            Box::new(user_name(ScimOperator::StartsWith, "ada")),
            Box::new(user_name(ScimOperator::Contains, "grace")),
        );
        let ordered = ListScimRequest {
            sort: ScimUserSort::By(ScimUserAttribute::UserName, SortDirection::Asc),
            ..request(filter)
        };

        let page = list(acme_users(), ordered);

        assert_eq!(page.total, 2);
        assert_eq!(page.items[0].email().as_str(), "ada@acme.com");
    }

    /// Both filters must hold under `and`. No address starts with `ada`
    /// and contains `grace`.
    #[test]
    fn filters_joined_with_and_must_both_hold() {
        let filter = ScimQuery::And(
            Box::new(user_name(ScimOperator::StartsWith, "ada")),
            Box::new(user_name(ScimOperator::Contains, "grace")),
        );

        let page = list(acme_users(), request(filter));

        assert_eq!(page.total, 0);
    }

    /// Okta looks for Alan, who works at Globex, not Acme. Acme has nobody
    /// with his address, so the page is empty.
    #[test]
    fn a_user_of_another_tenant_is_not_listed() {
        let globex = ScopedTenant::for_test(TenantId::new());
        let users = FakeScimUserQueries::holding(
            &globex,
            [stored_user(
                UserId::new(),
                "alan@globex.com",
                UserStatus::Active,
            )],
        );

        let page = list(
            users,
            request(user_name(ScimOperator::Equals, "alan@globex.com")),
        );

        assert_eq!(page.total, 0);
    }

    /// Every directory sign-in refusal returns unauthenticated instead of a user listing.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let use_case = use_case(scim_authorities, acme_users());

            let result = block_on(use_case.execute(&caller, request(ScimQuery::All)));

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
        }
    }
}
