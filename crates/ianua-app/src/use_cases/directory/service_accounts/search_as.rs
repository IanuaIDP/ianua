//! Search as service account: the users and groups an application bound as
//! a service account may read.
//!
//! LDAP keeps a bind for the whole connection, so every search reads the
//! account again: a secret rotated, a scope narrowed or an account switched
//! off since the bind stops the next search. A search is answered only
//! under a base its scope covers, so everything it returns lies in a
//! subtree the account was given, and only in the tenant it bound to.
//!
//! Each search is recorded, a refused one too, as a person's search is: a
//! secret leaked from an application's configuration is a way to export
//! the directory.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::account::DirectoryServiceAccount;
use ianua_domain::domains::authentication::directory_service::scope::BaseDn;
use ianua_domain::domains::authentication::operations::directory_attempt::ServiceSearchAttempt;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::DirectoryServiceAccountStore;
use crate::use_case::Command;
use crate::use_cases::directory::DirectoryListing;
use crate::use_cases::directory::listing::{EntryPorts, ensure_aimed_at_bind};
use crate::use_cases::directory::principal::DirectoryBase;
use crate::use_cases::directory::service_accounts::service_principal::ServiceAccountPrincipal;

/// What a service account searches.
pub struct ServiceSearchRequest {
    /// The organization and tenant the search's DN names.
    pub base: DirectoryBase,
    /// The subtree searched, by its DN.
    pub search_base: BaseDn,
}

/// The ports [`SearchAsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SearchAsPorts {
    /// The tenant's service accounts, read again for every search.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// Reads the tenant's users and groups.
    pub entries: EntryPorts,
}

/// Reads the directory for an application bound as a service account.
pub struct SearchAsUseCase {
    ports: SearchAsPorts,
}

impl SearchAsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SearchAsPorts) -> Self {
        Self { ports }
    }

    /// The account `principal` bound as, read now, while its bind still
    /// counts.
    async fn still_bound(
        &self,
        principal: &ServiceAccountPrincipal,
    ) -> Result<DirectoryServiceAccount<ResolvedTenant>, AppError> {
        let account = self
            .ports
            .accounts
            .find_by_id(principal.tenant(), principal.account())
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)?;
        if !principal.bind().still_admits(&account) {
            return Err(AppError::Unauthenticated);
        }
        Ok(account)
    }
}

impl Command for SearchAsUseCase {
    type Caller = ServiceAccountPrincipal;
    type Input = ServiceSearchRequest;
    type Output = Result<DirectoryListing, AppError>;

    /// The users and groups of the tenant `principal` bound in, for a search
    /// under `request`'s base.
    ///
    /// A search records `authentication.directory_service_search_performed`
    /// with how many entries it returned, never the entries; one refused
    /// for where it is aimed records
    /// `authentication.directory_service_search_denied`. Both are recorded
    /// as done by the system, which acts for an application, in the tenant
    /// bound to.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the account is gone, switched off,
    ///   or its secret changed since the bind.
    /// - `AppError::Forbidden` when the search is aimed outside the part of
    ///   the directory the bind named, or under a base the account's scope
    ///   does not cover.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        principal: &ServiceAccountPrincipal,
        auditor: &RequestAuditor,
        request: ServiceSearchRequest,
    ) -> Result<DirectoryListing, AppError> {
        let account = self.still_bound(principal).await?;
        let tenant = principal.tenant();
        let mut trail = ServiceSearchAttempt::by(&account);
        let listing = match ensure_reads(principal, &account, &request) {
            Ok(()) => self.ports.entries.listing(tenant).await,
            Err(refused) => Err(refused),
        };
        match &listing {
            Ok(read) => trail.record_search(read.users.len(), read.groups.len()),
            Err(AppError::Forbidden(_)) => trail.record_denial(),
            Err(_) => {}
        }
        auditor
            .with_organization(principal.organization())
            .with_tenant(**tenant)
            .dispatch_by(&ActorRef::System, trail.take_events(tenant))
            .await
            .or_internal()?;
        listing
    }
}

/// Refuses a search aimed outside the part of the directory `principal`
/// bound to, or under a base `account`'s scope does not cover.
fn ensure_reads(
    principal: &ServiceAccountPrincipal,
    account: &DirectoryServiceAccount<ResolvedTenant>,
    request: &ServiceSearchRequest,
) -> Result<(), AppError> {
    ensure_aimed_at_bind(principal.base(), &request.base)?;
    principal
        .bind()
        .ensure_may_read(account, request.search_base.as_str())
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{DirectoryServiceAccountId, TenantSlug, UserId};

    use super::*;
    use crate::test_support::directory_service::{
        FakeServiceAccountStore, PEOPLE_DN, acme_base, jira_bound, test_service_account,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::tenant::cfg;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Harness {
        accounts: Arc<FakeServiceAccountStore>,
        id: DirectoryServiceAccountId,
        principal: ServiceAccountPrincipal,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Harness {
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Jira, with read-only access under the people subtree, bound.
    fn bound() -> Harness {
        let id = DirectoryServiceAccountId::new();
        let jira =
            test_service_account(id, DirectoryAccess::ReadOnly, ServiceAccountStatus::Active);
        let tenant = test_ctx().tenant();
        let accounts = Arc::new(FakeServiceAccountStore::holding(&tenant, [jira]));
        let principal = jira_bound(accounts.clone());
        Harness {
            accounts,
            id,
            principal,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn search(h: &Harness, request: ServiceSearchRequest) -> Result<DirectoryListing, AppError> {
        let users = FakeUserStore::empty();
        users.add(stored_user(
            UserId::new(),
            "ann@acme.test",
            UserStatus::Active,
        ));
        let use_case = SearchAsUseCase::new(SearchAsPorts {
            accounts: h.accounts.clone(),
            entries: EntryPorts {
                users: Arc::new(users),
                ..EntryPorts::fakes()
            },
        });
        block_on(use_case.execute(&h.principal, &test_auditor(h.audit.clone()), request))
    }

    fn under(dn: &str) -> ServiceSearchRequest {
        ServiceSearchRequest {
            base: acme_base(),
            search_base: BaseDn::new(dn).unwrap(),
        }
    }

    /// Jira searches the people subtree it was given. It reads Acme's
    /// users, and the search is recorded.
    #[test]
    fn a_search_under_the_scope_reads_the_directory() {
        let h = bound();

        let listing = search(&h, under(PEOPLE_DN)).unwrap();

        assert_eq!(listing.users.len(), 1);
        assert_eq!(
            h.recorded(),
            ["authentication.directory_service_search_performed"]
        );
    }

    /// Searching above Jira's granted subtree is forbidden and records
    /// a denied directory search.
    #[test]
    fn a_search_above_the_scope_is_refused() {
        let h = bound();

        let result = search(&h, under("dc=acme,dc=test"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            h.recorded(),
            ["authentication.directory_service_search_denied"]
        );
    }

    /// Disabling Jira after it binds makes the next search on that
    /// connection fail authentication.
    #[test]
    fn a_switched_off_account_reads_nothing() {
        let h = bound();
        let off = test_service_account(
            h.id,
            DirectoryAccess::ReadOnly,
            ServiceAccountStatus::Disabled,
        );
        block_on(h.accounts.save(&test_ctx().tenant(), &off)).unwrap();

        let result = search(&h, under(PEOPLE_DN));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Jira's bind to Acme cannot search Globex, even with a search base
    /// covered by Jira's scope.
    #[test]
    fn a_search_aimed_at_another_tenant_is_refused() {
        let h = bound();
        let request = ServiceSearchRequest {
            base: DirectoryBase {
                tenant: TenantSlug::new("globex", &cfg().slug).unwrap(),
                ..acme_base()
            },
            search_base: BaseDn::new(PEOPLE_DN).unwrap(),
        };

        let result = search(&h, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
