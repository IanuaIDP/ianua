//! The domains a tenant has registered, for checks that ask whether a name
//! the caller gives is one the tenant has proved it owns.

use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::domain::RegisteredDomainStore;
use crate::tenancy::ScopedTenant;

/// How many of a tenant's domains a check considers.
///
/// Far above what any tenant registers; a name beyond this would be refused,
/// which is the safe direction to be wrong in.
const MAX_TENANT_DOMAINS: u32 = 500;

/// Every domain `tenant` has registered, verified or not.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(crate) async fn registered_domains(
    store: &dyn RegisteredDomainStore,
    tenant: &ScopedTenant,
) -> Result<Vec<RegisteredDomain<ResolvedTenant>>, AppError> {
    let domains = store
        .list_by_tenant(
            tenant,
            &SortOrder::default(),
            &PageRequest::first(Limit::internal(MAX_TENANT_DOMAINS)),
        )
        .await
        .or_internal()?
        .items;
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{DomainId, DomainName, TenantId};

    use super::*;
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::{block_on, test_ctx};

    fn unproved(name: &str) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: DomainName::new(name).unwrap(),
            connection: DomainConnection::SelfManaged,
            proof: DomainProof::Unproved,
            dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now(),
        })
        .unwrap()
    }

    fn store_holding(tenant: &ScopedTenant, names: &[&str]) -> FakeDomainStore {
        let store = FakeDomainStore::empty();
        for name in names {
            block_on(store.save(tenant, &unproved(name))).unwrap();
        }
        store
    }

    /// Ann's tenant registered two domains, proved or not, and both are
    /// considered.
    #[test]
    fn every_domain_the_tenant_registered_is_listed() {
        let tenant = test_ctx().tenant();
        let store = store_holding(&tenant, &["acme.com", "login.acme.com"]);

        let domains = block_on(registered_domains(&store, &tenant)).unwrap();

        assert_eq!(domains.len(), 2);
    }

    /// A tenant with no registered domains receives an empty list even when
    /// another tenant has a registration.
    #[test]
    fn another_tenants_domains_are_not_listed() {
        let store = store_holding(&test_ctx().tenant(), &["acme.com"]);
        let mallorys = ScopedTenant::for_test(TenantId::new());

        let domains = block_on(registered_domains(&store, &mallorys)).unwrap();

        assert!(domains.is_empty());
    }
}
