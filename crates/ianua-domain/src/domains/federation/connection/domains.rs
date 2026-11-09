//! The email domains a connection may vouch for.
//!
//! A provider vouching for an address makes it a verified address here, and
//! that proof travels: tokens this platform issues say the address is
//! verified, and an organization's tenants link accounts by it. So a
//! connection vouches only for domains its tenant, or another tenant of the
//! same organization, proved it owns.

use crate::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DomainName, Setting, TenantId};

/// The email domains a connection may vouch for, and the one that sends
/// people straight to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDomains {
    /// The domains the connection may vouch for, each proved by a tenant
    /// and listed once.
    pub allowed: Vec<OwnedDomain>,
    /// The allowed domain whose addresses are sent to this connection
    /// without asking.
    pub hint: Setting<DomainName>,
}

/// The tenants whose proved domains a connection may bind: its own, and the
/// other tenants of the same organization.
///
/// One company often runs a production and a staging tenant. Both sign
/// their people in through the same provider for the same domain, while
/// only one of them holds the DNS proof.
#[derive(Debug, Clone, Copy)]
pub struct DomainHolders<'a> {
    /// The tenant the connection belongs to.
    pub this_tenant: TenantId,
    /// The other tenants of its organization, as the organization lists
    /// them now.
    pub organization_tenants: &'a [TenantId],
}

impl DomainHolders<'_> {
    /// Refuses a domain proved by a tenant outside this organization.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `owned` was proved by a tenant of
    ///   another organization.
    pub(crate) fn ensure_may_bind(&self, owned: &OwnedDomain) -> Result<(), DomainError> {
        let holder = owned.tenant();
        if *holder == self.this_tenant || self.organization_tenants.contains(holder) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "federation-was-proved-by-a-tenant-outside",
            format!(
                "{} was proved by a tenant outside this organization",
                owned.domain().as_str()
            )
        )))
    }
}

/// Whether `hint` is unset or one of `allowed`.
pub(crate) fn hint_is_allowed(hint: &Setting<DomainName>, allowed: &[DomainName]) -> bool {
    hint.value().is_none_or(|hint| allowed.contains(hint))
}

/// The tenant every test connection belongs to.
#[cfg(test)]
const TEST_TENANT: uuid::Uuid = uuid::Uuid::from_u128(5);

/// Proof that `tenant` owns `name`, for tests that bind domains to a
/// connection.
#[cfg(test)]
pub(crate) fn owned_domain_of(tenant: TenantId, name: &str) -> OwnedDomain {
    OwnedDomain::new(
        tenant,
        DomainName::new(name).expect("a test passes a valid domain name"),
    )
}

/// Proof that the test connection's own tenant owns `name`.
#[cfg(test)]
pub(crate) fn owned_domain(name: &str) -> OwnedDomain {
    owned_domain_of(TenantId::from_uuid(TEST_TENANT), name)
}

/// The test connection's own tenant, in an organization of its own.
#[cfg(test)]
pub(crate) fn own_tenant() -> DomainHolders<'static> {
    DomainHolders {
        this_tenant: TenantId::from_uuid(TEST_TENANT),
        organization_tenants: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acme's staging tenant binds `acme.com`, which its production tenant
    /// proved. It is allowed. Globex's tenant proved `globex.com`, and Fay
    /// in Acme cannot bind it.
    #[test]
    fn a_domain_proved_in_the_same_organization_may_be_bound() {
        let staging = TenantId::new();
        let production = TenantId::new();
        let holders = DomainHolders {
            this_tenant: staging,
            organization_tenants: &[production],
        };

        let from_production = holders.ensure_may_bind(&owned_domain_of(production, "acme.com"));
        let from_globex = holders.ensure_may_bind(&owned_domain_of(TenantId::new(), "globex.com"));

        assert!(from_production.is_ok());
        assert!(matches!(from_globex, Err(DomainError::Forbidden(_))));
    }
}
