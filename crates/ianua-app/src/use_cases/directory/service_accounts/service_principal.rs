//! Who a directory connection is bound as when an application binds with a
//! service account.

use ianua_domain::domains::authentication::directory_service::bind::ServiceAccountBind;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{DirectoryServiceAccountId, OrganizationId};

use crate::tenancy::ScopedTenant;
use crate::use_cases::directory::principal::DirectoryBase;

/// A service account a directory connection is bound as.
///
/// Only a bind makes one: its fields are private, so the LDAP adapter keeps
/// it for the connection and hands it back, but can neither make one nor
/// change what it names. It holds no rights of its own: every request reads
/// the account again, so a secret rotated, a scope narrowed or an account
/// switched off since the bind stops the next request.
#[derive(Debug)]
pub struct ServiceAccountPrincipal {
    bind: ServiceAccountBind<ResolvedTenant>,
    organization: OrganizationId,
    tenant: ScopedTenant,
    base: DirectoryBase,
}

impl ServiceAccountPrincipal {
    /// `bind`, made in `tenant` of `organization` under `base`.
    pub(in crate::use_cases::directory) fn bound(
        bind: ServiceAccountBind<ResolvedTenant>,
        organization: OrganizationId,
        tenant: ScopedTenant,
        base: DirectoryBase,
    ) -> Self {
        Self {
            bind,
            organization,
            tenant,
            base,
        }
    }

    /// The account bound as.
    #[must_use]
    pub fn account(&self) -> &DirectoryServiceAccountId {
        self.bind.account()
    }

    /// The organization the bind found under its base.
    #[must_use]
    pub fn organization(&self) -> OrganizationId {
        self.organization
    }

    /// The tenant bound in.
    #[must_use]
    pub fn tenant(&self) -> &ScopedTenant {
        &self.tenant
    }

    /// The part of the directory the bind named.
    #[must_use]
    pub fn base(&self) -> &DirectoryBase {
        &self.base
    }

    /// The bind, which decides each request against the account read
    /// again.
    pub(in crate::use_cases::directory) fn bind(&self) -> &ServiceAccountBind<ResolvedTenant> {
        &self.bind
    }
}
