//! A directory calling a tenant's SCIM endpoint, known only by the bearer
//! token it came with.

use ianua_domain::shared::security::secret::Secret;

use crate::tenancy::ScopedTenant;

/// A directory calling a tenant's SCIM endpoint, known only by the bearer
/// token it came with.
#[derive(Debug, Clone)]
pub struct ScimCaller {
    tenant: ScopedTenant,
    bearer: Option<Secret>,
}

impl ScimCaller {
    /// A directory calling `tenant`, the tenant the request was addressed
    /// to, with `bearer`, the token from its `Authorization` header, or
    /// `None` when it sent none.
    #[must_use]
    pub fn new(tenant: ScopedTenant, bearer: Option<Secret>) -> Self {
        Self { tenant, bearer }
    }

    /// The tenant the request was addressed to.
    #[must_use]
    pub fn tenant(&self) -> &ScopedTenant {
        &self.tenant
    }

    /// The token the request came with, if it carried one.
    #[must_use]
    pub(crate) fn bearer(&self) -> Option<&Secret> {
        self.bearer.as_ref()
    }
}
