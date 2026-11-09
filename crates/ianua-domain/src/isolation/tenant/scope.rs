use crate::types::{TenantId, TenantSlug};

/// Proof that the current operation is scoped to a specific tenant.
///
/// Every tenant entity (`User<T>`, `Session<T>`, `Role<T>`) is parameterized
/// by `T: TenantScope`, which keeps it apart from organization records. It
/// does not keep one tenant's entity apart from another's. Every tenant is
/// [`ResolvedTenant`], so that separation happens at run time. The
/// application picks the tenant once, when it resolves the request. The
/// database's row-level security then holds every query to that tenant.
///
/// The only implementor is [`ResolvedTenant`].
pub trait TenantScope: crate::isolation::SecurityScope {
    /// The id stores filter by, as in `WHERE tenant_id = $1`.
    fn tenant_id(&self) -> &TenantId;

    /// The URL-safe slug used in subdomains and paths.
    fn tenant_slug(&self) -> &TenantSlug;
}

/// A tenant resolved from an incoming request, by subdomain, path or custom
/// domain.
///
/// The tenant resolver middleware builds it. So does an application use
/// case that loads the tenant itself, for a flow with no host or path to
/// resolve it from. Domain code receives it as a type parameter and never
/// builds one.
///
/// It says which tenant, not whether the tenant is open. What a suspended
/// or archived tenant may still do is each operation's own rule, read from
/// the tenant itself. An organization may still reactivate it, for example.
#[derive(Debug, Clone)]
pub struct ResolvedTenant {
    id: TenantId,
    slug: TenantSlug,
}

impl ResolvedTenant {
    /// Builds a resolved tenant from data loaded from the database or cache.
    #[must_use]
    pub fn new(id: TenantId, slug: TenantSlug) -> Self {
        Self { id, slug }
    }
}

impl crate::isolation::SecurityScope for ResolvedTenant {}

impl TenantScope for ResolvedTenant {
    fn tenant_id(&self) -> &TenantId {
        &self.id
    }

    fn tenant_slug(&self) -> &TenantSlug {
        &self.slug
    }
}
