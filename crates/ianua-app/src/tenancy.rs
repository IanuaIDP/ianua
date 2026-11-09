//! Which tenant a store call is for, and where that answer came from.
//!
//! A tenant-scoped store will not take a bare [`TenantId`]. It takes a
//! [`ScopedTenant`], and every way to hold one names where the tenant came
//! from:
//!
//! - [`CallerContext::tenant`](crate::context::CallerContext::tenant): the
//!   tenant the request resolved for its authenticated caller;
//! - `ScopedTenant::from(&ResolvedTenant)`: the tenant the request's host or
//!   path resolved to, for flows that run before anyone is signed in, or,
//!   through [`ScopedTenant::from_request_host`], the tenant the gateway's
//!   routing table maps the request's host to;
//! - [`ScopedTenant::from_listening_port`]: the tenant whose stream route
//!   owns the port a connection arrived on, for the gateway's stream
//!   listeners;
//! - [`ScopedTenant::from_verified_credential`]: the tenant inside a
//!   credential this platform signed, for adapters that authenticate a caller
//!   from it;
//! - `ScopedTenant::from_service_claim`: the tenant whose egress policy
//!   alone claims the service a verified client certificate names, for the
//!   egress gateway;
//! - [`ScopedTenant::for_background`]: work that runs outside any request,
//!   a worker step, a sweep, an event handler, naming its tenant explicitly.
//!
//! Inside this crate, a use case can also scope a tenant it loaded and checked
//! itself: one from the tenant registry, one its organization owns, or one
//! an organization's linked identity reaches.
//!
//! So an id read from a request body or a message cannot reach a store by
//! accident: the code compiles only once it has gone through one of these,
//! and each is a named call that review can find.

use std::ops::Deref;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::{ResolvedTenant, TenantScope as _};
use ianua_domain::shared::events::raised::SavedFor;
use ianua_domain::types::TenantId;

/// A tenant whose data a store call may read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopedTenant(TenantId);

impl ScopedTenant {
    /// The tenant the request resolved for its caller.
    pub(crate) fn from_resolved_caller(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant a request's host resolved to in a routing table the control
    /// plane published.
    ///
    /// For the gateway, whose table maps hosts to tenant ids without the rest
    /// of the tenant: the same answer `From<&ResolvedTenant>` gives where the
    /// whole tenant is at hand. Only ever from the host the connection came
    /// in on, never from a header or a token.
    #[must_use]
    pub fn from_request_host(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant whose stream route owns the port a connection arrived
    /// on, as the directory the control plane published lists it.
    ///
    /// For the gateway's stream listeners, where the port is the routing
    /// key and no host was asked for. Only ever from the port the socket
    /// was bound for, never from a server name, a header or a token.
    #[must_use]
    pub fn from_listening_port(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant a connector's certificate names, as the platform's
    /// connector authority signed it.
    ///
    /// For the gateway's connector listener, where the link's certificate,
    /// checked against that authority at the handshake, is the routing
    /// key. Only ever from such a certificate, never from a header, a
    /// token or anything the connector sends after the handshake.
    #[must_use]
    pub fn from_connector_certificate(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// A tenant named by work that runs outside any request.
    ///
    /// For worker steps, scheduled sweeps and event handlers, whose tenant
    /// comes from the job or event they were given rather than from a caller.
    /// Never for anything a request supplied: that goes through the caller's
    /// context, which only holds the tenant the request was resolved to.
    #[must_use]
    pub fn for_background(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant named inside a credential this platform signed.
    ///
    /// For adapters that authenticate a caller from such a credential, an
    /// agent's task token, a provenance assertion. Two uses only: reading that
    /// tenant's verification keys to check the credential's signature, and
    /// acting for the caller once the signature has verified.
    #[must_use]
    pub fn from_verified_credential(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant whose egress policy alone claims the service a verified
    /// client certificate names.
    ///
    /// For the egress gateway, where the certificate is the only thing
    /// known of the caller and the stored claim says whose it is. Only ever
    /// from that claim, never from a header or an assertion the call
    /// carries.
    pub(crate) fn from_service_claim(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant whose registration at a service a delivery's address or
    /// key names, as the platform keeps it.
    ///
    /// For deliveries from integrations' services, which no person sends.
    /// Only ever to read that registration and check the delivery's
    /// signature with its secret, and to act once the signature checked
    /// out; a delivery whose signature does not check out does nothing.
    pub(crate) fn for_signed_delivery(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// The tenant a pending account connection was begun in, found by the
    /// digest of the `state` a service sent the browser back with.
    ///
    /// For the one callback address every service's app is registered with.
    /// Only ever from that stored connection, never from anything else the
    /// request carries.
    pub(crate) fn from_connection_state(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    /// A tenant the use case resolved from the tenant registry itself.
    ///
    /// For flows with no host or path for the resolver middleware to read,
    /// a sign-in naming its tenant by slug, a directory bind naming it in the
    /// DN, an organization acting on one of its own tenants, the use case
    /// loads the tenant, checks it belongs where the request says, and scopes
    /// it exactly as the resolver would have.
    pub(crate) fn from_registry(tenant: &Tenant) -> Self {
        Self::from(&ResolvedTenant::new(*tenant.id(), tenant.slug().clone()))
    }

    /// Any tenant, for tests that exercise a store or a use case directly.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }
}

impl From<&ResolvedTenant> for ScopedTenant {
    fn from(resolved: &ResolvedTenant) -> Self {
        Self(*resolved.tenant_id())
    }
}

/// The events an aggregate raised are stamped with the tenant its store
/// call was scoped to, so a record names the tenant the change was written
/// to.
impl SavedFor for ScopedTenant {
    fn saved_for(&self) -> TenantId {
        self.0
    }
}

impl Deref for ScopedTenant {
    type Target = TenantId;

    fn deref(&self) -> &TenantId {
        &self.0
    }
}
