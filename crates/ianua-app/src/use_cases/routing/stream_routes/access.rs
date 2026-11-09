//! Refusing stream route access that names what the tenant does not have,
//! a consumer it never made or a permission its catalogue does not declare,
//! and changing a route's policy and access together.

use std::collections::HashSet;
use std::sync::Arc;

use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::stream::access::{StreamAccess, StreamConsumers};
use ianua_domain::domains::routing::stream::{StreamPolicy, StreamRoute};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::consumers::ConsumerStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::routing::lookup::ensure_policy_permissions_declared;

/// The ports stream route access is checked against, which every use case
/// that sets access holds together.
#[derive(ianua_macros::Fakes)]
pub struct StreamAccessPorts {
    /// The tenant's consumers, which a consumer list must name.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// The tenant's permission catalogue, which a people policy's custom
    /// permission must be declared in.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
}

impl StreamAccessPorts {
    /// The stores access is checked against, lent out.
    pub(crate) fn records(&self) -> AccessRecords<'_> {
        AccessRecords {
            consumers: self.consumer_store.as_ref(),
            resource_types: self.resource_type_store.as_ref(),
        }
    }
}

/// The stores stream route access is checked against.
#[derive(Clone, Copy)]
pub(crate) struct AccessRecords<'a> {
    /// The tenant's consumers, which a consumer list must name.
    pub(crate) consumers: &'a dyn ConsumerStore,
    /// The tenant's permission catalogue, which a people policy's custom
    /// permission must be declared in.
    pub(crate) resource_types: &'a dyn ResourceTypeStore,
}

/// Refuses `access` when it names a consumer the tenant does not have, or
/// holds people to a permission no role can grant.
///
/// # Errors
///
/// - `AppError::NotFound` when a named consumer is not the tenant's.
/// - `AppError::Domain` when a required custom permission is undeclared.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn ensure_access_known(
    records: AccessRecords<'_>,
    tenant: &ScopedTenant,
    access: &StreamAccess,
) -> Result<(), AppError> {
    match access {
        StreamAccess::AnyHolder => Ok(()),
        StreamAccess::People(policy) => {
            ensure_policy_permissions_declared(records.resource_types, tenant, policy).await
        }
        StreamAccess::Consumers(named) => ensure_consumers_known(records, tenant, named).await,
    }
}

/// Changes what the wire checks and who by name may pass, whichever of the
/// two `policy` and `access` carry, in one step the domain judges whole. A
/// side left `None` stays as it is.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `by` may not update routing.
/// - [`DomainError::Validation`] when the route's protocol and the policy
///   cannot deliver the access.
pub(crate) fn change_admission(
    route: &mut StreamRoute<ResolvedTenant>,
    policy: Option<StreamPolicy>,
    access: Option<StreamAccess>,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if policy.is_none() && access.is_none() {
        return Ok(());
    }
    let policy = policy.unwrap_or_else(|| route.policy());
    let access = access.unwrap_or_else(|| route.access().clone());
    route.change_admission(policy, access, by)
}

/// Refuses a consumer list naming one the tenant does not have.
async fn ensure_consumers_known(
    records: AccessRecords<'_>,
    tenant: &ScopedTenant,
    named: &StreamConsumers,
) -> Result<(), AppError> {
    let found = records
        .consumers
        .find_by_ids(tenant, named.as_slice())
        .await
        .or_internal()?;
    let ids: HashSet<_> = found.iter().map(|consumer| *consumer.id()).collect();
    if named.as_slice().iter().any(|id| !ids.contains(id)) {
        return Err(AppError::NotFound(message!(
            "consumers-consumer-not-found",
            "consumer not found"
        )));
    }
    Ok(())
}
