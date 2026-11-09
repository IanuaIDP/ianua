//! The zone behind a delegated domain, which every record operation opens
//! the same way.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::dns_zone::ZonePolicy;
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, RegisteredDomain,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{DomainId, DomainName, TenantId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::domain::{DnsZoneWriter, RegisteredDomainStore};
use crate::use_cases::domain::lookup::existing_domain;

/// The ports every DNS record operation needs.
#[derive(ianua_macros::Fakes)]
pub struct ZonePorts {
    /// Finds the domain a zone belongs to.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Reads and writes the zone itself.
    pub dns_zones: Arc<dyn DnsZoneWriter>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A zone the caller's tenant holds, and the rules for changing it.
///
/// Made only by [`DelegatedZone::resolve`] and
/// [`DelegatedZone::resolve_for_change`]. Holding one means the domain
/// exists, belongs to the caller's tenant and is delegated, so nothing
/// downstream checks any of that again.
pub(crate) struct DelegatedZone {
    tenant: TenantId,
    hostname: DomainName,
    policy: ZonePolicy,
}

impl DelegatedZone {
    /// The zone behind `domain_id` and the policy governing it, for reading.
    ///
    /// # Errors
    ///
    /// - [`AppError::NotFound`] if the tenant has no such domain.
    /// - [`AppError::Conflict`] if the domain is tenant-managed. Its records
    ///   live at the tenant's own provider, and accepting writes here would
    ///   reach no resolver.
    /// - [`AppError::Conflict`] if the domain is a wildcard. It has no zone
    ///   of its own, it is a record inside its parent's.
    /// - [`AppError::Internal`] on persistence failure.
    pub(crate) async fn resolve(
        ports: &ZonePorts,
        caller: &CallerContext,
        domain_id: &DomainId,
    ) -> Result<Self, AppError> {
        let domain =
            existing_domain(ports.domain_store.as_ref(), &caller.tenant(), domain_id).await?;
        Self::of(caller.tenant_id(), &domain)
    }

    /// The zone behind `domain_id`, for changing its records.
    ///
    /// The zone exists from registration so the nameserver check can be
    /// answered, but nobody fills it before proving they hold the name.
    /// Records staged under a name the tenant may not own would be served
    /// the moment anything marked it verified.
    ///
    /// # Errors
    ///
    /// Everything [`DelegatedZone::resolve`] returns, and
    /// [`AppError::Conflict`] if the domain is not verified yet.
    pub(crate) async fn resolve_for_change(
        ports: &ZonePorts,
        caller: &CallerContext,
        domain_id: &DomainId,
    ) -> Result<Self, AppError> {
        let domain =
            existing_domain(ports.domain_store.as_ref(), &caller.tenant(), domain_id).await?;
        let zone = Self::of(caller.tenant_id(), &domain)?;
        if domain.verification_status() != VerificationStatus::Verified {
            return Err(AppError::Conflict(message!(
                "domain-is-not-verified-yet-its-records",
                format!(
                    "{} is not verified yet; its records can be changed once the \
                 delegation is confirmed",
                    domain.domain().as_str()
                )
            )));
        }
        Ok(zone)
    }

    fn of(tenant: TenantId, domain: &RegisteredDomain<ResolvedTenant>) -> Result<Self, AppError> {
        if domain.connection() != DomainConnection::Delegated {
            return Err(AppError::Conflict(message!(
                "domain-is-managed-at-your-own-dns",
                format!(
                    "{} is managed at your own DNS provider, so its records are \
                 not ours to change; delegate it to us to edit them here",
                    domain.domain().as_str()
                )
            )));
        }
        if let Some(parent) = domain.domain().wildcard_parent() {
            return Err(AppError::Conflict(message!(
                "domain-has-no-zone-of-its-own",
                format!(
                    "{} has no zone of its own; a wildcard is a record inside its \
                 parent's zone, so manage it under {parent}",
                    domain.domain().as_str()
                )
            )));
        }
        Ok(Self {
            tenant,
            hostname: domain.domain().clone(),
            policy: ZonePolicy::new(tenant, domain.domain().clone()),
        })
    }

    /// The tenant holding the zone.
    #[must_use]
    pub(crate) fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The delegated hostname, which is the zone's apex.
    #[must_use]
    pub(crate) fn hostname(&self) -> &DomainName {
        &self.hostname
    }

    /// What the tenant may change inside it.
    #[must_use]
    pub(crate) fn policy(&self) -> &ZonePolicy {
        &self.policy
    }
}
