//! Handing a domain from one tenant to another of the same organization.
//!
//! The giving tenant offers it and the receiving tenant accepts it, through
//! [`HandoverOffer`](crate::domains::tenant::custom_domains::handover_offer::HandoverOffer).

use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::lifecycle::Tenant;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::DomainName;

/// A domain leaving one tenant for another.
#[derive(Debug, Clone, Copy)]
pub struct DomainHandover<'a> {
    /// The tenant that holds it now.
    pub from: &'a Tenant,
    /// The tenant it goes to.
    pub to: &'a Tenant,
    /// The registered name whose ownership will move between the tenants.
    pub domain: &'a DomainName,
}

impl DomainHandover<'_> {
    /// Refuses a handover the person may not make, or one that would leave
    /// a tenant routing a name it no longer holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   giving tenant's domains.
    /// - [`DomainError::InvalidTransition`] when either tenant is closed.
    /// - [`DomainError::Conflict`] when both are one tenant, when they belong
    ///   to different organizations, or when the domain is the giving
    ///   tenant's primary domain.
    pub fn ensure_allowed(&self, by: TenantControl<'_>) -> Result<(), DomainError> {
        self.from.ensure_changeable(by, TenantArea::Domains)?;
        self.ensure_still_possible()
    }

    /// Refuses a handover that would leave a tenant routing a name it no
    /// longer holds, whoever asks.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when either tenant is closed.
    /// - [`DomainError::Conflict`] when both are one tenant, when they belong
    ///   to different organizations, or when the domain is the giving
    ///   tenant's primary domain.
    pub fn ensure_still_possible(&self) -> Result<(), DomainError> {
        self.ensure_giver_open()?;
        self.ensure_receiver_open()?;
        self.ensure_between_siblings()?;
        if self.from.primary_domain() == Some(self.domain) {
            return Err(DomainError::conflict(message!(
                "tenant-is-the-tenant-s-primary-domain",
                format!(
                    "{} is the tenant's primary domain; choose another before handing it over",
                    self.domain
                )
            )));
        }
        Ok(())
    }

    /// Refuses a giving tenant that is suspended, archived or deleted. A
    /// tenant the platform froze keeps what it holds until it is let go.
    fn ensure_giver_open(&self) -> Result<(), DomainError> {
        if self.from.status().is_open() {
            return Ok(());
        }
        Err(DomainError::invalid_transition(message!(
            "tenant-a-tenant-cannot-give-a-domain",
            format!("a {} tenant cannot give a domain away", self.from.status())
        )))
    }

    /// Refuses a receiving tenant that is suspended, archived or deleted.
    fn ensure_receiver_open(&self) -> Result<(), DomainError> {
        if self.to.status().is_open() {
            return Ok(());
        }
        Err(DomainError::invalid_transition(message!(
            "tenant-a-tenant-cannot-receive-a-domain",
            format!("a {} tenant cannot receive a domain", self.to.status())
        )))
    }

    /// Refuses a handover to the same tenant, or across organizations.
    fn ensure_between_siblings(&self) -> Result<(), DomainError> {
        if self.from.id() == self.to.id() {
            return Err(DomainError::conflict(message!(
                "tenant-a-domain-is-handed-to-another",
                "a domain is handed to another tenant, not to the one holding it"
            )));
        }
        if self.from.organization_id() != self.to.organization_id() {
            return Err(DomainError::conflict(message!(
                "tenant-a-domain-moves-only-between-tenants",
                "a domain moves only between tenants of one organization"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::{
        ADMIN, acme_params, active, holding, person, proved_domain,
    };
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::types::{ActedBy, Setting};

    fn sibling_of(tenant: &Tenant) -> Tenant {
        let mut sibling = Tenant::provision(
            ProvisionTenantParams {
                organization_id: *tenant.organization_id(),
                ..acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap();
        sibling.activate(ActedBy::Platform).unwrap();
        sibling
    }

    fn domain() -> DomainName {
        DomainName::new("shop.acme.com").unwrap()
    }

    /// Acme hands `shop.acme.com` from its staging tenant to production.
    /// It is allowed.
    #[test]
    fn a_domain_moves_between_two_open_tenants_of_one_organization() {
        let ann = person("ann@acme.test");
        let staging = active();
        let production = sibling_of(&staging);
        let name = domain();

        let handover = DomainHandover {
            from: &staging,
            to: &production,
            domain: &name,
        };

        assert!(
            handover
                .ensure_allowed(holding(&ann, &staging, ADMIN))
                .is_ok()
        );
    }

    /// A tenant administrator cannot hand a domain to a tenant in another
    /// organization.
    #[test]
    fn a_domain_never_crosses_organizations() {
        let eve = person("eve@evil.test");
        let hers = active();
        let theirs = active();
        let name = domain();

        let handover = DomainHandover {
            from: &hers,
            to: &theirs,
            domain: &name,
        };

        assert!(matches!(
            handover.ensure_allowed(holding(&eve, &hers, ADMIN)),
            Err(DomainError::Conflict(_))
        ));
    }

    /// An archived sibling tenant cannot receive a domain from an active tenant.
    #[test]
    fn a_closed_tenant_receives_no_domain() {
        let ann = person("ann@acme.test");
        let staging = active();
        let mut archived = sibling_of(&staging);
        archived.archive(ActedBy::Platform).unwrap();
        let name = domain();

        let handover = DomainHandover {
            from: &staging,
            to: &archived,
            domain: &name,
        };

        assert!(matches!(
            handover.ensure_allowed(holding(&ann, &staging, ADMIN)),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A tenant cannot hand its primary domain to a sibling tenant.
    #[test]
    fn the_primary_domain_is_not_handed_away() {
        let ann = person("ann@acme.test");
        let mut production = active();
        let staging = sibling_of(&production);
        let owned = proved_domain(&production, "shop.acme.com");
        production
            .change_primary_domain(holding(&ann, &production, ADMIN), Setting::Set(owned))
            .unwrap();
        let name = domain();

        let handover = DomainHandover {
            from: &production,
            to: &staging,
            domain: &name,
        };

        assert!(matches!(
            handover.ensure_allowed(holding(&ann, &production, ADMIN)),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A caller without the right to change domains cannot authorize a handover.
    #[test]
    fn handing_over_a_domain_needs_the_right_for_domains() {
        let sam = person("sam@acme.test");
        let staging = active();
        let production = sibling_of(&staging);
        let name = domain();

        let handover = DomainHandover {
            from: &staging,
            to: &production,
            domain: &name,
        };

        assert!(matches!(
            handover.ensure_allowed(holding(&sam, &staging, &[])),
            Err(DomainError::Forbidden(_))
        ));
    }
}
