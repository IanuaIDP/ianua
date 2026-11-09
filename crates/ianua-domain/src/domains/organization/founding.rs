//! Proof that an organization was just created, which makes its founder its
//! first owner.

use crate::domains::organization::billing::plan::OrganizationPlan;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::OrganizationId;

/// Proof that an organization was just created, which makes its founder its
/// first owner, once.
///
/// Only [`Organization::create`](crate::domains::organization::lifecycle::Organization::create)
/// and [`Organization::create_installation`](crate::domains::organization::lifecycle::Organization::create_installation)
/// make one, for the organization they create, and making the owner uses
/// it up. Without it, any call that says it founds makes an owner of an
/// organization that already has owners, such as a retried sign-up naming
/// Acme.
#[derive(Debug)]
pub struct Founding {
    organization_id: OrganizationId,
    founds: Founded,
}

/// What a founding made: an ordinary organization, or an installation's
/// own one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Founded {
    Organization,
    Installation,
}

impl Founding {
    /// The founding of `organization_id` on `plan`: an installation's own
    /// organization on the self-hosted plan, an ordinary one otherwise.
    pub(crate) fn of(organization_id: OrganizationId, plan: OrganizationPlan) -> Self {
        let founds = match plan {
            OrganizationPlan::SelfHosted => Founded::Installation,
            OrganizationPlan::Free
            | OrganizationPlan::Starter
            | OrganizationPlan::Business
            | OrganizationPlan::Custom => Founded::Organization,
        };
        Self {
            organization_id,
            founds,
        }
    }

    /// The organization that was created.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Refuses unless this founded an installation's own organization.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] for an ordinary organization.
    pub(crate) fn ensure_installation(&self) -> Result<(), DomainError> {
        match self.founds {
            Founded::Installation => Ok(()),
            Founded::Organization => Err(DomainError::forbidden(message!(
                "organization-only-founding-an-installation-hands-its",
                "only founding an installation hands its owner a setup token"
            ))),
        }
    }
}
