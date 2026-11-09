//! Who takes a platform action on an organization: one of its members, or
//! the platform through an operator.
//!
//! On the organization plane operators keep only platform actions: the
//! status of an organization or a member, adding and removing tenants,
//! withdrawing invitations and grants, revoking keys and sessions. Every
//! other change is a member's, and its use case takes an [`OrgCaller`]
//! alone. A use case serving both resolves the caller here and lets the
//! domain decide as whoever it turned out to be.

use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActedBy, ActorRef, OrganizationId};

use crate::acting::organization::OrgActor;
use crate::acting::{OperatorAuthorities, OrgActors};
use crate::context::{OperatorCaller, OrgCaller};
use crate::error::AppError;
use crate::ports::organization::OrganizationStore;
use crate::use_cases::organization::lookup::existing_organization;

/// Who asks for a platform action on an organization.
pub enum OrganizationSteward {
    /// A member of the organization.
    Member(OrgCaller),
    /// A platform operator, acting for the platform.
    Platform(OperatorCaller),
}

/// Where a steward is resolved from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization) struct StewardSources<'a> {
    /// Who acts on an organization.
    pub(in crate::use_cases::organization) org_actors: &'a dyn OrgActors,
    /// What an operator may do on the platform.
    pub(in crate::use_cases::organization) operators: &'a dyn OperatorAuthorities,
    /// Organizations, for the one an operator names.
    pub(in crate::use_cases::organization) organizations: &'a dyn OrganizationStore,
}

/// A steward as the stored records prove them, with the organization they
/// act on, loaded fresh.
pub(in crate::use_cases::organization) struct Stewarding {
    organization: Organization,
    by: Steward,
}

/// Who the steward turned out to be.
enum Steward {
    /// A member, with what they act through.
    Member(Box<OrgActor>),
    /// The platform, through an operator acting now.
    Platform(OperatorAuthority),
}

impl Stewarding {
    /// `caller` acting on the organization `named`, worked out from the
    /// stored records. A member reaches only their own organization.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the credential is someone else's, or the
    ///   operator is disabled.
    /// - `AppError::NotFound` when there is no such organization, or a
    ///   member names one other than their own.
    /// - `AppError::Internal` when a store fails.
    pub(in crate::use_cases::organization) async fn resolve(
        sources: StewardSources<'_>,
        caller: &OrganizationSteward,
        named: &OrganizationId,
    ) -> Result<Self, AppError> {
        match caller {
            OrganizationSteward::Member(member) => {
                let (organization, actor) = sources.org_actors.actor(member).await?;
                if organization.id() != named {
                    return Err(AppError::NotFound(message!(
                        "authentication-organization-not-found",
                        "organization not found"
                    )));
                }
                Ok(Self {
                    organization,
                    by: Steward::Member(Box::new(actor)),
                })
            }
            OrganizationSteward::Platform(operator) => {
                let authority = sources.operators.authority(operator).await?;
                let organization = existing_organization(sources.organizations, named).await?;
                Ok(Self {
                    organization,
                    by: Steward::Platform(authority),
                })
            }
        }
    }

    /// The organization acted on.
    pub(in crate::use_cases::organization) fn organization(&self) -> &Organization {
        &self.organization
    }

    /// What `change` to the organization gives back, with the domain
    /// deciding as this steward.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the member's session no longer
    ///   passes its check.
    /// - The error the domain refuses `change` with.
    pub(in crate::use_cases::organization) fn change_organization<T>(
        &mut self,
        change: impl FnOnce(&mut Organization, ActedBy<OrgControl<'_>>) -> Result<T, DomainError>,
    ) -> Result<T, AppError> {
        let by = acting_as(&self.by)?;
        change(&mut self.organization, by).map_err(AppError::from_domain)
    }

    /// What the organization raised while this steward changed it, taken
    /// once it is saved.
    pub(in crate::use_cases::organization) fn organization_raised(&mut self) -> Vec<DomainEvent> {
        self.organization.take_events()
    }

    /// What `decision` gives back about a record of the organization, such
    /// as a member, key or invitation, with the domain deciding as this
    /// steward.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the member's session no longer
    ///   passes its check.
    /// - The error the domain refuses `decision` with.
    pub(in crate::use_cases::organization) fn decide<T>(
        &self,
        decision: impl FnOnce(ActedBy<OrgControl<'_>>) -> Result<T, DomainError>,
    ) -> Result<T, AppError> {
        decision(acting_as(&self.by)?).map_err(AppError::from_domain)
    }

    /// The steward, as the actor an audit record names.
    pub(in crate::use_cases::organization) fn audit_actor(&self) -> ActorRef {
        match &self.by {
            Steward::Member(actor) => ActorRef::OrgUser(*actor.member().id()),
            Steward::Platform(authority) => authority.actor(),
        }
    }
}

/// `by` as the domain names who acts: the member's control, or the
/// platform.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the member's session no longer passes
///   its check.
fn acting_as(by: &Steward) -> Result<ActedBy<OrgControl<'_>>, AppError> {
    match by {
        Steward::Member(actor) => Ok(ActedBy::By(actor.control()?)),
        Steward::Platform(_) => Ok(ActedBy::Platform),
    }
}
