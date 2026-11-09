//! Who moves a tenant through its life, worked out from the stored records:
//! a member of its organization, or the platform through an operator.
//!
//! Every lifecycle use case starts here. It resolves the caller into the
//! proof the domain asks for, finds the tenant they reach, and lets the
//! domain decide each step.

use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::tenant::control::Steward;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActedBy, ActorRef, OrganizationId, TenantId};

use crate::acting::organization::OrgActor;
use crate::acting::{OperatorAuthorities, OrgActors};
use crate::context::{OperatorCaller, OrgCaller};
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrganizationStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// Who asks to move a tenant through its life.
pub enum TenantSteward {
    /// A member of the tenant's organization.
    Member(OrgCaller),
    /// A platform operator, acting for the platform.
    Platform(OperatorCaller),
}

/// The proofs a steward is resolved through.
pub(in crate::use_cases::tenant) struct StewardSources<'a> {
    /// Who acts on an organization.
    pub(in crate::use_cases::tenant) org_actors: &'a dyn OrgActors,
    /// What an operator may do on the platform.
    pub(in crate::use_cases::tenant) operator_authorities: &'a dyn OperatorAuthorities,
}

/// The ports of a use case that resolves its steward.
pub(in crate::use_cases::tenant) trait StewardPorts: Sync {
    /// Who acts on an organization.
    fn org_actors(&self) -> &dyn OrgActors;

    /// What an operator may do on the platform.
    fn operator_authorities(&self) -> &dyn OperatorAuthorities;

    /// What `caller` acts as, from the stored records.
    ///
    /// # Errors
    ///
    /// As [`Acting::resolve`].
    async fn acting(&self, caller: &TenantSteward) -> Result<Acting, AppError> {
        let sources = StewardSources {
            org_actors: self.org_actors(),
            operator_authorities: self.operator_authorities(),
        };
        Acting::resolve(sources, caller).await
    }
}

/// A steward as the stored records prove them.
pub(in crate::use_cases::tenant) enum Acting {
    /// A member, with their organization as it stands.
    Member {
        /// The member's organization.
        organization: Box<Organization>,
        /// The member, with what they act through.
        actor: Box<OrgActor>,
    },
    /// The platform, through an operator acting now.
    Platform(OperatorAuthority),
}

impl Acting {
    /// What `caller` acts as, worked out from the stored records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the credential is someone else's, or the
    ///   operator is disabled.
    /// - `AppError::Internal` when a store fails.
    pub(in crate::use_cases::tenant) async fn resolve(
        sources: StewardSources<'_>,
        caller: &TenantSteward,
    ) -> Result<Self, AppError> {
        match caller {
            TenantSteward::Member(member) => {
                let (organization, actor) = sources.org_actors.actor(member).await?;
                Ok(Self::Member {
                    organization: Box::new(organization),
                    actor: Box::new(actor),
                })
            }
            TenantSteward::Platform(operator) => sources
                .operator_authorities
                .authority(operator)
                .await
                .map(Self::Platform),
        }
    }

    /// The tenant `tenant_id`, when this steward reaches it: any tenant for
    /// the platform, only their own organization's for a member.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when there is no such tenant, or it belongs to
    ///   another organization than the member's.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::tenant) async fn reached_tenant(
        &self,
        store: &dyn TenantStore,
        tenant_id: &TenantId,
    ) -> Result<Tenant, AppError> {
        let tenant = existing_tenant(store, tenant_id).await?;
        match self {
            Self::Member { organization, .. } if tenant.organization_id() != organization.id() => {
                Err(AppError::NotFound(message!(
                    "app-tenant-not-found",
                    "tenant not found"
                )))
            }
            Self::Member { .. } | Self::Platform(_) => Ok(tenant),
        }
    }

    /// The organization `organization_id` as this steward acts on it: a
    /// member's own, or any for the platform.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when there is no such organization, or a
    ///   member names one other than their own.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::tenant) async fn organization(
        &self,
        store: &dyn OrganizationStore,
        organization_id: &OrganizationId,
    ) -> Result<Organization, AppError> {
        match self {
            Self::Member { organization, .. } if organization.id() == organization_id => {
                Ok(Organization::clone(organization))
            }
            Self::Member { .. } => Err(AppError::NotFound(message!(
                "authentication-organization-not-found",
                "organization not found"
            ))),
            Self::Platform(_) => store
                .find_by_id(organization_id)
                .await
                .or_internal()?
                .ok_or_else(|| {
                    AppError::NotFound(message!(
                        "authentication-organization-not-found",
                        "organization not found"
                    ))
                }),
        }
    }

    /// What `step` gives back, with the domain deciding as this steward.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the member's session no longer
    ///   passes its check.
    /// - The error the domain refuses `step` with.
    pub(in crate::use_cases::tenant) fn decide<T>(
        &self,
        step: impl FnOnce(Steward<'_>) -> Result<T, DomainError>,
    ) -> Result<T, AppError> {
        match self {
            Self::Member { actor, .. } => {
                let control = actor.control()?;
                step(ActedBy::By(&control)).map_err(AppError::from_domain)
            }
            Self::Platform(_) => step(ActedBy::Platform).map_err(AppError::from_domain),
        }
    }

    /// What `change` to an organization gives back, with the domain deciding
    /// as this steward.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the member's session no longer
    ///   passes its check.
    /// - The error the domain refuses `change` with.
    pub(in crate::use_cases::tenant) fn decide_for_organization<T>(
        &self,
        change: impl FnOnce(ActedBy<OrgControl<'_>>) -> Result<T, DomainError>,
    ) -> Result<T, AppError> {
        match self {
            Self::Member { actor, .. } => {
                change(ActedBy::By(actor.control()?)).map_err(AppError::from_domain)
            }
            Self::Platform(_) => change(ActedBy::Platform).map_err(AppError::from_domain),
        }
    }

    /// The steward, as the actor an audit record names.
    pub(in crate::use_cases::tenant) fn actor(&self) -> ActorRef {
        match self {
            Self::Member { actor, .. } => ActorRef::OrgUser(*actor.member().id()),
            Self::Platform(authority) => authority.actor(),
        }
    }
}

/// Revokes every session of `tenant`, so a tenant taken out of service
/// stops answering. The cached callers go with the `tenant.status_changed`
/// its change records.
///
/// # Errors
///
/// - `AppError::Internal` if the store fails.
pub(in crate::use_cases::tenant) async fn sign_out_tenant(
    sessions: &dyn SessionStore,
    tenant: &Tenant,
) -> Result<(), AppError> {
    sessions
        .revoke_all_by_tenant(&ScopedTenant::from_registry(tenant))
        .await
        .or_internal()?;
    Ok(())
}
