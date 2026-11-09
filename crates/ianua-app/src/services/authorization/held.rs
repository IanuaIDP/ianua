//! What a principal holds in a tenant now, read from its records, never
//! from what a token claims: one read the gateway's credential check and
//! its access decision share, so a request reads each principal's records
//! once.

use ianua_domain::domains::authorization::held::Held;
use ianua_domain::domains::organization::members::tenant_authority::{
    MemberInTenant, held_by_member,
};
use ianua_domain::domains::proxy::access::question::{Records, Standing};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, PrincipalRef, RoleId};

use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::organization::{MemberStanding, MemberStandings};
use crate::ports::routing::PolicyDecisionPoint;
use crate::tenancy::ScopedTenant;

/// Where what a principal holds is read from: whether the tenant's records
/// let it act, what they give it, and for an organization member, their
/// standing in their organization and their grants.
#[derive(Clone, Copy)]
pub(crate) struct RecordSources<'a> {
    /// Whether the records know a user, agent or consumer and let it act.
    pub(crate) decisions: &'a dyn PolicyDecisionPoint,
    /// What the tenant's records give.
    pub(crate) access: &'a dyn AccessRecordStore,
    /// Organization members as the tenant reads them.
    pub(crate) members: &'a dyn MemberStandings,
}

/// What `principal` holds in `tenant` now: its permissions, widened by the
/// ladders and for a person by live break-glass access, its roles and its
/// groups. A principal the records do not name holds nothing.
///
/// # Errors
///
/// Returns [`DomainError`] when the records cannot be read, or name a role
/// or group that is not there.
pub(crate) async fn held(
    access: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    principal: PrincipalRef,
) -> Result<Held, DomainError> {
    let records = access.load_held_by(tenant, Holder::of(principal)).await?;
    Held::of(&records.access(**tenant), principal, clock::now())
}

/// What the records say of `principal`: unknown, barred, or what it holds
/// while it may act. Anything that cannot be read is
/// [`Records::Unreadable`], which every decision refuses.
///
/// An organization member is read as their organization holds them: they
/// may act in the tenant only while they reach it, and hold what their role
/// and grants there give, the same rule as for work done for them while
/// they are signed out anywhere else.
pub(crate) async fn records_of(
    sources: RecordSources<'_>,
    tenant: &ScopedTenant,
    principal: PrincipalRef,
) -> Records {
    if let PrincipalRef::OrgUser(member) = principal {
        return member_records(sources, tenant, &member).await;
    }
    match sources.decisions.standing(tenant, &principal).await {
        Ok(Standing::Good) => holding(sources.access, tenant, principal).await,
        Ok(Standing::Unknown) => Records::Unknown,
        Ok(Standing::Barred) => Records::Barred,
        Err(error) => {
            tracing::warn!(%error, "a principal's standing could not be read; refusing");
            Records::Unreadable
        }
    }
}

/// What `member` holds in `tenant` now, unknown when they or their
/// organization are gone, barred when they do not reach the tenant.
async fn member_records(
    sources: RecordSources<'_>,
    tenant: &ScopedTenant,
    member: &OrgUserId,
) -> Records {
    let standing = match sources.members.member_in(tenant, member).await {
        Ok(Some(standing)) => standing,
        Ok(None) => return Records::Unknown,
        Err(error) => {
            tracing::warn!(%error, "a member's standing could not be read; refusing");
            return Records::Unreadable;
        }
    };
    match member_held(sources.access, tenant, &standing).await {
        Ok(held) => Records::Holds(held),
        Err(DomainError::Forbidden(_)) => Records::Barred,
        Err(error) => {
            tracing::warn!(%error, "a member's holdings could not be read; refusing");
            Records::Unreadable
        }
    }
}

/// What the member `standing` describes holds in `tenant`, by the tenant's
/// records and their grants.
async fn member_held(
    access: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    standing: &MemberStanding,
) -> Result<Held, DomainError> {
    let granted: Vec<RoleId> = standing
        .grants
        .iter()
        .map(|grant| *grant.role_id())
        .collect();
    let holder = Holder {
        principal: PrincipalRef::OrgUser(*standing.member.id()),
        granted_roles: &granted,
    };
    let records = access.load_held_by(tenant, holder).await?;
    held_by_member(
        &records.access(**tenant),
        MemberInTenant {
            member: standing.member,
            organization: &standing.organization,
            grants: &standing.grants,
        },
    )
}

/// What `principal`, in good standing, holds, or that it could not be read.
async fn holding(
    access: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    principal: PrincipalRef,
) -> Records {
    match held(access, tenant, principal).await {
        Ok(held) => Records::Holds(held),
        Err(error) => {
            tracing::warn!(%error, "a principal's access records could not be read; refusing");
            Records::Unreadable
        }
    }
}
