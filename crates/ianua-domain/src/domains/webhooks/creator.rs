//! The person who made a webhook, as the records hold them at delivery.
//!
//! A webhook keeps sending long after its creator made it, while they are
//! signed out. So every delivery works out again what they may see, from
//! their account as it stands now: a tenant user's roles, or an
//! organization member's tenant grants. A creator who can no longer sign
//! in sees nothing, so their webhooks send nothing.

use crate::domains::authorization::authority::{Holdings, TenantAccess};
use crate::domains::identity::account::user::User;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::tenant_authority;
use crate::domains::organization::members::tenant_grant::OrgTenantGrant;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::PrincipalRef;

/// A webhook's creator, as the records hold them now.
///
/// Sam made a webhook for user events as a member of Acme's organization.
/// His tenant rights come from his tenant grants. Once his grant is
/// withdrawn, his membership ends or Acme is suspended, his webhook sends
/// nothing more.
#[derive(Debug)]
pub enum CreatorNow<'a, T: TenantScope> {
    /// A tenant user's account.
    User(&'a User<T>),
    /// An organization member's account, with their organization and tenant
    /// grants, loaded fresh.
    Member {
        /// The member's account.
        member: &'a OrgUser,
        /// The freshly loaded owner whose standing constrains the creator's tenant rights.
        organization: &'a Organization,
        /// Their tenant grants.
        grants: &'a [OrgTenantGrant],
    },
}

impl<T: TenantScope> CreatorNow<'_, T> {
    /// The account as a principal.
    pub(super) fn principal(&self) -> PrincipalRef {
        match self {
            Self::User(user) => PrincipalRef::User(*user.id()),
            Self::Member { member, .. } => PrincipalRef::OrgUser(*member.id()),
        }
    }

    /// What the creator holds in `access`'s tenant now, or `None` when they
    /// may not act there now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub(super) fn standing_in(
        &self,
        access: &TenantAccess<'_, T>,
    ) -> Result<Option<Holdings>, DomainError> {
        match self {
            Self::User(user) if user.can_authenticate() => {
                access.standing_of(self.principal()).map(Some)
            }
            Self::Member {
                member,
                organization,
                grants,
            } if tenant_authority::ensure_member_reaches(member, organization, &access.tenant)
                .is_ok() =>
            {
                tenant_authority::standing_in(access, member, grants).map(Some)
            }
            Self::User(_) | Self::Member { .. } => Ok(None),
        }
    }
}
