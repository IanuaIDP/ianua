//! A person's account as the records hold it now, and what it holds in a
//! tenant while nobody is signed in.
//!
//! Work that goes on for a person after they leave it, such as a workflow a
//! schedule fires or an agent run a worker drives under their delegation,
//! asks again what they hold. A tenant user holds what their roles give. An
//! organization member holds what their organization role and tenant grants
//! give. Someone who left or was shut out holds nothing.

use crate::domains::authorization::authority::{Holdings, TenantAccess};
use crate::domains::identity::account::user::User;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::tenant_authority;
use crate::domains::organization::members::tenant_grant::OrgTenantGrant;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::PrincipalRef;

/// The account a person acts through, as the records hold it now.
///
/// Sam published the nightly export as a member of Acme's organization. His
/// tenant rights come from his tenant grants, so what he holds counts only
/// while those grants, his membership and the organization still let him
/// in.
#[derive(Debug)]
pub enum AccountNow<'a, T: TenantScope> {
    /// A tenant user's account.
    User(&'a User<T>),
    /// An organization member's account.
    Member(MemberNow<'a>),
}

/// An organization member as the records hold them now: their account,
/// their organization and their tenant grants, loaded fresh.
#[derive(Debug, Clone, Copy)]
pub struct MemberNow<'a> {
    /// The member's account.
    pub member: &'a OrgUser,
    /// The freshly loaded owner of this member's account and tenant grants.
    pub organization: &'a Organization,
    /// Their tenant grants.
    pub grants: &'a [OrgTenantGrant],
}

impl<T: TenantScope> AccountNow<'_, T> {
    /// The account as a principal.
    #[must_use]
    pub fn principal(&self) -> PrincipalRef {
        match self {
            Self::User(user) => PrincipalRef::User(*user.id()),
            Self::Member(now) => PrincipalRef::OrgUser(*now.member.id()),
        }
    }

    /// What the account holds in `access`'s tenant now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account may not sign in now.
    /// - [`DomainError::Forbidden`] when a member's organization is not
    ///   theirs, does not own the tenant, is closed, or is suspended and
    ///   they are not an owner.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub(crate) fn standing_in(
        &self,
        access: &TenantAccess<'_, T>,
    ) -> Result<Holdings, DomainError> {
        match self {
            Self::User(user) => {
                if !user.can_authenticate() {
                    return Err(DomainError::forbidden(message!(
                        "organization-the-account-may-not-act-now",
                        "the account may not act now"
                    )));
                }
                access.standing_of(self.principal())
            }
            Self::Member(now) => {
                tenant_authority::ensure_member_reaches(
                    now.member,
                    now.organization,
                    &access.tenant,
                )?;
                tenant_authority::standing_in(access, now.member, now.grants)
            }
        }
    }
}
