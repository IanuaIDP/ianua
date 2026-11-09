//! Who a directory connection is bound as, and the part of the directory
//! its DN names.

use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{EventLabel, TenantSlug, UserId};

use crate::context::CallerContext;
use crate::email::LinkScope;
use crate::tenancy::ScopedTenant;

/// The organization and tenant a DN names, by their slugs: the part of the
/// directory a bind or a search is aimed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryBase {
    /// The organization's slug.
    pub organization: TenantSlug,
    /// The tenant's slug, unique inside its organization.
    pub tenant: TenantSlug,
}

/// A person a directory connection is bound as, with what they held in
/// their tenant when they bound.
///
/// Only a bind makes one: its fields are private, so the LDAP adapter keeps
/// it for the connection and hands it back, but can neither make one nor
/// widen what it holds. LDAP has no sessions, so the bind's proof of the
/// person lasts for the connection. A search or a write made through it
/// works out again what the person holds, and checks the certificate they
/// bound over, so a revoked certificate or a shut account stops the next
/// one.
#[derive(Debug, Clone)]
pub struct DirectoryPrincipal {
    authority: TenantAuthority,
    caller: CallerContext,
    tenant: ScopedTenant,
    base: DirectoryBase,
    user_id: UserId,
    user_label: EventLabel,
}

impl DirectoryPrincipal {
    /// `account`, bound as `caller` under `base`, holding `authority`.
    pub(in crate::use_cases::directory) fn bound(
        authority: TenantAuthority,
        caller: CallerContext,
        base: DirectoryBase,
        account: &User<ResolvedTenant>,
    ) -> Self {
        Self {
            authority,
            tenant: caller.tenant(),
            caller,
            base,
            user_id: *account.id(),
            user_label: EventLabel::of(account.email().as_str()),
        }
    }

    /// What the person held in their tenant when they bound.
    #[must_use]
    pub fn authority(&self) -> &TenantAuthority {
        &self.authority
    }

    /// The tenant the person bound in.
    #[must_use]
    pub fn tenant(&self) -> &ScopedTenant {
        &self.tenant
    }

    /// The part of the directory the bind named.
    #[must_use]
    pub fn base(&self) -> &DirectoryBase {
        &self.base
    }

    /// The account bound as.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// How audit records name the person: the address they bound with.
    #[must_use]
    pub fn user_label(&self) -> &EventLabel {
        &self.user_label
    }

    /// What the records of a request on this bind carry: the person, their
    /// organization and tenant, and the address they bound from.
    #[must_use]
    pub fn audit_context(&self) -> AuditContext {
        self.caller.audit_context()
    }

    /// The person as a caller of the tenant's use cases, coming with their
    /// directory bind.
    pub(in crate::use_cases::directory) fn caller(&self) -> &CallerContext {
        &self.caller
    }

    /// Where links mailed for a write over the directory land: the tenant
    /// the bind found under its base.
    pub(in crate::use_cases::directory) fn link_scope(&self) -> LinkScope {
        LinkScope::tenant(self.base.organization.clone(), self.base.tenant.clone())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditActor;
    use ianua_domain::types::{ActorRef, Fact};

    use crate::test_support::directory::BoundDirectory;
    use crate::test_support::test_ctx;

    /// What Ann does over her bind is recorded as hers, in the tenant and
    /// organization she bound in.
    #[test]
    fn records_on_a_bind_name_the_person_and_where_they_bound() {
        let directory = BoundDirectory::holding(&[]);
        let principal = directory.bind();

        let context = principal.audit_context();

        assert!(matches!(
            context.actor(),
            AuditActor::Caller(ActorRef::User(user)) if *user == directory.ann
        ));
        assert_eq!(context.tenant_id(), Fact::Known(test_ctx().tenant_id()));
        assert_eq!(
            context.organization_id(),
            Fact::Known(test_ctx().organization_id())
        );
    }
}
