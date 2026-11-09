use time::{Duration, OffsetDateTime};

use crate::domains::authorization::authority::{Holdings, TenantAccess, TenantAuthority};
use crate::domains::identity::account::user::User;
use crate::domains::operator::control::OperatorAuthority;
use crate::domains::operator::events::{ImpersonationGranted, ImpersonationRevoked};
use crate::domains::operator::identity::Operator;
use crate::domains::tenant::compliance::OperatorImpersonation;
use crate::domains::tenant::lifecycle::Tenant;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    ActorRef, EventLabel, Human, HumanAccount, ImpersonationGrantId, OperatorId, PersonKey,
    PrincipalRef, Revocation, TenantId, Text, UserId,
};

/// Stored fields of an [`ImpersonationGrant`], read back by repositories.
pub struct ImpersonationGrantRow {
    /// Unique grant identifier.
    pub id: ImpersonationGrantId,
    /// The operator who was granted impersonation access.
    pub operator_id: OperatorId,
    /// The tenant containing the target user.
    pub tenant_id: TenantId,
    /// The user being impersonated.
    pub user_id: UserId,
    /// Why this impersonation was granted.
    pub reason: Text,
    /// When this grant expires and becomes unusable.
    pub expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    pub revocation: Revocation,
    /// When this grant was created.
    pub created_at: OffsetDateTime,
}

/// A time-limited grant that lets an operator act as one tenant user.
///
/// The grant names both the operator and the user, so audit events can show
/// both. A tenant can forbid impersonation in its compliance posture. A grant
/// is made against the [`Tenant`] itself, and every use goes through
/// [`ImpersonationGrant::ensure_usable`], so that setting is read each time.
#[derive(Debug)]
pub struct ImpersonationGrant {
    id: ImpersonationGrantId,
    operator_id: OperatorId,
    tenant_id: TenantId,
    user_id: UserId,
    reason: Text,
    expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    revocation: Revocation,
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// Which user an operator may act as, why, and until when.
pub struct ImpersonationTerms {
    /// The tenant the user belongs to.
    pub tenant_id: TenantId,
    /// The user to act as.
    pub user_id: UserId,
    /// Why, kept in the audit trail.
    pub reason: Text,
    /// When the grant ends.
    pub expires_at: OffsetDateTime,
}

/// The longest an operator may act as somebody else's user in one grant.
pub(crate) const MAX_GRANT_LENGTH: Duration = Duration::hours(24);

/// Who a grant is used by and on, each as it stands now.
#[derive(Debug, Clone, Copy)]
pub struct Impersonated<'a, T: TenantScope> {
    /// The operator using the grant, freshly loaded.
    pub operator: &'a Operator,
    /// The tenant the grant is in, freshly loaded.
    pub tenant: &'a Tenant,
    /// The user acted as, loaded from the tenant's own store.
    pub user: &'a User<T>,
}

/// An operator acting inside a tenant as the user a grant names.
///
/// Its authority is the user's, so every rule reads what the user holds.
/// It also names the operator and the grant, so an audit record of the
/// change shows the operator behind it, not just the user. Only
/// [`ImpersonationGrant::act_as`] makes one.
#[derive(Debug, Clone)]
pub struct Impersonation {
    authority: TenantAuthority,
    operator: OperatorId,
    grant: ImpersonationGrantId,
}

impl Impersonation {
    /// What the user holds in the tenant, for the change being made.
    #[must_use]
    pub fn authority(&self) -> &TenantAuthority {
        &self.authority
    }

    /// The operator acting as the user.
    #[must_use]
    pub fn operator(&self) -> &OperatorId {
        &self.operator
    }

    /// The grant the operator acts under.
    #[must_use]
    pub fn grant(&self) -> &ImpersonationGrantId {
        &self.grant
    }

    /// The operator, as the actor an audit record names beside the user.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        ActorRef::Operator(self.operator)
    }
}

impl ImpersonationGrant {
    /// Creates a new impersonation grant in `tenant`, for the operator `by`
    /// who asks for it.
    ///
    /// The grant is always the asking operator's own, so nobody holds one
    /// they did not ask for under their own name. Without this, Bob names
    /// Carol as the holder and acts as Acme's admin with her name on every
    /// audit line. The reason is kept in the audit trail. From `expires_at`
    /// on, the operator cannot act as the user.
    ///
    /// Raises `operator.impersonation_granted` in the user's tenant, with
    /// `user_label` naming the user, the reason and the expiry.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if the tenant's compliance posture
    ///   forbids operator impersonation.
    /// - [`DomainError::Validation`] if the terms name a different tenant, or
    ///   `expires_at` is not in the future or is more than
    ///   `MAX_GRANT_LENGTH` away.
    pub fn create(
        by: &OperatorAuthority,
        tenant: &Tenant,
        terms: ImpersonationTerms,
        user_label: EventLabel,
    ) -> Result<Self, DomainError> {
        let ImpersonationTerms {
            tenant_id,
            user_id,
            reason,
            expires_at,
        } = terms;
        ensure_tenant_allows_impersonation(tenant, tenant_id)?;
        let now = crate::shared::clock::now();
        ensure_within_window(expires_at, now)?;
        let mut grant = Self {
            id: ImpersonationGrantId::new(),
            operator_id: *by.operator(),
            tenant_id,
            user_id,
            reason,
            expires_at,
            revocation: Revocation::InForce,
            created_at: now,
            raised: RaisedEvents::default(),
        };
        grant.raise_granted(user_label);
        Ok(grant)
    }

    /// Raises the grant's making in the user's tenant, with `user_label`
    /// naming the user.
    fn raise_granted(&mut self, user_label: EventLabel) {
        self.raised.raise_tenant(
            self.tenant_id,
            ImpersonationGranted {
                user_id: self.user_id,
                user_label,
                reason: self.reason.clone(),
                expires_at: self.expires_at,
                occurred_at: self.created_at,
            },
        );
    }

    /// Rebuilds an impersonation grant from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row ends before it was
    ///   granted, lasts longer than `MAX_GRANT_LENGTH`, or was revoked
    ///   before it was granted.
    pub fn reconstitute(row: ImpersonationGrantRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            operator_id: row.operator_id,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            reason: row.reason,
            expires_at: row.expires_at,
            revocation: row.revocation,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ImpersonationGrantRow) -> Result<(), DomainError> {
        RowCheck::of("impersonation grant")
            .holds(
                ensure_within_window(row.expires_at, row.created_at).is_ok(),
                "a window no grant may have",
            )
            .in_order_if(
                row.created_at,
                row.revocation.revoked_at(),
                "revoked before it was granted",
            )
            .finish()
    }

    /// Unique grant identifier.
    #[must_use]
    pub fn id(&self) -> &ImpersonationGrantId {
        &self.id
    }

    /// The operator who was granted impersonation access.
    #[must_use]
    pub fn operator_id(&self) -> &OperatorId {
        &self.operator_id
    }

    /// The tenant containing the target user.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The user being impersonated.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Why this impersonation was granted. Required for audit.
    #[must_use]
    pub fn reason(&self) -> &Text {
        &self.reason
    }

    /// When this grant expires and becomes unusable.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When this grant was explicitly revoked, if at all.
    #[must_use]
    pub fn revoked_at(&self) -> Option<OffsetDateTime> {
        self.revocation.revoked_at()
    }

    /// When this grant was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Refuses to let `operator` act as the user in `tenant` unless the grant
    /// still holds at `now`.
    ///
    /// Time alone is not enough. The tenant and the operator are read again
    /// on every use. Acme gives Bob a two-hour grant, then forbids
    /// impersonation ten minutes later. Bob is refused from that moment, not
    /// when the two hours end. The same holds when an admin disables Bob.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `operator` is not the one the grant
    ///   names or is disabled, when `tenant` is not the grant's tenant or
    ///   now forbids impersonation, or when the grant is revoked or has
    ///   expired.
    pub fn ensure_usable(
        &self,
        operator: &Operator,
        tenant: &Tenant,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.ensure_held_by(operator)?;
        if *tenant.id() != self.tenant_id {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonation-grant-is-for-a",
                "the impersonation grant is for a different tenant"
            )));
        }
        ensure_tenant_admits_impersonation(tenant)?;
        self.ensure_in_force(now)
    }

    /// Refuses an operator other than the one the grant names, or one who
    /// has been disabled.
    fn ensure_held_by(&self, operator: &Operator) -> Result<(), DomainError> {
        if *operator.id() != self.operator_id {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonation-grant-names-a-different-2",
                "the impersonation grant names a different operator"
            )));
        }
        if !operator.is_active() {
            return Err(DomainError::forbidden(message!(
                "operator-disabled-operators-cannot-impersonate",
                "disabled operators cannot impersonate"
            )));
        }
        Ok(())
    }

    /// Refuses a grant that was revoked or whose end has come.
    fn ensure_in_force(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.revocation.is_revoked() {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonation-grant-was-revoked",
                "the impersonation grant was revoked"
            )));
        }
        if now >= self.expires_at {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonation-grant-has-expired",
                "the impersonation grant has expired"
            )));
        }
        Ok(())
    }

    /// The operator `by`, acting in the tenant `access` was read from as
    /// the user the grant names, with what that user holds there now.
    ///
    /// An operator holds no tenant rights of their own. Inside a tenant
    /// they act only as the user they were granted, with the user's
    /// standing rights worked out from the tenant's records, never more.
    /// Break-glass access is the user's, given for their emergency, so it
    /// is not carried. The answer names the operator and the grant, so every
    /// change made shows who really made it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the operator the grant
    ///   names.
    /// - The cases [`Self::ensure_usable`] lists, with the operator and the
    ///   tenant as they stand now.
    /// - [`DomainError::Forbidden`] when `access` was read from another
    ///   tenant, or `parties.user` is not the user the grant names.
    /// - [`DomainError::Forbidden`] when the user may not sign in now.
    /// - The cases
    ///   [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators)
    ///   lists, for records that name a role or group that is not there.
    pub fn act_as<T: TenantScope>(
        &self,
        access: &TenantAccess<'_, T>,
        by: &OperatorAuthority,
        parties: &Impersonated<'_, T>,
        now: OffsetDateTime,
    ) -> Result<Impersonation, DomainError> {
        if *by.operator() != self.operator_id {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonation-grant-names-a-different-2",
                "the impersonation grant names a different operator"
            )));
        }
        self.ensure_usable(parties.operator, parties.tenant, now)?;
        if access.tenant != self.tenant_id {
            return Err(DomainError::forbidden(message!(
                "operator-the-tenant-s-records-were-read",
                "the tenant's records were read from another tenant than the grant's"
            )));
        }
        let user = parties.user;
        self.ensure_names(user)?;
        Ok(Impersonation {
            authority: TenantAuthority::assemble(
                Human::new(HumanAccount::User(*user.id()), PersonKey::of(user.email())),
                access.tenant,
                access.standing_of(PrincipalRef::User(*user.id()))?,
                Holdings::default(),
            ),
            operator: self.operator_id,
            grant: self.id,
        })
    }

    /// Refuses `user` unless it is the account the grant names and may
    /// sign in now. A locked or deactivated account acts for nobody, its
    /// impersonator included.
    fn ensure_names<T: TenantScope>(&self, user: &User<T>) -> Result<(), DomainError> {
        if *user.id() != self.user_id {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonation-grant-names-a-different",
                "the impersonation grant names a different user"
            )));
        }
        if !user.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "operator-the-impersonated-account-may-not-act",
                "the impersonated account may not act now"
            )));
        }
        Ok(())
    }

    /// Whether this grant has been explicitly revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revocation.is_revoked()
    }

    /// Revokes this grant immediately, for the operator `by` who holds it.
    ///
    /// The holder ends their own grant when the work is done. Another
    /// operator who sees a grant misused ends it by disabling its holder,
    /// which stops every grant they hold at once and names who did it.
    ///
    /// Raises `operator.impersonation_revoked` in the user's tenant, with
    /// `user_label` naming the user.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the grant's operator.
    /// - [`DomainError::InvalidTransition`] when it is already revoked. The
    ///   first revocation time is kept.
    pub fn revoke(
        &mut self,
        by: &OperatorAuthority,
        user_label: EventLabel,
    ) -> Result<(), DomainError> {
        if *by.operator() != self.operator_id {
            return Err(DomainError::forbidden(message!(
                "operator-only-the-operator-holding-the-grant",
                "only the operator holding the grant revokes it"
            )));
        }
        if self.revocation.is_revoked() {
            return Err(DomainError::invalid_transition(message!(
                "operator-the-impersonation-grant-is-already-revoked",
                "the impersonation grant is already revoked"
            )));
        }
        let at = crate::shared::clock::now();
        self.revocation = Revocation::Revoked { at };
        self.raised.raise_tenant(
            self.tenant_id,
            ImpersonationRevoked {
                user_id: self.user_id,
                user_label,
                occurred_at: at,
            },
        );
        Ok(())
    }
}

impl RaisesComplete for ImpersonationGrant {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses a grant in a tenant other than the one the terms name, or in a
/// tenant whose compliance posture forbids operators acting as its users.
fn ensure_tenant_allows_impersonation(
    tenant: &Tenant,
    tenant_id: TenantId,
) -> Result<(), DomainError> {
    if *tenant.id() != tenant_id {
        return Err(DomainError::invalid(message!(
            "operator-the-impersonation-terms-name-a-different",
            "the impersonation terms name a different tenant"
        )));
    }
    ensure_tenant_admits_impersonation(tenant)
}

/// Refuses a tenant that is not open, or whose compliance posture forbids
/// operators acting as its users. Acting as a user is acting in the
/// tenant's name, which a suspended, archived or deleted tenant serves to
/// nobody.
fn ensure_tenant_admits_impersonation(tenant: &Tenant) -> Result<(), DomainError> {
    if !tenant.status().is_open() {
        return Err(DomainError::forbidden(message!(
            "operator-this-tenant-is-closed-so-nobody",
            "this tenant is closed, so nobody acts as its users"
        )));
    }
    match tenant.compliance().operator_impersonation() {
        OperatorImpersonation::Allowed => Ok(()),
        OperatorImpersonation::Forbidden => Err(DomainError::forbidden(message!(
            "operator-this-tenant-does-not-allow-operator",
            "this tenant does not allow operator impersonation"
        ))),
    }
}

/// Refuses an expiry that has already passed or lies beyond the longest
/// grant allowed.
fn ensure_within_window(
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if expires_at <= now {
        return Err(DomainError::invalid(message!(
            "operator-expires-at-must-be-in-the",
            "expires_at must be in the future"
        )));
    }
    if expires_at > now.saturating_add(MAX_GRANT_LENGTH) {
        return Err(DomainError::invalid(message!(
            "operator-impersonation-grant-cannot-exceed-24-hours",
            "impersonation grant cannot exceed 24 hours"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::break_glass::{
        BreakGlassAccess, BreakGlassGrant, BreakGlassGrantRow, GrantApproval,
    };
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::authorization::role::{
        DefaultAssignment, NewRole, Role, RoleAssignment, RoleAssignmentRow,
    };
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::tenant::compliance_limits::{ComplianceLimits, ComplianceLimitsParams};
    use crate::domains::tenant::hosts::PlatformLabel;
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::domains::tenant::provisioning::infrastructure::{DeploymentRegion, TenantResidency};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DomainLimits;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::{label, user};
    use crate::test_support::events::raised_complete_names;
    use crate::types::{
        ActedBy, BreakGlassGrantId, DisplayName, Email, Locale, OrganizationId, PasswordHash,
        RoleId, TenantSlug, Timezone,
    };

    fn text(s: &str) -> Text {
        Text::new("reason", s).unwrap()
    }

    fn tenant_where(impersonation: OperatorImpersonation) -> Tenant {
        tenant_with_id(TenantId::new(), impersonation)
    }

    fn tenant_with_id(id: TenantId, impersonation: OperatorImpersonation) -> Tenant {
        let limits = DomainLimits::default();
        Tenant::provision(
            ProvisionTenantParams {
                id,
                platform_label: PlatformLabel::new("k7f3q9").unwrap(),
                organization_id: OrganizationId::new(),
                slug: TenantSlug::new("acme", &limits.slug).unwrap(),
                display_name: DisplayName::new("Acme", &limits.display_name).unwrap(),
                contact_email: Email::new("admin@acme.com").unwrap(),
                timezone: Timezone::new("UTC").unwrap(),
                locale: Locale::new("en-US").unwrap(),
                residency: TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1),
            },
            &ComplianceLimits::new(ComplianceLimitsParams {
                default_operator_impersonation: impersonation,
                ..ComplianceLimitsParams::default()
            })
            .unwrap(),
            ActedBy::Platform,
        )
        .unwrap()
    }

    fn terms_in(tenant: &Tenant, expires_at: OffsetDateTime) -> ImpersonationTerms {
        ImpersonationTerms {
            tenant_id: *tenant.id(),
            user_id: UserId::new(),
            reason: text("Customer reported login issue, investigating"),
            expires_at,
        }
    }

    /// An operator a test does not name, acting now.
    fn some_operator() -> OperatorAuthority {
        OperatorAuthority::assumed(OperatorId::new())
    }

    /// `operator`, acting now.
    fn acting(operator: &Operator) -> OperatorAuthority {
        OperatorAuthority::assumed(*operator.id())
    }

    /// The operator holding `grant`, acting now.
    fn holder_of(grant: &ImpersonationGrant) -> OperatorAuthority {
        OperatorAuthority::assumed(*grant.operator_id())
    }

    fn test_grant() -> ImpersonationGrant {
        let tenant = tenant_where(OperatorImpersonation::Allowed);
        let terms = terms_in(&tenant, crate::shared::clock::now() + Duration::hours(1));
        ImpersonationGrant::create(&some_operator(), &tenant, terms, ada()).unwrap()
    }

    /// How the audit trail names the user acted as.
    fn ada() -> EventLabel {
        EventLabel::of("ada@acme.com")
    }

    fn operator_named(name: &str) -> Operator {
        Operator::create(
            OperatorId::new(),
            Email::new(format!("{name}@ianua.dev")).unwrap(),
            PasswordHash::from_stored("hashed_password".to_owned()),
            &some_operator(),
        )
        .unwrap()
    }

    struct Granted {
        bob: Operator,
        acme: Tenant,
        grant: ImpersonationGrant,
    }

    fn bob_granted_in_acme() -> Granted {
        let bob = operator_named("bob");
        let acme = tenant_where(OperatorImpersonation::Allowed);
        let terms = terms_in(&acme, crate::shared::clock::now() + Duration::hours(2));
        let grant = ImpersonationGrant::create(&acting(&bob), &acme, terms, ada()).unwrap();
        Granted { bob, acme, grant }
    }

    impl Granted {
        fn usable_at(&self, now: OffsetDateTime) -> bool {
            self.grant.ensure_usable(&self.bob, &self.acme, now).is_ok()
        }
    }

    /// Suspending an active tenant makes its existing two-hour impersonation
    /// grant unusable.
    #[test]
    fn a_grant_stops_when_the_tenant_is_suspended() {
        let Granted {
            bob,
            mut acme,
            grant,
        } = bob_granted_in_acme();
        acme.activate(ActedBy::Platform).unwrap();
        acme.suspend(ActedBy::Platform).unwrap();

        let used = grant.ensure_usable(&bob, &acme, crate::shared::clock::now());

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }

    /// An existing grant is rejected when the tenant's current compliance
    /// settings forbid operator impersonation.
    #[test]
    fn a_grant_stops_when_the_tenant_forbids_impersonation() {
        let Granted { bob, acme, grant } = bob_granted_in_acme();
        let acme_now = tenant_with_id(*acme.id(), OperatorImpersonation::Forbidden);

        let used = grant.ensure_usable(&bob, &acme_now, crate::shared::clock::now());

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }

    /// Disabling the operator makes their unexpired impersonation grant unusable.
    #[test]
    fn a_grant_stops_when_the_operator_is_disabled() {
        let Granted {
            mut bob,
            acme,
            grant,
        } = bob_granted_in_acme();
        bob.disable(&some_operator()).unwrap();

        let used = grant.ensure_usable(&bob, &acme, crate::shared::clock::now());

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }

    /// A grant for Acme is rejected against another tenant even when that
    /// tenant allows impersonation.
    #[test]
    fn a_grant_is_refused_in_another_tenant() {
        let Granted { bob, grant, .. } = bob_granted_in_acme();
        let globex = tenant_where(OperatorImpersonation::Allowed);

        let used = grant.ensure_usable(&bob, &globex, crate::shared::clock::now());

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }

    /// Bob's impersonation grant is rejected when presented with Carol's account.
    #[test]
    fn a_grant_is_refused_to_another_operator() {
        let Granted { acme, grant, .. } = bob_granted_in_acme();
        let carol = operator_named("carol");

        let used = grant.ensure_usable(&carol, &acme, crate::shared::clock::now());

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }

    fn grant_until(expires_at: OffsetDateTime) -> Result<ImpersonationGrant, DomainError> {
        let tenant = tenant_where(OperatorImpersonation::Allowed);
        let terms = terms_in(&tenant, expires_at);
        ImpersonationGrant::create(&some_operator(), &tenant, terms, ada())
    }

    /// A tenant that forbids operator impersonation rejects creation of a
    /// one-hour grant.
    #[test]
    fn a_tenant_that_forbids_impersonation_gets_no_grant() {
        let tenant = tenant_where(OperatorImpersonation::Forbidden);
        let terms = terms_in(&tenant, crate::shared::clock::now() + Duration::hours(1));

        let refused = ImpersonationGrant::create(&some_operator(), &tenant, terms, ada());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Grant creation rejects terms naming a different tenant, even when
    /// the supplied tenant allows impersonation.
    #[test]
    fn terms_naming_another_tenant_are_refused() {
        let allowing = tenant_where(OperatorImpersonation::Allowed);
        let forbidding = tenant_where(OperatorImpersonation::Forbidden);
        let terms = terms_in(
            &forbidding,
            crate::shared::clock::now() + Duration::hours(1),
        );

        let refused = ImpersonationGrant::create(&some_operator(), &allowing, terms, ada());

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Bob gets a two-hour grant in a tenant that allows impersonation. He
    /// can use it right away, and it is not revoked.
    #[test]
    fn create_active_grant() {
        let granted = bob_granted_in_acme();

        assert!(granted.usable_at(crate::shared::clock::now()));
        assert!(!granted.grant.is_revoked());
    }

    /// A grant asked to end now, or a second ago, is refused. It would only
    /// sit in the audit trail as access that was never usable.
    #[test]
    fn a_grant_that_has_already_ended_is_refused() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(now);

        assert!(matches!(grant_until(now), Err(DomainError::Validation(_))));
        assert!(matches!(
            grant_until(now - Duration::seconds(1)),
            Err(DomainError::Validation(_))
        ));
    }

    /// A grant lasting exactly twenty-four hours is accepted, while one
    /// lasting one second longer is rejected.
    #[test]
    fn a_grant_longer_than_a_day_is_refused() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(now);

        assert!(grant_until(now + MAX_GRANT_LENGTH).is_ok());
        assert!(matches!(
            grant_until(now + MAX_GRANT_LENGTH + Duration::seconds(1)),
            Err(DomainError::Validation(_))
        ));
    }

    /// A grant is revoked before it expires. It reads as revoked and is no
    /// longer usable.
    #[test]
    fn revoked_grant_is_not_active() {
        let mut granted = bob_granted_in_acme();
        granted.grant.revoke(&acting(&granted.bob), ada()).unwrap();

        assert!(granted.grant.is_revoked());
        assert!(!granted.usable_at(crate::shared::clock::now()));
    }

    /// Another operator cannot revoke Bob's grant, which remains usable
    /// after the refused revocation.
    #[test]
    fn only_the_operator_holding_a_grant_revokes_it() {
        let mut granted = bob_granted_in_acme();
        let carol = some_operator();

        let revoked = granted.grant.revoke(&carol, ada());

        assert!(matches!(revoked, Err(DomainError::Forbidden(_))));
        assert!(granted.usable_at(crate::shared::clock::now()));
    }

    /// Bob revokes his grant twice. The second revoke is refused and the
    /// first revoke's time stays, so the record shows when access ended.
    #[test]
    fn a_revoked_grant_cannot_be_revoked_again() {
        let mut grant = test_grant();
        let holder = holder_of(&grant);
        grant.revoke(&holder, ada()).unwrap();
        let first = grant.revoked_at().unwrap();

        let again = grant.revoke(&holder, ada());

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert_eq!(grant.revoked_at(), Some(first));
    }

    /// Bob gets a grant to act as a user for support ticket 12345. The grant
    /// names Bob, who asked for it, the tenant, the user and the reason, so
    /// the audit trail can show all four.
    #[test]
    fn grant_carries_all_context_for_audit() {
        let op_id = OperatorId::new();
        let tenant = tenant_where(OperatorImpersonation::Allowed);
        let tenant_id = *tenant.id();
        let user_id = UserId::new();

        let grant = ImpersonationGrant::create(
            &OperatorAuthority::assumed(op_id),
            &tenant,
            ImpersonationTerms {
                tenant_id,
                user_id,
                reason: text("Support ticket #12345"),
                expires_at: crate::shared::clock::now() + Duration::hours(2),
            },
            ada(),
        )
        .unwrap();

        assert_eq!(*grant.operator_id(), op_id);
        assert_eq!(*grant.tenant_id(), tenant_id);
        assert_eq!(*grant.user_id(), user_id);
        assert_eq!(grant.reason().as_str(), "Support ticket #12345");
    }

    /// The expiry instant itself is outside the grant. Counting it as inside
    /// lets Bob act as the user a moment past the time he was given. The
    /// grant also has a real id to revoke it by.
    #[test]
    fn a_grant_is_inactive_from_the_instant_it_expires() {
        let granted = bob_granted_in_acme();
        let expires_at = granted.grant.expires_at();

        assert!(granted.usable_at(expires_at - Duration::seconds(1)));
        assert!(!granted.usable_at(expires_at));
        assert!(!granted.grant.id().as_uuid().is_nil());
    }

    /// A stored grant with a three-day lifetime is rejected as corrupt
    /// during reconstitution.
    #[test]
    fn a_stored_grant_longer_than_any_may_last_is_refused() {
        let grant = test_grant();
        let row = ImpersonationGrantRow {
            id: grant.id,
            operator_id: grant.operator_id,
            tenant_id: grant.tenant_id,
            user_id: grant.user_id,
            reason: grant.reason.clone(),
            expires_at: grant.created_at + time::Duration::days(3),
            revocation: grant.revocation,
            created_at: grant.created_at,
        };

        assert!(refused_as_corrupt(&ImpersonationGrant::reconstitute(row)));
    }

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// An active account in Acme at `address`.
    fn account(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// Bob, granted two hours as Ann in Acme, with Acme's records: Ann is a
    /// viewer there.
    struct ActingAsAnn {
        bob: Operator,
        acme: Tenant,
        grant: ImpersonationGrant,
        ann: User<ResolvedTenant>,
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
        break_glass: Vec<BreakGlassGrant>,
    }

    fn bob_as_ann() -> ActingAsAnn {
        let bob = operator_named("bob");
        let acme = tenant_where(OperatorImpersonation::Allowed);
        let ann = account("ann@acme.test");
        let terms = ImpersonationTerms {
            user_id: *ann.id(),
            ..terms_in(&acme, crate::shared::clock::now() + Duration::hours(2))
        };
        let grant = ImpersonationGrant::create(&acting(&bob), &acme, terms, ada()).unwrap();
        let viewer = viewer_role();
        let assignment = RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(*ann.id()),
            role_id: *viewer.id(),
            assigned_by: ActorRef::System,
            assigned_at: now(),
            expires: crate::types::Expiry::Never,
        })
        .unwrap();
        ActingAsAnn {
            bob,
            acme,
            grant,
            ann,
            roles: vec![viewer],
            assignments: vec![assignment],
            break_glass: Vec::new(),
        }
    }

    /// A manually assigned role granting only permission to view users.
    fn viewer_role() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("viewer"),
            system_permissions: vec![VIEW_USERS],
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    impl ActingAsAnn {
        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: *self.acme.id(),
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &[],
                break_glass: &self.break_glass,
            }
        }

        fn parties(&self) -> Impersonated<'_, ResolvedTenant> {
            Impersonated {
                operator: &self.bob,
                tenant: &self.acme,
                user: &self.ann,
            }
        }

        /// The grant used by `by`, with the parties as they stand.
        fn used_by(&self, by: &OperatorAuthority) -> Result<Impersonation, DomainError> {
            self.grant
                .act_as(&self.access(), by, &self.parties(), now())
        }

        fn used(&self) -> Result<Impersonation, DomainError> {
            self.used_by(&acting(&self.bob))
        }
    }

    /// Bob acts in Acme as Ann, a viewer there. He holds what Ann holds and
    /// nothing more, and the answer names him and his grant for the audit
    /// trail.
    #[test]
    fn an_operator_acts_as_the_user_with_what_the_user_holds() {
        let acting = bob_as_ann();

        let impersonation = acting.used().unwrap();

        let authority = impersonation.authority();
        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(MANAGE_ROLES));
        assert_eq!(
            authority.who().account(),
            HumanAccount::User(*acting.ann.id())
        );
        assert_eq!(*authority.tenant(), *acting.acme.id());
        assert_eq!(impersonation.operator(), acting.bob.id());
        assert_eq!(impersonation.grant(), acting.grant.id());
        assert!(matches!(
            impersonation.actor(),
            ActorRef::Operator(id) if id == *acting.bob.id()
        ));
    }

    /// Impersonation remains usable when Ann has emergency access, but
    /// the operator does not receive her break-glass role-management right.
    #[test]
    fn the_users_break_glass_is_not_carried_by_the_operator() {
        let mut acting = bob_as_ann();
        let emergency = BreakGlassGrant::reconstitute(BreakGlassGrantRow {
            id: BreakGlassGrantId::new(),
            tenant_id: *acting.acme.id(),
            user_id: *acting.ann.id(),
            grantee_person: PersonKey::of(acting.ann.email()),
            access: BreakGlassAccess::new(vec![MANAGE_ROLES], Vec::new()).unwrap(),
            reason: text("Production incident INC-1234"),
            approved_by: GrantApproval::SelfApproved,
            expires_at: now() + Duration::hours(1),
            revocation: Revocation::InForce,
            created_at: now(),
        })
        .unwrap();
        acting.break_glass = vec![emergency];

        let impersonation = acting.used().unwrap();

        assert!(!impersonation.authority().holds(MANAGE_ROLES));
    }

    /// Carol's authority cannot use Bob's grant with either Bob's account
    /// or her own account loaded.
    #[test]
    fn only_the_operator_holding_a_grant_acts_under_it() {
        let mut acting = bob_as_ann();
        let carol = operator_named("carol");

        let with_bobs_account = acting.used_by(&OperatorAuthority::assumed(*carol.id()));
        acting.bob = carol;
        let with_her_own = acting.used();

        assert!(matches!(with_bobs_account, Err(DomainError::Forbidden(_))));
        assert!(matches!(with_her_own, Err(DomainError::Forbidden(_))));
    }

    /// A grant naming Ann cannot produce impersonation authority with
    /// Sam's account supplied as the target.
    #[test]
    fn a_grant_acts_only_as_the_user_it_names() {
        let mut acting = bob_as_ann();
        acting.ann = account("sam@acme.test");

        assert!(matches!(acting.used(), Err(DomainError::Forbidden(_))));
    }

    /// A grant for Acme rejects authority records loaded from another tenant.
    #[test]
    fn a_grant_acts_only_on_its_own_tenants_records() {
        let acting = bob_as_ann();
        let globex = ActingAsAnn {
            acme: tenant_where(OperatorImpersonation::Allowed),
            ..bob_as_ann()
        };

        let used = acting.grant.act_as(
            &globex.access(),
            &OperatorAuthority::assumed(*acting.bob.id()),
            &acting.parties(),
            now(),
        );

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }

    /// Deactivating the target user prevents an existing grant from producing
    /// impersonation authority.
    #[test]
    fn a_deactivated_user_is_acted_as_by_nobody() {
        let mut acting = bob_as_ann();
        let control = control_over(&acting.ann);
        acting.ann.deactivate(&control).unwrap();

        assert!(matches!(acting.used(), Err(DomainError::Forbidden(_))));
    }

    /// A grant issued while impersonation was allowed cannot produce authority
    /// once the tenant forbids it.
    #[test]
    fn a_tenant_that_now_forbids_impersonation_is_closed_to_the_operator() {
        let mut acting = bob_as_ann();
        acting.acme = tenant_with_id(*acting.acme.id(), OperatorImpersonation::Forbidden);

        assert!(matches!(acting.used(), Err(DomainError::Forbidden(_))));
    }

    /// Bob is granted two hours as Ada in Acme. The grant is raised in
    /// Acme's trail, naming Ada, the reason and the expiry.
    #[test]
    fn granting_raises_operator_impersonation_granted_in_the_users_tenant() {
        let mut granted = bob_granted_in_acme();

        let events = granted.grant.take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "operator.impersonation_granted"
        );
        assert_eq!(events[0].tenant_id(), Some(granted.acme.id()));
        let payload = events[0].payload();
        assert_eq!(payload.get("reason"), Some(granted.grant.reason().as_str()));
        assert_eq!(
            payload.get("expires_at"),
            Some(granted.grant.expires_at().to_string().as_str())
        );
    }

    /// Bob ends his grant early. The revocation is raised in Acme's trail.
    #[test]
    fn revoking_raises_operator_impersonation_revoked_in_the_users_tenant() {
        let mut granted = bob_granted_in_acme();
        raised_complete_names(&mut granted.grant);

        granted.grant.revoke(&acting(&granted.bob), ada()).unwrap();

        let events = granted.grant.take_events();
        assert_eq!(
            events[0].event_type().to_string(),
            "operator.impersonation_revoked"
        );
        assert_eq!(events[0].tenant_id(), Some(granted.acme.id()));
    }

    /// Another operator's revocation is rejected; after the holder revokes
    /// the grant, a repeat revocation fails without raising a further event.
    #[test]
    fn a_refused_revocation_raises_nothing() {
        let mut granted = bob_granted_in_acme();
        let by_carol = granted.grant.revoke(&some_operator(), ada());
        granted.grant.revoke(&acting(&granted.bob), ada()).unwrap();
        raised_complete_names(&mut granted.grant);

        let again = granted.grant.revoke(&acting(&granted.bob), ada());

        assert!(by_carol.is_err());
        assert!(again.is_err());
        assert!(raised_complete_names(&mut granted.grant).is_empty());
    }

    /// Bob's grant is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn a_grant_read_back_from_storage_has_raised_nothing() {
        let grant = test_grant();
        let row = ImpersonationGrantRow {
            id: grant.id,
            operator_id: grant.operator_id,
            tenant_id: grant.tenant_id,
            user_id: grant.user_id,
            reason: grant.reason.clone(),
            expires_at: grant.expires_at,
            revocation: grant.revocation,
            created_at: grant.created_at,
        };

        let mut read = ImpersonationGrant::reconstitute(row).unwrap();

        assert!(raised_complete_names(&mut read).is_empty());
    }
}
