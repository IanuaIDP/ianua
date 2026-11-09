use time::OffsetDateTime;

use self::tenants::ensure_plan_allows;
use crate::domains::organization::access::auth_config::OrganizationAuthConfig;
use crate::domains::organization::billing::negotiated::PlanTerms;
use crate::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
use crate::domains::organization::billing::subscription::PlanMove;
use crate::domains::organization::events::access::OrganizationAuthConfigUpdated;
use crate::domains::organization::events::organization::{
    OrgPlanChanged, OrganizationCreated, OrganizationStatusChanged,
};
pub use crate::domains::organization::founding::Founding;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use crate::domains::organization::slugs::ensure_organization_label;
use crate::domains::organization::status::{
    OrgStanding, OrgSuspensionReason, OrganizationStatus, Suspension,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{ActedBy, DisplayName, Email, Label, OrganizationId, TenantId, TenantSlug};

mod non_payment;
mod profile;
mod tenants;

/// Parameters for creating a new organization.
pub struct CreateOrganizationParams {
    /// Globally unique identifier.
    pub id: OrganizationId,
    /// URL-safe slug for API paths, such as `/orgs/acme/...`.
    pub slug: TenantSlug,
    /// Organization name shown in admin UIs.
    pub name: Label,
    /// Billing and admin contact email.
    pub contact_email: Email,
    /// Display name shown in admin UIs.
    pub display_name: DisplayName,
    /// Subscription plan. Never [`OrganizationPlan::SelfHosted`], which only
    /// [`Organization::create_installation`] gives.
    pub plan: OrganizationPlan,
}

/// The organization an installation creates for itself, on the self-hosted
/// plan.
pub struct InstallationParams {
    /// Globally unique identifier.
    pub id: OrganizationId,
    /// URL-safe slug for API paths.
    pub slug: TenantSlug,
    /// Organization name shown in admin UIs.
    pub name: Label,
    /// Billing and admin contact email.
    pub contact_email: Email,
    /// Display name shown in admin UIs.
    pub display_name: DisplayName,
}

/// An organization as stored, for rebuilding it with
/// [`Organization::reconstitute`].
pub struct OrganizationRow {
    /// Unique identifier.
    pub id: OrganizationId,
    /// URL-safe slug.
    pub slug: TenantSlug,
    /// Organization name.
    pub name: Label,
    /// Billing and admin contact email.
    pub contact_email: Email,
    /// The human-readable label presented to members and other organizations.
    pub display_name: DisplayName,
    /// Subscription plan.
    pub plan: OrganizationPlan,
    /// The limits it works under: its plan's, or limits negotiated for a
    /// Custom plan.
    pub terms: PlanTerms,
    /// Current lifecycle status.
    pub status: OrganizationStatus,
    /// Who suspended it, while it is suspended.
    pub suspended_by: Suspension,
    /// Tenants belonging to this organization.
    pub tenant_ids: Vec<TenantId>,
    /// How the organization's administrators sign in.
    pub auth_config: OrganizationAuthConfig,
    /// When this organization was created.
    pub created_at: OffsetDateTime,
    /// When this organization was last modified.
    pub updated_at: OffsetDateTime,
}

/// The organization aggregate root.
///
/// An organization is the top-level entity that owns tenants. A company
/// signs up, gets an organization, then creates tenants in it for teams,
/// projects or subsidiaries.
///
/// The stores and the database keep each tenant's data apart from the
/// others'. See [`crate::isolation`]. The organization is where work across
/// tenants happens. The org admin can create, suspend and delete tenants,
/// manage billing and view organization-wide audit logs.
///
/// Every change names who makes it: a member acting through an
/// [`OrgControl`], who needs the organization right for it, or the platform.
#[derive(Debug, Clone)]
pub struct Organization {
    id: OrganizationId,
    slug: TenantSlug,
    name: Label,
    contact_email: Email,
    display_name: DisplayName,
    plan: OrganizationPlan,
    terms: PlanTerms,
    status: OrganizationStatus,
    suspended_by: Suspension,
    tenant_ids: Vec<TenantId>,
    auth_config: OrganizationAuthConfig,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl Organization {
    /// Creates a new active organization, with the [`Founding`] that makes
    /// its first owner. Raises `organization.created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for the self-hosted plan. It has no limits
    ///   at all and belongs only to the organization an installation makes
    ///   for itself, through [`create_installation`](Self::create_installation).
    pub fn create(params: CreateOrganizationParams) -> Result<(Self, Founding), DomainError> {
        ensure_organization_label(&params.slug, &[])?;
        if params.plan == OrganizationPlan::SelfHosted {
            return Err(DomainError::invalid(message!(
                "organization-the-self-hosted-plan-is-given",
                "the self-hosted plan is given only to an installation's own organization"
            )));
        }
        Ok(Self::open(
            InstallationParams {
                id: params.id,
                slug: params.slug,
                name: params.name,
                contact_email: params.contact_email,
                display_name: params.display_name,
            },
            params.plan,
        ))
    }

    /// Creates the one organization of an installation its owner runs
    /// themselves, on the self-hosted plan, with the [`Founding`] that makes
    /// its first owner. Raises `organization.created`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` for a reserved platform label.
    pub fn create_installation(
        params: InstallationParams,
    ) -> Result<(Self, Founding), DomainError> {
        ensure_organization_label(&params.slug, &[])?;
        Ok(Self::open(params, OrganizationPlan::SelfHosted))
    }

    fn open(params: InstallationParams, plan: OrganizationPlan) -> (Self, Founding) {
        let now = crate::shared::clock::now();
        let founding = Founding::of(params.id, plan);
        let mut organization = Self {
            id: params.id,
            slug: params.slug,
            name: params.name,
            contact_email: params.contact_email,
            display_name: params.display_name,
            plan,
            terms: PlanTerms::Standard,
            status: OrganizationStatus::Active,
            suspended_by: Suspension::NotSuspended,
            tenant_ids: Vec::new(),
            auth_config: OrganizationAuthConfig::default(),
            created_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        };
        organization.raised.raise_organization(OrganizationCreated {
            organization_id: organization.id,
            name: organization.name.clone(),
            occurred_at: now,
        });
        (organization, founding)
    }

    /// Rebuilds an organization from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row counts a tenant twice.
    /// - [`DomainError::Infrastructure`] when the row names who suspended an
    ///   organization that is not suspended, or names nobody for one that is.
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was created.
    /// - [`DomainError::Infrastructure`] when the row holds negotiated
    ///   limits on a plan other than Custom.
    pub fn reconstitute(row: OrganizationRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            slug: row.slug,
            name: row.name,
            contact_email: row.contact_email,
            display_name: row.display_name,
            plan: row.plan,
            terms: row.terms,
            status: row.status,
            suspended_by: row.suspended_by,
            tenant_ids: row.tenant_ids,
            auth_config: row.auth_config,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OrganizationRow) -> Result<(), DomainError> {
        RowCheck::of("organization")
            .holds(
                ensure_organization_label(&row.slug, &[]).is_ok(),
                "a reserved platform label",
            )
            .holds(
                first_repeat(&row.tenant_ids).is_none(),
                "a tenant counted twice",
            )
            .holds(
                (row.status == OrganizationStatus::Suspended)
                    == (row.suspended_by != Suspension::NotSuspended),
                "a suspension that does not fit its status",
            )
            .holds(
                row.terms.fit(row.plan),
                "negotiated limits on a plan other than Custom",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// Unique organization identifier.
    #[must_use]
    pub fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// URL-safe slug for API paths.
    #[must_use]
    pub fn slug(&self) -> &TenantSlug {
        &self.slug
    }

    /// Organization name shown in admin UIs.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Billing and admin contact email.
    #[must_use]
    pub fn contact_email(&self) -> &Email {
        &self.contact_email
    }

    /// Display name shown in admin UIs.
    #[must_use]
    pub fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    /// Subscription plan.
    #[must_use]
    pub fn plan(&self) -> OrganizationPlan {
        self.plan
    }

    /// The terms it works under: its plan's, or limits negotiated for it.
    #[must_use]
    pub fn terms(&self) -> &PlanTerms {
        &self.terms
    }

    /// The limits every creation in the organization is checked against:
    /// the plan's, or those negotiated for a Custom plan.
    #[must_use]
    pub fn limits(&self) -> PlanLimits {
        self.terms.limits_on(self.plan)
    }

    /// Current lifecycle status.
    #[must_use]
    pub fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// The organization as a member acting on it finds it now.
    #[must_use]
    pub fn standing(&self) -> OrgStanding {
        OrgStanding::new(self.id, self.status)
    }

    /// Who suspended the organization, while it is suspended.
    #[must_use]
    pub fn suspended_by(&self) -> Suspension {
        self.suspended_by
    }

    /// How this organization's administrators sign in.
    #[must_use]
    pub fn auth_config(&self) -> &OrganizationAuthConfig {
        &self.auth_config
    }

    /// Tenants belonging to this organization.
    #[must_use]
    pub fn tenant_ids(&self) -> &[TenantId] {
        &self.tenant_ids
    }

    /// Number of tenants in this organization.
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.tenant_ids.len()
    }

    /// When this organization was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this organization was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Replaces the organization's sign-in settings, as `by` decides. An
    /// [`OrganizationAuthConfig`] is checked when it is built, so whatever
    /// arrives here can already sign administrators in. Raises
    /// `organization.auth_config_updated`.
    ///
    /// The settings decide who reaches the management plane at all. So `by`
    /// must be signed in, not a script with a key, and the new settings must
    /// still let in the very sign-in that saves them. Ann saves an address
    /// list that leaves out her own network, or turns off the way she signed
    /// in. Without this check she locks every owner out, herself included.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is closed.
    /// - [`DomainError::Forbidden`] when `by` may not change the sign-in
    ///   settings, or acts through a key.
    /// - [`DomainError::Forbidden`] when the settings would not admit the
    ///   session that saves them.
    pub fn replace_auth_config(
        &mut self,
        auth_config: OrganizationAuthConfig,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_open()?;
        by.ensure_may(
            &self.id,
            OrgPermission::Organization(OrganizationAction::AuthConfig),
        )?;
        let Some(session) = by.session() else {
            return Err(DomainError::forbidden(message!(
                "organization-the-sign-in-settings-change-only",
                "the sign-in settings change only from a signed-in session"
            )));
        };
        auth_config
            .admits(session.auth_method(), session.ip_address())
            .map_err(|_| {
                DomainError::forbidden(message!(
                    "organization-these-settings-would-lock-out-the",
                    "these settings would lock out the very sign-in saving them"
                ))
            })?;
        self.auth_config = auth_config;
        self.touch();
        self.raised
            .raise_organization(OrganizationAuthConfigUpdated {
                organization_id: self.id,
                occurred_at: self.updated_at,
            });
        Ok(())
    }

    /// Moves to the plan, and the terms, `change` carries. The plan sets what
    /// the organization pays for, so it follows the subscription alone: a
    /// [`PlanMove`] comes only from
    /// [`OrgSubscription`](crate::domains::organization::billing::subscription::OrgSubscription),
    /// once it checked who chose the plan, how it is paid and that usage
    /// fits. Raises `organization.plan_changed` with the plan it replaced.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `change` is another organization's.
    /// - [`DomainError::InvalidTransition`] when the organization is closed.
    /// - [`DomainError::InvalidTransition`] when either side is
    ///   [`OrganizationPlan::SelfHosted`], which is fixed for as long as the
    ///   installation exists.
    /// - [`DomainError::Conflict`] when the new limits allow fewer tenants
    ///   than the organization has.
    pub fn change_plan(&mut self, change: PlanMove) -> Result<(), DomainError> {
        if change.organization_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "organization-a-plan-move-applies-to-its",
                "a plan move applies to its own organization only"
            )));
        }
        self.ensure_open()?;
        let plan = change.plan();
        if !self.plan.can_change_to(plan) {
            return Err(DomainError::invalid_transition(message!(
                "organization-an-organization-cannot-move-from-the",
                format!(
                    "an organization cannot move from the {} plan to the {plan} plan",
                    self.plan
                )
            )));
        }
        let terms = change.into_terms();
        ensure_plan_allows(&terms.limits_on(plan), self.tenant_count())?;
        let old_plan = std::mem::replace(&mut self.plan, plan);
        self.terms = terms;
        self.touch();
        self.raised.raise_organization(OrgPlanChanged {
            organization_id: self.id,
            old_plan,
            new_plan: self.plan,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Moves the organization to a new status, as `by` decides. Raises
    /// `organization.status_changed`, from the status it had to the one it
    /// has now.
    ///
    /// A member needs the suspend right to suspend or lift a suspension,
    /// and the close right to close. Only the platform lifts a suspension
    /// the platform made. A suspension the platform makes here is an
    /// operator's, which paying never lifts; the billing sweep suspends
    /// through [`suspend_for_non_payment`](Self::suspend_for_non_payment).
    ///
    /// The platform suspending an organization a member already suspended,
    /// or one suspended for not paying, takes the suspension over. Acme's
    /// owner sees the unpaid-bill notice coming and suspends Acme herself.
    /// Without this, the platform's suspension is refused, hers stays, and
    /// she lifts it again. Likewise an operator suspending Mallory's unpaid
    /// organization for abuse keeps it suspended once she pays.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a member lacks the right, or lifts
    ///   a suspension the platform made.
    /// - [`DomainError::InvalidTransition`] when `to` is the current status,
    ///   other than the platform taking over a member's suspension, or the
    ///   organization is closed.
    pub fn change_status(
        &mut self,
        to: OrganizationStatus,
        by: ActedBy<OrgControl<'_>>,
    ) -> Result<(), DomainError> {
        self.ensure_may_move(to, by)?;
        let from = self.status;
        if self.platform_takes_over(to, by) {
            self.suspended_by = Suspension::ByPlatform(OrgSuspensionReason::Operator);
            self.touch();
            self.raise_status_change(from);
            return Ok(());
        }
        self.status = self.status.try_transition(to)?;
        self.suspended_by = match (to, by) {
            (OrganizationStatus::Suspended, ActedBy::By(control)) => {
                Suspension::ByMember(*control.by().id())
            }
            (OrganizationStatus::Suspended, ActedBy::Platform) => {
                Suspension::ByPlatform(OrgSuspensionReason::Operator)
            }
            (OrganizationStatus::Active | OrganizationStatus::Closed, _) => {
                Suspension::NotSuspended
            }
        };
        self.touch();
        self.raise_status_change(from);
        Ok(())
    }

    /// Raises the move from `from` to the status the organization has now.
    fn raise_status_change(&mut self, from: OrganizationStatus) {
        self.raised.raise_organization(OrganizationStatusChanged {
            organization_id: self.id,
            from,
            to: self.status,
            occurred_at: self.updated_at,
        });
    }

    /// Whether this is an operator suspending an organization a member has
    /// already suspended, or one suspended for not paying.
    fn platform_takes_over(&self, to: OrganizationStatus, by: ActedBy<OrgControl<'_>>) -> bool {
        let overridable = matches!(
            self.suspended_by,
            Suspension::ByMember(_) | Suspension::ByPlatform(OrgSuspensionReason::NonPayment)
        );
        overridable && to == OrganizationStatus::Suspended && matches!(by, ActedBy::Platform)
    }

    /// Refuses `by` moving the organization to `to` without the right for
    /// it, or lifting a suspension the platform made.
    fn ensure_may_move(
        &self,
        to: OrganizationStatus,
        by: ActedBy<OrgControl<'_>>,
    ) -> Result<(), DomainError> {
        let ActedBy::By(control) = by else {
            return Ok(());
        };
        let action = match to {
            OrganizationStatus::Active | OrganizationStatus::Suspended => {
                OrganizationAction::Suspend
            }
            OrganizationStatus::Closed => OrganizationAction::Close,
        };
        control.ensure_may(&self.id, OrgPermission::Organization(action))?;
        if to == OrganizationStatus::Active
            && matches!(self.suspended_by, Suspension::ByPlatform(_))
        {
            return Err(DomainError::forbidden(message!(
                "organization-the-platform-suspended-this-organization-so",
                "the platform suspended this organization, so only the platform lifts it"
            )));
        }
        Ok(())
    }

    /// Refuses a change to a closed organization.
    ///
    /// Closed is final. Without this, Mallory could add a tenant to Acme
    /// after it closed, or move it to a paid plan nobody pays for.
    fn ensure_open(&self) -> Result<(), DomainError> {
        if self.status == OrganizationStatus::Closed {
            return Err(DomainError::invalid_transition(message!(
                "organization-the-organization-is-closed",
                "the organization is closed"
            )));
        }
        Ok(())
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

/// Organization is a control-plane aggregate root. It owns tenants, billing
/// and work across tenants, and is identified by [`OrganizationId`].
impl Aggregate for Organization {
    /// The organization's unique identifier type.
    type Id = OrganizationId;

    /// The organization's globally unique identifier.
    fn id(&self) -> &Self::Id {
        &self.id
    }

    /// When this organization was created.
    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this organization was last modified.
    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

impl RaisesComplete for Organization {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::organization::access::auth_config::OrganizationAuthSettings;
    use crate::domains::organization::billing::negotiated::NegotiatedLimits;
    use crate::domains::organization::members::control::Carried;
    use crate::domains::organization::members::control::tests::{acting, key_of, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
    };
    use crate::domains::organization::status::{OrgStanding, OrganizationStatus};
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::acme_params;
    use crate::domains::tenant::lifecycle::{ProvisionTenantParams, Tenant};
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::{OrgUserId, Seconds};

    /// A founding for `organization_id`, as if it had just been created.
    /// Only tests make one without creating the organization.
    pub(crate) fn founding_of(organization_id: OrganizationId) -> Founding {
        Founding::of(organization_id, OrganizationPlan::Free)
    }

    /// A tenant of its own, just provisioned, for an organization to take
    /// in.
    fn tenant() -> Tenant {
        tenant_with(TenantId::new())
    }

    /// The tenant `id`, just provisioned, for an organization to take in.
    pub(crate) fn tenant_with(id: TenantId) -> Tenant {
        Tenant::provision(
            ProvisionTenantParams {
                id,
                ..acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap()
    }

    fn org() -> Organization {
        org_on(OrganizationPlan::Free)
    }

    fn org_on(plan: OrganizationPlan) -> Organization {
        founded_on(plan).0
    }

    /// A new organization on `plan`, with the founding it gives.
    fn founded_on(plan: OrganizationPlan) -> (Organization, Founding) {
        Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme Corp").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme Corporation", &DisplayNameLimits::default())
                .unwrap(),
            plan,
        })
        .unwrap()
    }

    /// Someone joining `organization_id` with `role`.
    fn member_params(organization_id: OrganizationId, role: OrgRole) -> CreateOrgUserParams {
        CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id,
            email: Email::new("someone@acme.com").unwrap(),
            display_name: DisplayName::new("Someone", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        }
    }

    /// Someone in `o` with `role`.
    fn person(o: &Organization, role: OrgRole) -> OrgUser {
        let founder = OrgUser::create(
            member_params(o.id, OrgRole::Owner),
            AddedBy::Founding(founding_of(o.id)),
        )
        .unwrap();
        if role == OrgRole::Owner {
            return founder;
        }
        let session = session_of(&founder);
        OrgUser::create(
            member_params(o.id, role),
            AddedBy::Member(acting(&founder, &session)),
        )
        .unwrap()
    }

    /// Acme is founded. Its founding makes Ann its first owner.
    #[test]
    fn a_founding_makes_the_first_owner_of_its_organization() {
        let (acme, founding) = founded_on(OrganizationPlan::Free);

        let ann = OrgUser::create(
            member_params(acme.id, OrgRole::Owner),
            AddedBy::Founding(founding),
        )
        .unwrap();

        assert_eq!(ann.role(), OrgRole::Owner);
        assert_eq!(ann.organization_id(), acme.id());
    }

    /// Globex's founding cannot create an owner for Acme.
    #[test]
    fn a_founding_makes_no_owner_in_another_organization() {
        let (_globex, founding) = founded_on(OrganizationPlan::Free);
        let acme = org();

        let result = OrgUser::create(
            member_params(acme.id, OrgRole::Owner),
            AddedBy::Founding(founding),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The platform takes over an owner's suspension. Her attempt to lift
    /// it is refused, leaving Acme suspended for an operator's reason.
    #[test]
    fn a_platform_suspension_takes_over_an_owners_own() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);
        by(&owner, |c| {
            o.change_status(OrganizationStatus::Suspended, ActedBy::By(*c))
        })
        .unwrap();

        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let lifted = by(&owner, |c| {
            o.change_status(OrganizationStatus::Active, ActedBy::By(*c))
        });

        assert!(matches!(lifted, Err(DomainError::Forbidden(_))));
        assert_eq!(o.status(), OrganizationStatus::Suspended);
        assert_eq!(
            o.suspended_by(),
            Suspension::ByPlatform(OrgSuspensionReason::Operator)
        );
    }

    /// Repeating an operator suspension is an invalid transition and
    /// leaves the operator's suspension in place.
    #[test]
    fn a_second_platform_suspension_is_refused() {
        let mut o = org();
        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        let again = o.change_status(OrganizationStatus::Suspended, ActedBy::Platform);

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert_eq!(
            o.suspended_by(),
            Suspension::ByPlatform(OrgSuspensionReason::Operator)
        );
    }

    /// What `f` gives back when `member` acts through a fresh session.
    fn by<R>(member: &OrgUser, f: impl FnOnce(&OrgControl<'_>) -> R) -> R {
        let session = session_of(member);
        f(&acting(member, &session))
    }

    fn label(name: &str) -> Label {
        Label::new("org_name", name).unwrap()
    }

    fn tightened() -> OrganizationAuthConfig {
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            session_lifetime_secs: Seconds::new(7_200),
            idle_timeout_secs: Seconds::new(900),
            ..OrganizationAuthSettings::default()
        })
        .unwrap()
    }

    /// Ordinary organization creation refuses the self-hosted plan.
    #[test]
    fn an_organization_cannot_be_created_on_the_self_hosted_plan() {
        let refused = Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme Corp").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme Corporation", &DisplayNameLimits::default())
                .unwrap(),
            plan: OrganizationPlan::SelfHosted,
        });

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Acme runs the platform on its own servers. The organization the
    /// installation makes for itself is on the self-hosted plan.
    #[test]
    fn an_installation_creates_its_own_organization_self_hosted() {
        let (own, _) = Organization::create_installation(InstallationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme Corp").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme Corporation", &DisplayNameLimits::default())
                .unwrap(),
        })
        .unwrap();

        assert_eq!(own.plan(), OrganizationPlan::SelfHosted);
    }

    /// Acme signs up on the free plan. Its organization starts active, keeps
    /// the slug, name and plan it was given, and has no tenants.
    #[test]
    fn create_produces_active_org() {
        let o = org();
        assert!(o.status().is_active());
        assert_eq!(o.slug().as_str(), "acme");
        assert_eq!(o.name().as_str(), "Acme Corp");
        assert_eq!(o.plan(), OrganizationPlan::Free);
        assert_eq!(o.tenant_count(), 0);
        assert_eq!(o.suspended_by(), Suspension::NotSuspended);
    }

    /// Acme's owner adds a tenant. It counts one tenant and owns that one.
    #[test]
    fn an_added_tenant_belongs_to_the_organization() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);
        let production = tenant();

        by(&owner, |c| o.add_tenant(&production, ActedBy::By(*c))).unwrap();

        assert_eq!(o.tenant_count(), 1);
        assert!(o.owns_tenant(production.id()));
    }

    /// Sam's member role cannot add a tenant to Acme, which remains without
    /// tenants after the refusal.
    #[test]
    fn a_plain_member_adds_no_tenant() {
        let mut o = org();
        let sam = person(&o, OrgRole::Member);

        let refused = by(&sam, |c| o.add_tenant(&tenant(), ActedBy::By(*c)));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(o.tenant_count(), 0);
    }

    /// The same tenant is added twice, as a retried request would. Acme still
    /// counts it once, so the tenant limit is not used up twice.
    #[test]
    fn add_tenant_is_idempotent() {
        let mut o = org();
        let production = tenant();
        o.add_tenant(&production, ActedBy::Platform).unwrap();
        o.add_tenant(&production, ActedBy::Platform).unwrap();
        assert_eq!(o.tenant_count(), 1);
    }

    /// Free refuses a second tenant, leaving Acme's tenant count at one.
    #[test]
    fn a_tenant_past_the_plan_limit_is_refused() {
        let mut o = org();
        o.add_tenant(&tenant(), ActedBy::Platform).unwrap();

        let refused = o.add_tenant(&tenant(), ActedBy::Platform);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(o.tenant_count(), 1);
    }

    /// Three tenants prevent Acme from changing to Free; it stays on
    /// Business after the refusal.
    #[test]
    fn a_plan_below_the_tenants_in_use_is_refused() {
        let mut o = org_on(OrganizationPlan::Business);
        for _ in 0..3 {
            o.add_tenant(&tenant(), ActedBy::Platform).unwrap();
        }

        let refused = o.change_plan(moved(&o, OrganizationPlan::Free));

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(o.plan(), OrganizationPlan::Business);
    }

    /// Acme removes its only tenant. It counts none and no longer owns it.
    #[test]
    fn a_removed_tenant_no_longer_belongs() {
        let mut o = org();
        let production = tenant();
        o.add_tenant(&production, ActedBy::Platform).unwrap();
        o.remove_tenant(production.id(), ActedBy::Platform).unwrap();
        assert_eq!(o.tenant_count(), 0);
        assert!(!o.owns_tenant(production.id()));
    }

    /// Acme's owner pauses Acme and switches it back on. It reads as
    /// inactive in between and active after.
    #[test]
    fn an_owner_suspends_and_reactivates() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);

        by(&owner, |c| {
            o.change_status(OrganizationStatus::Suspended, ActedBy::By(*c))
        })
        .unwrap();
        assert!(!o.status().is_active());
        assert_eq!(o.suspended_by(), Suspension::ByMember(*owner.id()));
        by(&owner, |c| {
            o.change_status(OrganizationStatus::Active, ActedBy::By(*c))
        })
        .unwrap();
        assert!(o.status().is_active());
        assert_eq!(o.suspended_by(), Suspension::NotSuspended);
    }

    /// An owner cannot lift a platform suspension, leaving Acme inactive.
    /// The platform can then reactivate it.
    #[test]
    fn only_the_platform_lifts_its_own_suspension() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);
        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        let by_owner = by(&owner, |c| {
            o.change_status(OrganizationStatus::Active, ActedBy::By(*c))
        });

        assert!(matches!(by_owner, Err(DomainError::Forbidden(_))));
        assert!(!o.status().is_active());
        o.change_status(OrganizationStatus::Active, ActedBy::Platform)
            .unwrap();
        assert!(o.status().is_active());
    }

    /// Sam's member role cannot close Acme; it remains active.
    #[test]
    fn a_plain_member_cannot_close_the_organization() {
        let mut o = org();
        let sam = person(&o, OrgRole::Member);

        let refused = by(&sam, |c| {
            o.change_status(OrganizationStatus::Closed, ActedBy::By(*c))
        });

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(o.status().is_active());
    }

    /// Acme is closed. Making it active again is refused.
    #[test]
    fn close_is_terminal() {
        let mut o = org();
        o.change_status(OrganizationStatus::Closed, ActedBy::Platform)
            .unwrap();
        assert!(
            o.change_status(OrganizationStatus::Active, ActedBy::Platform)
                .is_err()
        );
    }

    /// Acme Corp's owner renames it Acme Industries. The new name is the one
    /// it reports.
    #[test]
    fn rename_updates_name() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);

        by(&owner, |c| o.rename(label("Acme Industries"), c)).unwrap();

        assert_eq!(o.name().as_str(), "Acme Industries");
    }

    /// A member cannot rename Acme or change its contact email; both
    /// refusals preserve the original values.
    #[test]
    fn a_plain_member_changes_no_profile() {
        let mut o = org();
        let sam = person(&o, OrgRole::Member);

        let renamed = by(&sam, |c| o.rename(label("Sam Corp"), c));
        let recontacted = by(&sam, |c| {
            o.change_contact_email(Email::new("sam@evil.com").unwrap(), c)
        });

        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert!(matches!(recontacted, Err(DomainError::Forbidden(_))));
        assert_eq!(o.name().as_str(), "Acme Corp");
        assert_eq!(o.contact_email().as_str(), "admin@acme.com");
    }

    /// The platform moves Acme from the free plan to Business. It reports
    /// Business.
    #[test]
    fn change_plan_updates_plan() {
        let mut o = org();
        assert_eq!(o.plan(), OrganizationPlan::Free);
        o.change_plan(moved(&o, OrganizationPlan::Business))
            .unwrap();
        assert_eq!(o.plan(), OrganizationPlan::Business);
    }

    /// Moving a Free organization to self-hosted is refused, leaving its
    /// plan unchanged.
    #[test]
    fn change_plan_refuses_to_lift_an_organization_onto_self_hosted() {
        let mut o = org();

        let result = o.change_plan(moved(&o, OrganizationPlan::SelfHosted));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(o.plan(), OrganizationPlan::Free);
    }

    /// Acme is created with a chosen id. It reports that id, both directly
    /// and as an aggregate, so its tenants attach to the right organization.
    #[test]
    fn an_organization_carries_its_own_id() {
        let id = OrganizationId::new();
        let (o, _) = Organization::create(CreateOrganizationParams {
            id,
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme Corp").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme Corporation", &DisplayNameLimits::default())
                .unwrap(),
            plan: OrganizationPlan::Free,
        })
        .unwrap();

        assert_eq!(*o.id(), id);
        assert_eq!(Aggregate::id(&o), o.id());
    }

    /// Acme adds two tenants and then removes the first. It lists exactly the
    /// tenants it still has, in order, and owns no tenant it never added.
    #[test]
    fn an_organization_lists_exactly_the_tenants_it_owns() {
        let mut o = org_on(OrganizationPlan::Business);
        let (staging, production) = (tenant(), tenant());
        let (first, second) = (*staging.id(), *production.id());

        o.add_tenant(&staging, ActedBy::Platform).unwrap();
        o.add_tenant(&production, ActedBy::Platform).unwrap();

        assert_eq!(o.tenant_ids(), &[first, second]);
        assert!(!o.owns_tenant(&TenantId::new()));

        o.remove_tenant(&first, ActedBy::Platform).unwrap();
        assert_eq!(o.tenant_ids(), &[second]);
    }

    /// Acme's owner cuts admin sessions to two hours. The new sign-in
    /// settings are the ones in force.
    #[test]
    fn replacing_the_sign_in_settings_takes_effect() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);

        by(&owner, |c| o.replace_auth_config(tightened(), c)).unwrap();

        assert_eq!(o.auth_config().session_lifetime_secs(), Seconds::new(7_200));
    }

    /// A password session cannot save passkey-only settings that exclude
    /// itself; the existing sign-in settings remain intact.
    #[test]
    fn sign_in_settings_that_shut_out_the_saver_are_refused() {
        let mut o = org();
        let ann = person(&o, OrgRole::Owner);
        let before = o.auth_config().clone();
        let passkeys_only = OrganizationAuthConfig::new(OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Passkey],
            ..OrganizationAuthSettings::default()
        })
        .unwrap();

        let refused = by(&ann, |c| o.replace_auth_config(passkeys_only, c));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(o.auth_config(), &before);
    }

    /// An owner's key cannot replace sign-in settings even with the
    /// matching scope.
    #[test]
    fn a_key_does_not_change_the_sign_in_settings() {
        let mut o = org();
        let ann = person(&o, OrgRole::Owner);
        let key = key_of(&ann, &["org:organization:auth_config"]);
        let by_key = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&key),
        );

        let refused = o.replace_auth_config(tightened(), &by_key);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Acme's owner changes its display name and moves billing mail to
    /// `billing@acme.com`. Both changes are kept.
    #[test]
    fn changing_the_display_name_or_contact_email_takes_effect() {
        let mut o = org();
        let owner = person(&o, OrgRole::Owner);

        by(&owner, |c| {
            o.change_display_name(
                DisplayName::new("Acme Industries", &DisplayNameLimits::default()).unwrap(),
                c,
            )
        })
        .unwrap();
        by(&owner, |c| {
            o.change_contact_email(Email::new("billing@acme.com").unwrap(), c)
        })
        .unwrap();

        assert_eq!(o.display_name().as_str(), "Acme Industries");
        assert_eq!(o.contact_email().as_str(), "billing@acme.com");
    }

    /// Acme changes its plan five minutes after it was created. `updated_at`
    /// moves to that moment and `created_at` stays, so caches see the change.
    #[test]
    fn editing_an_organization_moves_the_timestamp_readers_watch() {
        let mut o = org();
        let created = o.updated_at();
        let later = created + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        o.change_plan(moved(&o, OrganizationPlan::Business))
            .unwrap();

        assert_eq!(o.updated_at(), later);
        assert_eq!(o.created_at(), created);
    }

    fn stored(organization: &Organization) -> OrganizationRow {
        OrganizationRow {
            id: organization.id,
            slug: organization.slug.clone(),
            name: organization.name.clone(),
            contact_email: organization.contact_email.clone(),
            display_name: organization.display_name.clone(),
            plan: organization.plan,
            terms: organization.terms.clone(),
            status: organization.status,
            suspended_by: organization.suspended_by,
            tenant_ids: organization.tenant_ids.clone(),
            auth_config: organization.auth_config.clone(),
            created_at: organization.created_at,
            updated_at: organization.updated_at,
        }
    }

    /// A move of `o` to `plan` on its plan's own limits, as its subscription
    /// would hand it over.
    fn moved(o: &Organization, plan: OrganizationPlan) -> PlanMove {
        PlanMove::assumed(o.id, plan, PlanTerms::Standard)
    }

    /// Limits sales agreed for Acme: Business, with forty tenants.
    fn forty_tenants() -> PlanTerms {
        PlanTerms::Negotiated(
            NegotiatedLimits::new(PlanLimits {
                max_tenants_per_org: 40,
                ..PlanLimits::business()
            })
            .unwrap(),
        )
    }

    /// Acme moves to Custom with forty tenants agreed. Its limits are the
    /// agreed ones, not Business's twenty-five.
    #[test]
    fn a_custom_organization_works_under_its_negotiated_limits() {
        let mut o = org();

        o.change_plan(PlanMove::assumed(
            o.id,
            OrganizationPlan::Custom,
            forty_tenants(),
        ))
        .unwrap();

        assert_eq!(o.limits().max_tenants_per_org, 40);
        assert_eq!(o.terms(), &forty_tenants());
    }

    /// A plan move naming Globex is refused by Acme, which stays on Free.
    #[test]
    fn a_plan_move_for_another_organization_is_refused() {
        let mut acme = org();
        let globex = org();

        let refused = acme.change_plan(moved(&globex, OrganizationPlan::Business));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(acme.plan(), OrganizationPlan::Free);
    }

    /// A stored row holds negotiated limits on the Starter plan. It is
    /// refused as corrupt, since only a Custom plan has its own limits.
    #[test]
    fn a_stored_negotiation_on_a_sold_tier_is_refused() {
        let row = OrganizationRow {
            terms: forty_tenants(),
            ..stored(&org_on(OrganizationPlan::Starter))
        };

        assert!(refused_as_corrupt(&Organization::reconstitute(row)));
    }

    /// A stored row lists the same tenant twice. Loading it is refused as a
    /// corrupt row, since the tenant count would be wrong.
    #[test]
    fn a_stored_organization_counting_a_tenant_twice_is_refused() {
        let tenant = TenantId::new();
        let row = OrganizationRow {
            tenant_ids: vec![tenant, tenant],
            ..stored(&org())
        };

        assert!(refused_as_corrupt(&Organization::reconstitute(row)));
    }

    /// A stored row says Acme is active yet suspended by the platform, or
    /// suspended by nobody. Both are refused as corrupt.
    #[test]
    fn a_stored_suspension_that_does_not_fit_the_status_is_refused() {
        let active_but_held = OrganizationRow {
            suspended_by: Suspension::ByPlatform(OrgSuspensionReason::Operator),
            ..stored(&org())
        };
        let suspended_by_nobody = OrganizationRow {
            status: OrganizationStatus::Suspended,
            ..stored(&org())
        };

        assert!(refused_as_corrupt(&Organization::reconstitute(
            active_but_held
        )));
        assert!(refused_as_corrupt(&Organization::reconstitute(
            suspended_by_nobody
        )));
    }

    fn closed() -> Organization {
        let mut o = org();
        o.change_status(OrganizationStatus::Closed, ActedBy::Platform)
            .unwrap();
        o
    }

    /// Even the platform cannot add a tenant to closed Acme; its tenant
    /// count remains zero.
    #[test]
    fn a_closed_organization_takes_no_new_tenant() {
        let mut o = closed();

        let refused = o.add_tenant(&tenant(), ActedBy::Platform);

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert_eq!(o.tenant_count(), 0);
    }

    /// Closed Acme refuses a move to Business and keeps its Free plan.
    #[test]
    fn a_closed_organization_keeps_its_plan() {
        let mut o = closed();

        let refused = o.change_plan(moved(&o, OrganizationPlan::Business));

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert_eq!(o.plan(), OrganizationPlan::Free);
    }

    /// An owner cannot replace closed Acme's sign-in settings; the original
    /// settings remain in place.
    #[test]
    fn a_closed_organization_keeps_its_sign_in_settings() {
        let mut o = closed();
        let owner = person(&o, OrgRole::Owner);
        let before = o.auth_config().clone();

        let refused = by(&owner, |c| o.replace_auth_config(tightened(), c));

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert_eq!(o.auth_config(), &before);
    }

    /// Closed Acme is renamed, given a new display name and a new contact
    /// email. Each is refused and the old values stay.
    #[test]
    fn a_closed_organization_keeps_its_names_and_contact() {
        let mut o = closed();
        let owner = person(&o, OrgRole::Owner);

        let renamed = by(&owner, |c| o.rename(label("Evil Corp"), c));
        let redisplayed = by(&owner, |c| {
            o.change_display_name(
                DisplayName::new("Evil Corp", &DisplayNameLimits::default()).unwrap(),
                c,
            )
        });
        let recontacted = by(&owner, |c| {
            o.change_contact_email(Email::new("mallory@evil.com").unwrap(), c)
        });

        assert!(renamed.is_err() && redisplayed.is_err() && recontacted.is_err());
        assert_eq!(o.name().as_str(), "Acme Corp");
        assert_eq!(o.display_name().as_str(), "Acme Corporation");
        assert_eq!(o.contact_email().as_str(), "admin@acme.com");
    }

    /// Acme is suspended over a bill. It may still change its plan, so it
    /// can pay and be made active again.
    #[test]
    fn a_suspended_organization_can_still_change_its_plan() {
        let mut o = org();
        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        assert!(o.change_plan(moved(&o, OrganizationPlan::Business)).is_ok());
    }

    /// Closed Acme detaches its last tenant while shutting down. The tenant
    /// is removed.
    #[test]
    fn a_closed_organization_can_still_let_a_tenant_go() {
        let mut o = org();
        let production = tenant();
        o.add_tenant(&production, ActedBy::Platform).unwrap();
        o.change_status(OrganizationStatus::Closed, ActedBy::Platform)
            .unwrap();

        o.remove_tenant(production.id(), ActedBy::Platform).unwrap();

        assert!(!o.owns_tenant(production.id()));
    }

    /// Acme as just founded, with its creation taken out already.
    fn fresh_org() -> Organization {
        let mut o = org_on(OrganizationPlan::Business);
        raised_complete_names(&mut o);
        o
    }

    /// Acme is founded. Its creation is raised, naming it by its name.
    #[test]
    fn founding_raises_organization_created() {
        let mut o = org();

        let events = o.take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "organization.created");
        assert_eq!(events[0].organization_id(), Some(o.id()));
        assert_eq!(events[0].payload().get("name"), Some("Acme Corp"));
    }

    /// Acme takes in a tenant, and is asked to take it in again. The first
    /// raises the tenant's creation under its name; the second raises
    /// nothing.
    #[test]
    fn adding_a_tenant_raises_it_once() {
        let mut o = fresh_org();
        let production = tenant();

        o.add_tenant(&production, ActedBy::Platform).unwrap();
        o.add_tenant(&production, ActedBy::Platform).unwrap();

        let events = o.take_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "organization.tenant_created"
        );
        let payload = events[0].payload();
        let Some(FieldValue::Reference(named)) = payload.value("tenant") else {
            panic!("the tenant is not referenced");
        };
        assert_eq!(named.label(), production.display_name().as_str());
    }

    /// Acme's owner renames Acme, changes its display name, contact address
    /// and sign-in settings, and the platform moves it to another plan and
    /// suspends it. Each change is raised, in order.
    #[test]
    fn every_change_raises_its_record() {
        let mut o = fresh_org();
        let owner = person(&o, OrgRole::Owner);

        by(&owner, |c| {
            o.rename(label("Acme Inc"), c)?;
            o.change_display_name(
                DisplayName::new("Acme Inc", &DisplayNameLimits::default()).unwrap(),
                c,
            )?;
            o.change_contact_email(Email::new("ops@acme.com").unwrap(), c)?;
            o.replace_auth_config(tightened(), c)
        })
        .unwrap();
        o.change_plan(moved(&o, OrganizationPlan::Custom)).unwrap();
        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        assert_eq!(
            raised_complete_names(&mut o),
            [
                "organization.renamed",
                "organization.display_name_changed",
                "organization.contact_email_changed",
                "organization.auth_config_updated",
                "organization.plan_changed",
                "organization.status_changed",
            ]
        );
    }

    /// Acme is renamed from Acme Corp. The record keeps the name it had.
    #[test]
    fn a_rename_records_the_name_it_replaced() {
        let mut o = fresh_org();
        let owner = person(&o, OrgRole::Owner);

        by(&owner, |c| o.rename(label("Acme Inc"), c)).unwrap();

        let payload = o.take_events()[0].payload();
        let Some(FieldValue::Change(name)) = payload.value("name") else {
            panic!("expected a name change");
        };
        assert_eq!(name.from(), Some("Acme Corp"));
        assert_eq!(name.to(), Some("Acme Inc"));
    }

    /// Acme's owner suspended it, and the platform takes the suspension
    /// over. The status stays suspended, and the takeover is still raised.
    #[test]
    fn a_platform_takeover_raises_a_status_change() {
        let mut o = fresh_org();
        let owner = person(&o, OrgRole::Owner);
        by(&owner, |c| {
            o.change_status(OrganizationStatus::Suspended, ActedBy::By(*c))
        })
        .unwrap();
        raised_complete_names(&mut o);

        o.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        assert_eq!(
            raised_complete_names(&mut o),
            ["organization.status_changed"]
        );
    }

    /// Refusing a member's rename and tenant-addition attempts raises no
    /// organization events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut o = fresh_org();
        let sam = person(&o, OrgRole::Member);

        let renamed = by(&sam, |c| o.rename(label("Mallory Corp"), c));
        let added = by(&sam, |c| o.add_tenant(&tenant(), ActedBy::By(*c)));

        assert!(renamed.is_err());
        assert!(added.is_err());
        assert!(raised_complete_names(&mut o).is_empty());
    }

    /// Acme is read back from storage. Loading it is no change, so it has
    /// raised nothing.
    #[test]
    fn an_organization_read_back_from_storage_has_raised_nothing() {
        let mut o = Organization::reconstitute(stored(&org())).unwrap();

        assert!(raised_complete_names(&mut o).is_empty());
    }
}
