//! The tenant aggregate: what it is made of, and how it is created and read
//! back.
//!
//! How it moves through its life is in `moves.rs`, and how its settings
//! change is in `settings.rs`.

mod moves;
mod settings;

pub use moves::EarlyDeletion;
use time::OffsetDateTime;

use crate::domains::tenant::access::auth_config::TenantAuthConfig;
use crate::domains::tenant::access::network_security::MtlsConfig;
use crate::domains::tenant::compliance::CompliancePosture;
use crate::domains::tenant::compliance_limits::ComplianceLimits;
use crate::domains::tenant::control::{LifecycleStep, Steward, ensure_may_take};
use crate::domains::tenant::environment::TenantEnvironment;
use crate::domains::tenant::events::lifecycle::TenantProvisioned;
use crate::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
use crate::domains::tenant::provisioning::infrastructure::TenantResidency;
use crate::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete, TenantEventBody};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    DisplayName, DomainName, Email, EventLabel, Locale, OrganizationId, Setting, TenantId,
    TenantSlug, Timezone,
};

/// Parameters for provisioning a new tenant.
///
/// A new tenant has no primary domain. A domain becomes primary only once
/// the tenant has proved it owns it, see
/// [`change_primary_domain`](Tenant::change_primary_domain).
pub struct ProvisionTenantParams {
    /// Globally unique identifier.
    pub id: TenantId,
    /// A securely generated label independent of this tenant's identifier.
    pub platform_label: PlatformLabel,
    /// The organization that owns this tenant.
    pub organization_id: OrganizationId,
    /// URL-safe slug for subdomains and API paths.
    pub slug: TenantSlug,
    /// Tenant name shown in admin UIs.
    pub display_name: DisplayName,
    /// Where billing and security notices for the tenant go.
    pub contact_email: Email,
    /// The IANA timezone times are shown in, such as `"America/New_York"`.
    pub timezone: Timezone,
    /// The locale of login pages and emails, such as `"en-US"`.
    pub locale: Locale,
    /// Where this tenant's data lives. It is chosen at creation and then
    /// fixed. Moving a tenant is a data migration, not an edit.
    pub residency: TenantResidency,
}

/// Stored fields of a [`Tenant`], read back by repositories.
pub struct TenantRow {
    /// Globally unique tenant identifier.
    pub id: TenantId,
    /// The organization that owns this tenant.
    pub organization_id: OrganizationId,
    /// URL-safe slug used in subdomains and API paths.
    pub slug: TenantSlug,
    /// Permanent random label, independent of the tenant's id and names.
    pub platform_label: PlatformLabel,
    /// Explicit consent to publishing the tenant's readable address.
    pub readable_address: ReadableAddress,
    /// Tenant name shown in admin UIs and branding.
    pub display_name: DisplayName,
    /// The tenant's primary domain, if one has been configured.
    pub primary_domain: Setting<DomainName>,
    /// Contact email for tenant-level notifications.
    pub contact_email: Email,
    /// Current lifecycle status.
    pub status: TenantStatus,
    /// Whether the platform holds the tenant out of service.
    pub hold: PlatformHold,
    /// Whether the tenant was archived, and when.
    pub archival: Archival,
    /// Per-tenant compliance requirements.
    pub compliance: CompliancePosture,
    /// Per-tenant authentication configuration.
    pub auth_config: TenantAuthConfig,
    /// Per-tenant mTLS trust anchor.
    pub mtls: MtlsConfig,
    /// IANA timezone identifier.
    pub timezone: Timezone,
    /// Locale for the tenant's login pages and emails.
    pub locale: Locale,
    /// Where this tenant's data lives.
    pub residency: TenantResidency,
    /// The stage of the product this tenant serves.
    pub environment: TenantEnvironment,
    /// When this tenant was provisioned.
    pub created_at: OffsetDateTime,
    /// When this tenant was last modified.
    pub updated_at: OffsetDateTime,
}

/// A tenant: one isolated set of users, settings and data inside an
/// organization.
///
/// It moves from provisioning through activation, suspension and archival
/// to deletion. Every move is checked by [`TenantStatus`] and names who
/// makes it. Every settings change names the person making it and needs
/// their right for it. Each field is a checked type such as `DisplayName`
/// or `CompliancePosture`, so the tenant does not check them again.
///
/// This is a control-plane entity. Tenant-plane entities like `User<T>` and
/// `Session<T>` refer to it through [`TenantId`] and
/// [`TenantScope`](crate::isolation::scope::TenantScope), never through this
/// type.
///
/// It raises its own records as it changes, each filed under the tenant it
/// is, and hands them over through [`RaisesComplete`] once it is saved.
#[derive(Debug, Clone)]
pub struct Tenant {
    id: TenantId,
    organization_id: OrganizationId,
    slug: TenantSlug,
    platform_label: PlatformLabel,
    readable_address: ReadableAddress,
    display_name: DisplayName,
    primary_domain: Setting<DomainName>,
    contact_email: Email,
    status: TenantStatus,
    hold: PlatformHold,
    archival: Archival,
    compliance: CompliancePosture,
    auth_config: TenantAuthConfig,
    mtls: MtlsConfig,
    timezone: Timezone,
    locale: Locale,
    residency: TenantResidency,
    environment: TenantEnvironment,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl Tenant {
    /// Creates a new tenant in the `Provisioning` state, as `by` decides:
    /// the platform, or a member of the owning organization with the right
    /// to create tenants.
    ///
    /// A tenant is billed to its organization and its first admin reaches
    /// all it holds. Sam is a plain member of Acme. Without this check, he
    /// makes a tenant of his own on Acme's bill.
    ///
    /// Default roles, sign-in settings and signing keys are set up next. The
    /// platform makes the tenant `Active` once they are done.
    ///
    /// The placement must meet the data residency the deployment requires.
    /// So no tenant can claim EU residency while its data lives in the US.
    ///
    /// Raises `tenant.provisioned`. The organization's own record of its new
    /// tenant is its own to raise, since the tenant context sits below it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is a member of another
    ///   organization, or one without the right to create tenants.
    /// - [`DomainError::Validation`] when the placement's region lies
    ///   outside the required residency. See
    ///   [`TenantResidency::satisfies_declared_residency`].
    pub fn provision(
        params: ProvisionTenantParams,
        compliance_limits: &ComplianceLimits,
        by: Steward<'_>,
    ) -> Result<Self, DomainError> {
        ensure_may_take(by, &params.organization_id, LifecycleStep::Provision)?;
        let compliance = Self::initial_compliance(&params, compliance_limits)?;
        let now = crate::shared::clock::now();
        let mut tenant = Self {
            id: params.id,
            organization_id: params.organization_id,
            slug: params.slug,
            platform_label: params.platform_label,
            readable_address: ReadableAddress::Off,
            display_name: params.display_name,
            primary_domain: Setting::Unset,
            contact_email: params.contact_email,
            status: TenantStatus::Provisioning,
            hold: PlatformHold::Free,
            archival: Archival::NotArchived,
            compliance,
            auth_config: TenantAuthConfig::default(),
            mtls: MtlsConfig::disabled(),
            timezone: params.timezone,
            locale: params.locale,
            residency: params.residency,
            environment: TenantEnvironment::Production,
            created_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        };
        tenant.raise_provisioned();
        Ok(tenant)
    }

    /// Applies deployment defaults only when the chosen placement meets them.
    fn initial_compliance(
        params: &ProvisionTenantParams,
        limits: &ComplianceLimits,
    ) -> Result<CompliancePosture, DomainError> {
        let compliance = CompliancePosture::default_from(limits);
        params
            .residency
            .satisfies_declared_residency(compliance.data_residency())?;
        Ok(compliance)
    }

    /// Raises the tenant's coming into existence.
    fn raise_provisioned(&mut self) {
        self.raise(TenantProvisioned {
            tenant_id: self.id,
            slug: self.slug.clone(),
            display_name: self.display_name.clone(),
            occurred_at: self.created_at,
        });
    }

    /// Rebuilds a tenant from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row places the tenant
    ///   outside the residency it requires, or says it changed before it
    ///   was provisioned.
    /// - [`DomainError::Infrastructure`] when the row holds an open tenant
    ///   for the platform, or has an archive time its status does not have.
    /// - [`DomainError::Infrastructure`] when the row's primary domain is a
    ///   wildcard, which no tenant can prove it owns.
    pub fn reconstitute(row: TenantRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            slug: row.slug,
            platform_label: row.platform_label,
            readable_address: row.readable_address,
            display_name: row.display_name,
            primary_domain: row.primary_domain,
            contact_email: row.contact_email,
            status: row.status,
            hold: row.hold,
            archival: row.archival,
            compliance: row.compliance,
            auth_config: row.auth_config,
            mtls: row.mtls,
            timezone: row.timezone,
            locale: row.locale,
            residency: row.residency,
            environment: row.environment,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &TenantRow) -> Result<(), DomainError> {
        RowCheck::of("tenant")
            .holds(
                !row.primary_domain
                    .value()
                    .is_some_and(DomainName::is_wildcard),
                "a wildcard primary domain",
            )
            .holds(
                row.residency
                    .satisfies_declared_residency(row.compliance.data_residency())
                    .is_ok(),
                "a placement outside the residency it requires",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was provisioned",
            )
            .finish()?;
        Self::ensure_status_consistent(row)
    }

    /// Refuses a stored row whose hold or archive time its status does not
    /// have.
    fn ensure_status_consistent(row: &TenantRow) -> Result<(), DomainError> {
        let archived = matches!(row.status, TenantStatus::Archived | TenantStatus::Deleted);
        let out_of_service = archived || row.status == TenantStatus::Suspended;
        RowCheck::of("tenant")
            .holds(
                row.hold == PlatformHold::Free || out_of_service,
                "held by the platform while open",
            )
            .holds(
                row.archival.at().is_some() == archived,
                "an archive time its status does not have",
            )
            .in_order_if(
                row.created_at,
                row.archival.at(),
                "archived before it was provisioned",
            )
            .finish()
    }

    /// Globally unique tenant identifier.
    #[must_use]
    pub fn id(&self) -> &TenantId {
        &self.id
    }

    /// The organization that owns this tenant.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// URL-safe slug used in subdomains and API paths.
    #[must_use]
    pub fn slug(&self) -> &TenantSlug {
        &self.slug
    }

    /// The permanent random platform label, unchanged by settings clones.
    #[must_use]
    pub fn platform_label(&self) -> &PlatformLabel {
        &self.platform_label
    }

    /// Whether the tenant explicitly enabled its public readable address.
    #[must_use]
    pub fn readable_address(&self) -> ReadableAddress {
        self.readable_address
    }

    /// Tenant name shown in admin UIs and branding.
    #[must_use]
    pub fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    /// The tenant's primary domain, used for email routing and federation
    /// domain hints. `None` when none is set.
    #[must_use]
    pub fn primary_domain(&self) -> Option<&DomainName> {
        self.primary_domain.value()
    }

    /// Contact email for tenant-level notifications.
    #[must_use]
    pub fn contact_email(&self) -> &Email {
        &self.contact_email
    }

    /// Where the tenant is in its lifecycle.
    #[must_use]
    pub fn status(&self) -> TenantStatus {
        self.status
    }

    /// Whether the platform holds the tenant out of service, so only the
    /// platform brings it back.
    #[must_use]
    pub fn hold(&self) -> PlatformHold {
        self.hold
    }

    /// Whether the tenant was archived, and when.
    #[must_use]
    pub fn archival(&self) -> Archival {
        self.archival
    }

    /// The tenant's audit retention, data residency and impersonation rule.
    #[must_use]
    pub fn compliance(&self) -> &CompliancePosture {
        &self.compliance
    }

    /// The tenant's sign-in settings: MFA policy, methods and session rules.
    #[must_use]
    pub fn auth_config(&self) -> &TenantAuthConfig {
        &self.auth_config
    }

    /// Per-tenant mTLS trust anchor for verifying inbound client certificates.
    #[must_use]
    pub fn mtls(&self) -> &MtlsConfig {
        &self.mtls
    }

    /// The IANA timezone, such as `"America/New_York"`.
    #[must_use]
    pub fn timezone(&self) -> &Timezone {
        &self.timezone
    }

    /// The locale of the tenant's login pages and emails, such as `"en-US"`.
    #[must_use]
    pub fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Where this tenant's data lives.
    ///
    /// Read by provisioning to decide what to create, and by the pool
    /// resolver to decide where a query goes.
    #[must_use]
    pub fn residency(&self) -> &TenantResidency {
        &self.residency
    }

    /// The stage of the product this tenant serves. Every tenant starts as
    /// production.
    #[must_use]
    pub fn environment(&self) -> TenantEnvironment {
        self.environment
    }

    /// When this tenant was provisioned.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this tenant was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// Keeps `event` as one of this tenant's own records until it is taken.
    fn raise(&mut self, event: impl TenantEventBody + 'static) {
        self.raised.raise_tenant(self.id, event);
    }

    /// The tenant's name as its records show it.
    fn label(&self) -> EventLabel {
        EventLabel::of(self.display_name.as_str())
    }
}

/// The tenant's records are its own: each is filed under the tenant it is,
/// so taking them needs no scope.
impl RaisesComplete for Tenant {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// A tenant is a top-level aggregate, identified by [`TenantId`].
impl Aggregate for Tenant {
    /// The tenant's unique identifier type.
    type Id = TenantId;

    /// The tenant's globally unique identifier.
    fn id(&self) -> &Self::Id {
        &self.id
    }

    /// When this tenant was provisioned.
    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this tenant was last modified.
    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance::{DataResidency, OperatorImpersonation, Residency};
    use crate::domains::tenant::compliance_limits::ComplianceLimitsParams;
    use crate::domains::tenant::fixtures::{Member, acme_params, provisioned};
    use crate::domains::tenant::provisioning::infrastructure::DeploymentRegion;
    use crate::shared::config::DomainLimits;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::ActedBy;

    /// Provisioning in `us-east-1` is refused when deployment limits require
    /// EU data residency.
    #[test]
    fn a_placement_outside_the_required_residency_is_refused() {
        let eu_only = ComplianceLimits::new(ComplianceLimitsParams {
            default_data_residency: Residency::Within(DataResidency::Eu),
            ..ComplianceLimitsParams::default()
        })
        .unwrap();

        let refused = Tenant::provision(
            ProvisionTenantParams {
                residency: TenantResidency::shared_on_platform(DeploymentRegion::UsEast1),
                ..acme_params()
            },
            &eu_only,
            ActedBy::Platform,
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Provisioning rejects a member with only suspension rights and a member
    /// of another organization. A member with creation rights succeeds.
    #[test]
    fn only_a_member_who_may_create_tenants_provisions_one() {
        let params = acme_params();
        let acme = params.organization_id;
        let sam = Member::of_organization(acme, &[LifecycleStep::Suspend]);
        let eve = Member::elsewhere();
        let creator = Member::of_organization(acme, &[LifecycleStep::Provision]);
        let limits = ComplianceLimits::default();

        let by_sam = Tenant::provision(acme_params_for(acme), &limits, ActedBy::By(&sam));
        let by_eve = Tenant::provision(acme_params_for(acme), &limits, ActedBy::By(&eve));
        let by_creator = Tenant::provision(params, &limits, ActedBy::By(&creator));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_eve, Err(DomainError::Forbidden(_))));
        assert!(by_creator.is_ok());
    }

    fn acme_params_for(organization_id: OrganizationId) -> ProvisionTenantParams {
        ProvisionTenantParams {
            organization_id,
            ..acme_params()
        }
    }

    /// Acme Corp is provisioned. It starts in `Provisioning`, free of any
    /// hold, with no primary domain, and keeps the name, slug, contact,
    /// timezone and locale it was given.
    #[test]
    fn provision_creates_in_provisioning_state() {
        let tenant = provisioned();

        assert_eq!(tenant.status(), TenantStatus::Provisioning);
        assert_eq!(tenant.hold(), PlatformHold::Free);
        assert_eq!(tenant.archival(), Archival::NotArchived);
        assert_eq!(tenant.primary_domain(), None);
        assert_eq!(tenant.display_name().as_str(), "Acme Corp");
        assert_eq!(tenant.slug().as_str(), "acme");
        assert_eq!(tenant.contact_email().as_str(), "admin@acme.com");
        assert_eq!(tenant.timezone().as_str(), "UTC");
        assert_eq!(tenant.locale().as_str(), "en-US");
    }

    /// Acme Corp is provisioned without saying which stage it serves. It
    /// starts as production.
    #[test]
    fn a_new_tenant_serves_production() {
        assert_eq!(provisioned().environment(), TenantEnvironment::Production);
    }

    /// A tenant provisioned under the default limits may keep data anywhere,
    /// keeps audit events for 365 days and forbids impersonation.
    #[test]
    fn provision_sets_default_compliance() {
        let tenant = provisioned();
        let compliance = tenant.compliance();

        assert_eq!(compliance.data_residency(), Residency::Anywhere);
        assert_eq!(compliance.audit_retention_days(), 365);
        assert_eq!(
            compliance.operator_impersonation(),
            OperatorImpersonation::Forbidden
        );
    }

    /// A new tenant's created time falls within the call, and its
    /// last-changed time equals it.
    #[test]
    fn provision_sets_timestamps() {
        let before = crate::shared::clock::now();
        let tenant = provisioned();
        let after = crate::shared::clock::now();

        assert!(tenant.created_at() >= before);
        assert!(tenant.created_at() <= after);
        assert_eq!(tenant.created_at(), tenant.updated_at());
    }

    /// A new tenant has mutual TLS turned off and trusts no CA certificate.
    #[test]
    fn provision_defaults_to_mtls_disabled() {
        let tenant = provisioned();
        assert_eq!(
            tenant.mtls().mode(),
            crate::domains::tenant::access::network_security::MtlsMode::Disabled
        );
        assert!(tenant.mtls().trusted_ca_certs().is_empty());
    }

    /// Acme is provisioned under a given organization and id. It keeps both,
    /// and the aggregate id matches, so billing and admin find the right
    /// owner.
    #[test]
    fn a_tenant_names_its_organization_and_carries_its_own_id() {
        let id = TenantId::new();
        let organization = OrganizationId::new();

        let tenant = Tenant::provision(
            ProvisionTenantParams {
                id,
                organization_id: organization,
                ..acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap();

        assert_eq!(*tenant.organization_id(), organization);
        assert_eq!(*tenant.id(), id);
        assert_eq!(Aggregate::id(&tenant), tenant.id());
    }

    fn stored_requiring(bloc: DataResidency, id: TenantId) -> TenantRow {
        let c = DomainLimits::default();
        let now = crate::shared::clock::now();
        TenantRow {
            id,
            organization_id: OrganizationId::new(),
            slug: TenantSlug::new("globex", &c.slug).unwrap(),
            platform_label: PlatformLabel::new("k7f3q9").unwrap(),
            readable_address: ReadableAddress::Off,
            display_name: DisplayName::new("Globex Corp", &c.display_name).unwrap(),
            primary_domain: Setting::Set(DomainName::new("globex.com").unwrap()),
            contact_email: Email::new("admin@globex.com").unwrap(),
            status: TenantStatus::Active,
            hold: PlatformHold::Free,
            archival: Archival::NotArchived,
            compliance: CompliancePosture::new(
                Residency::Within(bloc),
                730,
                OperatorImpersonation::Forbidden,
                &ComplianceLimits::default(),
            )
            .unwrap(),
            auth_config: TenantAuthConfig::default(),
            mtls: MtlsConfig::disabled(),
            timezone: Timezone::new("America/Chicago").unwrap(),
            locale: Locale::new("en-US").unwrap(),
            residency: TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1),
            environment: TenantEnvironment::Staging,
            created_at: now,
            updated_at: now,
        }
    }

    /// Globex is read back from a stored row. Its id, slug, domain, contact,
    /// status and timezone come back as stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let id = TenantId::new();

        let tenant = Tenant::reconstitute(stored_requiring(DataResidency::Eu, id)).unwrap();

        assert_eq!(*tenant.id(), id);
        assert_eq!(tenant.slug().as_str(), "globex");
        assert_eq!(
            tenant.primary_domain().map(DomainName::as_str),
            Some("globex.com")
        );
        assert_eq!(tenant.contact_email().as_str(), "admin@globex.com");
        assert_eq!(tenant.status(), TenantStatus::Active);
        assert_eq!(tenant.timezone().as_str(), "America/Chicago");
        assert_eq!(tenant.environment(), TenantEnvironment::Staging);
    }

    /// A stored tenant requiring US residency while placed in Frankfurt is
    /// rejected as corrupt.
    #[test]
    fn a_stored_tenant_placed_outside_its_residency_is_refused() {
        let row = stored_requiring(DataResidency::Us, TenantId::new());

        assert!(refused_as_corrupt(&Tenant::reconstitute(row)));
    }

    /// An active tenant with a stored platform hold is rejected as corrupt.
    #[test]
    fn a_stored_open_tenant_held_by_the_platform_is_refused() {
        let row = TenantRow {
            hold: PlatformHold::Held,
            ..stored_requiring(DataResidency::Eu, TenantId::new())
        };

        assert!(refused_as_corrupt(&Tenant::reconstitute(row)));
    }

    /// An archived row without an archive time and an active row with one are
    /// both rejected as corrupt.
    #[test]
    fn a_stored_archive_time_must_match_the_status() {
        let now = crate::shared::clock::now();
        let archived_without_time = TenantRow {
            status: TenantStatus::Archived,
            ..stored_requiring(DataResidency::Eu, TenantId::new())
        };
        let active_with_time = TenantRow {
            archival: Archival::Since(now),
            ..stored_requiring(DataResidency::Eu, TenantId::new())
        };

        assert!(refused_as_corrupt(&Tenant::reconstitute(
            archived_without_time
        )));
        assert!(refused_as_corrupt(&Tenant::reconstitute(active_with_time)));
    }

    /// Reconstitution rejects a wildcard primary domain as corrupt storage.
    #[test]
    fn a_stored_wildcard_primary_domain_is_refused() {
        let row = TenantRow {
            primary_domain: Setting::Set(DomainName::new("*.globex.com").unwrap()),
            ..stored_requiring(DataResidency::Eu, TenantId::new())
        };

        assert!(refused_as_corrupt(&Tenant::reconstitute(row)));
    }

    /// The platform provisions Acme Corp. It raises `tenant.provisioned`,
    /// filed under the new tenant, with its slug.
    #[test]
    fn provisioning_raises_tenant_provisioned() {
        let mut tenant = provisioned();

        let events = tenant.take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "tenant.provisioned");
        assert_eq!(events[0].tenant_id(), Some(tenant.id()));
        assert_eq!(events[0].payload().get("slug"), Some("acme"));
    }

    /// A member with only suspension rights cannot provision a tenant.
    #[test]
    fn a_refused_provisioning_raises_nothing() {
        let params = acme_params();
        let sam = Member::of_organization(params.organization_id, &[LifecycleStep::Suspend]);

        let refused = Tenant::provision(params, &ComplianceLimits::default(), ActedBy::By(&sam));

        assert!(refused.is_err());
    }

    /// Globex is read back from storage. Loading it is no change, so it has
    /// raised nothing.
    #[test]
    fn a_tenant_read_back_from_storage_has_raised_nothing() {
        let row = stored_requiring(DataResidency::Eu, TenantId::new());

        let mut stored = Tenant::reconstitute(row).unwrap();

        assert!(raised_complete_names(&mut stored).is_empty());
    }
}
