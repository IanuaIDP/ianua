//! A tenant as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
use ianua_domain::domains::tenant::provisioning::infrastructure::{Placement, TenantResidency};
use ianua_domain::domains::tenant::status::{Archival, PlatformHold};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    DisplayName, DomainName, Email, Locale, OrganizationId, Setting, TenantId, TenantSlug, Timezone,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const TENANT: Stored = Stored("tenant");

const COMPLIANCE: Kept = Kept {
    entity: TENANT.0,
    column: "compliance",
    shape: 1,
};

const AUTH_CONFIG: Kept = Kept {
    entity: TENANT.0,
    column: "auth_config",
    shape: 1,
};

const MTLS: Kept = Kept {
    entity: TENANT.0,
    column: "mtls",
    shape: 1,
};

const RESIDENCY: Kept = Kept {
    entity: TENANT.0,
    column: "residency",
    shape: 1,
};

/// A tenant as it is read. The store's checked queries fill it.
pub(super) struct TenantRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) slug: String,
    pub(super) platform_label: String,
    pub(super) readable_address: bool,
    pub(super) display_name: String,
    pub(super) primary_domain: Option<String>,
    pub(super) contact_email: String,
    pub(super) status: String,
    pub(super) held: bool,
    pub(super) archived_at: Option<OffsetDateTime>,
    pub(super) compliance: Value,
    pub(super) auth_config: Value,
    pub(super) mtls: Value,
    pub(super) timezone: String,
    pub(super) locale: String,
    pub(super) residency: Value,
    pub(super) environment: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl TenantRecord {
    /// The tenant the record holds, rebuilt through the domain's checks,
    /// each name checked against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the tenant
    /// keeps.
    pub(super) fn into_tenant(self, limits: &DomainLimits) -> Result<Tenant, DomainError> {
        let readable_address = self.readable_address();
        let primary_domain = primary_domain_from(self.primary_domain)?;
        Tenant::reconstitute(TenantRow {
            id: TenantId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            slug: TENANT.value("slug", TenantSlug::new(self.slug, &limits.slug))?,
            platform_label: TENANT
                .value("platform label", PlatformLabel::new(self.platform_label))?,
            readable_address,
            display_name: TENANT.value(
                "display name",
                DisplayName::new(self.display_name, &limits.display_name),
            )?,
            primary_domain: Setting::from_stored(primary_domain),
            contact_email: TENANT.value("contact email", Email::new(self.contact_email))?,
            status: TENANT.choice(&self.status)?,
            hold: PlatformHold::from(self.held),
            archival: Archival::from_stored(self.archived_at),
            compliance: COMPLIANCE.open(self.compliance)?,
            auth_config: AUTH_CONFIG.open(self.auth_config)?,
            mtls: MTLS.open(self.mtls)?,
            timezone: TENANT.value("timezone", Timezone::new(self.timezone))?,
            locale: TENANT.value("locale", Locale::new(self.locale))?,
            residency: RESIDENCY.open(self.residency)?,
            environment: TENANT.choice(&self.environment)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// Reads this row's publication choice, leaving unpublished readable addresses off.
    fn readable_address(&self) -> ReadableAddress {
        if self.readable_address {
            ReadableAddress::On
        } else {
            ReadableAddress::Off
        }
    }
}

/// Validates a stored primary domain while preserving the absence of a custom domain.
fn primary_domain_from(domain: Option<String>) -> Result<Option<DomainName>, DomainError> {
    domain
        .map(|domain| TENANT.value("primary domain", DomainName::new(domain)))
        .transpose()
}

/// A tenant's columns, as they are written.
pub(super) struct TenantColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) slug: &'a str,
    pub(super) platform_label: &'a str,
    pub(super) readable_address: bool,
    pub(super) display_name: &'a str,
    pub(super) primary_domain: Option<&'a str>,
    pub(super) contact_email: &'a str,
    pub(super) status: &'static str,
    pub(super) held: bool,
    pub(super) archived_at: Option<OffsetDateTime>,
    pub(super) compliance: Value,
    pub(super) auth_config: Value,
    pub(super) mtls: Value,
    pub(super) timezone: &'a str,
    pub(super) locale: &'a str,
    pub(super) residency: Value,
    pub(super) customer_cloud: Option<&'static str>,
    pub(super) environment: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> TenantColumns<'a> {
    /// The columns `tenant` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON.
    pub(super) fn of(tenant: &'a Tenant) -> Result<Self, DomainError> {
        Ok(Self {
            id: tenant.id().as_uuid(),
            organization_id: tenant.organization_id().as_uuid(),
            slug: tenant.slug().as_str(),
            platform_label: tenant.platform_label().as_str(),
            readable_address: tenant.readable_address() == ReadableAddress::On,
            display_name: tenant.display_name().as_str(),
            primary_domain: tenant.primary_domain().map(DomainName::as_str),
            contact_email: tenant.contact_email().as_str(),
            status: tenant.status().word(),
            held: tenant.hold().into(),
            archived_at: tenant.archival().at(),
            compliance: COMPLIANCE.seal(tenant.compliance())?,
            auth_config: AUTH_CONFIG.seal(tenant.auth_config())?,
            mtls: MTLS.seal(tenant.mtls())?,
            timezone: tenant.timezone().as_str(),
            locale: tenant.locale().as_str(),
            residency: RESIDENCY.seal(tenant.residency())?,
            customer_cloud: customer_cloud_of(tenant.residency()),
            environment: tenant.environment().word(),
            created_at: tenant.created_at(),
            updated_at: tenant.updated_at(),
        })
    }
}

/// The customer's own cloud `residency` places the tenant in, if any.
fn customer_cloud_of(residency: &TenantResidency) -> Option<&'static str> {
    match residency.placement() {
        Placement::CustomerCloud { provider, .. } => Some(provider.word()),
        Placement::Platform { .. } | Placement::CustomerDatabase => None,
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;
    use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
    use ianua_domain::domains::tenant::compliance::CompliancePosture;
    use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
    use ianua_domain::domains::tenant::provisioning::infrastructure::DeploymentRegion;
    use serde_json::json;

    use super::*;

    /// Pins the password policy's nested storage shape independently of other sign-in settings.
    fn stored_password_policy() -> Value {
        json!({
            "hygiene": {
                "common_passwords": true,
                "expiry": "Never",
                "personal_data": true,
                "reuse": 0
            },
            "min_length": 12,
            "require": {"digit": true, "lowercase": true, "special": false, "uppercase": true}
        })
    }

    /// The compliance posture is written in the shape pinned here, and a
    /// row in that shape reads back.
    #[test]
    fn the_compliance_posture_is_stored_in_its_pinned_shape() {
        let posture = CompliancePosture::default_from(&ComplianceLimits::default());
        let stored = json!({"v": 1, "value": {
            "allow_operator_impersonation": false,
            "audit_retention_days": 365,
            "data_residency": null,
            "older_records": "SameRetention"
        }});

        assert_eq!(COMPLIANCE.seal(&posture).unwrap(), stored);
        assert_eq!(
            COMPLIANCE.open::<CompliancePosture>(stored).unwrap(),
            posture
        );
    }

    /// The sign-in configuration is written in the shape pinned here, and
    /// a row in that shape reads back.
    #[test]
    fn the_auth_config_is_stored_in_its_pinned_shape() {
        let config = TenantAuthConfig::default();
        let stored = json!({"v": 1, "value": {
            "breached_passwords": "Block",
            "challenge_threshold": 200,
            "enabled_methods": ["Password", "Passkey"],
            "idle_timeout_secs": 3600,
            "impersonation_consent": "HolderApproves",
            "ip_allowlist": [],
            "lockout_duration_secs": 900,
            "max_login_attempts": 10,
            "mfa_policy": "Disabled",
            "password_policy": stored_password_policy(),
            "second_factors": ["Totp"],
            "self_registration": false,
            "session_lifetime_secs": 28800,
            "step_up_policy": {
                "baseline_aal": "Aal1",
                "deny_risk_threshold": "Critical",
                "mfa_risk_threshold": "Critical",
                "require_mfa_new_country": false,
                "require_mfa_new_device": false,
                "sensitive_aal": "Aal2"
            }
        }});

        assert_eq!(AUTH_CONFIG.seal(&config).unwrap(), stored);
        assert_eq!(
            AUTH_CONFIG.open::<TenantAuthConfig>(stored).unwrap(),
            config
        );
    }

    /// The client certificate setting is written in the shape pinned here,
    /// and a row in that shape reads back the same.
    #[test]
    fn the_mtls_config_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {"mode": "Disabled", "trusted_ca_certs": []}});

        assert_eq!(MTLS.seal(&MtlsConfig::disabled()).unwrap(), stored);
        let read: MtlsConfig = MTLS.open(stored.clone()).unwrap();
        assert_eq!(MTLS.seal(&read).unwrap(), stored);
    }

    /// Where the tenant runs is written in the shape pinned here, and a row
    /// in that shape reads back.
    #[test]
    fn the_residency_is_stored_in_its_pinned_shape() {
        let residency = TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1);
        let stored = json!({"v": 1, "value": {
            "isolation": "Shared",
            "placement": {"Platform": {"region": "EuCentral1"}}
        }});

        assert_eq!(RESIDENCY.seal(&residency).unwrap(), stored);
        assert_eq!(
            RESIDENCY.open::<TenantResidency>(stored).unwrap(),
            residency
        );
    }
}
