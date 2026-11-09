//! An organization as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::organization::billing::negotiated::{NegotiatedLimits, PlanTerms};
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::domains::organization::lifecycle::{Organization, OrganizationRow};
use ianua_domain::domains::organization::status::{OrgSuspensionReason, Suspension};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    DisplayName, Email, Label, OrgUserId, OrganizationId, TenantId, TenantSlug,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const ORGANIZATION: Stored = Stored("organization");

const AUTH_CONFIG: Kept = Kept {
    entity: ORGANIZATION.0,
    column: "auth_config",
    shape: 1,
};

const NEGOTIATED_LIMITS: Kept = Kept {
    entity: ORGANIZATION.0,
    column: "negotiated_limits",
    shape: 1,
};

/// An organization as it is read: its row, and the tenants it holds.
pub(super) struct OrganizationRecord {
    pub(super) id: Uuid,
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) contact_email: String,
    pub(super) display_name: String,
    pub(super) plan: String,
    pub(super) negotiated_limits: Option<Value>,
    pub(super) status: String,
    pub(super) suspended_by_member: Option<Uuid>,
    pub(super) suspended_by_platform: Option<String>,
    pub(super) auth_config: Value,
    pub(super) tenant_ids: Vec<Uuid>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl OrganizationRecord {
    /// The organization the record holds, rebuilt through the domain's
    /// checks, each name checked against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// organization keeps.
    pub(super) fn into_organization(
        self,
        limits: &DomainLimits,
    ) -> Result<Organization, DomainError> {
        Organization::reconstitute(OrganizationRow {
            id: OrganizationId::from_uuid(self.id),
            slug: ORGANIZATION.value("slug", TenantSlug::new(self.slug, &limits.slug))?,
            name: ORGANIZATION.value("name", Label::new("name", self.name))?,
            contact_email: ORGANIZATION.value("contact email", Email::new(self.contact_email))?,
            display_name: ORGANIZATION.value(
                "display name",
                DisplayName::new(self.display_name, &limits.display_name),
            )?,
            plan: ORGANIZATION.choice(&self.plan)?,
            terms: terms_from(self.negotiated_limits)?,
            status: ORGANIZATION.choice(&self.status)?,
            suspended_by: suspension_from(
                self.suspended_by_member,
                self.suspended_by_platform.as_deref(),
            )?,
            tenant_ids: self
                .tenant_ids
                .into_iter()
                .map(TenantId::from_uuid)
                .collect(),
            auth_config: AUTH_CONFIG.open(self.auth_config)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// An organization's columns, as they are written.
pub(super) struct OrganizationColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) slug: &'a str,
    pub(super) name: &'a str,
    pub(super) contact_email: &'a str,
    pub(super) display_name: &'a str,
    pub(super) plan: &'static str,
    pub(super) negotiated_limits: Option<Value>,
    pub(super) status: &'static str,
    pub(super) suspended_by_member: Option<Uuid>,
    pub(super) suspended_by_platform: Option<&'static str>,
    pub(super) auth_config: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> OrganizationColumns<'a> {
    /// The columns `organization` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON.
    pub(super) fn of(organization: &'a Organization) -> Result<Self, DomainError> {
        let (suspended_by_member, suspended_by_platform) =
            suspension_columns(organization.suspended_by());
        Ok(Self {
            id: organization.id().as_uuid(),
            slug: organization.slug().as_str(),
            name: organization.name().as_str(),
            contact_email: organization.contact_email().as_str(),
            display_name: organization.display_name().as_str(),
            plan: organization.plan().word(),
            negotiated_limits: negotiated_limits_of(organization.terms())?,
            status: organization.status().word(),
            suspended_by_member,
            suspended_by_platform,
            auth_config: AUTH_CONFIG.seal(organization.auth_config())?,
            created_at: organization.created_at(),
            updated_at: organization.updated_at(),
        })
    }
}

fn negotiated_limits_of(terms: &PlanTerms) -> Result<Option<Value>, DomainError> {
    match terms {
        PlanTerms::Standard => Ok(None),
        PlanTerms::Negotiated(negotiated) => NEGOTIATED_LIMITS.seal(negotiated.limits()).map(Some),
    }
}

fn terms_from(stored: Option<Value>) -> Result<PlanTerms, DomainError> {
    let Some(stored) = stored else {
        return Ok(PlanTerms::Standard);
    };
    let limits: PlanLimits = NEGOTIATED_LIMITS.open(stored)?;
    NegotiatedLimits::new(limits)
        .map(PlanTerms::Negotiated)
        .map_err(DomainError::infra)
}

/// Who suspended it, as its two columns hold it: one of its members, or
/// the platform for a reason.
fn suspension_columns(suspension: Suspension) -> (Option<Uuid>, Option<&'static str>) {
    match suspension {
        Suspension::NotSuspended => (None, None),
        Suspension::ByMember(member) => (Some(*member.as_uuid()), None),
        Suspension::ByPlatform(reason) => (None, Some(reason.word())),
    }
}

fn suspension_from(
    member: Option<Uuid>,
    platform: Option<&str>,
) -> Result<Suspension, DomainError> {
    match (member, platform) {
        (None, None) => Ok(Suspension::NotSuspended),
        (Some(member), None) => Ok(Suspension::ByMember(OrgUserId::from_uuid(member))),
        (None, Some(reason)) => ORGANIZATION
            .choice::<OrgSuspensionReason>(reason)
            .map(Suspension::ByPlatform),
        (Some(_), Some(_)) => Err(DomainError::corrupt_row(
            ORGANIZATION.0,
            "suspended by a member and by the platform at once",
        )),
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
    use serde_json::json;

    use super::*;

    /// The pinned authentication envelope, including the separately specified password policy.
    fn stored_auth_config() -> Value {
        json!({"v": 1, "value": {
            "breached_passwords": "Block",
            "challenge_threshold": 200,
            "enabled_methods": ["Password", "Passkey"],
            "idle_timeout_secs": 3600,
            "ip_allowlist": [],
            "lockout_duration_secs": 900,
            "max_login_attempts": 10,
            "mfa_policy": "Optional",
            "password_policy": stored_password_policy(),
            "second_factors": ["Totp"],
            "session_lifetime_secs": 28800,
            "sso": "Optional",
            "step_up_policy": {
                "baseline_aal": "Aal1",
                "deny_risk_threshold": "Critical",
                "mfa_risk_threshold": "Critical",
                "require_mfa_new_country": false,
                "require_mfa_new_device": true,
                "sensitive_aal": "Aal2"
            }
        }})
    }

    /// The password policy's pinned nested JSON shape.
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

    /// Combines every pinned limit into the single stored negotiated-limits envelope.
    fn stored_negotiated_limits() -> Value {
        let mut limits = stored_access_limits();
        limits
            .as_object_mut()
            .unwrap()
            .extend(stored_product_limits());
        json!({"v": 1, "value": limits})
    }

    /// Pinned tenant, account and access-management limits with their stored scalar types.
    fn stored_access_limits() -> Value {
        json!({
            "allowed_isolation": ["Shared", "DedicatedSchema", "DedicatedInstance", "DedicatedCluster"],
            "api_rate_limit_per_minute": 10000,
            "audit_retention_days": 365,
            "max_api_keys": 250,
            "max_consumers": 100,
            "max_directory_service_accounts": 20,
            "max_federation_connections": 10,
            "max_groups": 250,
            "max_oauth_clients": 100,
            "max_resource_types": 200,
            "max_roles": 250,
            "max_saml_service_providers": 50,
            "max_tenants_per_org": 25,
            "max_user_attributes": 300,
            "max_users": 100_000,
        })
    }

    /// Pinned gateway, automation and delivery limits merged into the same stored object.
    fn stored_product_limits() -> serde_json::Map<String, Value> {
        serde_json::from_value(json!({
            "max_active_agent_runs": 250,
            "max_agent_tools": 500,
            "max_agents": 250,
            "max_audit_streams": 5,
            "max_connectors": 10,
            "max_dns_record_sets": 1000,
            "max_domains": 250,
            "max_egress_policies": 25,
            "max_log_targets": 5,
            "max_message_subscriptions": 250,
            "max_model_providers": 25,
            "max_notification_destinations": 25,
            "max_pending_approvals": 1000,
            "max_proxy_requests_per_month": 500_000_000,
            "max_routes": 250,
            "max_services": 100,
            "max_stream_routes": 25,
            "max_webhooks": 50,
            "max_workflows": 150,
            "max_sandboxes": 150,
            "max_running_trials": 25,
            "max_running_evaluations": 10,
            "max_own_images": 25,
            "max_memories": 100,
            "max_memory_entries": 5000000
        }))
        .unwrap()
    }

    /// The sign-in configuration is written in the shape pinned here, and
    /// a row in that shape reads back.
    #[test]
    fn the_auth_config_is_stored_in_its_pinned_shape() {
        let config = OrganizationAuthConfig::default();

        assert_eq!(AUTH_CONFIG.seal(&config).unwrap(), stored_auth_config());
        assert_eq!(
            AUTH_CONFIG
                .open::<OrganizationAuthConfig>(stored_auth_config())
                .unwrap(),
            config
        );
    }

    /// Negotiated limits stored in the shape pinned here read back, and are
    /// written again in the same shape.
    #[test]
    fn negotiated_limits_are_stored_in_their_pinned_shape() {
        let read: PlanLimits = NEGOTIATED_LIMITS.open(stored_negotiated_limits()).unwrap();

        assert_eq!(
            NEGOTIATED_LIMITS.seal(&read).unwrap(),
            stored_negotiated_limits()
        );
    }
}
