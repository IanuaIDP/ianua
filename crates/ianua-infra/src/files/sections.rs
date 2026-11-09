//! The sections of a person's data export that are read whole: each read
//! through the port that keeps it, and written as JSON a person and
//! another service can read.
//!
//! No section writes a secret. A section names what exists and when: a
//! passkey by its name and dates, never its key; a session by where and
//! when it began and how it stands, never its token; a second factor by
//! its method, never its secret or codes. Each section reads only what one
//! person holds, which stays small, so it is held in memory whole; the
//! audit trail's records and the notices sent to them, which grow without
//! bound, are written a page at a time instead.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::future::try_join_all;
use ianua_app::ports::audit::TenantAuditLogStore;
use ianua_app::ports::authentication::{
    BreakGlassStore, MfaEnrollmentStore, PasskeyStore, ResetRequestStore, SignInAttemptCounts,
    SignInHistoryStore, TrustedDeviceStore,
};
use ianua_app::ports::authorization::{GroupMembershipStore, GroupStore, RoleStore};
use ianua_app::ports::federation::FederatedLinkStore;
use ianua_app::ports::identity::{
    ConsentStore, InvitationStore, MetadataStore, SupportImpersonationStore, UserStore,
};
use ianua_app::ports::notifications::{NotificationPreferenceStore, TenantNotificationStore};
use ianua_app::ports::oauth::OAuthConsentStore;
use ianua_app::ports::shared::SessionStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName, PhoneNumber, PreferredUsername,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::domains::identity::privacy::consent::ConsentType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, HttpsUrl, Label, Locale, PrincipalRef, Scope, Timezone, UserId};
use serde_json::{Map, Number, Value, json};
use time::OffsetDateTime;

use crate::files::records::moment;

mod history;

pub(crate) use self::history::notice_item;

/// The ports a person's data is read through, one per kind of record.
pub struct PersonalDataSources {
    /// The accounts.
    pub users: Arc<dyn UserStore>,
    /// The custom attributes stored on accounts.
    pub metadata: Arc<dyn MetadataStore>,
    /// The consents people gave and withdrew.
    pub consents: Arc<dyn ConsentStore>,
    /// The apps people let act for them.
    pub app_grants: Arc<dyn OAuthConsentStore>,
    /// The outside identities linked to accounts.
    pub linked_identities: Arc<dyn FederatedLinkStore>,
    /// The roles, each person's held ones among them.
    pub roles: Arc<dyn RoleStore>,
    /// The groups, for the names of those a person is in.
    pub groups: Arc<dyn GroupStore>,
    /// Who is in which group.
    pub memberships: Arc<dyn GroupMembershipStore>,
    /// Reads sign-in metadata for export without bearer credentials.
    pub sessions: Arc<dyn SessionStore>,
    /// The second factors.
    pub factors: Arc<dyn MfaEnrollmentStore>,
    /// Reads enrolled authenticator names and dates for export.
    pub passkeys: Arc<dyn PasskeyStore>,
    /// The remembered devices.
    pub devices: Arc<dyn TrustedDeviceStore>,
    /// The countries people signed in from.
    pub sign_in_places: Arc<dyn SignInHistoryStore>,
    /// The notices sent to people.
    pub notifications: Arc<dyn TenantNotificationStore>,
    /// How people chose to be told.
    pub notification_choices: Arc<dyn NotificationPreferenceStore>,
    /// The times staff acted as someone for support.
    pub impersonations: Arc<dyn SupportImpersonationStore>,
    /// The failed sign-ins counted against each address, read plainly.
    pub sign_in_counts: Arc<dyn SignInAttemptCounts>,
    /// The password reset links people were sent.
    pub resets: Arc<dyn ResetRequestStore>,
    /// The invitations sent to people's accounts.
    pub invitations: Arc<dyn InvitationStore>,
    /// The emergency access given to people.
    pub break_glass: Arc<dyn BreakGlassStore>,
    /// The tenant's audit log, for what the person did and the records
    /// about them.
    pub activity: Arc<dyn TenantAuditLogStore>,
}

/// The person an export is about, in their tenant.
#[derive(Clone, Copy)]
pub(crate) struct Person<'a> {
    /// Scopes every export read to the account's owning boundary.
    pub(crate) tenant: &'a ScopedTenant,
    /// Their account.
    pub(crate) user: &'a UserId,
}

impl PersonalDataSources {
    /// The address the person's account holds now, which their failed
    /// sign-ins were typed with.
    pub(crate) async fn address(&self, person: Person<'_>) -> Result<Email, DomainError> {
        let account = self
            .users
            .find_by_id(person.tenant, person.user)
            .await?
            .ok_or_else(|| DomainError::infra_msg("the export's account is gone"))?;
        Ok(account.email().clone())
    }

    /// The account: address, name, language, timezone, status, the
    /// person's own details and the directory's records about them.
    pub(crate) async fn profile(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let account = self
            .users
            .find_by_id(person.tenant, person.user)
            .await?
            .ok_or_else(|| DomainError::infra_msg("the export's account is gone"))?;
        let details = &account.profile().details;
        let records = &account.profile().records;
        Ok(json!({
            "id": account.id().to_string(),
            "email": account.email().as_str(),
            "email_verified": account.email_verified(),
            "display_name": account.display_name().as_str(),
            "status": account.status().to_string(),
            "locale": account.locale().value().map(Locale::as_str),
            "timezone": account.timezone().value().map(Timezone::as_str),
            "given_name": details.given_name.value().map(GivenName::as_str),
            "family_name": details.family_name.value().map(FamilyName::as_str),
            "preferred_username": details.preferred_username.value().map(PreferredUsername::as_str),
            "picture": details.picture.value().map(HttpsUrl::as_str),
            "phone_number": details.phone_number.value().map(PhoneNumber::as_str),
            "external_id": records.external_id.value().map(ExternalId::as_str),
            "department": records.department.value().map(Department::as_str),
            "manager": records.manager.value().map(ToString::to_string),
            "employee_number": records.employee_number.value().map(EmployeeNumber::as_str),
            "created_at": moment(account.created_at())?,
            "joined_at": maybe(account.joined_at())?,
            "last_login_at": maybe(account.last_login_at())?,
        }))
    }

    /// The custom attributes stored on the person, in the namespace they
    /// write and the one only admins write.
    pub(crate) async fn attributes(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let (own, admins) = self
            .metadata
            .find_by_user(person.tenant, person.user)
            .await?;
        Ok(json!({ "user": attribute_map(&own), "app": attribute_map(&admins) }))
    }

    /// Every consent the person gave or withdrew, newest first, with the
    /// version of the terms each was about.
    pub(crate) async fn consents(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let history = self.consents.history(person.tenant, person.user).await?;
        let items = history
            .iter()
            .map(|record| -> Result<Value, DomainError> {
                Ok(json!({
                    "consent": consent_word(record.consent_type()),
                    "granted": record.granted(),
                    "version": record.version().as_str(),
                    "recorded_at": moment(record.recorded_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// The apps the person let act for them, and what each may do.
    pub(crate) async fn app_grants(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let grants = self
            .app_grants
            .list_for_user(person.tenant, person.user)
            .await?;
        let items = grants
            .iter()
            .map(|grant| -> Result<Value, DomainError> {
                let scopes: Vec<&str> = grant.scopes().iter().map(Scope::as_str).collect();
                Ok(json!({
                    "client_id": grant.client_id().to_string(),
                    "scopes": scopes,
                    "granted_at": moment(grant.granted_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// The outside identity providers linked to the account, by the
    /// connection and the name the provider knows the person by.
    pub(crate) async fn linked_identities(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let links = self
            .linked_identities
            .list_by_user(person.tenant, person.user)
            .await?;
        let items = links
            .iter()
            .map(|link| -> Result<Value, DomainError> {
                Ok(json!({
                    "connection_id": link.connection_id().to_string(),
                    "subject": link.subject().as_str(),
                    "linked_at": moment(link.linked_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// The roles the person holds, directly or through a group, and the
    /// groups they are in.
    pub(crate) async fn roles_and_groups(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let principal = PrincipalRef::User(*person.user);
        let roles = self
            .roles
            .find_effective_by_principal(person.tenant, &principal)
            .await?;
        let memberships = self
            .memberships
            .find_by_principal(person.tenant, &principal)
            .await?;
        let groups = try_join_all(
            memberships
                .iter()
                .map(|membership| self.groups.find_by_id(person.tenant, membership.group_id())),
        )
        .await?;
        let role_names: Vec<&str> = roles.iter().map(|role| role.name().as_str()).collect();
        let group_items = memberships
            .iter()
            .zip(&groups)
            .map(|(membership, group)| -> Result<Value, DomainError> {
                Ok(json!({
                    "group_id": membership.group_id().to_string(),
                    "name": group.as_ref().map(|group| group.name().as_str()),
                    "joined_at": moment(membership.joined_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(json!({ "roles": role_names, "groups": group_items }))
    }

    /// The person's sessions still kept, open or ended, one for each time
    /// they signed in, with where and when each began and how it stands.
    pub(crate) async fn sessions(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let kept = self
            .sessions
            .list_by_user(person.tenant, person.user)
            .await?;
        let items = kept
            .iter()
            .map(|session| -> Result<Value, DomainError> {
                Ok(json!({
                    "id": session.id().to_string(),
                    "status": session_word(session.status()),
                    "auth_method": session.auth_method().as_str(),
                    "ip_address": session.ip_address().known().map(|ip| ip.as_str()),
                    "user_agent": session.user_agent().known().map(|agent| agent.as_str()),
                    "signed_in_at": moment(session.signed_in_at())?,
                    "last_active_at": moment(session.last_active_at())?,
                    "expires_at": moment(session.expires_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// The person's second factor, passkeys and remembered devices, by
    /// method or name and by date.
    pub(crate) async fn devices(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let factor = self
            .factors
            .find_by_user(person.tenant, person.user)
            .await?;
        let passkeys = self
            .passkeys
            .list_by_user(person.tenant, person.user)
            .await?;
        let devices = self
            .devices
            .list_by_user(person.tenant, person.user)
            .await?;
        let factor = factor.as_ref().map(factor_item).transpose()?;
        let passkeys = passkeys
            .iter()
            .map(passkey_item)
            .collect::<Result<Vec<Value>, DomainError>>()?;
        let devices = devices
            .iter()
            .map(device_item)
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(json!({ "second_factor": factor, "passkeys": passkeys, "remembered_devices": devices }))
    }
}

/// Exports the factor's method, standing and dates without its secret.
fn factor_item(factor: &MfaEnrollment<ResolvedTenant>) -> Result<Value, DomainError> {
    Ok(json!({
        "method": factor.method().as_str(),
        "active": factor.is_active(),
        "enrolled_at": moment(factor.enrolled_at())?,
        "verified_at": maybe(factor.verified_at())?,
    }))
}

/// Exports the passkey's name, kind and dates without credential material.
fn passkey_item(passkey: &PasskeyCredential<ResolvedTenant>) -> Result<Value, DomainError> {
    Ok(json!({
        "name": passkey.name().as_str(),
        "kind": passkey.authenticator_type().as_str(),
        "created_at": moment(passkey.created_at())?,
        "last_used_at": maybe(passkey.last_used_at())?,
    }))
}

/// Exports a remembered device's name, standing and observation dates.
fn device_item(device: &TrustedDevice<ResolvedTenant>) -> Result<Value, DomainError> {
    Ok(json!({
        "name": device.device_name().as_str(),
        "trusted": device.status().is_trusted(),
        "created_at": moment(device.created_at())?,
        "last_seen_at": moment(device.last_seen_at())?,
    }))
}

/// The word a session's status is written as.
fn session_word(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active => "active",
        SessionStatus::Suspended => "suspended",
        SessionStatus::Revoked => "ended",
    }
}

/// `at` as RFC 3339 text, when there is a moment.
pub(crate) fn maybe(at: Option<OffsetDateTime>) -> Result<Option<String>, DomainError> {
    at.map(moment).transpose()
}

/// One namespace of attributes as a JSON object, by key.
fn attribute_map(values: &HashMap<Label, MetadataValue>) -> Value {
    let fields: Map<String, Value> = values
        .iter()
        .map(|(key, value)| (key.as_str().to_owned(), attribute(value)))
        .collect();
    Value::Object(fields)
}

/// One attribute's value as JSON.
fn attribute(value: &MetadataValue) -> Value {
    match value {
        MetadataValue::String(text) => Value::String(text.clone()),
        MetadataValue::Integer(number) => Value::from(*number),
        MetadataValue::Number(number) => {
            Number::from_f64(*number).map_or(Value::Null, Value::Number)
        }
        MetadataValue::Bool(flag) => Value::Bool(*flag),
        MetadataValue::StringArray(items) => Value::from(items.clone()),
        MetadataValue::Null => Value::Null,
    }
}

/// The word a consent's kind is written as.
fn consent_word(kind: ConsentType) -> &'static str {
    match kind {
        ConsentType::DataProcessing => "data_processing",
        ConsentType::Marketing => "marketing",
        ConsentType::TermsOfService => "terms_of_service",
        ConsentType::PrivacyPolicy => "privacy_policy",
        ConsentType::HealthDataSharing => "health_data_sharing",
        ConsentType::Cookies => "cookies",
    }
}
