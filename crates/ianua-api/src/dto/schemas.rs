//! OpenAPI schemas for the domain values the API carries as they
//! serialize: each enum is documented with every value it can take.
//!
//! The values come from serializing each variant, so the document never
//! disagrees with the JSON; the variants are listed through an exhaustive
//! `match`, so a variant the domain adds stops the build until it is
//! documented here.

use ianua_domain::domains::activity::ActivityCategory;
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::domains::authentication::credentials::breach::BreachedPasswordCheck;
use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;
use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
use ianua_domain::domains::authentication::mfa::enrollment::MfaMethod;
use ianua_domain::domains::authentication::risk_engine::assessment::RiskLevel;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authorization::policy::condition::RiskThreshold;
use ianua_domain::domains::authorization::policy::status::PolicyStatus;
use ianua_domain::domains::branding::email_template::EmailTemplateType;
use ianua_domain::domains::consumers::consumer::ConsumerStatus;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::crypto::migration_status::MigrationStatus;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::domains::data_classification::classification::RedactionStrategy;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::federation::connection::FederationProtocol;
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::attribute::{
    AttributeControl, AttributeKind, AttributeNamespace, AttributeOperator,
};
use ianua_domain::domains::identity::impersonation::state::ImpersonationConsent;
use ianua_domain::domains::identity::privacy::consent::ConsentType;
use ianua_domain::domains::messaging::schema::{CompatibilityMode, SchemaFormat};
use ianua_domain::domains::messaging::subscription::{DeliveryMode, SubscriptionStatus};
use ianua_domain::domains::messaging::topic::TopicStatus;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::domains::oauth::clients::client::GrantType;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::domains::operator::status::OperatorStatus;
use ianua_domain::domains::organization::access::auth_config::SsoEnforcement;
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::domains::proxy::log_shipping::{LogFormat, LogTargetStatus};
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::routing::connector::ConnectorStatus;
use ianua_domain::domains::routing::matching::parameter::RouteReach;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::stream::{StreamPolicy, StreamProtocol};
use ianua_domain::domains::signals::delivery::SignalDeliveryStatus;
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{DeliveryMethod, StreamStatus};
use ianua_domain::domains::tenant::access::network_security::MtlsMode;
use ianua_domain::domains::tenant::compliance::DataResidency;
use ianua_domain::domains::tenant::provisioning::infrastructure::IsolationLevel;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::domains::webhooks::delivery::WebhookDeliveryStatus;
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::types::{ActionClass, HttpMethod, TokenStatus};
use serde::Serialize;
use utoipa::openapi::schema::{ArrayBuilder, ObjectBuilder, Type};
use utoipa::openapi::{Array, Object};

/// A string schema that takes only `values`, each written as serde writes
/// it.
fn text_enum<T: Serialize>(values: &[T]) -> Object {
    let names = values
        .iter()
        .filter_map(|value| serde_json::to_value(value).ok())
        .collect::<Vec<_>>();
    ObjectBuilder::new()
        .schema_type(Type::String)
        .enum_values(Some(names))
        .build()
}

/// A list whose items take only `values`.
fn text_enum_list<T: Serialize>(values: &[T]) -> Array {
    ArrayBuilder::new().items(text_enum(values)).build()
}

/// Writes the schema of one domain enum, or of a list of it, from its
/// variants, with a `match` that names every one.
macro_rules! documented_enum {
    (one $name:ident, $kind:ident { $($variant:ident),+ $(,)? }) => {
        /// Restricts a documented field to the domain enum's serialized variants.
        pub(crate) fn $name() -> Object {
            text_enum(&every_value_of_kind!($kind { $($variant),+ }))
        }
    };
    (list $name:ident, $kind:ident { $($variant:ident),+ $(,)? }) => {
        /// Restricts each documented list item to the domain enum's serialized variants.
        pub(crate) fn $name() -> Array {
            text_enum_list(&every_value_of_kind!($kind { $($variant),+ }))
        }
    };
}

/// Every variant of `$kind`, checked to be all of them by a `match` that
/// stops compiling when the domain adds one.
macro_rules! every_value_of_kind {
    ($kind:ident { $($variant:ident),+ }) => {{
        let every = [$($kind::$variant),+];
        if let Some(value) = every.first() {
            match value {
                $($kind::$variant => {}),+
            }
        }
        every
    }};
}

documented_enum!(one action_class, ActionClass { Read, Write, Delete, Configure, Communicate, Financial, Admin });
documented_enum!(list action_class_list, ActionClass { Read, Write, Delete, Configure, Communicate, Financial, Admin });
documented_enum!(one activity_category, ActivityCategory { Authentication, Access, Administration, Identity, Provisioning, Other });
documented_enum!(list activity_category_list, ActivityCategory { Authentication, Access, Administration, Identity, Provisioning, Other });
documented_enum!(one agent_status, AgentStatus { Active, Suspended, Revoked });
documented_enum!(one assurance_level, AssuranceLevel { Aal1, Aal2, Aal3 });
documented_enum!(one attribute_control, AttributeControl { TextInput, TextArea, NumberInput, CurrencyInput, PercentInput, Slider, Toggle, Checkbox, Select, RadioGroup, MultiSelect, CheckboxGroup, TagInput, DatePicker, DateTimePicker, EmailInput, PhoneInput, UrlInput, ColourPicker, CountrySelect, StarRating });
documented_enum!(list attribute_control_list, AttributeControl { TextInput, TextArea, NumberInput, CurrencyInput, PercentInput, Slider, Toggle, Checkbox, Select, RadioGroup, MultiSelect, CheckboxGroup, TagInput, DatePicker, DateTimePicker, EmailInput, PhoneInput, UrlInput, ColourPicker, CountrySelect, StarRating });
documented_enum!(one attribute_kind, AttributeKind { Text, LongText, WholeNumber, Decimal, Money, Percent, YesNo, SingleChoice, MultipleChoice, Tags, Date, DateTime, Email, Phone, Link, Colour, Country, Rating });
documented_enum!(one attribute_namespace, AttributeNamespace { User, App });
documented_enum!(list attribute_operator_list, AttributeOperator { Is, IsNot, Contains, IsOneOf, GreaterThan, GreaterThanOrEqual, LessThan, LessThanOrEqual, HasAny, HasAll, IsPresent, IsAbsent });
documented_enum!(list auth_method_list, AuthMethod { Password, MagicLink, Passkey, Saml, Oidc });
documented_enum!(one breached_password_check, BreachedPasswordCheck { Off, Warn, Block });
documented_enum!(one compatibility_mode, CompatibilityMode { None, Backward, Forward, Full });
documented_enum!(one connection_status, ConnectionStatus { Active, Disabled });
documented_enum!(one connector_status, ConnectorStatus { Active, Revoked });
documented_enum!(one consent_type, ConsentType { DataProcessing, Marketing, TermsOfService, PrivacyPolicy, HealthDataSharing, Cookies });
documented_enum!(one consumer_status, ConsumerStatus { Active, Disabled });
documented_enum!(one data_class_level, DataClassLevel { Public, Internal, Confidential, Restricted });
documented_enum!(list data_class_level_list, DataClassLevel { Public, Internal, Confidential, Restricted });
documented_enum!(one data_residency, DataResidency { Eu, Uk, Switzerland, Us, Canada, Brazil, India, Japan, Australia, Singapore });
documented_enum!(one delivery_method, DeliveryMethod { Push, Poll });
documented_enum!(one delivery_mode, DeliveryMode { Push, Pull });
documented_enum!(one directory_access, DirectoryAccess { ReadOnly });
documented_enum!(one email_template_type, EmailTemplateType { Verification, PasswordReset, MagicLink, Invitation, AccountLocked, MfaEnrolled, RecoveryCodes, DeviceTrusted, SessionSuspended, BreachedPassword, ErasureConfirmation, ErasureCompleted, Welcome, EmailChangeVerification, EmailChanged, EmailChangeRequested, AccountLinked, SignInCode, ExportReady, ImpersonationRequested, OrgVerification, OrgInvitation, OrgWelcome, OrgMfaReset, OrgEmailChangeRequested, SignupVerification, SignupWelcome, SignupAccountExists, ActivationWelcome, ActivityNotice });
documented_enum!(one federation_protocol, FederationProtocol { Saml, Oidc });
documented_enum!(list grant_type_list, GrantType { AuthorizationCode, ClientCredentials, RefreshToken, DeviceCode, TokenExchange });
documented_enum!(one http_method, HttpMethod { Get, Post, Put, Patch, Delete, Head, Options, Any });
documented_enum!(list http_method_list, HttpMethod { Get, Post, Put, Patch, Delete, Head, Options, Any });
documented_enum!(one impersonation_consent, ImpersonationConsent { AdminDecides, HolderApproves });
documented_enum!(one isolation_level, IsolationLevel { Shared, DedicatedSchema, DedicatedInstance, DedicatedCluster });
documented_enum!(list isolation_level_list, IsolationLevel { Shared, DedicatedSchema, DedicatedInstance, DedicatedCluster });
documented_enum!(one key_status, KeyStatus { Active, Rotated, Revoked });
documented_enum!(one log_format, LogFormat { JsonLines, OpenTelemetry });
documented_enum!(one log_target_status, LogTargetStatus { Active, Paused });
documented_enum!(list mfa_method_list, MfaMethod { Totp, EmailCode, SmsCode });
documented_enum!(one mfa_policy, MfaPolicy { Disabled, Optional, Required });
documented_enum!(one migration_status, MigrationStatus { Planned, InProgress, Validating, Completed, RolledBack, Cancelled });
documented_enum!(one mtls_mode, MtlsMode { Disabled, Optional, Required });
documented_enum!(one notification_category, NotificationCategory { Identity, Crypto, OAuth, Authorization, Federation, Routing, Pipeline, Signals, Webhooks, Branding, Authentication, Organization, Tenant, Agents, Consumers, Messaging, Domains, Mtls, Scim, Classification, Policy, Audit, Workflows });
documented_enum!(list notification_category_list, NotificationCategory { Identity, Crypto, OAuth, Authorization, Federation, Routing, Pipeline, Signals, Webhooks, Branding, Authentication, Organization, Tenant, Agents, Consumers, Messaging, Domains, Mtls, Scim, Classification, Policy, Audit, Workflows });
documented_enum!(one notification_channel, NotificationChannel { InApp, InAppAndEmail, Disabled });
documented_enum!(one notification_severity, NotificationSeverity { Info, Warning, Critical });
documented_enum!(one o_auth_client_status, OAuthClientStatus { Active, Revoked });
documented_enum!(one operator_status, OperatorStatus { Active, Disabled });
documented_enum!(one org_role, OrgRole { Viewer, Billing, Member, Admin, Owner });
documented_enum!(one organization_plan, OrganizationPlan { Free, Starter, Business, Custom, SelfHosted });
documented_enum!(one organization_status, OrganizationStatus { Active, Suspended, Closed });
documented_enum!(one pipeline_status, PipelineStatus { Draft, Active, Disabled });
documented_enum!(one policy_status, PolicyStatus { Draft, Review, Active, Archived });
documented_enum!(one redaction_strategy, RedactionStrategy { Remove, Mask, Hash, Encrypt });
documented_enum!(one retry_preset, RetryPreset { Standard, Aggressive, Patient });
documented_enum!(one risk_level, RiskLevel { Low, Medium, High, Critical });
documented_enum!(one risk_threshold, RiskThreshold { Low, Medium, High, Critical });
documented_enum!(one route_reach, RouteReach { Fixed, OpenEnded });
documented_enum!(one route_status, RouteStatus { Active, Disabled });
documented_enum!(one schema_format, SchemaFormat { JsonSchema, Avro, Protobuf });
documented_enum!(one security_signal_type, SecuritySignalType { SessionRevoked, SessionSuspended, CredentialChanged, AccountLocked, AccountDisabled, PermissionsChanged, DeviceCompromised, TokenCompromised, RiskLevelChanged, AssuranceChanged, CredentialCompromised, IdentifierChanged, AccountPurged });
documented_enum!(list security_signal_type_list, SecuritySignalType { SessionRevoked, SessionSuspended, CredentialChanged, AccountLocked, AccountDisabled, PermissionsChanged, DeviceCompromised, TokenCompromised, RiskLevelChanged, AssuranceChanged, CredentialCompromised, IdentifierChanged, AccountPurged });
documented_enum!(one service_account_status, ServiceAccountStatus { Active, Disabled });
documented_enum!(one signal_delivery_status, SignalDeliveryStatus { Success, Failed, Timeout, Unreachable, Queued });
documented_enum!(one signing_algorithm, SigningAlgorithm { Rs256, Es256, EdDsa });
documented_enum!(one sso_enforcement, SsoEnforcement { Optional, Enforced });
documented_enum!(one stream_policy, StreamPolicy { MutualTls, Tunnel, Public });
documented_enum!(one stream_protocol, StreamProtocol { Tcp, TlsTerminate, TlsPassthrough, Udp });
documented_enum!(one stream_status, StreamStatus { Active, Paused, Disabled });
documented_enum!(one subscription_status, SubscriptionStatus { Active, Paused });
documented_enum!(one tenant_status, TenantStatus { Provisioning, Active, Suspended, Archived, Deleted });
documented_enum!(one token_status, TokenStatus { Valid, Expired, AlreadyUsed, Invalid });
documented_enum!(one topic_status, TopicStatus { Active, Paused, Archived });
documented_enum!(one user_status, UserStatus { Invited, PendingVerification, Active, Locked, Deactivated, Closing });
documented_enum!(one webhook_delivery_status, WebhookDeliveryStatus { Success, Failed, Timeout, Unreachable });
documented_enum!(one webhook_subscription_status, WebhookSubscriptionStatus { Active, Paused, Disabled });
