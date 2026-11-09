//! What the server hands the assembly: the adapter behind every port the
//! use cases need, and the settings they are built with.
//!
//! The server fills both once at startup; each group's `build` makes its
//! use cases from them. No caller picks an adapter itself.

use std::sync::Arc;

use ianua_app::services::account_grants::{AccountGrants, AccountGrantsPorts};
use ianua_app::services::account_now::{AccountsNow, AccountsNowPorts};

use crate::tunables::Tunables;

/// The adapter behind each port, one field per port trait, named after it
/// (a port with a purpose, such as `OrgTokenStore<PasswordReset>`, has one
/// field per purpose).
#[derive(Clone, ianua_macros::Fakes)]
pub struct Adapters {
    /// Records each request's events in the audit trail, through the
    /// request's auditor.
    pub event_dispatcher: Arc<dyn ianua_app::ports::shared::EventDispatcher>,
    /// Turns a bearer token into the caller behind it.
    pub token_resolver: Arc<dyn ianua_app::ports::shared::TokenResolver>,
    /// Counts each tenant's requests against its plan's rate.
    pub rate_limiter: Arc<dyn ianua_app::ports::limits::RateLimiter>,
    /// Words an error answer's refusal in the reader's language.
    pub refusal_wording: Arc<dyn ianua_app::ports::shared::RefusalWording>,
    /// Hands a dashboard's live socket the notifications published for it.
    pub notification_subscriber: Arc<dyn ianua_app::ports::realtime::NotificationSubscriber>,
    /// Reads how much of its budget an agent has spent.
    pub budget_usage_reader: Arc<dyn ianua_app::ports::agents::BudgetUsageReader>,
    /// Hashes a message payload for its provenance.
    pub payload_hasher: Arc<dyn ianua_app::ports::broker::PayloadHasher>,
    /// Signs where a relayed message came from.
    pub message_provenance_signer: Arc<dyn ianua_app::ports::broker::MessageProvenanceSigner>,
    /// Checks where a relayed message came from.
    pub message_provenance_verifier: Arc<dyn ianua_app::ports::broker::MessageProvenanceVerifier>,
    /// Checks an app session is still live before it is handed on.
    pub app_session_check: Arc<dyn ianua_app::ports::authentication::AppSessionCheck>,
    /// Mints and reads app session tokens.
    pub app_session_tokens: Arc<dyn ianua_app::ports::authentication::AppSessionTokens>,
    /// Checks the gateway's seal on its questions about agent approvals,
    /// under a key of that channel alone, never the app sign-in key.
    pub approval_request_seal: Arc<dyn ianua_app::ports::authentication::RequestSeal>,
    /// The one-time codes that carry a session to another host.
    pub handoff_store: Arc<dyn ianua_app::ports::authentication::HandoffStore>,
    /// An app sign-in's second-factor step.
    pub mfa_challenge_store: Arc<dyn ianua_app::ports::authentication::MfaChallengeStore>,
    /// Earlier passwords a new one may not repeat.
    pub password_history: Arc<dyn ianua_app::ports::authentication::PasswordHistory>,
    /// Passwords too common to take.
    pub common_password_list: Arc<dyn ianua_app::ports::authentication::CommonPasswordList>,
    /// Tells a stored password hash that is due to be replaced.
    pub password_hash_format: Arc<dyn ianua_app::ports::authentication::PasswordHashFormat>,
    /// Hands mailed and texted second-factor codes to their provider.
    pub factor_code_sender: Arc<dyn ianua_app::ports::authentication::FactorCodeSender>,
    /// People's requests for a copy of their data.
    pub data_export_store: Arc<dyn ianua_app::ports::identity::DataExportStore>,
    /// Where built data exports are kept and handed out from.
    pub data_export_files: Arc<dyn ianua_app::ports::identity::DataExportFiles>,
    /// Requests by a tenant admin to act as a user for support.
    pub support_impersonation_store: Arc<dyn ianua_app::ports::identity::SupportImpersonationStore>,
    /// Imports of accounts from another system, and how far each got.
    pub user_import_store: Arc<dyn ianua_app::ports::identity::UserImportStore>,
    /// Asks the database whether it answers, for the readiness check.
    pub database_readiness: Arc<dyn ianua_app::ports::runtime::ReadinessProbe>,
    /// Asks the message bus whether it answers, for the readiness check.
    pub message_bus_readiness: Arc<dyn ianua_app::ports::runtime::ReadinessProbe>,
    /// Asks the cache whether it answers, for the readiness check.
    pub cache_readiness: Arc<dyn ianua_app::ports::runtime::ReadinessProbe>,
    /// Writes out the process's metrics for the internal listener's scrape.
    pub metrics_exporter: Arc<dyn ianua_app::ports::runtime::MetricsExporter>,
    /// Counts every request the API answers into the metrics the exporter
    /// writes out.
    pub served_request_observer: Arc<dyn ianua_app::ports::runtime::ServedRequestObserver>,
    /// Whether this deployment can text a second-factor code.
    pub text_messaging: Arc<dyn ianua_app::ports::authentication::TextMessaging>,
    /// Whether this deployment can send mail at all.
    pub mail_setup: Arc<dyn ianua_app::ports::shared::MailSetup>,
    /// Draws the sign-in pages the gateway shows on an app's host.
    pub page_renderer: Arc<dyn ianua_app::ports::pages::PageRenderer>,
    pub access_record_store: Arc<dyn ianua_app::ports::authorization::AccessRecordStore>,
    pub access_request_policy_store:
        Arc<dyn ianua_app::ports::authorization::AccessRequestPolicyStore>,
    pub access_request_store: Arc<dyn ianua_app::ports::authorization::AccessRequestStore>,
    pub access_review_store: Arc<dyn ianua_app::ports::authorization::AccessReviewStore>,
    pub access_token_store: Arc<dyn ianua_app::ports::oauth::AccessTokenStore>,
    pub access_token_jwt_verifier: Arc<dyn ianua_app::ports::oauth::AccessTokenJwtVerifier>,
    pub at_hash_calculator: Arc<dyn ianua_app::ports::oauth::AtHashCalculator>,
    pub client_assertion_verifier: Arc<dyn ianua_app::ports::oauth::ClientAssertionVerifier>,
    /// The OAuth port of that name; the agents' port of the same name is a
    /// different trait.
    pub client_assertion_replay_guard: Arc<dyn ianua_app::ports::oauth::AssertionReplayGuard>,
    /// Checks the `DPoP` proofs clients send for their bound tokens.
    pub dpop_proof_verifier: Arc<dyn ianua_app::ports::oauth::DpopProofVerifier>,
    /// Remembers the `DPoP` proofs already used.
    pub dpop_replay_guard: Arc<dyn ianua_app::ports::oauth::DpopReplayGuard>,
    pub id_token_hint_verifier: Arc<dyn ianua_app::ports::oauth::IdTokenHintVerifier>,
    pub initial_access_token_store: Arc<dyn ianua_app::ports::oauth::InitialAccessTokenStore>,
    pub pushed_request_store: Arc<dyn ianua_app::ports::oauth::PushedRequestStore>,
    pub refresh_token_store: Arc<dyn ianua_app::ports::oauth::RefreshTokenStore>,
    pub activity_store: Arc<dyn ianua_app::ports::activity::ActivityStore>,
    pub agent_activity_store: Arc<dyn ianua_app::ports::agents::AgentActivityStore>,
    pub agent_actors: Arc<dyn ianua_app::acting::AgentActors>,
    /// Holds back repeats of a security alert where it is recorded: an
    /// agent's sign-in refused as an attack, once a window per agent.
    pub alert_throttle: Arc<dyn ianua_app::ports::notifications::AlertThrottle>,
    pub agent_attestor: Arc<dyn ianua_app::ports::agents::AgentAttestor>,
    pub agent_channel_store: Arc<dyn ianua_app::ports::messaging::AgentChannelStore>,
    pub agent_credential_store: Arc<dyn ianua_app::ports::agents::AgentCredentialStore>,
    pub agent_exposure_gate: Arc<dyn ianua_app::ports::agents::AgentExposureGate>,
    pub agent_sighting_store: Arc<dyn ianua_app::ports::agents::AgentSightingStore>,
    pub agent_standing_check: Arc<dyn ianua_app::ports::agents::AgentStandingCheck>,
    pub agent_store: Arc<dyn ianua_app::ports::agents::AgentStore>,
    pub api_key_generator: Arc<dyn ianua_app::ports::shared::ApiKeyGenerator>,
    pub api_key_store: Arc<dyn ianua_app::ports::oauth::ApiKeyStore>,
    pub approval_store: Arc<dyn ianua_app::ports::agents::ApprovalStore>,
    pub approval_pages: Arc<dyn ianua_app::ports::workflows::ApprovalPages>,
    pub assertion_key_store: Arc<dyn ianua_app::ports::crypto::AssertionKeyStore>,
    pub attestation_challenge_store: Arc<dyn ianua_app::ports::agents::AttestationChallengeStore>,
    pub attestation_nonce_generator: Arc<dyn ianua_app::ports::agents::AttestationNonceGenerator>,
    /// Keeps the sweep's last verdict on each tenant's audit chain.
    pub audit_chain_verdict_store: Arc<dyn ianua_app::ports::audit::AuditChainVerdictStore>,
    /// Keeps the exports of the audit logs.
    pub audit_export_store: Arc<dyn ianua_app::ports::audit::AuditExportStore>,
    /// Where audit log export files are kept and handed out from.
    pub audit_export_files: Arc<dyn ianua_app::ports::audit::AuditExportFiles>,
    pub audit_label_resolver: Arc<dyn ianua_app::ports::shared::AuditLabelResolver>,
    /// Keeps each tenant's streams of audit records to its SIEM.
    pub audit_stream_store: Arc<dyn ianua_app::ports::audit::AuditStreamStore>,
    /// Reads one tenant's own audit records.
    pub tenant_audit_log_store: Arc<dyn ianua_app::ports::audit::TenantAuditLogStore>,
    /// Reads the audit records of the whole platform, for operators.
    pub platform_audit_log_store: Arc<dyn ianua_app::ports::audit::PlatformAuditLogStore>,
    /// Keeps the copies of one tenant's setup into another.
    pub tenant_clone_store: Arc<dyn ianua_app::ports::tenant::TenantCloneStore>,
    /// Keeps the mail provider each tenant's mail goes out through.
    pub tenant_mail_provider_store: Arc<dyn ianua_app::ports::branding::TenantMailProviderStore>,
    /// Delivers mail through a tenant's named provider, with a timeout.
    pub mail_provider_transport: Arc<dyn ianua_app::ports::branding::MailProviderTransport>,
    /// Renders a tenant's email with sample values for a preview.
    pub template_renderer: Arc<dyn ianua_app::ports::branding::TemplateRenderer>,
    /// Keeps and serves each tenant's uploaded logo.
    pub logo_store: Arc<dyn ianua_app::ports::branding::LogoStore>,
    /// Reads the logos the public logo address serves.
    pub public_logos: Arc<dyn ianua_app::ports::files::PublicLogos>,
    /// Opens the export files the platform's download links name, once.
    pub linked_files: Arc<dyn ianua_app::ports::files::LinkedFiles>,
    /// Reads the files the platform publishes: its mail logo and its AWS
    /// connect template.
    pub published_files: Arc<dyn ianua_app::ports::files::PublishedFiles>,
    /// Keeps the places outside the app an organization's notifications go.
    pub notification_destination_store:
        Arc<dyn ianua_app::ports::notifications::NotificationDestinationStore>,
    /// Makes a webhook destination's signing secret.
    pub destination_secret_generator:
        Arc<dyn ianua_app::ports::notifications::DestinationSecretGenerator>,
    /// Keeps each organization member's notification choices.
    pub member_preference_store: Arc<dyn ianua_app::ports::notifications::MemberPreferenceStore>,
    /// Keeps each operator's notification choices.
    pub operator_preference_store:
        Arc<dyn ianua_app::ports::notifications::OperatorPreferenceStore>,
    pub auth_code_store: Arc<dyn ianua_app::ports::oauth::AuthCodeStore>,
    pub bind_throttle: Arc<dyn ianua_app::ports::directory::BindThrottle>,
    pub branding_store: Arc<dyn ianua_app::ports::branding::BrandingStore>,
    pub break_glass_store: Arc<dyn ianua_app::ports::authentication::BreakGlassStore>,
    pub broker_authenticator: Arc<dyn ianua_app::ports::broker::BrokerAuthenticator>,
    pub cert_pem_validator: Arc<dyn ianua_app::ports::crypto::CertPemValidator>,
    pub certificate_parser: Arc<dyn ianua_app::ports::domain::CertificateParser>,
    pub certificate_store: Arc<dyn ianua_app::ports::domain::CertificateStore>,
    /// The deployment's challenge provider, when one is set up. Without one,
    /// a device nobody trusted is refused while sign-in is under pressure.
    pub challenge_verifier: Option<Arc<dyn ianua_app::ports::authentication::ChallengeVerifier>>,
    /// Sets the puzzles the platform's own challenge provider checks; none
    /// when the provider is Turnstile, which sets its own.
    pub challenge_issuer: Option<Arc<dyn ianua_app::ports::authentication::ChallengeIssuer>>,
    pub classification_store: Arc<dyn ianua_app::ports::data_classification::ClassificationStore>,
    pub clearance_rule_store: Arc<dyn ianua_app::ports::authorization::ClearanceRuleStore>,
    pub client_secret_generator: Arc<dyn ianua_app::ports::oauth::ClientSecretGenerator>,
    pub client_secret_verifier: Arc<dyn ianua_app::ports::oauth::ClientSecretVerifier>,
    pub cloud_account_store: Arc<dyn ianua_app::ports::cloud::CloudAccountStore>,
    pub cloud_provider_registry: Arc<dyn ianua_app::ports::cloud::CloudProviderRegistry>,
    pub code_hasher: Arc<dyn ianua_app::ports::oauth::CodeHasher>,
    pub connection_store: Arc<dyn ianua_app::ports::federation::ConnectionStore>,
    /// Reads a connector's signing request and signs the certificate it
    /// holds its link to the gateway with.
    pub connector_authority: Arc<dyn ianua_app::ports::routing::ConnectorAuthority>,
    /// Makes a connector's one-time enrollment code and hashes a presented
    /// one.
    pub connector_code_generator: Arc<dyn ianua_app::ports::routing::ConnectorCodeGenerator>,
    pub consent_store: Arc<dyn ianua_app::ports::identity::ConsentStore>,
    pub consumer_authorities: Arc<dyn ianua_app::acting::ConsumerAuthorities>,
    /// Makes the API keys consumers sign in with at the gateway.
    pub consumer_key_generator: Arc<dyn ianua_app::ports::consumers::ConsumerKeyGenerator>,
    pub consumer_store: Arc<dyn ianua_app::ports::consumers::ConsumerStore>,
    /// Keeps each tenant's private-network connectors.
    pub connector_store: Arc<dyn ianua_app::ports::routing::ConnectorStore>,
    pub control_plane_label_resolver: Arc<dyn ianua_app::ports::shared::ControlPlaneLabelResolver>,
    pub credential_breach_checker:
        Arc<dyn ianua_app::ports::authentication::CredentialBreachChecker>,
    pub credential_store: Arc<dyn ianua_app::ports::authentication::CredentialStore>,
    pub cross_tenant_domain_store: Arc<dyn ianua_app::ports::domain::CrossTenantDomainStore>,
    pub cross_tenant_user_checker: Arc<dyn ianua_app::ports::shared::CrossTenantUserChecker>,
    pub css_sanitizer: Arc<dyn ianua_app::ports::branding::CssSanitizer>,
    pub dead_letters: Arc<dyn ianua_app::ports::messaging::DeadLetters>,
    pub decision_record_store: Arc<dyn ianua_app::ports::authorization::DecisionRecordStore>,
    pub delegation_request_store: Arc<dyn ianua_app::ports::agents::DelegationRequestStore>,
    pub delegation_store: Arc<dyn ianua_app::ports::agents::DelegationStore>,
    pub device_auth_store: Arc<dyn ianua_app::ports::oauth::DeviceAuthStore>,
    pub directory_authorities: Arc<dyn ianua_app::acting::directory::DirectoryAuthorities>,
    pub dns_resolver: Arc<dyn ianua_app::ports::domain::DnsResolver>,
    pub dns_zone_writer: Arc<dyn ianua_app::ports::domain::DnsZoneWriter>,
    pub egress_policy_store: Arc<dyn ianua_app::ports::routing::EgressPolicyStore>,
    pub email_template_store: Arc<dyn ianua_app::ports::branding::EmailTemplateStore>,
    pub erasure_request_store: Arc<dyn ianua_app::ports::identity::ErasureRequestStore>,
    pub evidence_store: Arc<dyn ianua_app::ports::audit::EvidenceStore>,
    pub external_id_generator: Arc<dyn ianua_app::ports::cloud::ExternalIdGenerator>,
    pub federated_link_store: Arc<dyn ianua_app::ports::federation::FederatedLinkStore>,
    pub fresh_proofs: Arc<dyn ianua_app::services::authentication::fresh_proof::FreshProofs>,
    pub geolocator: Arc<dyn ianua_app::ports::authentication::Geolocator>,
    pub group_membership_store: Arc<dyn ianua_app::ports::authorization::GroupMembershipStore>,
    pub group_store: Arc<dyn ianua_app::ports::authorization::GroupStore>,
    pub handover_offer_store: Arc<dyn ianua_app::ports::domain::HandoverOfferStore>,
    pub impersonation_grant_store: Arc<dyn ianua_app::ports::operator::ImpersonationGrantStore>,
    pub integration_account_store: Arc<dyn ianua_app::ports::workflows::IntegrationAccountStore>,
    pub integration_catalog: Arc<dyn ianua_app::ports::workflows::IntegrationCatalog>,
    /// Asks an integration whether an account's credential works.
    pub account_verifier: Arc<dyn ianua_app::ports::workflows::AccountVerifier>,
    /// Calls an integration's read operations, to fill a step form's
    /// pickers.
    pub action_runner: Arc<dyn ianua_app::ports::workflows::ActionRunner>,
    /// Asks an integration about the grant an account holds, and exchanges
    /// it ahead of a call.
    pub grant_exchanger: Arc<dyn ianua_app::ports::workflows::GrantExchanger>,
    /// Lets one caller at a time exchange an account's grant.
    pub grant_exchange_lease: Arc<dyn ianua_app::ports::workflows::GrantExchangeLease>,
    /// Sends a person to sign in at a service to connect an account, and
    /// trades the code it answers with for a credential.
    pub service_sign_in: Arc<dyn ianua_app::ports::workflows::ServiceSignIn>,
    /// Makes the state and verifier of a sign-in, and digests the state.
    pub connection_secrets: Arc<dyn ianua_app::ports::workflows::ConnectionSecrets>,
    pub pending_connection_store: Arc<dyn ianua_app::ports::workflows::PendingConnectionStore>,
    /// Finds a sign-in by the state its service answered with, before its
    /// tenant is known.
    pub connection_states: Arc<dyn ianua_app::ports::workflows::ConnectionStates>,
    /// Registers a workflow for a service's events, and removes it.
    pub service_registrar: Arc<dyn ianua_app::ports::workflows::ServiceRegistrar>,
    /// Says how each installed service's channels work.
    pub service_channel_setup: Arc<dyn ianua_app::ports::workflows::ServiceChannelSetup>,
    pub service_subscription_store: Arc<dyn ianua_app::ports::workflows::ServiceSubscriptionStore>,
    /// Finds a registration by the address or key an event arrived with.
    pub subscription_directory: Arc<dyn ianua_app::ports::workflows::SubscriptionDirectory>,
    /// Checks an arrived event's signature and reads it.
    pub service_event_reader: Arc<dyn ianua_app::ports::workflows::ServiceEventReader>,
    /// Remembers the events already taken, so a resent one starts nothing.
    pub delivery_ledger: Arc<dyn ianua_app::ports::workflows::DeliveryLedger>,
    /// Keeps the channels of services with one address per account.
    pub account_channel_store: Arc<dyn ianua_app::ports::workflows::AccountChannelStore>,
    /// Finds a channel by the address an event arrived at.
    pub channel_directory: Arc<dyn ianua_app::ports::workflows::ChannelDirectory>,
    pub sandbox_store: Arc<dyn ianua_app::ports::workflows::SandboxStore>,
    pub sandbox_version_store: Arc<dyn ianua_app::ports::workflows::SandboxVersionStore>,
    /// Keeps the trials of sandbox versions.
    pub sandbox_trial_store: Arc<dyn ianua_app::ports::workflows::SandboxTrialStore>,
    /// Keeps each workflow's sample cases.
    pub evaluation_set_store: Arc<dyn ianua_app::ports::workflows::EvaluationSetStore>,
    /// Keeps the evaluations of workflows against their cases.
    pub evaluation_store: Arc<dyn ianua_app::ports::workflows::EvaluationStore>,
    /// The runtimes offered for new sandbox versions, each in its image.
    pub sandbox_runtimes: Arc<dyn ianua_app::ports::workflows::SandboxRuntimes>,
    /// Keeps the image registries tenants allow their own images from.
    pub image_registry_store: Arc<dyn ianua_app::ports::workflows::ImageRegistryStore>,
    /// Asks a registry what a company's named image points to now.
    pub image_resolver: Arc<dyn ianua_app::ports::workflows::ImageResolver>,
    /// Reads sandbox code from repositories and pushes versions to them.
    pub code_repositories: Arc<dyn ianua_app::ports::workflows::CodeRepositories>,
    /// Keeps the tenants' memories.
    pub memory_store: Arc<dyn ianua_app::ports::workflows::MemoryStore>,
    /// The vector store keeping the memories' texts.
    pub memory_entries: Arc<dyn ianua_app::ports::workflows::MemoryEntries>,
    /// Turns texts into vectors through a memory's embedding model.
    pub embedder: Arc<dyn ianua_app::ports::workflows::Embedder>,
    pub intent_compiler: Arc<dyn ianua_app::ports::agents::IntentCompiler>,
    pub invitation_store: Arc<dyn ianua_app::ports::identity::InvitationStore>,
    pub job_queue: Arc<dyn ianua_app::ports::scheduling::JobQueue>,
    pub jwt_signer: Arc<dyn ianua_app::ports::crypto::JwtSigner>,
    pub redaction_digest: Arc<dyn ianua_app::ports::data_classification::RedactionDigest>,
    pub key_generator: Arc<dyn ianua_app::ports::crypto::KeyGenerator>,
    pub ldap_certificate_authority: Arc<dyn ianua_app::ports::directory::LdapCertificateAuthority>,
    pub ldap_certificate_store: Arc<dyn ianua_app::ports::directory::LdapCertificateStore>,
    pub limit_enforcer: Arc<dyn ianua_app::ports::limits::LimitEnforcer>,
    pub linked_identity_lookup: Arc<dyn ianua_app::ports::organization::LinkedIdentityLookup>,
    pub linked_identity_store: Arc<dyn ianua_app::ports::organization::LinkedIdentityStore>,
    /// Keeps each tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn ianua_app::ports::proxy::LogShippingStore>,
    pub mail_throttle: Arc<dyn ianua_app::ports::limits::MailThrottle>,
    /// Sends templated mail. The app's
    /// [`TenantMailer`](ianua_app::services::branding::mailer::TenantMailer),
    /// which picks the template and sender before queueing on the mail
    /// outbox.
    pub mailer: Arc<dyn ianua_app::ports::shared::Mailer>,
    pub message_consumer: Arc<dyn ianua_app::ports::messaging::MessageConsumer>,
    pub message_publisher: Arc<dyn ianua_app::ports::messaging::MessagePublisher>,
    pub message_shape: Arc<dyn ianua_app::ports::messaging::MessageShape>,
    pub metadata_store: Arc<dyn ianua_app::ports::identity::MetadataStore>,
    pub mfa_enrollment_store: Arc<dyn ianua_app::ports::authentication::MfaEnrollmentStore>,
    pub factor_standing: Arc<dyn ianua_app::ports::authentication::FactorStanding>,
    pub mfa_verifier: Arc<dyn ianua_domain::domains::authentication::mfa::verifier::MfaVerifier>,
    pub migration_store: Arc<dyn ianua_app::ports::crypto::MigrationStore>,
    pub model_client: Arc<dyn ianua_app::ports::agents::ModelClient>,
    pub model_provider_store: Arc<dyn ianua_app::ports::agents::ModelProviderStore>,
    pub nonce_ledger: Arc<dyn ianua_app::ports::authentication::NonceLedger>,
    pub notification_preference_store:
        Arc<dyn ianua_app::ports::notifications::NotificationPreferenceStore>,
    pub notification_publisher: Arc<dyn ianua_app::ports::realtime::NotificationPublisher>,
    pub o_auth_client_store: Arc<dyn ianua_app::ports::oauth::OAuthClientStore>,
    pub o_auth_consent_store: Arc<dyn ianua_app::ports::oauth::OAuthConsentStore>,
    pub oidc_flow_store: Arc<dyn ianua_app::ports::federation::OidcFlowStore>,
    pub oidc_validator: Arc<dyn ianua_app::ports::federation::OidcValidator>,
    pub operation_risk_override_store:
        Arc<dyn ianua_app::ports::workflows::OperationRiskOverrideStore>,
    pub operator_authorities: Arc<dyn ianua_app::acting::OperatorAuthorities>,
    pub operator_key_store: Arc<dyn ianua_app::ports::operator::OperatorKeyStore>,
    pub operator_store: Arc<dyn ianua_app::ports::operator::OperatorStore>,
    pub org_actors: Arc<dyn ianua_app::acting::OrgActors>,
    pub org_api_key_store: Arc<dyn ianua_app::ports::organization::OrgApiKeyStore>,
    pub org_audit_log_store: Arc<dyn ianua_app::ports::audit::OrgAuditLogStore>,
    pub org_email_change_store: Arc<dyn ianua_app::ports::shared::OrgEmailChangeStore>,
    pub org_invitation_store: Arc<dyn ianua_app::ports::organization::OrgInvitationStore>,
    pub org_mfa_enrollment_store: Arc<dyn ianua_app::ports::organization::OrgMfaEnrollmentStore>,
    pub org_notification_store: Arc<dyn ianua_app::ports::notifications::OrgNotificationStore>,
    pub org_passkey_ceremony_store:
        Arc<dyn ianua_app::ports::organization::OrgPasskeyCeremonyStore>,
    pub org_passkey_store: Arc<dyn ianua_app::ports::organization::OrgPasskeyStore>,
    pub org_recovery_code_store: Arc<dyn ianua_app::ports::organization::OrgRecoveryCodeStore>,
    pub org_session_store: Arc<dyn ianua_app::ports::organization::OrgSessionStore>,
    pub org_tenant_grant_store: Arc<dyn ianua_app::ports::organization::OrgTenantGrantStore>,
    pub org_token_store_email_verification: Arc<
        dyn ianua_app::ports::organization::OrgTokenStore<
                ianua_domain::domains::identity::tokens::email_verification::EmailVerification,
            >,
    >,
    pub org_token_store_installation_setup: Arc<
        dyn ianua_app::ports::organization::OrgTokenStore<
                ianua_domain::domains::identity::tokens::installation_setup::InstallationSetup,
            >,
    >,
    pub org_token_store_password_reset: Arc<
        dyn ianua_app::ports::organization::OrgTokenStore<
                ianua_domain::domains::identity::tokens::password_reset::PasswordReset,
            >,
    >,
    pub org_token_store_sign_in_confirmation: Arc<
        dyn ianua_app::ports::organization::OrgTokenStore<
                ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation,
            >,
    >,
    pub org_trusted_device_store: Arc<dyn ianua_app::ports::organization::OrgTrustedDeviceStore>,
    pub org_user_store: Arc<dyn ianua_app::ports::organization::OrgUserStore>,
    pub org_token_store_magic_link: Arc<
        dyn ianua_app::ports::organization::OrgTokenStore<
                ianua_domain::domains::identity::tokens::magic_link::MagicLink,
            >,
    >,
    pub org_subscription_store: Arc<dyn ianua_app::ports::organization::OrgSubscriptionStore>,
    pub plan_usage_counter: Arc<dyn ianua_app::ports::organization::PlanUsageCounter>,
    pub payment_provider: Arc<dyn ianua_app::ports::organization::PaymentProvider>,
    /// The payment provider's events acted on, so each is acted on once and
    /// in order.
    pub payment_event_ledger: Arc<dyn ianua_app::ports::organization::PaymentEventLedger>,
    pub org_identity_provider_store:
        Arc<dyn ianua_app::ports::organization::OrgIdentityProviderStore>,
    pub org_sso_request_store: Arc<dyn ianua_app::ports::organization::OrgSsoRequestStore>,
    pub org_saml_assertion_ledger: Arc<dyn ianua_app::ports::organization::OrgSamlAssertionLedger>,
    pub org_erasure_request_store: Arc<dyn ianua_app::ports::organization::OrgErasureRequestStore>,
    pub org_consent_store: Arc<dyn ianua_app::ports::organization::OrgConsentStore>,
    pub org_branding_store: Arc<dyn ianua_app::ports::organization::OrgBrandingStore>,
    /// Sign-ups waiting for their link.
    pub pending_signup_store: Arc<dyn ianua_app::ports::organization::PendingSignupStore>,
    pub organization_metrics_reader: Arc<dyn ianua_app::ports::metrics::OrganizationMetricsReader>,
    pub organization_store: Arc<dyn ianua_app::ports::organization::OrganizationStore>,
    pub passkey_ceremony_store: Arc<dyn ianua_app::ports::authentication::PasskeyCeremonyStore>,
    pub passkey_store: Arc<dyn ianua_app::ports::authentication::PasskeyStore>,
    pub passkey_verifier: Arc<dyn ianua_app::ports::authentication::PasskeyVerifier>,
    pub password_hasher:
        Arc<dyn ianua_domain::domains::authentication::credentials::password::PasswordHasher>,
    /// Caps how many password hashes run at once on this node.
    pub password_hash_permits: Arc<dyn ianua_app::ports::authentication::PasswordHashPermits>,
    pub pipeline_store: Arc<dyn ianua_app::ports::proxy::PipelineStore>,
    pub pkce_verifier: Arc<dyn ianua_app::ports::oauth::PkceVerifier>,
    pub plan_limits_source: Arc<dyn ianua_app::ports::limits::PlanLimitsSource>,
    pub platform_notification_store:
        Arc<dyn ianua_app::ports::notifications::PlatformNotificationStore>,
    /// Whether the tenant's records know a caller and let it act now.
    pub policy_decisions: Arc<dyn ianua_app::ports::routing::PolicyDecisionPoint>,
    /// Organization members an agent acts for, as a tenant reads them.
    pub member_standings: Arc<dyn ianua_app::ports::organization::MemberStandings>,
    pub policy_store: Arc<dyn ianua_app::ports::authorization::PolicyStore>,
    pub principal_existence_checker: Arc<dyn ianua_app::ports::shared::PrincipalExistenceChecker>,
    /// Searches the request records the gateway kept.
    pub proxy_request_log: Arc<dyn ianua_app::ports::proxy::ProxyRequestLog>,
    pub public_key_decoder: Arc<dyn ianua_app::ports::crypto::PublicKeyDecoder>,
    pub push_secret_generator: Arc<dyn ianua_app::ports::messaging::PushSecretGenerator>,
    pub receiver_keys: Arc<dyn ianua_app::ports::signals::ReceiverKeys>,
    pub recovery_code_generator: Arc<dyn ianua_app::ports::authentication::RecoveryCodeGenerator>,
    pub recovery_code_store: Arc<dyn ianua_app::ports::authentication::RecoveryCodeStore>,
    pub refresh_token_generator:
        Arc<dyn ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator>,
    pub registered_domain_store: Arc<dyn ianua_app::ports::domain::RegisteredDomainStore>,
    pub relationship_resolver: Arc<dyn ianua_app::ports::agents::RelationshipResolver>,
    pub relationship_store: Arc<dyn ianua_app::ports::authorization::RelationshipStore>,
    pub request_seal: Arc<dyn ianua_app::ports::authentication::RequestSeal>,
    pub reset_request_store: Arc<dyn ianua_app::ports::authentication::ResetRequestStore>,
    pub resource_grant_store: Arc<dyn ianua_app::ports::agents::ResourceGrantStore>,
    pub resource_type_store: Arc<dyn ianua_app::ports::authorization::ResourceTypeStore>,
    pub review_assignment_store: Arc<dyn ianua_app::ports::agents::ReviewAssignmentStore>,
    pub role_assignment_store: Arc<dyn ianua_app::ports::authorization::RoleAssignmentStore>,
    pub role_deletion_unit_of_work:
        Arc<dyn ianua_app::ports::authorization::RoleDeletionUnitOfWork>,
    pub role_holder_queries: Arc<dyn ianua_app::ports::authorization::RoleHolderQueries>,
    pub role_store: Arc<dyn ianua_app::ports::authorization::RoleStore>,
    pub route_store: Arc<dyn ianua_app::ports::routing::RouteStore>,
    pub route_traffic_reader: Arc<dyn ianua_app::ports::metrics::RouteTrafficReader>,
    pub backend_health_reader: Arc<dyn ianua_app::ports::routing::BackendHealthReader>,
    pub run_cancellation: Arc<dyn ianua_app::ports::agents::RunCancellation>,
    pub run_store: Arc<dyn ianua_app::ports::agents::RunStore>,
    pub saml_assertion_ledger: Arc<dyn ianua_app::ports::federation::SamlAssertionLedger>,
    pub saml_request_store: Arc<dyn ianua_app::ports::federation::SamlRequestStore>,
    pub saml_service_provider_messages:
        Arc<dyn ianua_app::ports::federation::SamlServiceProviderMessages>,
    pub saml_validator: Arc<dyn ianua_app::ports::federation::SamlValidator>,
    /// Reads an identity provider's SAML metadata, fetched or pasted.
    pub saml_metadata_reader: Arc<dyn ianua_app::ports::federation::SamlMetadataReader>,
    /// Makes and checks the key pairs a SAML provider seals assertions to.
    pub saml_encryption_keys: Arc<dyn ianua_app::ports::federation::SamlEncryptionKeys>,
    /// The tenant's SAML apps, with this platform as their identity provider.
    pub saml_service_provider_store:
        Arc<dyn ianua_app::ports::federation::SamlServiceProviderStore>,
    /// Reads the SAML messages peers send and checks their signatures.
    pub saml_message_reader: Arc<dyn ianua_app::ports::federation::SamlMessageReader>,
    /// Makes pairwise and transient SAML `NameID`s.
    pub saml_name_ids: Arc<dyn ianua_app::ports::federation::SamlNameIds>,
    /// Seals an assertion to a SAML app's key.
    pub assertion_encrypter: Arc<dyn ianua_app::ports::federation::AssertionEncrypter>,
    /// The SAML apps each session signed in to, for single logout.
    pub saml_app_session_store: Arc<dyn ianua_app::ports::federation::SamlAppSessionStore>,
    /// The SAML sign-in requests held from their arrival until answered.
    pub held_saml_sign_in_store: Arc<dyn ianua_app::ports::federation::HeldSamlSignInStore>,
    /// The provider session behind each session opened through SAML.
    pub provider_session_store: Arc<dyn ianua_app::ports::federation::ProviderSessionStore>,
    /// What a connection's group mapping gave each person, to take back
    /// what the provider no longer brings.
    pub mapped_holdings_store: Arc<dyn ianua_app::ports::federation::MappedHoldingsStore>,
    /// The logout requests sent, kept until they are answered.
    pub sent_logout_request_store: Arc<dyn ianua_app::ports::federation::SentLogoutRequestStore>,
    /// The peers' logout requests taken already, so each is taken once.
    pub saml_logout_ledger: Arc<dyn ianua_app::ports::federation::SamlLogoutLedger>,
    /// The service accounts applications bind to the directory as.
    pub directory_service_account_store:
        Arc<dyn ianua_app::ports::directory::DirectoryServiceAccountStore>,
    /// Makes and hashes service account secrets.
    pub service_account_secrets: Arc<dyn ianua_app::ports::directory::ServiceAccountSecrets>,
    pub schema_store: Arc<dyn ianua_app::ports::messaging::SchemaStore>,
    pub scim_authorities: Arc<dyn ianua_app::acting::ScimAuthorities>,
    /// Finds the directory's groups a SCIM filter picks, a page at a time.
    pub scim_group_queries: Arc<dyn ianua_app::ports::federation::ScimGroupQueries>,
    pub scim_store: Arc<dyn ianua_app::ports::federation::ScimStore>,
    pub scim_token_generator: Arc<dyn ianua_app::ports::federation::ScimTokenGenerator>,
    /// Finds the users a SCIM filter picks, in the order a directory asks.
    pub scim_user_queries: Arc<dyn ianua_app::ports::federation::ScimUserQueries>,
    pub secure_random: Arc<dyn ianua_app::ports::runtime::SecureRandom>,
    pub secret_encryptor: Arc<dyn ianua_app::ports::authentication::SecretEncryptor>,
    pub secure_token_generator: Arc<dyn ianua_app::ports::crypto::SecureTokenGenerator>,
    pub separation_rule_store: Arc<dyn ianua_app::ports::authorization::SeparationRuleStore>,
    pub service_store: Arc<dyn ianua_app::ports::routing::ServiceStore>,
    pub sent_code_generator: Arc<dyn ianua_app::ports::authentication::SentCodeGenerator>,
    pub sent_code_store: Arc<dyn ianua_app::ports::authentication::SentCodeStore>,
    pub session_store: Arc<dyn ianua_app::ports::shared::SessionStore>,
    /// Counts failed passwords per account and network, and per account.
    pub sign_in_attempt_counts: Arc<dyn ianua_app::ports::authentication::SignInAttemptCounts>,
    pub sign_in_code_store: Arc<dyn ianua_app::ports::authentication::SignInCodeStore>,
    /// Counts failed password sign-ins per tenant and per organization.
    pub sign_in_failure_budget: Arc<dyn ianua_app::ports::authentication::SignInFailureBudget>,
    pub sign_in_history_store: Arc<dyn ianua_app::ports::authentication::SignInHistoryStore>,
    /// Holds a sign-in back while its account is guessed at from many
    /// networks.
    pub pause: Arc<dyn ianua_app::ports::runtime::Pause>,
    pub sign_in_link_store_magic_link: Arc<
        dyn ianua_app::ports::identity::SignInLinkStore<
                ianua_domain::domains::identity::tokens::magic_link::MagicLink,
            >,
    >,
    pub sign_in_link_store_sign_in_confirmation: Arc<
        dyn ianua_app::ports::identity::SignInLinkStore<
                ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation,
            >,
    >,
    pub signal_deliverer: Arc<dyn ianua_app::ports::signals::SignalDeliverer>,
    pub signal_poll_queue: Arc<dyn ianua_app::ports::signals::SignalPollQueue>,
    pub signal_stream_store: Arc<dyn ianua_app::ports::signals::SignalStreamStore>,
    pub signing_certificate_issuer: Arc<dyn ianua_app::ports::federation::SigningCertificateIssuer>,
    pub signing_key_store: Arc<dyn ianua_app::ports::crypto::SigningKeyStore>,
    pub site_rules: Arc<dyn ianua_app::ports::shared::SiteRules>,
    pub stream_route_logins: Arc<dyn ianua_app::ports::routing::StreamRouteLogins>,
    pub stream_route_store: Arc<dyn ianua_app::ports::routing::StreamRouteStore>,
    pub subscription_store: Arc<dyn ianua_app::ports::messaging::SubscriptionStore>,
    pub task_template_store: Arc<dyn ianua_app::ports::agents::TaskTemplateStore>,
    pub task_token_issuer: Arc<dyn ianua_app::ports::agents::TaskTokenIssuer>,
    pub tenant_authorities: Arc<dyn ianua_app::acting::TenantAuthorities>,
    pub tenant_email_change_store: Arc<dyn ianua_app::ports::shared::TenantEmailChangeStore>,
    pub tenant_member_roster: Arc<dyn ianua_app::ports::organization::TenantMemberRoster>,
    pub tenant_metrics_reader: Arc<dyn ianua_app::ports::metrics::TenantMetricsReader>,
    pub tenant_notification_store:
        Arc<dyn ianua_app::ports::notifications::TenantNotificationStore>,
    pub tenant_setup_store: Arc<dyn ianua_app::ports::tenant::TenantSetupStore>,
    pub tenant_store: Arc<dyn ianua_app::ports::tenant::TenantStore>,
    /// The time of day in a zone, for access rules that name one.
    pub time_zones: Arc<dyn ianua_app::ports::scheduling::TimeZones>,
    pub tool_store: Arc<dyn ianua_app::ports::agents::ToolStore>,
    pub topic_authorizer: Arc<dyn ianua_app::ports::broker::TopicAuthorizer>,
    pub topic_store: Arc<dyn ianua_app::ports::messaging::TopicStore>,
    pub trusted_device_store: Arc<dyn ianua_app::ports::authentication::TrustedDeviceStore>,
    pub unit_of_work: Arc<dyn ianua_app::ports::runtime::UnitOfWork>,
    pub user_attribute_store: Arc<dyn ianua_app::ports::identity::UserAttributeStore>,
    pub user_existence_checker: Arc<dyn ianua_app::ports::shared::UserExistenceChecker>,
    pub user_lookup: Arc<dyn ianua_app::ports::authentication::UserLookup>,
    pub user_store: Arc<dyn ianua_app::ports::identity::UserStore>,
    pub verification_throttle: Arc<dyn ianua_app::ports::signals::VerificationThrottle>,
    pub verification_token_store: Arc<dyn ianua_app::ports::identity::VerificationTokenStore>,
    pub verifying_key_store: Arc<dyn ianua_app::ports::crypto::VerifyingKeyStore>,
    pub wasm_module_store: Arc<dyn ianua_app::ports::proxy::WasmModuleStore>,
    pub webhook_deliverer: Arc<dyn ianua_app::ports::webhooks::WebhookDeliverer>,
    pub webhook_secret_generator: Arc<dyn ianua_app::ports::webhooks::WebhookSecretGenerator>,
    pub webhook_send_throttle: Arc<dyn ianua_app::ports::webhooks::WebhookSendThrottle>,
    pub webhook_store: Arc<dyn ianua_app::ports::webhooks::WebhookStore>,
    pub workflow_execution_store: Arc<dyn ianua_app::ports::workflows::WorkflowExecutionStore>,
    pub workflow_store: Arc<dyn ianua_app::ports::workflows::WorkflowStore>,
    pub workflow_trigger_secret_generator:
        Arc<dyn ianua_app::ports::workflows::WorkflowTriggerSecretGenerator>,
    pub workflow_trigger_secret_store:
        Arc<dyn ianua_app::ports::workflows::WorkflowTriggerSecretStore>,
    pub workload_token_verifier: Arc<dyn ianua_app::ports::agents::WorkloadTokenVerifier>,
    pub xml_signer: Arc<dyn ianua_app::ports::crypto::XmlSigner>,
}
impl Adapters {
    /// What people hold now, worked out from their accounts as they stand:
    /// the person a workflow acts for, and the person behind an agent's
    /// delegation.
    pub(crate) fn accounts_now(&self) -> Arc<AccountsNow> {
        Arc::new(AccountsNow::new(AccountsNowPorts {
            access_records: self.access_record_store.clone(),
            users: self.user_store.clone(),
            org_users: self.org_user_store.clone(),
            organizations: self.organization_store.clone(),
            org_grants: self.org_tenant_grant_store.clone(),
            relationships: self.relationship_resolver.clone(),
        }))
    }

    /// What keeps accounts' short-lived tokens good just before a call.
    pub(crate) fn account_grants(&self) -> Arc<AccountGrants> {
        Arc::new(AccountGrants::new(AccountGrantsPorts {
            accounts: self.integration_account_store.clone(),
            exchanger: self.grant_exchanger.clone(),
            lease: self.grant_exchange_lease.clone(),
            unit_of_work: self.unit_of_work.clone(),
        }))
    }
}

/// The settings the use cases are built with: limits, lifetimes and
/// addresses.
#[derive(Clone)]
pub struct Settings {
    /// Lengths and counts the domain checks values against.
    pub domain_limits: ianua_domain::shared::config::DomainLimits,
    /// Every lifetime, limit and window the use cases are built with.
    pub tunables: Tunables,
    /// The deployment's public base URL, which emailed links and identity
    /// providers name.
    pub app_base_url: ianua_domain::types::HttpsUrl,
    /// Internal networks a service upstream or stream backend may target
    /// besides public addresses. The operator sets it for the whole
    /// deployment; no tenant can.
    pub upstream_networks: ianua_domain::shared::security::ssrf::UpstreamNetworks,
    /// The compliance limits tenants are provisioned and changed under.
    pub compliance_limits: ianua_domain::domains::tenant::compliance_limits::ComplianceLimits,
    /// Whether strangers may sign up and found organizations here.
    pub enrollment: ianua_app::use_cases::onboarding::Enrollment,
    /// A link opening a customer's cloud console with the onboarding
    /// template loaded, `{external_id}` to substitute; `None` offers written
    /// steps only.
    pub cloud_console_template: Option<String>,
    /// Where the OAuth device flow sends a person to type their code: the
    /// dashboard's `/device` page.
    pub device_verification_uri: ianua_domain::types::HttpsUrl,
    /// The audience agents sign their assertions for: the token endpoint.
    pub agent_token_audience: ianua_domain::types::Audience,
    /// The domain each tenant's platform subdomains sit under, such as
    /// `ianua.example.com`.
    pub base_domain: ianua_domain::types::DomainName,
    /// The platform address shape this deployment can serve.
    pub platform_addressing: ianua_domain::domains::tenant::hosts::PlatformAddressing,
    /// Deployment host labels unavailable as organization slugs.
    pub platform_hosts: Vec<ianua_domain::types::DomainName>,
    /// What this deployment offers tenants' custom domains: nameservers,
    /// proxy address, vouched-for domains and claim lifetimes.
    pub custom_domains: crate::domain::CustomDomainSettings,
    /// Whether the operator lets tenants run their own container images in
    /// sandboxes; off unless turned on.
    pub own_images: ianua_app::ports::workflows::OwnImages,
}
