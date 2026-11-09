//! The adapter behind every port the API's use cases need, from the
//! platform's shared parts and the configuration.
//!
//! What the platform holds is taken from it, never built again: the
//! databases, the wrapped unit of work and dispatcher, the cached bearer
//! lookup and access records, the seals and digests, the file store, the
//! bus and the two states. Counts a node keeps for itself, the rate limits
//! and the throttles, go on the node's own state; counts every node must
//! agree on, the ledgers, budgets and quotas, on the shared one. The stores
//! several ports read through are built once here and handed to each.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::acting::agent::{AgentActing, AgentActingPorts};
use ianua_app::acting::consumer::{ConsumerActing, ConsumerActingPorts};
use ianua_app::acting::directory::DirectoryActing;
use ianua_app::acting::operator::{OperatorActing, OperatorActingPorts};
use ianua_app::acting::organization::{OrgActing, OrgActingPorts};
use ianua_app::acting::scim::{ScimActing, ScimActingPorts};
use ianua_app::acting::tenant::{
    MemberPorts, OperatorPorts, TenantActing, TenantActingPorts, TenantCredentialPorts,
};
use ianua_app::ports::messaging::{DeadLetters, MessageConsumer, MessagePublisher};
use ianua_app::services::authentication::fresh_proof::{
    FactorProof, FreshProofPorts, FreshProofStep, LinkProof, MemberProof, PasskeyProof,
    PasswordProof,
};
use ianua_app::services::authentication::password_hashing::PasswordHashing;
use ianua_app::services::authentication::sign_in_counts::SignInCounts;
use ianua_app::services::branding::mailer::{TenantMailer, TenantMailerPorts};
use ianua_app::services::issuers::TenantIssuers;
use ianua_app::services::limits::enforcer::PlanLimitEnforcer;
use ianua_app::services::limits::plan::StoredPlanLimits;
use ianua_app::services::messaging::broker_authenticator::DelegationBrokerAuthenticator;
use ianua_app::services::messaging::topic_authorizer::DelegationTopicAuthorizer;
use ianua_assembly::deps::{Adapters, Settings};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::HttpsUrl;
use ianua_infra::bundled::{BundledCommonPasswordList, BundledPublishedFiles, BundledSiteRules};
use ianua_infra::bus::{
    BusDeadLetters, BusMessageConsumer, BusMessagePublisher, BusNotificationPublisher,
    BusNotificationSubscriber, NoDeadLetters, NoMessageConsumer, NoMessagePublisher,
};
use ianua_infra::cache::{
    Allowance, CacheAlertThrottle, CacheBackendHealthReader, CacheBindThrottle,
    CacheBudgetUsageReader, CacheConsumerQuotaCounter, CacheMailThrottle, CacheNonceLedger,
    CacheRateLimiter, CacheSignInAttemptCounts, CacheSignInFailureBudget,
    CacheVerificationThrottle, CacheWebhookSendThrottle,
};
use ianua_infra::crypto::{
    AesGcmSecretEncryptor, HmacRedactionDigest, JwkClientAssertionVerifier, JwkDpopProofVerifier,
    OsAttestationNonceGenerator, OsDestinationSecretGenerator, OsExternalIdGenerator,
    OsPushSecretGenerator, OsSecureRandom, OsSecureTokenGenerator, OsWebhookSecretGenerator,
    Pkcs8AccessTokenJwtVerifier, Pkcs8AgentAssertionVerifier, Pkcs8AppSessionTokens,
    Pkcs8IdTokenHintVerifier, Pkcs8JwtSigner, Pkcs8KeyGenerator, Pkcs8MessageProvenanceSigner,
    Pkcs8MessageProvenanceVerifier, Pkcs8PublicKeyDecoder, Pkcs8TaskTokenIssuer,
    Pkcs8TaskTokenVerifier, Sha2AtHashCalculator, Sha256PayloadHasher, Sha256PkceVerifier,
    TotpMfaVerifier, X509CertPemValidator, X509CertificateParser,
};
use ianua_infra::css::AllowListCssSanitizer;
use ianua_infra::files::{
    FileAuditExportFiles, FileDataExportFiles, FileLinkedFiles, FileLogoStore, FilePublicLogos,
};
use ianua_infra::integrations::{
    EventAddresses, InstalledAccountVerifier, InstalledActionRunner, InstalledCodeRepositories,
    InstalledGrantExchanger, InstalledIntegrationCatalog, InstalledServiceChannelSetup,
    InstalledServiceEventReader, InstalledServiceRegistrar, InstalledServiceSignIn,
};
use ianua_infra::language::FluentRefusalWording;
use ianua_infra::mail::{JinjaTemplateRenderer, OutboundMailProviderTransport, QueuedMailOutbox};
use ianua_infra::pages::TemplatePageRenderer;
use ianua_infra::postgres::activity::PgActivityStore;
use ianua_infra::postgres::agents::{
    PgAgentActivityStore, PgAgentAssertionReplayGuard, PgAgentCredentialStore, PgAgentExposureGate,
    PgAgentSightingStore, PgAgentStandingCheck, PgAgentStore, PgApprovalStore,
    PgAttestationChallengeStore, PgDelegationRequestStore, PgDelegationRevocationCheck,
    PgDelegationStore, PgModelProviderStore, PgRelationshipResolver, PgResourceGrantStore,
    PgReviewAssignmentStore, PgRunCancellation, PgRunStore, PgTaskTemplateStore, PgToolStore,
};
use ianua_infra::postgres::audit::{
    PgAuditChainVerdictStore, PgAuditExportStore, PgAuditStreamStore, PgEvidenceStore,
    PgOrgAuditLogStore, PgPlatformAuditLogStore, PgTenantAuditLogStore,
};
use ianua_infra::postgres::authentication::{
    PgBreakGlassStore, PgCredentialStore, PgFactorStanding, PgHandoffStore, PgMfaChallengeStore,
    PgMfaEnrollmentStore, PgPasskeyCeremonyStore, PgPasskeyStore, PgPasswordHistory,
    PgRecoveryCodeStore, PgResetRequestStore, PgSentCodeStore, PgSignInCodeStore,
    PgSignInHistoryStore, PgTrustedDeviceStore, PgUserLookup,
};
use ianua_infra::postgres::authorization::{
    PgAccessRequestPolicyStore, PgAccessRequestStore, PgAccessReviewStore, PgClearanceRuleStore,
    PgDecisionRecordStore, PgGroupMembershipStore, PgGroupStore, PgPolicyStore,
    PgRelationshipStore, PgResourceTypeStore, PgRoleAssignmentStore, PgRoleDeletionUnitOfWork,
    PgRoleHolderQueries, PgRoleStore, PgSeparationRuleStore,
};
use ianua_infra::postgres::branding::{
    PgBrandingStore, PgEmailTemplateStore, PgTenantMailProviderStore,
};
use ianua_infra::postgres::cloud::PgCloudAccountStore;
use ianua_infra::postgres::consumers::PgConsumerStore;
use ianua_infra::postgres::crypto::{
    PgAssertionKeyStore, PgMigrationStore, PgSigningKeyStore, PgVerifyingKeyStore,
};
use ianua_infra::postgres::data_classification::PgClassificationStore;
use ianua_infra::postgres::directory::{PgDirectoryServiceAccountStore, PgLdapCertificateStore};
use ianua_infra::postgres::domain::{
    PgCertificateStore, PgCrossTenantDomainStore, PgDnsZoneWriter, PgHandoverOfferStore,
    PgRegisteredDomainStore,
};
use ianua_infra::postgres::federation::{
    PgConnectionStore, PgFederatedLinkStore, PgHeldSamlSignInStore, PgMappedHoldingsStore,
    PgOidcFlowStore, PgProviderSessionStore, PgSamlAppSessionStore, PgSamlAssertionLedger,
    PgSamlLogoutLedger, PgSamlRequestStore, PgSamlServiceProviderStore, PgScimGroupQueries,
    PgScimStore, PgScimUserQueries, PgSentLogoutRequestStore,
};
use ianua_infra::postgres::identity::{
    PgConsentStore, PgDataExportStore, PgErasureRequestStore, PgInvitationStore, PgMetadataStore,
    PgSignInLinkStore, PgSupportImpersonationStore, PgUserAttributeStore, PgUserImportStore,
    PgUserStore, PgVerificationTokenStore,
};
use ianua_infra::postgres::limits::{PgOrgResourceCounter, PgResourceCounter};
use ianua_infra::postgres::messaging::{
    PgAgentChannelStore, PgSchemaStore, PgSubscriptionStore, PgTopicStore,
};
use ianua_infra::postgres::metrics::{
    PgOrganizationMetricsReader, PgRouteTrafficReader, PgTenantMetricsReader,
};
use ianua_infra::postgres::notifications::{
    PgMemberPreferenceStore, PgNotificationDestinationStore, PgNotificationPreferenceStore,
    PgOperatorPreferenceStore, PgOrgNotificationStore, PgPlatformNotificationStore,
    PgTenantNotificationStore,
};
use ianua_infra::postgres::oauth::{
    PgAccessTokenStore, PgApiKeyStore, PgAssertionReplayGuard, PgAuthCodeStore, PgDeviceAuthStore,
    PgDpopReplayGuard, PgInitialAccessTokenStore, PgOAuthClientStore, PgOAuthConsentStore,
    PgPushedRequestStore, PgRefreshTokenStore,
};
use ianua_infra::postgres::operator::{
    PgImpersonationGrantStore, PgOperatorKeyStore, PgOperatorStore,
};
use ianua_infra::postgres::organization::{
    PgLinkedIdentityLookup, PgLinkedIdentityStore, PgMemberStandings, PgOrgApiKeyStore,
    PgOrgBrandingStore, PgOrgConsentStore, PgOrgErasureRequestStore, PgOrgIdentityProviderStore,
    PgOrgInvitationStore, PgOrgMfaEnrollmentStore, PgOrgPasskeyCeremonyStore, PgOrgPasskeyStore,
    PgOrgRecoveryCodeStore, PgOrgSamlAssertionLedger, PgOrgSessionStore, PgOrgSsoRequestStore,
    PgOrgSubscriptionStore, PgOrgTenantGrantStore, PgOrgTokenStore, PgOrgTrustedDeviceStore,
    PgOrgUserStore, PgOrganizationStore, PgPaymentEventLedger, PgPendingSignupStore,
    PgPlanUsageCounter, PgTenantMemberRoster,
};
use ianua_infra::postgres::proxy::{
    PgLogShippingStore, PgPipelineStore, PgProxyRequestLog, PgWasmModuleStore,
};
use ianua_infra::postgres::routing::{
    PgConnectorStore, PgEgressPolicyStore, PgPolicyDecisionPoint, PgRouteStore, PgServiceStore,
    PgStreamRouteLogins, PgStreamRouteStore,
};
use ianua_infra::postgres::scheduling::PgJobQueue;
use ianua_infra::postgres::shared::{
    PgAppSessionCheck, PgAuditLabelResolver, PgControlPlaneLabelResolver, PgCrossTenantUserChecker,
    PgOrgEmailChangeStore, PgPrincipalExistenceChecker, PgSessionStore, PgTenantEmailChangeStore,
    PgUserExistenceChecker,
};
use ianua_infra::postgres::signals::{PgSignalPollQueue, PgSignalStreamStore};
use ianua_infra::postgres::tenant::{PgTenantCloneStore, PgTenantSetupStore, PgTenantStore};
use ianua_infra::postgres::webhooks::PgWebhookStore;
use ianua_infra::postgres::workflows::{
    PgAccountChannelStore, PgApprovalPages, PgChannelDirectory, PgConnectionStates,
    PgDeliveryLedger, PgEvaluationSetStore, PgEvaluationStore, PgGrantExchangeLease,
    PgImageRegistryStore, PgIntegrationAccountStore, PgOperationRiskOverrideStore,
    PgPendingConnectionStore, PgSandboxStore, PgSandboxTrialStore, PgSandboxVersionStore,
    PgServiceSubscriptionStore, PgSubscriptionDirectory, PgWorkflowExecutionStore, PgWorkflowStore,
    PgWorkflowTriggerSecretStore,
};
use ianua_infra::reading::JsonSchemaMessageShape;
use ianua_infra::runtime::{LocalPause, LocalTimeZones};
use ianua_infra::saml::{
    DsigSamlMessageReader, DsigSamlValidator, EnvelopedXmlSigner,
    RedirectSamlServiceProviderMessages, RsaSamlEncryptionKeys, X509SigningCertificateIssuer,
    XmlEncAssertionEncrypter,
};

use crate::assembly::outward::Outward;
use crate::config::Config;
use crate::error::{PlatformError, ServerError};
use crate::platform::Platform;

/// Where tenants' logos are served, under `APP_BASE_URL`.
const LOGOS_PATH: &str = "/api/v1/files/logos";

/// The adapter behind every port, from `platform` and `config`, the use
/// cases' lifetimes as `settings` holds them.
///
/// # Errors
///
/// [`ServerError`] naming the setting refused, or the part whose client
/// could not be built.
pub(super) fn adapters(
    platform: &Platform,
    config: &Config,
    settings: &Settings,
) -> Result<Adapters, ServerError> {
    let stores = Stores::over(platform, config);
    let outward = Outward::build(platform, config, stores.mailer.clone())?;
    Ok(fill(&Parts {
        platform,
        config,
        settings,
        plane: Plane::of(platform),
        logos: logos_address(config)?,
        pages: Arc::new(
            TemplatePageRenderer::new().map_err(PlatformError::of("the page templates"))?,
        ),
        wording: Arc::new(
            FluentRefusalWording::new().map_err(PlatformError::of("the translated messages"))?,
        ),
        stores,
        outward,
    }))
}

/// Where tenants' logos are served from.
fn logos_address(config: &Config) -> Result<HttpsUrl, PlatformError> {
    let base = config
        .deployment
        .app_base_url
        .as_str()
        .trim_end_matches('/');
    HttpsUrl::new(format!("{base}{LOGOS_PATH}")).map_err(PlatformError::of("the logo address"))
}

/// The stores more than one port reads through, built once.
struct Stores {
    tenants: Arc<PgTenantStore>,
    organizations: Arc<PgOrganizationStore>,
    org_users: Arc<PgOrgUserStore>,
    org_sessions: Arc<PgOrgSessionStore>,
    org_api_keys: Arc<PgOrgApiKeyStore>,
    org_grants: Arc<PgOrgTenantGrantStore>,
    org_enrollments: Arc<PgOrgMfaEnrollmentStore>,
    org_passkeys: Arc<PgOrgPasskeyStore>,
    org_ceremonies: Arc<PgOrgPasskeyCeremonyStore>,
    org_tokens: Arc<PgOrgTokenStore>,
    users: Arc<PgUserStore>,
    sessions: Arc<PgSessionStore>,
    api_keys: Arc<PgApiKeyStore>,
    operators: Arc<PgOperatorStore>,
    operator_keys: Arc<PgOperatorKeyStore>,
    impersonations: Arc<PgImpersonationGrantStore>,
    support_impersonations: Arc<PgSupportImpersonationStore>,
    ldap_certificates: Arc<PgLdapCertificateStore>,
    executions: Arc<PgWorkflowExecutionStore>,
    signing_keys: Arc<PgSigningKeyStore>,
    services: Arc<PgServiceStore>,
    agents: Arc<PgAgentStore>,
    agent_credentials: Arc<PgAgentCredentialStore>,
    scim: Arc<PgScimStore>,
    consumers: Arc<PgConsumerStore>,
    templates: Arc<PgEmailTemplateStore>,
    branding: Arc<PgBrandingStore>,
    domains: Arc<PgRegisteredDomainStore>,
    jobs: Arc<PgJobQueue>,
    credentials: Arc<PgCredentialStore>,
    attempt_counts: Arc<CacheSignInAttemptCounts>,
    enrollments: Arc<PgMfaEnrollmentStore>,
    sent_codes: Arc<PgSentCodeStore>,
    sign_in_links: Arc<PgSignInLinkStore>,
    passkeys: Arc<PgPasskeyStore>,
    ceremonies: Arc<PgPasskeyCeremonyStore>,
    encryptor: Arc<AesGcmSecretEncryptor>,
    mailer: Arc<TenantMailer>,
}

impl Stores {
    /// The shared stores over the platform's databases, mail queued with
    /// `MAIL_DELIVERY_ATTEMPTS` tries.
    fn over(platform: &Platform, config: &Config) -> Self {
        let mail = MailStores::over(platform, config);
        Self::with_mail(platform, mail)
    }

    /// Fills the shared stores without constructing a second copy of any mail dependency.
    /// This exhaustive initializer keeps the ownership of all reused adapters together.
    #[allow(clippy::too_many_lines)]
    fn with_mail(platform: &Platform, mail: MailStores) -> Self {
        let db = || Arc::clone(&platform.databases);
        let limits = DomainLimits::default();
        Self {
            organizations: Arc::new(PgOrganizationStore::new(db(), limits.clone())),
            org_users: Arc::new(PgOrgUserStore::new(db(), limits.clone())),
            org_sessions: Arc::new(PgOrgSessionStore::new(db())),
            org_api_keys: Arc::new(PgOrgApiKeyStore::new(db())),
            org_grants: Arc::new(PgOrgTenantGrantStore::new(db())),
            org_enrollments: Arc::new(PgOrgMfaEnrollmentStore::new(db())),
            org_passkeys: Arc::new(PgOrgPasskeyStore::new(db())),
            org_ceremonies: Arc::new(PgOrgPasskeyCeremonyStore::new(db())),
            org_tokens: Arc::new(PgOrgTokenStore::new(db())),
            users: Arc::new(PgUserStore::new(db(), limits)),
            sessions: Arc::new(PgSessionStore::new(db())),
            api_keys: Arc::new(PgApiKeyStore::new(db())),
            operators: Arc::new(PgOperatorStore::new(db())),
            operator_keys: Arc::new(PgOperatorKeyStore::new(db())),
            impersonations: Arc::new(PgImpersonationGrantStore::new(db())),
            support_impersonations: Arc::new(PgSupportImpersonationStore::new(db())),
            ldap_certificates: Arc::new(PgLdapCertificateStore::new(db())),
            executions: Arc::new(PgWorkflowExecutionStore::new(db())),
            signing_keys: Arc::new(PgSigningKeyStore::new(db(), mail.encryptor.clone())),
            services: Arc::new(PgServiceStore::new(db())),
            agents: Arc::new(PgAgentStore::new(db())),
            agent_credentials: Arc::new(PgAgentCredentialStore::new(db())),
            scim: Arc::new(PgScimStore::new(db())),
            consumers: Arc::new(PgConsumerStore::new(db())),
            credentials: Arc::new(PgCredentialStore::new(db())),
            attempt_counts: Arc::new(CacheSignInAttemptCounts::new(Arc::clone(
                &platform.shared_state,
            ))),
            enrollments: Arc::new(PgMfaEnrollmentStore::new(db())),
            sent_codes: Arc::new(PgSentCodeStore::new(db())),
            sign_in_links: Arc::new(PgSignInLinkStore::new(db())),
            passkeys: Arc::new(PgPasskeyStore::new(db())),
            ceremonies: Arc::new(PgPasskeyCeremonyStore::new(db())),
            tenants: mail.tenants,
            templates: mail.templates,
            branding: mail.branding,
            domains: mail.domains,
            jobs: mail.jobs,
            encryptor: mail.encryptor,
            mailer: mail.mailer,
        }
    }
}

/// The mail dependencies shared with the rest of the API's stores.
struct MailStores {
    tenants: Arc<PgTenantStore>,
    templates: Arc<PgEmailTemplateStore>,
    branding: Arc<PgBrandingStore>,
    domains: Arc<PgRegisteredDomainStore>,
    jobs: Arc<PgJobQueue>,
    encryptor: Arc<AesGcmSecretEncryptor>,
    mailer: Arc<TenantMailer>,
}

impl MailStores {
    /// Queues mail through the same tenant, branding and job stores exposed to API use cases.
    fn over(platform: &Platform, config: &Config) -> Self {
        let db = || Arc::clone(&platform.databases);
        let limits = DomainLimits::default();
        let encryptor = Arc::clone(&platform.secrets.encryptor);
        let tenants = Arc::new(PgTenantStore::new(db(), limits));
        let templates = Arc::new(PgEmailTemplateStore::new(db()));
        let branding = Arc::new(PgBrandingStore::new(db()));
        let domains = Arc::new(PgRegisteredDomainStore::new(db()));
        let jobs = Arc::new(PgJobQueue::new(db()));
        let tries = NonZeroU32::new(config.mail.delivery_attempts).unwrap_or(NonZeroU32::MIN);
        let mailer = Arc::new(TenantMailer::new(TenantMailerPorts {
            templates: templates.clone(),
            branding: branding.clone(),
            domains: domains.clone(),
            tenants: tenants.clone(),
            outbox: Arc::new(QueuedMailOutbox::new(
                jobs.clone(),
                encryptor.clone(),
                tries,
            )),
        }));
        Self {
            tenants,
            templates,
            branding,
            domains,
            jobs,
            encryptor,
            mailer,
        }
    }
}

/// The agent message plane on a bus server, or none on a bus in process.
struct Plane {
    publisher: Arc<dyn MessagePublisher>,
    consumer: Arc<dyn MessageConsumer>,
    dead_letters: Arc<dyn DeadLetters>,
}

impl Plane {
    /// The platform's message plane, or the refusal of every message.
    fn of(platform: &Platform) -> Self {
        let Some(plane) = &platform.message_plane else {
            return Self {
                publisher: Arc::new(NoMessagePublisher),
                consumer: Arc::new(NoMessageConsumer),
                dead_letters: Arc::new(NoDeadLetters),
            };
        };
        Self {
            publisher: Arc::new(BusMessagePublisher::new(Arc::clone(plane))),
            consumer: Arc::new(BusMessageConsumer::new(Arc::clone(plane))),
            dead_letters: Arc::new(BusDeadLetters::new(Arc::clone(plane))),
        }
    }
}

/// Everything the adapters are filled from.
struct Parts<'a> {
    platform: &'a Platform,
    config: &'a Config,
    settings: &'a Settings,
    stores: Stores,
    outward: Outward,
    plane: Plane,
    logos: HttpsUrl,
    pages: Arc<TemplatePageRenderer>,
    wording: Arc<FluentRefusalWording>,
}

/// Every port's adapter.
///
/// One field a line, in the order `Adapters` lists them: a flat list read
/// top to bottom, which splitting would only scatter.
#[allow(clippy::too_many_lines)]
fn fill(parts: &Parts<'_>) -> Adapters {
    let Parts {
        platform: p,
        config,
        settings,
        stores: s,
        outward: o,
        plane,
        logos,
        pages,
        wording,
    } = parts;
    let registrar = Arc::new(InstalledServiceRegistrar::new(
        Arc::clone(&p.integrations),
        s.encryptor.clone(),
        EventAddresses::new(&config.deployment.app_base_url),
        config.integrations.timeout,
    ));
    let db = || Arc::clone(&p.databases);
    let shared = || Arc::clone(&p.shared_state);
    let node = || Arc::clone(&p.node_state);
    let limits = DomainLimits::default();
    let grace = settings.tunables.jwks_grace;
    let digests = &p.digests;
    let files = || Arc::clone(&p.files);
    let logo_files = Arc::new(FileLogoStore::new(files(), logos.clone()));
    Adapters {
        event_dispatcher: Arc::clone(&p.event_dispatcher),
        token_resolver: p.token_resolver.clone(),
        rate_limiter: Arc::new(CacheRateLimiter::new(node())),
        refusal_wording: Arc::<FluentRefusalWording>::clone(wording),
        notification_subscriber: Arc::new(BusNotificationSubscriber::new(
            Arc::clone(&p.bus),
            p.keys.broadcast_check.clone(),
        )),
        budget_usage_reader: Arc::new(CacheBudgetUsageReader::new(shared())),
        payload_hasher: Arc::new(Sha256PayloadHasher),
        message_provenance_signer: Arc::new(Pkcs8MessageProvenanceSigner::new(
            s.signing_keys.clone(),
            grace,
        )),
        message_provenance_verifier: Arc::new(Pkcs8MessageProvenanceVerifier::new(
            s.signing_keys.clone(),
            grace,
        )),
        app_session_check: Arc::new(PgAppSessionCheck::new(db())),
        app_session_tokens: Arc::new(Pkcs8AppSessionTokens::new(s.signing_keys.clone(), grace)),
        approval_request_seal: p.keys.approval_request_seal.clone(),
        handoff_store: Arc::new(PgHandoffStore::new(db())),
        mfa_challenge_store: Arc::new(PgMfaChallengeStore::new(db())),
        password_history: Arc::new(PgPasswordHistory::new(db())),
        common_password_list: Arc::new(BundledCommonPasswordList::new()),
        password_hash_format: p.secrets.password_format.clone(),
        factor_code_sender: o.factor_codes.clone(),
        data_export_store: Arc::new(PgDataExportStore::new(db())),
        data_export_files: Arc::new(FileDataExportFiles::new(files(), p.file_links.clone())),
        support_impersonation_store: s.support_impersonations.clone(),
        user_import_store: Arc::new(PgUserImportStore::new(db(), limits.clone())),
        database_readiness: Arc::clone(&p.readiness.database),
        message_bus_readiness: Arc::clone(&p.readiness.bus),
        cache_readiness: Arc::clone(&p.readiness.cache),
        metrics_exporter: p.metrics.exporter.clone(),
        served_request_observer: p.metrics.served_requests.clone(),
        text_messaging: Arc::new(o.factor_codes.text_messaging()),
        mail_setup: Arc::new(p.mail.platform.mail_setup()),
        page_renderer: Arc::<TemplatePageRenderer>::clone(pages),
        access_record_store: Arc::clone(&p.access_records),
        access_request_policy_store: Arc::new(PgAccessRequestPolicyStore::new(db())),
        access_request_store: Arc::new(PgAccessRequestStore::new(db())),
        access_review_store: Arc::new(PgAccessReviewStore::new(db())),
        access_token_store: Arc::new(PgAccessTokenStore::new(db())),
        access_token_jwt_verifier: Arc::new(Pkcs8AccessTokenJwtVerifier::new(grace)),
        at_hash_calculator: Arc::new(Sha2AtHashCalculator),
        client_assertion_verifier: Arc::new(JwkClientAssertionVerifier::new(Arc::clone(
            &o.client_keys,
        ))),
        client_assertion_replay_guard: Arc::new(PgAssertionReplayGuard::new(db())),
        dpop_proof_verifier: Arc::new(JwkDpopProofVerifier),
        dpop_replay_guard: Arc::new(PgDpopReplayGuard::new(db())),
        id_token_hint_verifier: Arc::new(Pkcs8IdTokenHintVerifier::new(grace)),
        initial_access_token_store: Arc::new(PgInitialAccessTokenStore::new(db())),
        pushed_request_store: Arc::new(PgPushedRequestStore::new(db())),
        refresh_token_store: Arc::new(PgRefreshTokenStore::new(db())),
        activity_store: Arc::new(PgActivityStore::new(db())),
        agent_activity_store: Arc::new(PgAgentActivityStore::new(db(), limits.clone())),
        agent_actors: Arc::new(AgentActing::new(AgentActingPorts {
            agent_store: s.agents.clone(),
            credential_store: s.agent_credentials.clone(),
            verifier: Arc::new(Pkcs8AgentAssertionVerifier),
            replay_guard: Arc::new(PgAgentAssertionReplayGuard::new(db())),
        })),
        alert_throttle: Arc::new(CacheAlertThrottle::new(shared())),
        agent_attestor: Arc::clone(&o.attestor),
        agent_channel_store: Arc::new(PgAgentChannelStore::new(db())),
        agent_credential_store: s.agent_credentials.clone(),
        agent_exposure_gate: Arc::new(PgAgentExposureGate::new(db())),
        agent_sighting_store: Arc::new(PgAgentSightingStore::new(db())),
        agent_standing_check: Arc::new(PgAgentStandingCheck::new(db())),
        agent_store: s.agents.clone(),
        api_key_generator: digests.api_keys.clone(),
        api_key_store: s.api_keys.clone(),
        approval_store: Arc::new(PgApprovalStore::new(db())),
        approval_pages: Arc::new(PgApprovalPages::new(db())),
        assertion_key_store: Arc::new(PgAssertionKeyStore::new(db(), s.encryptor.clone())),
        attestation_challenge_store: Arc::new(PgAttestationChallengeStore::new(db())),
        attestation_nonce_generator: Arc::new(OsAttestationNonceGenerator),
        audit_chain_verdict_store: Arc::new(PgAuditChainVerdictStore::new(
            db(),
            p.keys.audit_chain_seals.clone(),
        )),
        audit_export_store: Arc::new(PgAuditExportStore::new(db())),
        audit_export_files: Arc::new(FileAuditExportFiles::new(files(), p.file_links.clone())),
        audit_label_resolver: Arc::new(PgAuditLabelResolver::new(db())),
        audit_stream_store: Arc::new(PgAuditStreamStore::new(db())),
        tenant_audit_log_store: Arc::new(PgTenantAuditLogStore::new(db(), limits.clone())),
        platform_audit_log_store: Arc::new(PgPlatformAuditLogStore::new(db(), limits.clone())),
        tenant_clone_store: Arc::new(PgTenantCloneStore::new(db())),
        tenant_mail_provider_store: Arc::new(PgTenantMailProviderStore::new(db())),
        mail_provider_transport: Arc::new(OutboundMailProviderTransport::new(
            Arc::clone(&p.mail.platform),
            Arc::clone(&p.mail.delivery),
            s.encryptor.clone(),
        )),
        template_renderer: Arc::new(JinjaTemplateRenderer::new(
            Arc::clone(&p.mail.composer),
            Arc::clone(&p.mail.audience),
        )),
        logo_store: Arc::<FileLogoStore>::clone(&logo_files),
        public_logos: Arc::new(FilePublicLogos::new(logo_files)),
        linked_files: Arc::new(FileLinkedFiles::new(
            p.file_links.clone(),
            files(),
            Arc::new(CacheNonceLedger::new(shared())),
        )),
        published_files: Arc::new(BundledPublishedFiles),
        notification_destination_store: Arc::new(PgNotificationDestinationStore::new(db())),
        destination_secret_generator: Arc::new(OsDestinationSecretGenerator),
        member_preference_store: Arc::new(PgMemberPreferenceStore::new(db())),
        operator_preference_store: Arc::new(PgOperatorPreferenceStore::new(db())),
        auth_code_store: Arc::new(PgAuthCodeStore::new(db())),
        bind_throttle: Arc::new(CacheBindThrottle::new(
            node(),
            config.directory.binds_per_tenant_per_minute,
        )),
        branding_store: s.branding.clone(),
        break_glass_store: Arc::new(PgBreakGlassStore::new(db())),
        broker_authenticator: Arc::new(DelegationBrokerAuthenticator::new(
            Arc::new(Pkcs8TaskTokenVerifier::new(s.signing_keys.clone(), grace)),
            TenantIssuers::new(
                s.tenants.clone(),
                s.organizations.clone(),
                config.deployment.app_base_url.clone(),
            ),
            Arc::new(PgDelegationRevocationCheck::new(db())),
        )),
        cert_pem_validator: Arc::new(X509CertPemValidator),
        certificate_parser: Arc::new(X509CertificateParser),
        certificate_store: Arc::new(PgCertificateStore::new(db(), s.encryptor.clone())),
        challenge_verifier: Some(Arc::clone(&o.challenges.verifier)),
        challenge_issuer: o.challenges.issuer.clone(),
        classification_store: Arc::new(PgClassificationStore::new(db())),
        clearance_rule_store: Arc::new(PgClearanceRuleStore::new(db())),
        client_secret_generator: digests.client_secrets.clone(),
        client_secret_verifier: digests.client_secret_verifier.clone(),
        cloud_account_store: Arc::new(PgCloudAccountStore::new(db(), s.encryptor.clone())),
        cloud_provider_registry: p.clouds.clone(),
        code_hasher: digests.codes.clone(),
        connection_store: Arc::new(PgConnectionStore::new(db())),
        connector_authority: Arc::clone(&o.connector_authority),
        connector_code_generator: digests.connector_codes.clone(),
        consent_store: Arc::new(PgConsentStore::new(db())),
        consumer_authorities: Arc::new(ConsumerActing::new(ConsumerActingPorts {
            consumer_store: s.consumers.clone(),
            access_records: Arc::clone(&p.access_records),
            issuers: TenantIssuers::new(
                s.tenants.clone(),
                s.organizations.clone(),
                config.deployment.app_base_url.clone(),
            ),
            quota_counter: Arc::new(CacheConsumerQuotaCounter::new(shared())),
        })),
        consumer_key_generator: digests.consumer_keys.clone(),
        consumer_store: s.consumers.clone(),
        connector_store: Arc::new(PgConnectorStore::new(db())),
        control_plane_label_resolver: Arc::new(PgControlPlaneLabelResolver::new(db())),
        credential_breach_checker: Arc::clone(&o.breaches),
        credential_store: s.credentials.clone(),
        cross_tenant_domain_store: Arc::new(PgCrossTenantDomainStore::new(db())),
        cross_tenant_user_checker: Arc::new(PgCrossTenantUserChecker::new(db())),
        css_sanitizer: Arc::new(AllowListCssSanitizer),
        dead_letters: Arc::clone(&plane.dead_letters),
        decision_record_store: Arc::new(PgDecisionRecordStore::new(db())),
        delegation_request_store: Arc::new(PgDelegationRequestStore::new(db())),
        delegation_store: Arc::new(PgDelegationStore::new(db())),
        device_auth_store: Arc::new(PgDeviceAuthStore::new(
            db(),
            digests.codes.clone(),
            s.encryptor.clone(),
        )),
        directory_authorities: Arc::new(DirectoryActing::new(Arc::clone(&p.access_records))),
        dns_resolver: Arc::clone(&o.dns),
        dns_zone_writer: Arc::new(PgDnsZoneWriter::new(
            db(),
            config.domains.nameservers.clone(),
        )),
        egress_policy_store: Arc::new(PgEgressPolicyStore::new(db())),
        email_template_store: s.templates.clone(),
        erasure_request_store: Arc::new(PgErasureRequestStore::new(db())),
        evidence_store: Arc::new(PgEvidenceStore::new(db())),
        external_id_generator: Arc::new(OsExternalIdGenerator),
        federated_link_store: Arc::new(PgFederatedLinkStore::new(db())),
        fresh_proofs: Arc::new(fresh_proofs(parts)),
        geolocator: Arc::clone(&o.geolocator),
        group_membership_store: Arc::new(PgGroupMembershipStore::new(db())),
        group_store: Arc::new(PgGroupStore::new(db())),
        handover_offer_store: Arc::new(PgHandoverOfferStore::new(db())),
        impersonation_grant_store: s.impersonations.clone(),
        integration_account_store: Arc::new(PgIntegrationAccountStore::new(db())),
        integration_catalog: Arc::new(InstalledIntegrationCatalog::new(Arc::clone(
            &p.integrations,
        ))),
        account_verifier: Arc::new(InstalledAccountVerifier::new(
            Arc::clone(&p.integrations),
            config.integrations.timeout,
        )),
        action_runner: Arc::new(InstalledActionRunner::new(
            Arc::clone(&p.integrations),
            s.encryptor.clone(),
            config.integrations.timeout,
        )),
        grant_exchanger: Arc::new(InstalledGrantExchanger::new(
            Arc::clone(&p.integrations),
            s.encryptor.clone(),
            config.integrations.timeout,
        )),
        grant_exchange_lease: Arc::new(PgGrantExchangeLease::for_exchanges_within(
            db(),
            config.integrations.timeout,
        )),
        service_sign_in: Arc::new(InstalledServiceSignIn::new(
            Arc::clone(&p.integrations),
            &config.deployment.app_base_url,
            config.integrations.timeout,
        )),
        connection_secrets: digests.connections.clone(),
        pending_connection_store: Arc::new(PgPendingConnectionStore::new(db())),
        connection_states: Arc::new(PgConnectionStates::new(db())),
        service_channel_setup: Arc::new(InstalledServiceChannelSetup::new(Arc::clone(&registrar))),
        service_registrar: registrar,
        service_subscription_store: Arc::new(PgServiceSubscriptionStore::new(db())),
        subscription_directory: Arc::new(PgSubscriptionDirectory::new(db())),
        service_event_reader: Arc::new(InstalledServiceEventReader::new(
            Arc::clone(&p.integrations),
            EventAddresses::new(&config.deployment.app_base_url),
        )),
        delivery_ledger: Arc::new(PgDeliveryLedger::new(db())),
        account_channel_store: Arc::new(PgAccountChannelStore::new(db())),
        channel_directory: Arc::new(PgChannelDirectory::new(db())),
        sandbox_store: Arc::new(PgSandboxStore::new(db())),
        sandbox_version_store: Arc::new(PgSandboxVersionStore::new(db())),
        sandbox_trial_store: Arc::new(PgSandboxTrialStore::new(db())),
        evaluation_set_store: Arc::new(PgEvaluationSetStore::new(db())),
        evaluation_store: Arc::new(PgEvaluationStore::new(db())),
        sandbox_runtimes: Arc::new(config.sandboxes.runtimes.clone()),
        image_registry_store: Arc::new(PgImageRegistryStore::new(db())),
        image_resolver: Arc::clone(&o.image_resolver),
        code_repositories: Arc::new(InstalledCodeRepositories::new(
            Arc::clone(&p.integrations),
            s.encryptor.clone(),
            config.integrations.timeout,
        )),
        memory_store: Arc::clone(&p.memory.store),
        memory_entries: Arc::clone(&p.memory.entries),
        embedder: Arc::clone(&p.memory.embedder),
        intent_compiler: Arc::clone(&o.intents),
        invitation_store: Arc::new(PgInvitationStore::new(db())),
        job_queue: s.jobs.clone(),
        jwt_signer: Arc::new(Pkcs8JwtSigner),
        redaction_digest: Arc::new(HmacRedactionDigest::new(&p.keys.shared_root)),
        key_generator: Arc::new(Pkcs8KeyGenerator),
        ldap_certificate_authority: Arc::clone(&o.ldap_authority),
        ldap_certificate_store: s.ldap_certificates.clone(),
        limit_enforcer: Arc::new(PlanLimitEnforcer::new(
            Arc::new(PgResourceCounter::new(db())),
            Arc::new(PgOrgResourceCounter::new(db())),
        )),
        linked_identity_lookup: Arc::new(PgLinkedIdentityLookup::new(db())),
        linked_identity_store: Arc::new(PgLinkedIdentityStore::new(db())),
        log_shipping_store: Arc::new(PgLogShippingStore::new(db())),
        mail_throttle: Arc::new(CacheMailThrottle::new(node(), config.mail.cooldown)),
        mailer: s.mailer.clone(),
        message_consumer: Arc::clone(&plane.consumer),
        message_publisher: Arc::clone(&plane.publisher),
        message_shape: Arc::new(JsonSchemaMessageShape),
        metadata_store: Arc::new(PgMetadataStore::new(db())),
        mfa_enrollment_store: s.enrollments.clone(),
        factor_standing: Arc::new(PgFactorStanding::new(db())),
        mfa_verifier: Arc::new(TotpMfaVerifier),
        migration_store: Arc::new(PgMigrationStore::new(db())),
        model_client: Arc::clone(&o.models),
        model_provider_store: Arc::new(PgModelProviderStore::new(db())),
        nonce_ledger: Arc::new(CacheNonceLedger::new(shared())),
        notification_preference_store: Arc::new(PgNotificationPreferenceStore::new(db())),
        notification_publisher: Arc::new(BusNotificationPublisher::new(
            Arc::clone(&p.bus),
            p.keys.broadcast_seal.clone(),
        )),
        o_auth_client_store: Arc::new(PgOAuthClientStore::new(db())),
        o_auth_consent_store: Arc::new(PgOAuthConsentStore::new(db())),
        oidc_flow_store: Arc::new(PgOidcFlowStore::new(db(), s.encryptor.clone())),
        oidc_validator: Arc::clone(&o.oidc),
        operation_risk_override_store: Arc::new(PgOperationRiskOverrideStore::new(db())),
        operator_authorities: Arc::new(OperatorActing::new(OperatorActingPorts {
            operators: s.operators.clone(),
            operator_keys: s.operator_keys.clone(),
        })),
        operator_key_store: s.operator_keys.clone(),
        operator_store: s.operators.clone(),
        org_actors: Arc::new(OrgActing::new(OrgActingPorts {
            organizations: s.organizations.clone(),
            org_users: s.org_users.clone(),
            org_sessions: s.org_sessions.clone(),
            org_api_keys: s.org_api_keys.clone(),
        })),
        org_api_key_store: s.org_api_keys.clone(),
        org_audit_log_store: Arc::new(PgOrgAuditLogStore::new(db(), limits.clone())),
        org_email_change_store: Arc::new(PgOrgEmailChangeStore::new(db())),
        org_invitation_store: Arc::new(PgOrgInvitationStore::new(db())),
        org_mfa_enrollment_store: s.org_enrollments.clone(),
        org_notification_store: Arc::new(PgOrgNotificationStore::new(db())),
        org_passkey_ceremony_store: s.org_ceremonies.clone(),
        org_passkey_store: s.org_passkeys.clone(),
        org_recovery_code_store: Arc::new(PgOrgRecoveryCodeStore::new(db())),
        org_session_store: s.org_sessions.clone(),
        org_tenant_grant_store: s.org_grants.clone(),
        org_token_store_email_verification: s.org_tokens.clone(),
        org_token_store_installation_setup: s.org_tokens.clone(),
        org_token_store_password_reset: s.org_tokens.clone(),
        org_token_store_sign_in_confirmation: s.org_tokens.clone(),
        org_trusted_device_store: Arc::new(PgOrgTrustedDeviceStore::new(db())),
        org_user_store: s.org_users.clone(),
        org_token_store_magic_link: s.org_tokens.clone(),
        org_subscription_store: Arc::new(PgOrgSubscriptionStore::new(db())),
        plan_usage_counter: Arc::new(PgPlanUsageCounter::new(db(), s.tenants.clone())),
        payment_provider: Arc::clone(&o.payments),
        payment_event_ledger: Arc::new(PgPaymentEventLedger::new(db())),
        org_identity_provider_store: Arc::new(PgOrgIdentityProviderStore::new(db())),
        org_sso_request_store: Arc::new(PgOrgSsoRequestStore::new(
            db(),
            limits.clone(),
            s.encryptor.clone(),
        )),
        org_saml_assertion_ledger: Arc::new(PgOrgSamlAssertionLedger::new(db())),
        org_erasure_request_store: Arc::new(PgOrgErasureRequestStore::new(db())),
        org_consent_store: Arc::new(PgOrgConsentStore::new(db())),
        org_branding_store: Arc::new(PgOrgBrandingStore::new(db())),
        pending_signup_store: Arc::new(PgPendingSignupStore::new(db(), limits.clone())),
        organization_metrics_reader: Arc::new(PgOrganizationMetricsReader::new(db())),
        organization_store: s.organizations.clone(),
        passkey_ceremony_store: s.ceremonies.clone(),
        passkey_store: s.passkeys.clone(),
        passkey_verifier: Arc::clone(&o.passkeys),
        password_hasher: p.secrets.password_hasher.clone(),
        password_hash_permits: p.secrets.hash_permits.clone(),
        pipeline_store: Arc::new(PgPipelineStore::new(db())),
        pkce_verifier: Arc::new(Sha256PkceVerifier),
        plan_limits_source: Arc::new(StoredPlanLimits::new(
            s.tenants.clone(),
            s.organizations.clone(),
        )),
        platform_notification_store: Arc::new(PgPlatformNotificationStore::new(db())),
        policy_decisions: Arc::new(PgPolicyDecisionPoint::new(db(), limits.clone())),
        member_standings: Arc::new(PgMemberStandings::new(db(), limits.clone())),
        policy_store: Arc::new(PgPolicyStore::new(db())),
        time_zones: Arc::new(LocalTimeZones),
        principal_existence_checker: Arc::new(PgPrincipalExistenceChecker::new(db())),
        proxy_request_log: Arc::new(PgProxyRequestLog::new(db())),
        public_key_decoder: Arc::new(Pkcs8PublicKeyDecoder),
        push_secret_generator: Arc::new(OsPushSecretGenerator),
        receiver_keys: digests.receiver_keys.clone(),
        recovery_code_generator: digests.recovery_codes.clone(),
        recovery_code_store: Arc::new(PgRecoveryCodeStore::new(db())),
        refresh_token_generator: digests.refresh_tokens.clone(),
        registered_domain_store: s.domains.clone(),
        relationship_resolver: Arc::new(PgRelationshipResolver::new(db())),
        relationship_store: Arc::new(PgRelationshipStore::new(db())),
        request_seal: p.keys.request_seal.clone(),
        reset_request_store: Arc::new(PgResetRequestStore::new(db())),
        resource_grant_store: Arc::new(PgResourceGrantStore::new(db())),
        resource_type_store: Arc::new(PgResourceTypeStore::new(db())),
        review_assignment_store: Arc::new(PgReviewAssignmentStore::new(db())),
        role_assignment_store: Arc::new(PgRoleAssignmentStore::new(db())),
        role_deletion_unit_of_work: Arc::new(PgRoleDeletionUnitOfWork::new(db())),
        role_holder_queries: Arc::new(PgRoleHolderQueries::new(db())),
        role_store: Arc::new(PgRoleStore::new(db())),
        route_store: Arc::new(PgRouteStore::new(db())),
        route_traffic_reader: Arc::new(PgRouteTrafficReader::new(db())),
        backend_health_reader: Arc::new(CacheBackendHealthReader::new(shared())),
        run_cancellation: Arc::new(PgRunCancellation::new(db())),
        run_store: Arc::new(PgRunStore::new(db())),
        saml_assertion_ledger: Arc::new(PgSamlAssertionLedger::new(db())),
        saml_request_store: Arc::new(PgSamlRequestStore::new(db())),
        saml_service_provider_messages: Arc::new(RedirectSamlServiceProviderMessages),
        saml_validator: Arc::new(DsigSamlValidator::new(s.encryptor.clone())),
        saml_metadata_reader: Arc::clone(&o.saml_metadata),
        saml_encryption_keys: Arc::new(RsaSamlEncryptionKeys),
        saml_service_provider_store: Arc::new(PgSamlServiceProviderStore::new(db())),
        saml_message_reader: Arc::new(DsigSamlMessageReader),
        saml_name_ids: digests.saml_name_ids.clone(),
        assertion_encrypter: Arc::new(XmlEncAssertionEncrypter),
        saml_app_session_store: Arc::new(PgSamlAppSessionStore::new(db())),
        held_saml_sign_in_store: Arc::new(PgHeldSamlSignInStore::new(db())),
        provider_session_store: Arc::new(PgProviderSessionStore::new(db())),
        mapped_holdings_store: Arc::new(PgMappedHoldingsStore::new(db())),
        sent_logout_request_store: Arc::new(PgSentLogoutRequestStore::new(db())),
        saml_logout_ledger: Arc::new(PgSamlLogoutLedger::new(db())),
        directory_service_account_store: Arc::new(PgDirectoryServiceAccountStore::new(db())),
        service_account_secrets: digests.service_accounts.clone(),
        schema_store: Arc::new(PgSchemaStore::new(db())),
        scim_authorities: Arc::new(ScimActing::new(ScimActingPorts {
            scim_store: s.scim.clone(),
            tokens: digests.scim_tokens.clone(),
        })),
        scim_group_queries: Arc::new(PgScimGroupQueries::new(db())),
        scim_store: s.scim.clone(),
        scim_token_generator: digests.scim_tokens.clone(),
        scim_user_queries: Arc::new(PgScimUserQueries::new(db(), limits.clone())),
        secure_random: Arc::new(OsSecureRandom),
        secret_encryptor: s.encryptor.clone(),
        secure_token_generator: Arc::new(OsSecureTokenGenerator),
        separation_rule_store: Arc::new(PgSeparationRuleStore::new(db())),
        service_store: s.services.clone(),
        sent_code_generator: digests.sent_codes.clone(),
        sent_code_store: s.sent_codes.clone(),
        session_store: s.sessions.clone(),
        sign_in_attempt_counts: s.attempt_counts.clone(),
        sign_in_code_store: Arc::new(PgSignInCodeStore::new(db())),
        sign_in_failure_budget: Arc::new(CacheSignInFailureBudget::new(
            shared(),
            config.limits.sign_in_failure_window,
        )),
        sign_in_history_store: Arc::new(PgSignInHistoryStore::new(db())),
        pause: Arc::new(LocalPause),
        sign_in_link_store_magic_link: s.sign_in_links.clone(),
        sign_in_link_store_sign_in_confirmation: s.sign_in_links.clone(),
        signal_deliverer: Arc::clone(&o.signals),
        signal_poll_queue: Arc::new(PgSignalPollQueue::new(db())),
        signal_stream_store: Arc::new(PgSignalStreamStore::new(db())),
        signing_certificate_issuer: Arc::new(X509SigningCertificateIssuer),
        signing_key_store: s.signing_keys.clone(),
        site_rules: Arc::new(BundledSiteRules),
        stream_route_logins: Arc::new(PgStreamRouteLogins::new(db())),
        stream_route_store: Arc::new(PgStreamRouteStore::new(db())),
        subscription_store: Arc::new(PgSubscriptionStore::new(db())),
        task_template_store: Arc::new(PgTaskTemplateStore::new(db())),
        task_token_issuer: Arc::new(Pkcs8TaskTokenIssuer::new(
            s.signing_keys.clone(),
            grace,
            s.services.clone(),
            s.agent_credentials.clone(),
        )),
        tenant_authorities: Arc::new(tenant_authorities(p, s)),
        tenant_email_change_store: Arc::new(PgTenantEmailChangeStore::new(db())),
        tenant_member_roster: Arc::new(PgTenantMemberRoster::new(db(), limits)),
        tenant_metrics_reader: Arc::new(PgTenantMetricsReader::new(db())),
        tenant_notification_store: Arc::new(PgTenantNotificationStore::new(db())),
        tenant_setup_store: Arc::new(PgTenantSetupStore::new(db())),
        tenant_store: s.tenants.clone(),
        tool_store: Arc::new(PgToolStore::new(db())),
        topic_authorizer: Arc::new(DelegationTopicAuthorizer::new()),
        topic_store: Arc::new(PgTopicStore::new(db())),
        trusted_device_store: Arc::new(PgTrustedDeviceStore::new(db())),
        unit_of_work: Arc::clone(&p.unit_of_work),
        user_attribute_store: Arc::new(PgUserAttributeStore::new(db())),
        user_existence_checker: Arc::new(PgUserExistenceChecker::new(db())),
        user_lookup: Arc::new(PgUserLookup::new(db())),
        user_store: s.users.clone(),
        verification_throttle: Arc::new(CacheVerificationThrottle::new(
            node(),
            Allowance {
                most: config.limits.signal_verifications.max,
                window: config.limits.signal_verifications.window,
            },
        )),
        verification_token_store: Arc::new(PgVerificationTokenStore::new(db())),
        verifying_key_store: Arc::new(PgVerifyingKeyStore::new(db())),
        wasm_module_store: Arc::new(PgWasmModuleStore::new(
            db(),
            config.limits.wasm_module_max_bytes,
        )),
        webhook_deliverer: Arc::clone(&o.webhooks),
        webhook_secret_generator: Arc::new(OsWebhookSecretGenerator),
        webhook_send_throttle: Arc::new(CacheWebhookSendThrottle::new(
            node(),
            Allowance {
                most: config.limits.webhook_sends.max,
                window: config.limits.webhook_sends.window,
            },
        )),
        webhook_store: Arc::new(PgWebhookStore::new(db())),
        workflow_execution_store: s.executions.clone(),
        workflow_store: Arc::new(PgWorkflowStore::new(db())),
        workflow_trigger_secret_generator: digests.workflow_triggers.clone(),
        workflow_trigger_secret_store: Arc::new(PgWorkflowTriggerSecretStore::new(db())),
        workload_token_verifier: Arc::clone(&o.workload_tokens),
        xml_signer: Arc::new(EnvelopedXmlSigner),
    }
}

/// Who a tenant's callers are and what they hold, read again on every
/// request.
fn tenant_authorities(p: &Platform, s: &Stores) -> TenantActing {
    TenantActing::new(TenantActingPorts {
        access: Arc::clone(&p.access_records),
        tenants: s.tenants.clone(),
        executions: s.executions.clone(),
        tenant: TenantCredentialPorts {
            users: s.users.clone(),
            sessions: s.sessions.clone(),
            api_keys: s.api_keys.clone(),
            certificates: s.ldap_certificates.clone(),
        },
        members: MemberPorts {
            organizations: s.organizations.clone(),
            org_users: s.org_users.clone(),
            org_sessions: s.org_sessions.clone(),
            org_grants: s.org_grants.clone(),
        },
        operators: OperatorPorts {
            operators: s.operators.clone(),
            operator_keys: s.operator_keys.clone(),
            impersonations: s.impersonations.clone(),
            support_impersonations: s.support_impersonations.clone(),
        },
    })
}

/// The check of a proof a person gives again, over the same stores the
/// sign-in reads.
fn fresh_proofs(parts: &Parts<'_>) -> FreshProofStep {
    let (p, s) = (parts.platform, &parts.stores);
    FreshProofStep::new(
        parts.settings.tunables.mfa_lockout,
        FreshProofPorts {
            password: password_proof(p, s),
            factors: FactorProof {
                enrollments: s.enrollments.clone(),
                encryptor: s.encryptor.clone(),
                verifier: Arc::new(TotpMfaVerifier),
                sent_codes: s.sent_codes.clone(),
                sent_code_generator: p.digests.sent_codes.clone(),
            },
            links: LinkProof {
                magic_links: s.sign_in_links.clone(),
                link_hasher: p.digests.refresh_tokens.clone(),
            },
            passkeys: PasskeyProof {
                passkeys: s.passkeys.clone(),
                ceremonies: s.ceremonies.clone(),
                passkey_verifier: Arc::clone(&parts.outward.passkeys),
            },
            members: MemberProof {
                members: s.org_users.clone(),
                member_enrollments: s.org_enrollments.clone(),
                member_passkeys: s.org_passkeys.clone(),
                member_ceremonies: s.org_ceremonies.clone(),
            },
        },
    )
}

/// Rechecks a password under the same tenant, throttling and hashing rules as sign-in.
fn password_proof(platform: &Platform, stores: &Stores) -> PasswordProof {
    PasswordProof {
        tenants: stores.tenants.clone(),
        credentials: stores.credentials.clone(),
        attempts: SignInCounts::new(stores.attempt_counts.clone(), Arc::new(LocalPause)),
        hashing: PasswordHashing::new(
            platform.secrets.password_hasher.clone(),
            platform.secrets.hash_permits.clone(),
        ),
        certificates: stores.ldap_certificates.clone(),
    }
}

#[cfg(test)]
mod tests;
