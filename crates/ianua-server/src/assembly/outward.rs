//! The API's adapters that call out of the deployment or check a proof
//! made outside it, each built from the configuration with its client,
//! its timeout and the networks it may reach, and refused with the setting
//! at fault.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::agents::{AgentAttestor, IntentCompiler, ModelClient, WorkloadTokenVerifier};
use ianua_app::ports::authentication::{
    ChallengeIssuer, ChallengeVerifier, CredentialBreachChecker, FactorCodeSender, Geolocator,
    PasskeyVerifier,
};
use ianua_app::ports::directory::LdapCertificateAuthority;
use ianua_app::ports::domain::DnsResolver;
use ianua_app::ports::federation::{OidcValidator, SamlMetadataReader};
use ianua_app::ports::organization::PaymentProvider;
use ianua_app::ports::routing::ConnectorAuthority;
use ianua_app::ports::shared::Mailer;
use ianua_app::ports::signals::SignalDeliverer;
use ianua_app::ports::webhooks::WebhookDeliverer;
use ianua_app::ports::workflows::ImageResolver;
use ianua_boot::env::ConfigError;
use ianua_boot::network::PemFiles;
use ianua_domain::domains::agents::identity::attestation::AttestationMethod;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::CertificatePem;
use ianua_infra::billing::{NoPaymentProvider, STRIPE_API, StripePaymentProvider, StripeSettings};
use ianua_infra::cache::{CacheChallengeIssuer, CacheChallengeVerifier, Puzzles};
use ianua_infra::crypto::{
    NoConnectorAuthority, NoLdapCertificateAuthority, PublishedKeys, RcgenConnectorAuthority,
    RcgenLdapCertificateAuthority,
};
use ianua_infra::geo::{MmdbGeolocator, NoGeolocator};
use ianua_infra::http::{
    ChallengeSettings, HttpChallengeVerifier, HttpCredentialBreachChecker, HttpModelClient,
    HttpOidcValidator, HttpPublishedKeys, HttpSignalDeliverer, HttpWebhookDeliverer,
    TURNSTILE_SITEVERIFY,
};
use ianua_infra::mail::MailedFactorCodeSender;
use ianua_infra::proofs::{
    AwsAgentAttestor, DiscoveredIssuerKeys, FixedIssuerKeys, GcpAgentAttestor,
    JwksWorkloadTokenVerifier, KeyKeeping, MethodAgentAttestor, SpiffeAgentAttestor,
    SpiffeTrustBundle, TpmAgentAttestor, WebauthnPasskeyVerifier,
};
use ianua_infra::reading::{
    EmbeddingSettings, HttpEmbedder, KeywordIntentCompiler, SemanticIntentCompiler,
};
use ianua_infra::sandbox::RegistryImageResolver;
use ianua_infra::sms::{RoutedFactorCodeSender, TwilioFactorCodeSender};

use crate::config::Config;
use crate::config::serving::agents::{AttestationConfig, SpiffeConfig};
use crate::error::{PlatformError, ServerError};
use crate::platform::Platform;

/// The most issuers, or client key sets, whose keys are kept at once.
const MOST_KEY_SOURCES: usize = 256;

/// What the API calls out to, or checks proofs from outside with.
pub(super) struct Outward {
    /// Mailed codes through the tenant's mail, texted ones through Twilio
    /// when it is set up.
    pub(super) factor_codes: Arc<RoutedFactorCodeSender>,
    /// Tenants' model providers.
    pub(super) models: Arc<dyn ModelClient>,
    /// The platform attestations the deployment trusts.
    pub(super) attestor: Arc<dyn AgentAttestor>,
    /// Workload tokens, against their issuers' published keys.
    pub(super) workload_tokens: Arc<dyn WorkloadTokenVerifier>,
    /// Passkeys' answers.
    pub(super) passkeys: Arc<dyn PasskeyVerifier>,
    /// The challenge a flooded sign-in asks for: Turnstile, or the
    /// platform's own puzzle.
    pub(super) challenges: Challenges,
    /// Tenants' OpenID Connect providers.
    pub(super) oidc: Arc<dyn OidcValidator>,
    /// Signal receivers.
    pub(super) signals: Arc<dyn SignalDeliverer>,
    /// Webhook endpoints.
    pub(super) webhooks: Arc<dyn WebhookDeliverer>,
    /// Identity providers' SAML metadata.
    pub(super) saml_metadata: Arc<dyn SamlMetadataReader>,
    /// The DNS a tenant's domain proofs are read from.
    pub(super) dns: Arc<dyn DnsResolver>,
    /// The breach check of a new password.
    pub(super) breaches: Arc<dyn CredentialBreachChecker>,
    /// What a company's named image points to now, asked of its registry
    /// through a client screening the registry's addresses.
    pub(super) image_resolver: Arc<dyn ImageResolver>,
    /// Stripe, or none.
    pub(super) payments: Arc<dyn PaymentProvider>,
    /// The city database, or none.
    pub(super) geolocator: Arc<dyn Geolocator>,
    /// The authority LDAP client certificates are signed by, or none.
    pub(super) ldap_authority: Arc<dyn LdapCertificateAuthority>,
    /// The authority connectors' certificates are signed by, or none.
    pub(super) connector_authority: Arc<dyn ConnectorAuthority>,
    /// How a declared purpose is read.
    pub(super) intents: Arc<dyn IntentCompiler>,
    /// The key sets `private_key_jwt` clients publish.
    pub(super) client_keys: Arc<dyn PublishedKeys>,
}

impl Outward {
    /// Every adapter calling out, as `config` sets them up, codes mailed
    /// through `mailer`.
    ///
    /// # Errors
    ///
    /// [`ServerError`] naming the setting refused, or the part whose
    /// client could not be built.
    pub(super) fn build(
        platform: &Platform,
        config: &Config,
        mailer: Arc<dyn Mailer>,
    ) -> Result<Self, ServerError> {
        let networks = &config.http.upstream_networks;
        let issuer_wait = config.http.oidc_timeout;
        let keeping = config.agents.attestation.issuer_keys;
        Ok(Self {
            factor_codes: Arc::new(factor_codes(config, mailer)?),
            models: Arc::new(models(config)?),
            attestor: attestor(&config.agents.attestation, issuer_wait)?,
            workload_tokens: Arc::new(workload_tokens(config)?),
            passkeys: Arc::new(passkey_verifier(platform, config)?),
            challenges: challenges(platform, config)?,
            oidc: Arc::new(oidc(config)?),
            signals: Arc::new(signals(platform)?),
            webhooks: Arc::new(webhooks(platform, config)?),
            saml_metadata: Arc::clone(&platform.saml_metadata),
            dns: Arc::clone(&platform.dns),
            image_resolver: image_resolver(networks)?,
            breaches: Arc::new(
                HttpCredentialBreachChecker::new(config.sign_in.breach_service.as_str())
                    .map_err(PlatformError::of("the password breach check"))?,
            ),
            payments: payments(config)?,
            geolocator: geolocator(config)?,
            ldap_authority: ldap_authority(config.directory.client_ca.as_ref())?,
            connector_authority: connector_authority(config.connectors.authority.as_ref())?,
            intents: intents(config)?,
            client_keys: Arc::new(
                HttpPublishedKeys::new(issuer_wait, networks.clone(), keeping, MOST_KEY_SOURCES)
                    .map_err(PlatformError::of("the clients' published keys"))?,
            ),
        })
    }
}

/// Screens model calls under the deployment's model networks and timeout.
fn models(config: &Config) -> Result<HttpModelClient, PlatformError> {
    HttpModelClient::new(
        config.agents.model_networks.clone(),
        config.agents.model_timeout,
    )
    .map_err(PlatformError::of("the model client"))
}

/// Checks workload tokens against discovered issuer keys held within a bounded cache.
fn workload_tokens(config: &Config) -> Result<JwksWorkloadTokenVerifier, PlatformError> {
    let keys = DiscoveredIssuerKeys::new(
        config.http.oidc_timeout,
        config.http.upstream_networks.clone(),
        config.agents.attestation.issuer_keys,
        MOST_KEY_SOURCES,
    )
    .map_err(PlatformError::of("the workload token issuers' keys"))?;
    Ok(JwksWorkloadTokenVerifier::new(Arc::new(keys)))
}

/// Checks passkey ceremony responses under the platform's own control root.
fn passkey_verifier(
    platform: &Platform,
    config: &Config,
) -> Result<WebauthnPasskeyVerifier, ConfigError> {
    WebauthnPasskeyVerifier::new(&config.sign_in.passkeys, &platform.keys.control_root)
        .map_err(|cause| ConfigError::rejected("WEBAUTHN_RP_ID", cause))
}

/// Screens signal deliveries against the configured outbound networks.
fn signals(platform: &Platform) -> Result<HttpSignalDeliverer, PlatformError> {
    HttpSignalDeliverer::new(
        platform.outbound.upstream_networks.clone(),
        &platform.outbound.deliveries,
    )
    .map_err(PlatformError::of("the signal deliverer"))
}

/// Applies the configured network boundary and deadline to webhook deliveries.
fn webhooks(platform: &Platform, config: &Config) -> Result<HttpWebhookDeliverer, PlatformError> {
    HttpWebhookDeliverer::new(
        platform.outbound.upstream_networks.clone(),
        config.http.delivery_timeout,
        &platform.outbound.deliveries,
    )
    .map_err(PlatformError::of("the webhook deliverer"))
}

/// OIDC under the deployment's explicit private authority, or the public
/// roots when no authority is configured. A broken file stops startup.
fn oidc(config: &Config) -> Result<HttpOidcValidator, ServerError> {
    let networks = config.http.upstream_networks.clone();
    let wait = config.http.oidc_timeout;
    let Some(path) = &config.http.oidc_authority else {
        return HttpOidcValidator::new(wait, networks)
            .map_err(PlatformError::of("the OpenID Connect client"))
            .map_err(ServerError::from);
    };
    let pem = read_file("OIDC_PROVIDER_CA_FILE", path)?;
    let authority = CertificatePem::new(pem)
        .map_err(|cause| ConfigError::rejected("OIDC_PROVIDER_CA_FILE", cause))?;
    HttpOidcValidator::trusting(wait, networks, &authority)
        .map_err(|cause| ConfigError::rejected("OIDC_PROVIDER_CA_FILE", cause).into())
}

/// Mailed codes through `mailer`; texted ones through Twilio, at the API
/// address the settings name, when its account is set up, refused
/// otherwise.
fn factor_codes(
    config: &Config,
    mailer: Arc<dyn Mailer>,
) -> Result<RoutedFactorCodeSender, ServerError> {
    let mail: Arc<dyn FactorCodeSender> = Arc::new(MailedFactorCodeSender::new(mailer));
    let Some(account) = &config.sms.twilio else {
        return Ok(RoutedFactorCodeSender::new(mail, None));
    };
    let twilio = TwilioFactorCodeSender::new(
        account.clone(),
        config.sms.endpoint.clone(),
        config.sms.send_timeout,
    )
    .map_err(PlatformError::of("the Twilio text sender"))?;
    Ok(RoutedFactorCodeSender::new(mail, Some(Arc::new(twilio))))
}

/// One attestor per method `AGENT_ATTESTATION_ALLOWLIST` lists, each
/// fetch of an issuer's keys held to `wait`.
fn attestor(
    trusted: &AttestationConfig,
    wait: Duration,
) -> Result<Arc<dyn AgentAttestor>, ServerError> {
    let methods = [
        trusted.spiffe.as_ref().map(spiffe).transpose()?,
        trusted.tpm.as_deref().map(tpm).transpose()?,
        trusted
            .gcp
            .as_ref()
            .map(|keys| gcp(keys, wait, trusted.issuer_keys))
            .transpose()?,
        trusted.aws_iam.then(|| aws(wait)).transpose()?,
    ];
    let attestor = methods
        .into_iter()
        .flatten()
        .fold(MethodAgentAttestor::new(), |attestor, (method, one)| {
            attestor.with(method, one)
        });
    Ok(Arc::new(attestor))
}

/// A method and the attestor that checks it.
type Trusted = (AttestationMethod, Arc<dyn AgentAttestor>);

/// SVIDs of the one trust domain, under its bundle.
fn spiffe(spiffe: &SpiffeConfig) -> Result<Trusted, ServerError> {
    let bundle = SpiffeTrustBundle::new(&spiffe.trust_domain, &spiffe.anchors)
        .map_err(|cause| ConfigError::rejected("AGENT_SPIFFE_TRUST_BUNDLE_PATH", cause))?;
    Ok((
        AttestationMethod::Spiffe,
        Arc::new(SpiffeAgentAttestor::new(vec![bundle])),
    ))
}

/// Quotes under the attestation identity keys' issuers.
fn tpm(anchors: &[String]) -> Result<Trusted, ServerError> {
    let attestor = TpmAgentAttestor::new(anchors)
        .map_err(|cause| ConfigError::rejected("AGENT_TPM_TRUST_BUNDLE_PATH", cause))?;
    Ok((AttestationMethod::Tpm, Arc::new(attestor)))
}

/// Instance identity tokens under the keys Google publishes at `keys`.
fn gcp(keys: &url::Url, wait: Duration, keeping: KeyKeeping) -> Result<Trusted, ServerError> {
    let issuer = GcpAgentAttestor::google_issuer().map_err(PlatformError::of("Google's issuer"))?;
    let published = FixedIssuerKeys::new(issuer, keys.clone(), wait, keeping)
        .map_err(|cause| ConfigError::rejected("AGENT_GCP_JWKS_URL", cause))?;
    let attestor = GcpAgentAttestor::new(Arc::new(published))
        .map_err(PlatformError::of("the GCP attestor"))?;
    Ok((AttestationMethod::GcpInstanceIdentity, Arc::new(attestor)))
}

/// Signed `sts:GetCallerIdentity` requests AWS answers within `wait`.
fn aws(wait: Duration) -> Result<Trusted, ServerError> {
    let attestor = AwsAgentAttestor::new(wait).map_err(PlatformError::of("the AWS attestor"))?;
    Ok((AttestationMethod::AwsIam, Arc::new(attestor)))
}

/// The challenge a flooded sign-in asks for: Turnstile when its secret is
/// set, which sets no puzzle of its own; the platform's own puzzle
/// otherwise, sealed under the control root and spent on the shared state.
fn challenges(platform: &Platform, config: &Config) -> Result<Challenges, ServerError> {
    let Some(turnstile) = &config.sign_in.turnstile else {
        let puzzles = Arc::new(Puzzles::new(
            &platform.keys.control_root,
            config.sign_in.puzzles,
            Arc::clone(&platform.shared_state),
        ));
        return Ok(Challenges {
            verifier: Arc::new(CacheChallengeVerifier::new(Arc::clone(&puzzles))),
            issuer: Some(Arc::new(CacheChallengeIssuer::new(puzzles))),
        });
    };
    let verify_url =
        url::Url::parse(TURNSTILE_SITEVERIFY).map_err(PlatformError::of("Turnstile's address"))?;
    let verifier = HttpChallengeVerifier::new(ChallengeSettings {
        verify_url,
        secret: turnstile.secret.clone(),
        hostnames: turnstile.hostnames.clone(),
        timeout: turnstile.timeout,
    })
    .map_err(|cause| ConfigError::rejected("TURNSTILE_SECRET_KEY", cause))?;
    Ok(Challenges {
        verifier: Arc::new(verifier),
        issuer: None,
    })
}

/// The challenge provider, and what sets its puzzles when it is the
/// platform's own.
pub(super) struct Challenges {
    /// Checks a proof.
    pub(super) verifier: Arc<dyn ChallengeVerifier>,
    /// Sets the puzzles; none for Turnstile.
    pub(super) issuer: Option<Arc<dyn ChallengeIssuer>>,
}

/// Stripe when its account is set up; none otherwise.
fn payments(config: &Config) -> Result<Arc<dyn PaymentProvider>, ServerError> {
    let Some(stripe) = &config.billing.stripe else {
        return Ok(Arc::new(NoPaymentProvider));
    };
    let api = url::Url::parse(STRIPE_API).map_err(PlatformError::of("Stripe's address"))?;
    let provider = StripePaymentProvider::new(StripeSettings {
        api,
        api_key: stripe.api_key.clone(),
        webhook_secret: stripe.webhook_secret.clone(),
        success_url: stripe.success_url.clone(),
        cancel_url: stripe.cancel_url.clone(),
        currency: stripe.currency.clone(),
        timeout: stripe.timeout,
    })
    .map_err(|cause| ConfigError::rejected("STRIPE_CURRENCY", cause))?;
    Ok(Arc::new(provider))
}

/// The city database `GEOIP_DB_PATH` names, or none.
fn geolocator(config: &Config) -> Result<Arc<dyn Geolocator>, ServerError> {
    let Some(path) = &config.http.geoip_database else {
        return Ok(Arc::new(NoGeolocator));
    };
    let database = MmdbGeolocator::open(path)
        .map_err(|cause| ConfigError::rejected("GEOIP_DB_PATH", cause))?;
    Ok(Arc::new(database))
}

/// The authority in `LDAP_CLIENT_CA_CERT_PATH` and
/// `LDAP_CLIENT_CA_KEY_PATH`, or none, which issues no certificate.
fn ldap_authority(
    files: Option<&PemFiles>,
) -> Result<Arc<dyn LdapCertificateAuthority>, ServerError> {
    let Some(files) = files else {
        return Ok(Arc::new(NoLdapCertificateAuthority));
    };
    let certificate = read_file("LDAP_CLIENT_CA_CERT_PATH", &files.certificate)?;
    let key = Secret::new(read_file("LDAP_CLIENT_CA_KEY_PATH", &files.key)?);
    let certificate = CertificatePem::new(certificate)
        .map_err(|cause| ConfigError::rejected("LDAP_CLIENT_CA_CERT_PATH", cause))?;
    let authority = RcgenLdapCertificateAuthority::new(&certificate, &key)
        .map_err(|cause| ConfigError::rejected("LDAP_CLIENT_CA_KEY_PATH", cause))?;
    Ok(Arc::new(authority))
}

/// The authority in `CONNECTOR_CA_CERT_FILE` and `CONNECTOR_CA_KEY_FILE`,
/// or none, which refuses every enrollment and renewal.
fn connector_authority(
    files: Option<&PemFiles>,
) -> Result<Arc<dyn ConnectorAuthority>, ServerError> {
    let Some(files) = files else {
        return Ok(Arc::new(NoConnectorAuthority));
    };
    let certificate = read_file("CONNECTOR_CA_CERT_FILE", &files.certificate)?;
    let key = Secret::new(read_file("CONNECTOR_CA_KEY_FILE", &files.key)?);
    let certificate = CertificatePem::new(certificate)
        .map_err(|cause| ConfigError::rejected("CONNECTOR_CA_CERT_FILE", cause))?;
    let authority = RcgenConnectorAuthority::new(&certificate, &key)
        .map_err(|cause| ConfigError::rejected("CONNECTOR_CA_KEY_FILE", cause))?;
    Ok(Arc::new(authority))
}

/// The text of the file `name` names.
fn read_file(name: &str, path: &std::path::Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|cause| ConfigError::Unreadable {
        name: name.to_owned(),
        path: path.display().to_string(),
        cause,
    })
}

/// A declared purpose read by meaning through the embeddings API when one
/// is set up, by keyword otherwise.
fn intents(config: &Config) -> Result<Arc<dyn IntentCompiler>, ServerError> {
    let Some(embeddings) = &config.agents.embeddings else {
        return Ok(Arc::new(KeywordIntentCompiler));
    };
    let embedder = HttpEmbedder::new(EmbeddingSettings {
        endpoint: embeddings.endpoint.clone(),
        model: embeddings.model.clone(),
        api_key: embeddings.api_key.clone(),
    })
    .map_err(|cause| ConfigError::rejected("AGENT_INTENT_EMBEDDING_URL", cause))?;
    let compiler = SemanticIntentCompiler::new(embedder, embeddings.threshold)
        .map_err(|cause| ConfigError::rejected("AGENT_INTENT_SIMILARITY_THRESHOLD", cause))?;
    Ok(Arc::new(compiler))
}

/// What resolves a company image's tag to its digest, reaching registries
/// on the upstream `networks` allowed.
fn image_resolver(networks: &UpstreamNetworks) -> Result<Arc<RegistryImageResolver>, ServerError> {
    let resolver = RegistryImageResolver::new(networks.clone())
        .map_err(PlatformError::of("the image registry client"))?;
    Ok(Arc::new(resolver))
}
