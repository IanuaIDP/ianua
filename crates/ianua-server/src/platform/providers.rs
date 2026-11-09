//! The providers outside the deployment that the API and the worker both
//! call: the mail the platform sends, the clouds customers connect, and
//! the integrations workflows run; the DNS lookups that prove tenants'
//! domains; SAML providers' metadata; and the links export files are downloaded through, which the
//! worker makes and the API hands out. Each
//! is built once, with its own client, screened for an address a tenant
//! chose.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use ianua_app::ports::domain::DnsResolver;
use ianua_app::ports::federation::SamlMetadataReader;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{CertificatePem, HttpsUrl};
use ianua_infra::cloud::{
    AwsCloudProviderFactory, AwsPlatformCredentials, AzureCloudProviderFactory, CloudEndpoint,
    ConfiguredCloudProviderRegistry, DigitalOceanCloudProviderFactory, GcpCloudProviderFactory,
    KubernetesCloudProviderFactory,
};
use ianua_infra::dns::{LookupBounds, RecursiveDnsResolver};
use ianua_infra::files::FileLinks;
use ianua_infra::http::client::{NameLookup, Trust};
use ianua_infra::integrations::{
    AppSettings, CompanyIntegration, HttpRequests, Installed, MemorySteps, ProtectedApps,
    RequestSettings,
};
use ianua_infra::mail::{
    MailAudience, MailComposer, MailDelivery, PlatformLook, PlatformMail, ProviderEndpoints,
};
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::organization::PgOrganizationStore;
use ianua_infra::postgres::tenant::PgTenantStore;
use ianua_infra::saml::ScreenedSamlMetadataReader;
use ianua_integration::Integration;

use crate::config::Config;
use crate::config::serving::cloud::AwsKeys;
use crate::error::PlatformError;
use crate::platform::Keys;
use crate::platform::integrations::outside_services;
use crate::platform::protected_data::protected_data;
use crate::platform::services::Outbound;

/// The most sensitive data a company step may take. These steps act on the
/// tenant's own records and send nothing outside it, so the limits on outside
/// services do not apply, and a directory answer they give back is this
/// sensitive.
const COMPANY_STEPS_CEILING: DataClassLevel = DataClassLevel::Confidential;

/// The logo the platform's mail shows when `EMAIL_LOGO_URL` names none.
const PLATFORM_LOGO: &str = "https://api.ianua.io/email-logo.png";

/// Where export files are downloaded, under `APP_BASE_URL`.
const FILE_DOWNLOADS_PATH: &str = "/api/v1/files/download";

/// The links export files are downloaded through, made under the control
/// plane's root: the gateway, holding only the shared one, can neither
/// make a link nor read one.
///
/// # Errors
///
/// [`PlatformError`] when `APP_BASE_URL` and the download path make no
/// address, which a checked base never does.
pub(super) fn file_links(config: &Config, keys: &Keys) -> Result<FileLinks, PlatformError> {
    let base = config
        .deployment
        .app_base_url
        .as_str()
        .trim_end_matches('/');
    let served_from = HttpsUrl::new(format!("{base}{FILE_DOWNLOADS_PATH}"))
        .map_err(PlatformError::of("the file download address"))?;
    Ok(FileLinks::new(&keys.control_root, served_from))
}

/// The DNS lookups that prove tenants' domains, through `resolvers`, or
/// the host's resolvers when none are named, each held to the lookup's own
/// bounds.
///
/// # Errors
///
/// [`PlatformError`] when the host's resolver settings cannot be read, or
/// the resolver cannot be built.
pub(super) fn dns(resolvers: &[SocketAddr]) -> Result<Arc<dyn DnsResolver>, PlatformError> {
    let bounds = LookupBounds::default();
    let resolver = match resolvers {
        [] => RecursiveDnsResolver::from_host(bounds),
        named => RecursiveDnsResolver::asking(named, bounds),
    }
    .map_err(PlatformError::of("the DNS resolver"))?;
    Ok(Arc::new(resolver))
}

/// The reader of SAML providers' metadata: names looked up through
/// `resolvers` or the host's, addresses screened by `UPSTREAM_NETWORKS`,
/// and `SAML_METADATA_CA_FILE` trusted alone when it is set. A file that
/// cannot be read stops startup.
pub(super) fn saml_metadata(config: &Config) -> Result<Arc<dyn SamlMetadataReader>, PlatformError> {
    let lookup = NameLookup::asking(&config.domains.resolvers)
        .map_err(PlatformError::of("the SAML metadata resolver"))?;
    let trust = match &config.http.saml_metadata_authority {
        None => Trust::PublicRoots,
        Some(path) => metadata_authority(path)?,
    };
    let reader =
        ScreenedSamlMetadataReader::new(config.http.upstream_networks.clone(), lookup, trust)
            .map_err(PlatformError::of("the SAML metadata reader"))?;
    Ok(Arc::new(reader))
}

/// The private authority in the file at `path`, trusted alone.
fn metadata_authority(path: &Path) -> Result<Trust, PlatformError> {
    let pem = std::fs::read_to_string(path).map_err(PlatformError::of("SAML_METADATA_CA_FILE"))?;
    let authority = CertificatePem::new(pem).map_err(PlatformError::of("SAML_METADATA_CA_FILE"))?;
    Trust::only_authority(&authority).map_err(PlatformError::of("SAML_METADATA_CA_FILE"))
}

/// What the platform's own mail goes out through, and what makes it.
pub struct Mail {
    /// The platform's account and the address it sends from.
    pub platform: Arc<PlatformMail>,
    /// Hands a mail to the platform's account or a tenant's provider, each
    /// delivery held to `EMAIL_SEND_TIMEOUT_SECONDS`.
    pub delivery: Arc<MailDelivery>,
    /// Renders every mail from its template.
    pub composer: Arc<MailComposer>,
    /// The names each tenant's mail is addressed under.
    pub audience: Arc<MailAudience>,
}

/// The mail parts `config` describes, over `databases`.
///
/// # Errors
///
/// [`PlatformError`] when the delivery's client cannot be built or the
/// templates do not compile.
pub(super) fn mail(config: &Config, databases: &Arc<Databases>) -> Result<Mail, PlatformError> {
    let endpoints = ProviderEndpoints::public().map_err(PlatformError::of("the mail providers"))?;
    let delivery = MailDelivery::new(
        endpoints,
        config.http.upstream_networks.clone(),
        config.mail.send_timeout,
    )
    .map_err(PlatformError::of("the mail delivery"))?;
    let look = PlatformLook {
        logo_url: logo_url(config)?,
    };
    let limits = DomainLimits::default();
    Ok(Mail {
        platform: Arc::new(config.mail.platform.clone()),
        delivery: Arc::new(delivery),
        composer: Arc::new(
            MailComposer::new(&look).map_err(PlatformError::of("the mail templates"))?,
        ),
        audience: Arc::new(MailAudience::new(
            Arc::new(PgTenantStore::new(Arc::clone(databases), limits.clone())),
            Arc::new(PgOrganizationStore::new(Arc::clone(databases), limits)),
        )),
    })
}

/// `EMAIL_LOGO_URL`, or the platform's own logo.
fn logo_url(config: &Config) -> Result<HttpsUrl, PlatformError> {
    match &config.deployment.email_logo_url {
        Some(url) => Ok(url.clone()),
        None => HttpsUrl::new(PLATFORM_LOGO).map_err(PlatformError::of("the mail logo")),
    }
}

/// The integrations workflow steps call: the HTTP request step, held as
/// `WORKFLOW_HTTP_*` says and screened by `UPSTREAM_NETWORKS`, Protected
/// apps when `GATEWAY_WORKFLOW_URL` is set, and each outside service this
/// build includes, at the API its settings name.
///
/// # Errors
///
/// [`PlatformError`] when a step's client cannot be built.
pub(super) fn integrations(
    config: &Config,
    outbound: &Outbound,
) -> Result<Arc<Installed>, PlatformError> {
    let requests = &config.http.workflow_requests;
    let http = HttpRequests::new(RequestSettings {
        networks: config.http.upstream_networks.clone(),
        timeout: requests.timeout,
        most_answer: requests.most_answer,
        ceiling: requests.ceiling,
    })
    .map_err(PlatformError::of("the workflow HTTP request step"))?;
    let memory =
        MemorySteps::new(requests.ceiling).map_err(PlatformError::of("the memory steps"))?;
    let company = CompanyIntegration::new(COMPANY_STEPS_CEILING)
        .map_err(PlatformError::of("the company steps"))?;
    let mut steps: Vec<Arc<dyn Integration>> =
        vec![Arc::new(http), Arc::new(memory), Arc::new(company)];
    steps.extend(protected_apps(config)?);
    steps.extend(protected_data(config)?);
    let reach = outbound
        .deliveries
        .service_reach(outbound.upstream_networks.clone())
        .map_err(PlatformError::of("the integrations' reach"))?;
    steps.extend(outside_services(config, &reach)?);
    let installed = Installed::new(steps).map_err(PlatformError::of("the integrations"))?;
    Ok(Arc::new(installed))
}

/// Protected apps, calling the gateway's workflow listener at
/// `GATEWAY_WORKFLOW_URL` over mutual TLS, or nothing while it is unset.
///
/// # Errors
///
/// [`PlatformError`] when the internal authority does not read or its
/// client cannot be built.
fn protected_apps(config: &Config) -> Result<Option<Arc<dyn Integration>>, PlatformError> {
    let Some(link) = &config.gateway_link else {
        return Ok(None);
    };
    let requests = &config.http.workflow_requests;
    let apps = ProtectedApps::new(AppSettings {
        gateway: link.url.clone(),
        link: link.link.clone(),
        timeout: requests.timeout,
        most_answer: requests.most_answer,
        ceiling: requests.ceiling,
    })
    .map_err(PlatformError::of("the Protected apps step"))?;
    Ok(Some(Arc::new(apps)))
}

/// The clouds customers connect their accounts from: AWS when the
/// platform's keys are set, which assume customers' roles; Azure, Google
/// Cloud and DigitalOcean on the customer's own credential; and
/// Kubernetes clusters reached inside `UPSTREAM_NETWORKS`.
///
/// # Errors
///
/// [`PlatformError`] when a cloud's client cannot be built.
pub(super) fn clouds(
    config: &Config,
) -> Result<Arc<ConfiguredCloudProviderRegistry>, PlatformError> {
    let mut clouds = ConfiguredCloudProviderRegistry::new()
        .with(Arc::new(
            AzureCloudProviderFactory::new(CloudEndpoint::Public)
                .map_err(PlatformError::of("the Azure accounts"))?,
        ))
        .with(Arc::new(
            GcpCloudProviderFactory::new(CloudEndpoint::Public)
                .map_err(PlatformError::of("the Google Cloud accounts"))?,
        ))
        .with(Arc::new(
            DigitalOceanCloudProviderFactory::new(CloudEndpoint::Public)
                .map_err(PlatformError::of("the DigitalOcean accounts"))?,
        ))
        .with(Arc::new(KubernetesCloudProviderFactory::new(
            config.http.upstream_networks.clone(),
        )));
    if let Some(keys) = &config.cloud.aws {
        clouds = clouds.with(Arc::new(aws(keys)?));
    }
    Ok(Arc::new(clouds))
}

/// The AWS accounts, reached by assuming customers' roles with `keys`.
fn aws(keys: &AwsKeys) -> Result<AwsCloudProviderFactory, PlatformError> {
    let platform = AwsPlatformCredentials {
        access_key_id: keys.access_key_id.clone(),
        secret_access_key: keys.secret_access_key.clone(),
        session_token: keys.session_token.clone(),
    };
    AwsCloudProviderFactory::new(platform, CloudEndpoint::Public)
        .map_err(PlatformError::of("the AWS accounts"))
}
