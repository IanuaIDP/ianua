//! Who this deployment serves and where it is reached: the environment, the
//! run mode, the hosted service or one organization's own installation,
//! and the public addresses links and tenants' subdomains are made from.

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::hosts;
use ianua_domain::domains::tenant::custom_domains::trusted_domains::TrustedDomains;
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::types::{DomainName, HttpsUrl};

/// Which parts of the platform this process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The API alone.
    Api,
    /// The worker alone.
    Worker,
    /// Both, in one process.
    All,
}

impl Mode {
    /// Whether this process serves the API.
    #[must_use]
    pub fn runs_api(self) -> bool {
        matches!(self, Self::Api | Self::All)
    }

    /// Whether this process runs the worker.
    #[must_use]
    pub fn runs_worker(self) -> bool {
        matches!(self, Self::Worker | Self::All)
    }

    /// Whether this process is one of several sharing the work, so what it
    /// shares with the others must live outside it.
    #[must_use]
    pub fn is_split(self) -> bool {
        !matches!(self, Self::All)
    }
}

/// Who a deployment serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    /// The hosted service: any number of organizations, and public sign-up.
    Cloud,
    /// One organization, on its owner's own hardware, made by the install
    /// command.
    SelfHosted,
}

impl Deployment {
    /// Whether this is one organization's own installation.
    #[must_use]
    pub fn is_self_hosted(&self) -> bool {
        matches!(self, Self::SelfHosted)
    }
}

/// Who the deployment serves and where it is reached.
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    /// The address shape shared with the gateway.
    pub platform_addressing: PlatformAddressing,
    /// Hosts whose labels are reserved against organization slugs.
    pub platform_hosts: Vec<DomainName>,
    /// `APP_ENV`, `production` unless `development` is asked for by name.
    pub environment: Environment,
    /// `MODE`, `all` by default.
    pub mode: Mode,
    /// `DEPLOYMENT`, the hosted service by default.
    pub deployment: Deployment,
    /// `TRUSTED_DOMAINS`: parent domains whose names tenants use without a
    /// DNS proof. Only an installation may vouch for any.
    pub trusted_domains: TrustedDomains,
    /// `APP_BASE_URL`: the dashboard's public address, which emailed links
    /// and identity providers name.
    pub app_base_url: HttpsUrl,
    /// `EMAIL_LOGO_URL`: the logo shown in mail, when one is set.
    pub email_logo_url: Option<HttpsUrl>,
    /// `PROXY_BASE_DOMAIN`: the domain tenants' platform subdomains sit
    /// under.
    pub base_domain: DomainName,
    /// `OAUTH_DEVICE_VERIFICATION_URI`: where the device flow sends a
    /// person to type their code; the dashboard's `/device` page by
    /// default.
    pub device_verification_uri: HttpsUrl,
}

impl DeploymentConfig {
    /// The deployment settings `vars` holds.
    ///
    /// # Errors
    ///
    /// Any setting that is missing or does not read, or `TRUSTED_DOMAINS`
    /// on the hosted service.
    pub fn read(vars: &Env) -> Read<Self> {
        let environment = Environment::read(vars)?;
        let deployment = deployment(vars)?;
        let trusted_domains = trusted_domains(vars)?;
        if !deployment.is_self_hosted() && !trusted_domains.is_empty() {
            return Err(ConfigError::contradicts(
                "TRUSTED_DOMAINS",
                "is only allowed with DEPLOYMENT=self_hosted: on a shared deployment it would let \
                 any tenant claim any name beneath those domains",
            ));
        }
        let app_base_url = vars.required_parsed("APP_BASE_URL", HttpsUrl::new)?;
        Ok(Self {
            platform_addressing: hosts::addressing(vars)?,
            platform_hosts: hosts::reserved_hosts(vars)?,
            environment,
            mode: mode(vars)?,
            deployment,
            trusted_domains,
            device_verification_uri: device_verification_uri(vars, &app_base_url)?,
            app_base_url,
            email_logo_url: vars.parsed("EMAIL_LOGO_URL", HttpsUrl::new)?,
            base_domain: vars.required_parsed("PROXY_BASE_DOMAIN", DomainName::new)?,
        })
    }
}

fn mode(vars: &Env) -> Read<Mode> {
    vars.choice(
        "MODE",
        Mode::All,
        &[
            ("api", Mode::Api),
            ("worker", Mode::Worker),
            ("all", Mode::All),
        ],
    )
}

/// Which deployment `DEPLOYMENT` names.
fn deployment(vars: &Env) -> Read<Deployment> {
    vars.choice(
        "DEPLOYMENT",
        Deployment::Cloud,
        &[
            ("cloud", Deployment::Cloud),
            ("self_hosted", Deployment::SelfHosted),
            ("self-hosted", Deployment::SelfHosted),
        ],
    )
}

/// `TRUSTED_DOMAINS`, a comma-separated list of parent domains.
fn trusted_domains(vars: &Env) -> Read<TrustedDomains> {
    let mut parents = Vec::new();
    for entry in vars.list("TRUSTED_DOMAINS")? {
        parents.push(
            DomainName::new(entry)
                .map_err(|cause| ConfigError::rejected("TRUSTED_DOMAINS", cause))?,
        );
    }
    TrustedDomains::new(parents).map_err(|cause| ConfigError::rejected("TRUSTED_DOMAINS", cause))
}

/// `OAUTH_DEVICE_VERIFICATION_URI`, or the dashboard's `/device` page.
fn device_verification_uri(vars: &Env, app_base_url: &HttpsUrl) -> Read<HttpsUrl> {
    let name = "OAUTH_DEVICE_VERIFICATION_URI";
    if let Some(uri) = vars.parsed(name, HttpsUrl::new)? {
        return Ok(uri);
    }
    let derived = format!("{}/device", app_base_url.as_str().trim_end_matches('/'));
    HttpsUrl::new(derived).map_err(|cause| ConfigError::rejected(name, cause))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The settings every deployment needs, on the hosted service.
    fn hosted() -> Vec<(&'static str, &'static str)> {
        vec![
            ("APP_BASE_URL", "https://app.example.com"),
            ("PROXY_BASE_DOMAIN", "apps.example.com"),
        ]
    }

    /// An installation's settings beside the ones every deployment needs.
    fn installed() -> Vec<(&'static str, &'static str)> {
        let mut pairs = hosted();
        pairs.push(("DEPLOYMENT", "self_hosted"));
        pairs
    }

    /// With nothing but the addresses set, the deployment is the hosted
    /// service, in production, running both halves.
    #[test]
    fn the_defaults_are_the_hosted_service_in_production_running_both() {
        let config = DeploymentConfig::read(&Env::of(hosted())).unwrap();

        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.mode, Mode::All);
        assert!(matches!(config.deployment, Deployment::Cloud));
        assert_eq!(
            config.device_verification_uri.as_str(),
            "https://app.example.com/device"
        );
    }

    /// A deployment with only its proxy domain configured is refused for
    /// the missing public application URL.
    #[test]
    fn the_public_address_must_be_set() {
        let read = DeploymentConfig::read(&Env::of([("PROXY_BASE_DOMAIN", "apps.example.com")]));

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name == "APP_BASE_URL"));
    }

    /// A plain HTTP public application URL is rejected by setting name.
    #[test]
    fn the_public_address_must_be_https() {
        let mut pairs = hosted();
        pairs[0] = ("APP_BASE_URL", "http://app.example.com");

        let read = DeploymentConfig::read(&Env::of(pairs));

        assert!(matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "APP_BASE_URL"));
    }

    /// `DEPLOYMENT=self_hosted` is an installation.
    #[test]
    fn self_hosted_is_an_installation() {
        let config = DeploymentConfig::read(&Env::of(installed())).unwrap();

        assert_eq!(config.deployment, Deployment::SelfHosted);
    }

    /// Trusted parent domains are refused on a shared cloud deployment.
    #[test]
    fn trusted_domains_on_the_hosted_service_are_refused() {
        let mut pairs = hosted();
        pairs.push(("TRUSTED_DOMAINS", "corp.com"));

        let read = DeploymentConfig::read(&Env::of(pairs));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "TRUSTED_DOMAINS")
        );
    }

    /// An installation may vouch for parent domains.
    #[test]
    fn an_installation_may_vouch_for_parent_domains() {
        let mut pairs = installed();
        pairs.push(("TRUSTED_DOMAINS", "corp.com, internal.example.org"));

        let config = DeploymentConfig::read(&Env::of(pairs)).unwrap();

        assert_eq!(config.trusted_domains.parents().len(), 2);
    }

    /// Each mode says which halves it runs.
    #[test]
    fn each_mode_says_which_halves_it_runs() {
        assert!(Mode::Api.runs_api() && !Mode::Api.runs_worker());
        assert!(Mode::Worker.runs_worker() && !Mode::Worker.runs_api());
        assert!(Mode::All.runs_api() && Mode::All.runs_worker() && !Mode::All.is_split());
    }
}
