//! Starting the connector: from the binary, until a stop; or from a test
//! through [`serving`], under a stop the caller holds.
//!
//! On start the connector opens its folder and its key, enrolls when it has
//! not yet, then holds its links to the gateway and keeps its certificate
//! renewed.

use std::sync::Arc;
use std::time::Duration;

use ianua_boot::env::Env;
use ianua_boot::logging;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::security::secret::Secret;
use tokio::sync::watch;
use uuid::Uuid;

use crate::api::{ApiClient, Outcome, signing_request, until_answered};
use crate::backoff::Backoff;
use crate::config::Config;
use crate::dial::{Dialer, SystemResolver};
use crate::error::ConnectorError;
use crate::link::{LinkParts, LinkSettings, Links};
use crate::relay::Relay;
use crate::renewal::{Refusal, Renewal};
use crate::state::{Issued, StateDir};
use crate::tls::Credentials;

/// A serving connector.
#[derive(Debug, Clone)]
pub struct Serving {
    /// The connector it enrolled as.
    pub connector: Uuid,
    /// How many links to the gateway are open, as it changes.
    pub links: watch::Receiver<usize>,
    /// The API's refusal to renew, once it refused.
    pub refusal: Arc<Refusal>,
}

/// Reads the configuration from `vars`, sets up the logs, and serves until
/// SIGTERM, Ctrl-C or a refused renewal, then waits for the relays in
/// flight.
///
/// # Errors
///
/// [`ConnectorError`] for the first thing that failed, or the refusal that
/// stopped it.
pub async fn run(vars: &Env) -> Result<(), ConnectorError> {
    let config = Config::read(vars)?;
    logging::init(&config.logging)?;
    let shutdown = Shutdown::new(config.limits.shutdown_grace);
    shutdown.stop_on_signals()?;
    let serving = started(vars, &config, &shutdown).await?;
    shutdown.join().await?;
    if let Some(status) = serving.refusal.status() {
        return Err(ConnectorError::RenewalRefused { status });
    }
    tracing::info!("stopped");
    Ok(())
}

/// Starts the connector `vars` describes under `shutdown`, answering once
/// it has enrolled and its links are being opened. The caller holds the
/// stop and sets up the logs.
///
/// # Errors
///
/// [`ConnectorError`] for the first thing that failed.
pub async fn serving(vars: &Env, shutdown: &Shutdown) -> Result<Serving, ConnectorError> {
    let config = Config::read(vars)?;
    started(vars, &config, shutdown).await
}

/// Enrolls when needed, then starts the links and the renewal.
async fn started(
    vars: &Env,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<Serving, ConnectorError> {
    let refusal = Arc::new(Refusal::default());
    let renewal = enrolled_renewal(config, shutdown, &refusal).await?;
    let links = Arc::new(links_of(config, renewal.credentials.subscribe(), shutdown)?);
    let live = links.live();
    let connector = renewal.current.id;
    shutdown.spawn("the links to the gateway", links.hold());
    shutdown.spawn("the certificate renewal", renewal.keep_current());
    tracing::info!(%connector, settings = ?vars.set_names(), "connector serving");
    Ok(Serving {
        connector,
        links: live,
        refusal,
    })
}

/// Opens the connector's folder and key and enrolls when no certificate
/// was kept, ready to keep that certificate current.
async fn enrolled_renewal(
    config: &Config,
    shutdown: &Shutdown,
    refusal: &Arc<Refusal>,
) -> Result<Renewal, ConnectorError> {
    let state = StateDir::open(&config.state_dir)?;
    let key = state.key()?;
    let request = signing_request(&key)?;
    let api = ApiClient::new(&config.api, config.limits.request)?;
    let enrollment = Enrollment {
        api: &api,
        request: &request,
        backoff_max: config.limits.backoff_max,
        shutdown,
    };
    let current = enrollment
        .enrolled(&state, config.api.enrollment_code.as_ref())
        .await?;
    Ok(Renewal {
        credentials: watch::Sender::new(Credentials::of(&current, &key)?),
        api,
        state,
        key,
        request,
        current,
        backoff_max: config.limits.backoff_max,
        shutdown: shutdown.clone(),
        refusal: Arc::clone(refusal),
    })
}

/// How the connector enrolls: through `api` with its signing request,
/// waiting at most `backoff_max` between tries, until the stop.
struct Enrollment<'a> {
    api: &'a ApiClient,
    request: &'a str,
    backoff_max: Duration,
    shutdown: &'a Shutdown,
}

impl Enrollment<'_> {
    /// The certificate kept in `state` from an earlier start, or the one
    /// enrolling with `code` answers now.
    async fn enrolled(
        &self,
        state: &StateDir,
        code: Option<&Secret>,
    ) -> Result<Issued, ConnectorError> {
        if let Some(issued) = state.issued()? {
            return Ok(issued);
        }
        let code = code.ok_or(ConnectorError::NoCode)?;
        let issued = self.enroll_with(code).await?;
        state.keep(&issued)?;
        tracing::info!(connector = %issued.id, "the connector enrolled");
        Ok(issued)
    }

    /// Enrolls with `code`, trying again while the API is busy.
    async fn enroll_with(&self, code: &Secret) -> Result<Issued, ConnectorError> {
        let mut backoff = Backoff::new(self.backoff_max);
        let outcome = until_answered(&mut backoff, self.shutdown, "enroll", || {
            self.api.enroll(code, self.request)
        })
        .await;
        match outcome {
            Outcome::Issued(issued) => Ok(issued),
            Outcome::Refused(status) => Err(ConnectorError::EnrollmentRefused { status }),
            Outcome::Stopped => Err(ConnectorError::StoppedBeforeEnrolling),
        }
    }
}

/// The links `config` asks for, answering through a relay held to its
/// allow list and limits.
fn links_of(
    config: &Config,
    credentials: watch::Receiver<Credentials>,
    shutdown: &Shutdown,
) -> Result<Links<SystemResolver>, ConnectorError> {
    let limits = config.limits;
    let dialer = Dialer {
        resolver: SystemResolver,
        targets: config.targets.clone(),
        timeout: limits.dial,
    };
    let most = limits
        .links
        .saturating_mul(usize::try_from(limits.streams).unwrap_or(usize::MAX));
    let relay = Relay::new(dialer, limits.idle, most, shutdown.clone());
    Ok(Links::new(LinkParts {
        settings: LinkSettings {
            gateway: config.gateway.clone(),
            links: limits.links,
            streams: limits.streams,
            handshake: limits.handshake,
            resolve: limits.resolve,
            backoff_max: limits.backoff_max,
        },
        relay: Arc::new(relay),
        credentials,
        shutdown: shutdown.clone(),
    })?)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// An environment for a connector keeping its state in `state`, its API
    /// at `api`, with `code` when given.
    fn vars(api: &str, state: &std::path::Path, code: Option<&str>) -> Env {
        let state = state.to_string_lossy().into_owned();
        let mut pairs = vec![
            ("CONNECTOR_API_URL".to_owned(), api.to_owned()),
            ("CONNECTOR_TENANT".to_owned(), "acme/main".to_owned()),
            (
                "CONNECTOR_GATEWAY_ADDRESS".to_owned(),
                "127.0.0.1:9".to_owned(),
            ),
            (
                "CONNECTOR_ALLOWED_TARGETS".to_owned(),
                "wiki.corp.internal:443".to_owned(),
            ),
            ("CONNECTOR_STATE_DIR".to_owned(), state),
            ("CONNECTOR_BACKOFF_MAX_SECONDS".to_owned(), "1".to_owned()),
        ];
        if let Some(code) = code {
            pairs.push(("CONNECTOR_ENROLLMENT_CODE".to_owned(), code.to_owned()));
        }
        Env::of(
            pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
    }

    /// A connector without saved enrollment or a code fails startup with
    /// the missing-code error.
    #[tokio::test]
    async fn a_connector_without_a_code_does_not_start() {
        let folder = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(Duration::from_secs(1));

        let started = serving(
            &vars("http://127.0.0.1:9", &folder.path().join("state"), None),
            &shutdown,
        )
        .await;

        assert!(matches!(started, Err(ConnectorError::NoCode)));
    }

    /// A refused enrollment code fails startup after one request, keeps
    /// the refusal status and leaves no saved enrollment.
    #[tokio::test]
    async fn a_refused_code_stops_the_connector_without_retrying() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let folder = tempfile::tempdir().unwrap();
        let state = folder.path().join("state");
        let shutdown = Shutdown::new(Duration::from_secs(1));

        let started = serving(&vars(&server.uri(), &state, Some("spent code")), &shutdown).await;

        assert!(matches!(
            started,
            Err(ConnectorError::EnrollmentRefused { status: 403 })
        ));
        assert!(StateDir::open(&state).unwrap().issued().unwrap().is_none());
    }
}
