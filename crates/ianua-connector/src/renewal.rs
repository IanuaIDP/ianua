//! Keeping the connector's certificate current: from the time the last
//! answer said it is due, a new signing request for the same key goes to
//! the API, and the answer is kept and handed to the links, which open
//! with it from their next handshake.
//!
//! A busy or unreachable API is tried again with growing waits. A refusal
//! means the connector was revoked or its key is no longer taken: the
//! connector stops serving at once and says why, rather than holding on
//! until its certificate runs out.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::security::secret::Secret;
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::api::{ApiClient, Outcome, until_answered};
use crate::backoff::Backoff;
use crate::state::{Issued, StateDir};
use crate::tls::Credentials;

/// The least time between two renewals, so an answer whose renewal time
/// has already passed is never asked again in a tight loop.
const LEAST_GAP: Duration = Duration::from_secs(60);

/// The status the API refused the connector with, once it did.
#[derive(Debug, Default)]
pub struct Refusal(OnceLock<u16>);

impl Refusal {
    /// The status, once refused.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.0.get().copied()
    }
}

/// What renewing works with.
pub(crate) struct Renewal {
    /// The API renewals go to.
    pub api: ApiClient,
    /// Where each answer is kept.
    pub state: StateDir,
    /// The connector's key.
    pub key: Secret,
    /// A signing request for that key.
    pub request: String,
    /// The certificate held now.
    pub current: Issued,
    /// Where the links read the certificate from.
    pub credentials: watch::Sender<Credentials>,
    /// The longest wait between tries.
    pub backoff_max: Duration,
    /// Stopped when the API refuses.
    pub shutdown: Shutdown,
    /// Where a refusal is recorded for the process to report.
    pub refusal: Arc<Refusal>,
}

impl Renewal {
    /// Renews whenever due, until the stop or a refusal.
    pub(crate) async fn keep_current(mut self) {
        let mut gap = Duration::ZERO;
        loop {
            let wait = until(self.current.renew_after).max(gap);
            tokio::select! {
                () = self.shutdown.stopping() => return,
                () = tokio::time::sleep(wait) => {}
            }
            let Some(issued) = self.renewed().await else {
                return;
            };
            self.current = issued;
            gap = LEAST_GAP;
        }
    }

    /// The next certificate, kept and handed to the links, or `None` once
    /// stopping.
    async fn renewed(&self) -> Option<Issued> {
        let mut backoff = Backoff::new(self.backoff_max);
        loop {
            let outcome = until_answered(&mut backoff, &self.shutdown, "renew", || {
                self.api.renew(self.current.id, &self.request)
            })
            .await;
            let issued = match outcome {
                Outcome::Issued(issued) => issued,
                Outcome::Refused(status) => return self.refused(status),
                Outcome::Stopped => return None,
            };
            match self.install(&issued) {
                Ok(()) => return Some(issued),
                Err(reason) => {
                    tracing::warn!(%reason, "a renewed certificate could not be used; trying again")
                }
            }
            tokio::select! {
                () = self.shutdown.stopping() => return None,
                () = tokio::time::sleep(backoff.wait()) => {}
            }
        }
    }

    /// Keeps `issued` and hands it to the links.
    fn install(&self, issued: &Issued) -> Result<(), String> {
        let credentials = Credentials::of(issued, &self.key).map_err(|error| error.to_string())?;
        self.state.keep(issued).map_err(|error| error.to_string())?;
        self.credentials.send_replace(credentials);
        tracing::info!(expires_at = %issued.expires_at, "the connector's certificate was renewed");
        Ok(())
    }

    /// Records the API's refusal and stops the connector.
    fn refused(&self, status: u16) -> Option<Issued> {
        tracing::error!(
            status,
            "the API refused to renew the connector's certificate: it was revoked or its key is not taken; stopping"
        );
        let _ = self.refusal.0.set(status);
        self.shutdown.stop();
        None
    }
}

/// How long until `at`, nothing when it has passed.
fn until(at: OffsetDateTime) -> Duration {
    (at - OffsetDateTime::now_utc())
        .try_into()
        .unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use uuid::Uuid;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::api::signing_request;
    use crate::config::ApiConfig;

    fn issued(key: &KeyPair, renew_after: OffsetDateTime) -> Issued {
        let certificate = CertificateParams::new(vec!["c".to_owned()])
            .unwrap()
            .self_signed(key)
            .unwrap()
            .pem();
        Issued {
            id: Uuid::now_v7(),
            certificate_pem: certificate.clone(),
            authority_pem: certificate,
            expires_at: renew_after + time::Duration::hours(8),
            renew_after,
        }
    }

    /// A client of the API `server` stands in for, enrolled already.
    fn api_at(server: &MockServer) -> ApiClient {
        let api = ApiConfig {
            url: url::Url::parse(&server.uri()).unwrap(),
            tenant: "acme/main".parse().unwrap(),
            enrollment_code: None,
        };
        ApiClient::new(&api, Duration::from_secs(5)).unwrap()
    }

    /// A forbidden renewal response records its status and triggers
    /// connector shutdown after one API request.
    #[tokio::test]
    async fn a_refused_renewal_stops_the_connector() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let folder = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let secret = Secret::new(key.serialize_pem());
        let current = issued(&key, OffsetDateTime::now_utc() - time::Duration::minutes(1));
        let shutdown = Shutdown::new(Duration::from_secs(1));
        let refusal = Arc::new(Refusal::default());
        let renewal = Renewal {
            api: api_at(&server),
            state: StateDir::open(&folder.path().join("state")).unwrap(),
            request: signing_request(&secret).unwrap(),
            credentials: watch::Sender::new(Credentials::of(&current, &secret).unwrap()),
            key: secret,
            current,
            backoff_max: Duration::from_millis(10),
            shutdown: shutdown.clone(),
            refusal: Arc::clone(&refusal),
        };

        renewal.keep_current().await;

        assert_eq!(refusal.status(), Some(403));
        assert!(shutdown.is_stopping());
    }

    /// A renewal time already past waits nothing; one ahead waits until
    /// then.
    #[test]
    fn a_past_renewal_time_is_due_at_once() {
        assert_eq!(until(OffsetDateTime::UNIX_EPOCH), Duration::ZERO);
        assert!(
            until(OffsetDateTime::now_utc() + time::Duration::hours(1))
                > Duration::from_secs(3_000)
        );
    }
}
