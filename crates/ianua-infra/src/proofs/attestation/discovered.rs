//! The keys of any issuer a tenant trusts for workload tokens, read from
//! its OpenID Connect discovery document.
//!
//! As OpenID Connect Discovery 1.0 says
//! (<https://openid.net/specs/openid-connect-discovery-1_0.html>, sections
//! 3, 4 and 4.3), the document is read at the issuer with any trailing `/`
//! removed and `/.well-known/openid-configuration` added, its `issuer`
//! must be exactly the issuer it was read for, and its `jwks_uri` must use
//! `https`. A Kubernetes cluster publishes the same two documents for its
//! service account issuer, `/.well-known/openid-configuration` and
//! `/openid/v1/jwks`, and may move the key set to another host with
//! `--service-account-jwks-uri`
//! (<https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery>).
//! GitHub Actions publishes its key set at
//! `https://token.actions.githubusercontent.com/.well-known/jwks`, as its
//! discovery document names. So the key set may live on another host, but
//! only over `https`.
//!
//! The issuer is the tenant's choice, so both calls go through the
//! screened client: an address the deployment may not reach is refused
//! before the call, each name is screened when it resolves, no redirect is
//! followed, each call is held to a timeout and each answer to a size.
//! The keys are kept as [`KeyKeeping`] says, for a bounded number of
//! issuers.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::attestation::WorkloadIssuer;
use ianua_domain::shared::errors::{DomainError, causes};
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use serde::Deserialize;
use serde_json::Value;

use crate::http::client::{body_within, ensure_reachable, screened};
use crate::proofs::attestation::published::{
    IssuerKeys, KeyCache, KeyKeeping, MOST_KEY_SET_BYTES, Wanted, key_set_in,
};

/// Where a discovery document is published under its issuer.
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// The most bytes a discovery document may hold.
const MOST_DOCUMENT_BYTES: usize = 65_536;

/// The scheme every issuer and key set is reached over.
const HTTPS: &str = "https";

/// The parts of a discovery document the keys are found through.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

/// The keys of every trusted issuer, read through its discovery document.
pub struct DiscoveredIssuerKeys {
    client: reqwest::Client,
    networks: UpstreamNetworks,
    scheme: &'static str,
    cache: KeyCache,
}

impl DiscoveredIssuerKeys {
    /// Keys read with each call held to `timeout`, reaching public
    /// addresses and those in `networks`, kept as `keeping` says for at
    /// most `most_issuers` issuers.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        timeout: Duration,
        networks: UpstreamNetworks,
        keeping: KeyKeeping,
        most_issuers: usize,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: screened(timeout, networks.clone())?,
            networks,
            scheme: HTTPS,
            cache: KeyCache::new(keeping, most_issuers),
        })
    }

    /// The key set `issuer` publishes, read now.
    async fn fetch(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError> {
        let body = self
            .read(self.discovery_of(issuer)?, MOST_DOCUMENT_BYTES)
            .await?;
        let document: Discovery = serde_json::from_slice(&body).map_err(DomainError::infra)?;
        if document.issuer != issuer.as_str() {
            return Err(DomainError::infra_msg(
                "the discovery document names another issuer",
            ));
        }
        let key_set = self.reached(&document.jwks_uri)?;
        key_set_in(&self.read(key_set, MOST_KEY_SET_BYTES).await?)
    }

    /// Where `issuer` publishes its discovery document.
    fn discovery_of(&self, issuer: &WorkloadIssuer) -> Result<url::Url, DomainError> {
        let mut url = url::Url::parse(&format!(
            "{}{DISCOVERY_PATH}",
            issuer.as_str().trim_end_matches('/')
        ))
        .map_err(DomainError::infra)?;
        url.set_scheme(self.scheme)
            .map_err(|()| DomainError::infra_msg("the issuer cannot be read over https"))?;
        self.checked(url)
    }

    /// `address` as a URL to call, as [`checked`](Self::checked) allows.
    fn reached(&self, address: &str) -> Result<url::Url, DomainError> {
        self.checked(url::Url::parse(address).map_err(DomainError::infra)?)
    }

    /// `url`, refused unless it is over the scheme every issuer is reached
    /// over and names an address the deployment may reach.
    fn checked(&self, url: url::Url) -> Result<url::Url, DomainError> {
        if url.scheme() != self.scheme {
            return Err(DomainError::infra_msg("an issuer is read only over https"));
        }
        ensure_reachable(&url, &self.networks)?;
        Ok(url)
    }

    /// The body `url` answers with, at most `most` bytes.
    async fn read(&self, url: url::Url, most: usize) -> Result<Vec<u8>, DomainError> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(DomainError::infra)?
            .error_for_status()
            .map_err(DomainError::infra)?;
        body_within(response, most).await
    }

    /// The keys of `issuer` as `wanted` says, a failure logged for the
    /// operator with the issuer it was.
    async fn keys(
        &self,
        issuer: &WorkloadIssuer,
        wanted: Wanted,
    ) -> Result<Vec<Value>, DomainError> {
        self.cache
            .keys(issuer, wanted, || self.fetch(issuer))
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    issuer = %issuer.as_str(),
                    error = %causes(error),
                    "a workload token issuer's keys could not be read"
                );
            })
    }
}

#[async_trait]
impl IssuerKeys for DiscoveredIssuerKeys {
    async fn keys_of(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError> {
        self.keys(issuer, Wanted::Kept).await
    }

    async fn renewed_keys_of(&self, issuer: &WorkloadIssuer) -> Result<Vec<Value>, DomainError> {
        self.keys(issuer, Wanted::Renewed).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_domain::types::CidrRange;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The loopback networks the stand-in issuers listen on, as a
    /// self-hosted deployment would list its own.
    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    /// Keys kept ten minutes, asked again at most once a minute.
    pub(crate) fn keeping() -> KeyKeeping {
        KeyKeeping {
            keep_for: Duration::from_secs(600),
            renew_after: Duration::from_secs(60),
        }
    }

    /// Discovered keys reaching stand-in issuers over plain `http`, which
    /// a mock server speaks: an issuer named `https://localhost:<port>` is
    /// read at `http://localhost:<port>`, through the screened client with
    /// the loopback networks.
    pub(crate) fn over_plain_http(keeping: KeyKeeping) -> DiscoveredIssuerKeys {
        DiscoveredIssuerKeys {
            client: screened(Duration::from_secs(5), loopback()).unwrap(),
            networks: loopback(),
            scheme: "http",
            cache: KeyCache::new(keeping, 8),
        }
    }

    /// A stand-in issuer: a mock server, the `https` issuer naming it, and
    /// its address over `http`, as the mock answers.
    pub(crate) struct StandIn {
        pub(crate) server: MockServer,
        pub(crate) issuer: WorkloadIssuer,
        plain: String,
    }

    impl StandIn {
        /// A mock server named `localhost`, so calls go through the
        /// screening resolver, with nothing mounted yet.
        pub(crate) async fn start() -> Self {
            let server = MockServer::start().await;
            let plain = server.uri().replace("127.0.0.1", "localhost");
            let issuer = WorkloadIssuer::new(plain.replacen("http://", "https://", 1)).unwrap();
            Self {
                server,
                issuer,
                plain,
            }
        }

        /// The issuer's own address over `http`, as the mock answers it.
        fn plain(&self) -> &str {
            &self.plain
        }

        /// Publishes a discovery document naming `issuer` and the key set
        /// at `jwks_path`, and `keys` there, in the fields a Kubernetes
        /// cluster writes: the algorithms it lists are its keys' own.
        pub(crate) async fn publishing(&self, issuer: &str, jwks_path: &str, keys: Value) {
            let algorithms: std::collections::BTreeSet<&str> = keys["keys"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|key| key["alg"].as_str())
                .collect();
            let document = json!({
                "issuer": issuer,
                "jwks_uri": format!("{}{jwks_path}", self.plain()),
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": algorithms,
            });
            Mock::given(method("GET"))
                .and(path(DISCOVERY_PATH))
                .and(header("accept", "application/json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(document))
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path(jwks_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(keys))
                .mount(&self.server)
                .await;
        }
    }

    fn one_key() -> Value {
        json!({"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]})
    }

    /// An issuer's keys are read through its discovery document, then
    /// kept.
    #[tokio::test]
    async fn keys_are_read_through_the_discovery_document_and_kept() {
        let stand_in = StandIn::start().await;
        stand_in
            .publishing(stand_in.issuer.as_str(), "/openid/v1/jwks", one_key())
            .await;
        let keys = over_plain_http(keeping());

        let first = keys.keys_of(&stand_in.issuer).await.unwrap();
        let again = keys.keys_of(&stand_in.issuer).await.unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(first, again);
        assert_eq!(stand_in.server.received_requests().await.unwrap().len(), 2);
    }

    /// A discovery document naming another issuer fails with an infrastructure error.
    #[tokio::test]
    async fn a_document_naming_another_issuer_is_refused() {
        let stand_in = StandIn::start().await;
        stand_in
            .publishing("https://oidc.mallory.example", "/openid/v1/jwks", one_key())
            .await;

        let read = over_plain_http(keeping()).keys_of(&stand_in.issuer).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Private-address and FTP key-set URLs fail screening;
    /// only the discovery request reaches the stand-in server.
    #[tokio::test]
    async fn a_key_set_at_an_address_not_allowed_is_refused() {
        for jwks_uri in [
            "http://169.254.169.254/latest/meta-data/",
            "ftp://localhost/jwks",
        ] {
            let stand_in = StandIn::start().await;
            let document = json!({"issuer": stand_in.issuer.as_str(), "jwks_uri": jwks_uri});
            Mock::given(method("GET"))
                .and(path(DISCOVERY_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(document))
                .mount(&stand_in.server)
                .await;

            let read = over_plain_http(keeping()).keys_of(&stand_in.issuer).await;

            assert!(read.is_err(), "{jwks_uri}");
            assert_eq!(stand_in.server.received_requests().await.unwrap().len(), 1);
        }
    }

    /// An unreachable issuer returns an error instead of a key set.
    #[tokio::test]
    async fn an_issuer_that_cannot_be_reached_is_an_error() {
        let stand_in = StandIn::start().await;
        let issuer = stand_in.issuer.clone();
        drop(stand_in);

        let read = over_plain_http(keeping()).keys_of(&issuer).await;

        assert!(read.is_err());
    }

    /// A private issuer address fails public-network validation.
    #[tokio::test]
    async fn an_issuer_inside_the_deployment_is_not_called() {
        let keys = DiscoveredIssuerKeys::new(
            Duration::from_secs(5),
            UpstreamNetworks::public_only(),
            keeping(),
            8,
        )
        .unwrap();
        let metadata = WorkloadIssuer::new("https://169.254.169.254/issuer").unwrap();

        let read = keys.keys_of(&metadata).await;

        assert!(matches!(read, Err(DomainError::Validation(_))));
    }

    /// A discovery response exceeding the body limit returns an infrastructure error.
    #[tokio::test]
    async fn an_endless_document_is_refused() {
        let stand_in = StandIn::start().await;
        Mock::given(method("GET"))
            .and(path(DISCOVERY_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b' '; MOST_DOCUMENT_BYTES + 1]),
            )
            .mount(&stand_in.server)
            .await;

        let read = over_plain_http(keeping()).keys_of(&stand_in.issuer).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
