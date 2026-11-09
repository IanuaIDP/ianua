//! A customer's own Kubernetes cluster, reached at the API server they
//! named, with the service account token they handed us.
//!
//! The API server is an address the customer chose, so it is called only
//! through the screened client, with their CA as the one root it trusts:
//! a name resolving inside the deployment is never reached, and no other
//! certificate authority can stand in for the cluster. The token goes only
//! in a bearer header.
//!
//! The grant is proved by the cluster reviewing its own token, and the
//! cluster must run the CloudNativePG operator, or a database could never
//! be made in it. Its places are its namespaces. A cluster has no region
//! we can read, so every region is offered.

use std::sync::Arc;

use async_trait::async_trait;
use der::Encode as _;
use ianua_app::ports::cloud::{CloudProviderFactory, CredentialVerifier, NetworkDiscovery};
use ianua_domain::domains::organization::cloud::account::CloudIdentity;
use ianua_domain::domains::organization::cloud::credential::{CloudCredential, CloudSecret};
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use crate::cloud::answers::{
    CALL, CREDENTIAL_REFUSED, MOST, MOST_PAGES, Reply, another_cloud, bearer, found_identity,
    found_network, too_many_pages, within,
};
use crate::crypto::certificates::pem::certificate_in;
use crate::http::client::{body_within, ensure_reachable, refused_by_screen, screened_trusting};

/// The CloudNativePG resource a database is made as.
const OPERATOR: &str = "clusters.postgresql.cnpg.io";

/// What the customer is told when the cluster refuses the token.
const REFUSAL: &str = "the cluster rejected this token: check it belongs to the service \
                       account you created and that its role still allows what we asked for";

/// What the customer is told when the API server cannot be reached.
const UNREACHABLE: &str = "this API server could not be reached over TLS with the CA \
                           certificate given: check the address is reachable from the \
                           internet and that the CA matches the server";

/// Every region, since a cluster's own cannot be read.
const REGIONS: [DeploymentRegion; 15] = [
    DeploymentRegion::UsEast1,
    DeploymentRegion::UsWest2,
    DeploymentRegion::CaCentral1,
    DeploymentRegion::EuWest1,
    DeploymentRegion::EuWest2,
    DeploymentRegion::EuWest3,
    DeploymentRegion::EuCentral1,
    DeploymentRegion::EuCentral2,
    DeploymentRegion::EuNorth1,
    DeploymentRegion::EuSouth1,
    DeploymentRegion::SaEast1,
    DeploymentRegion::ApSouth1,
    DeploymentRegion::ApNortheast1,
    DeploymentRegion::ApSoutheast1,
    DeploymentRegion::ApSoutheast2,
];

/// `GET /api/v1/namespaces`.
#[derive(Deserialize)]
struct Namespaces {
    #[serde(default)]
    items: Vec<Namespace>,
    #[serde(default)]
    metadata: ListMetadata,
}

/// Where a list goes on, when it does.
#[derive(Deserialize, Default)]
struct ListMetadata {
    #[serde(default, rename = "continue")]
    next: Option<String>,
}

#[derive(Deserialize)]
struct Namespace {
    metadata: Metadata,
}

#[derive(Deserialize)]
struct Metadata {
    name: String,
}

/// The clusters of every factory's adapters, reached only within the
/// deployment's upstream networks.
pub(crate) struct Clusters {
    networks: UpstreamNetworks,
}

impl Clusters {
    /// The cluster `credential` names, with a client trusting its CA alone.
    fn open<'a>(&self, credential: &'a CloudCredential) -> Result<Cluster<'a>, DomainError> {
        let CloudCredential::KubernetesServiceAccount {
            server,
            ca_certificate,
            token,
        } = credential
        else {
            return Err(another_cloud("Kubernetes"));
        };
        let base = url::Url::parse(server.as_str()).map_err(DomainError::infra)?;
        ensure_reachable(&base, &self.networks)?;
        let unreadable = || {
            DomainError::invalid(message!(
                "infra-the-cluster-s-ca-certificate-could",
                "the cluster's CA certificate could not be read"
            ))
        };
        let read = certificate_in(ca_certificate.as_str()).map_err(|_| unreadable())?;
        let der = read.to_der().map_err(|_| unreadable())?;
        let root = reqwest::Certificate::from_der(&der).map_err(|_| unreadable())?;
        let http = screened_trusting(CALL, self.networks.clone(), root)?;
        Ok(Cluster { http, base, token })
    }
}

/// One cluster: the client that reaches it, its API server and the token.
struct Cluster<'a> {
    http: reqwest::Client,
    base: url::Url,
    token: &'a CloudSecret,
}

impl Cluster<'_> {
    /// The URL of `segments` under the API server.
    fn url(&self, segments: &[&str]) -> Result<url::Url, DomainError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| DomainError::infra_msg("the API server's address takes no path"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// What the cluster answered to `request`, sent with the token.
    async fn reply(&self, request: reqwest::RequestBuilder) -> Result<Reply, DomainError> {
        let response = request
            .header(AUTHORIZATION, bearer(self.token.expose())?)
            .send()
            .await
            .map_err(|error| unreached(&error))?;
        let status = response.status().as_u16();
        let body = body_within(response, MOST).await?;
        Ok(Reply { status, body })
    }

    /// Proves the token by having the cluster review it.
    async fn verify_token(&self) -> Result<(), DomainError> {
        let url = self.url(&["apis", "authentication.k8s.io", "v1", "selfsubjectreviews"])?;
        let review = serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "SelfSubjectReview",
        });
        self.reply(self.http.post(url).json(&review))
            .await?
            .checked(CREDENTIAL_REFUSED, REFUSAL)
            .map(|_| ())
    }

    /// Refuses a cluster without the CloudNativePG operator.
    async fn ensure_operator(&self) -> Result<(), DomainError> {
        let url = self.url(&[
            "apis",
            "apiextensions.k8s.io",
            "v1",
            "customresourcedefinitions",
            OPERATOR,
        ])?;
        let reply = self.reply(self.http.get(url)).await?;
        if reply.status == 404 {
            return Err(DomainError::invalid(message!(
                "infra-this-cluster-is-reachable-but-has",
                "this cluster is reachable but has no CloudNativePG operator: install it \
                 first, or the grant would be accepted and no database could ever be made \
                 with it"
            )));
        }
        reply.checked(CREDENTIAL_REFUSED, REFUSAL).map(|_| ())
    }

    /// The cluster's namespaces, offered in `region`, page by page.
    async fn namespaces(&self, region: DeploymentRegion) -> Result<Vec<CloudNetwork>, DomainError> {
        let mut networks = Vec::new();
        let mut next: Option<String> = None;
        for _ in 0..MOST_PAGES {
            let listed = self.namespaces_on(next.as_deref()).await?;
            for item in &listed.items {
                networks.push(found_network(
                    &item.metadata.name,
                    &item.metadata.name,
                    region,
                )?);
            }
            next = listed.metadata.next.filter(|token| !token.is_empty());
            if next.is_none() {
                return Ok(networks);
            }
        }
        Err(too_many_pages("The cluster"))
    }

    /// One page of the namespaces, after `token` when a page came before.
    async fn namespaces_on(&self, token: Option<&str>) -> Result<Namespaces, DomainError> {
        let mut url = self.url(&["api", "v1", "namespaces"])?;
        url.query_pairs_mut().append_pair("limit", "500");
        if let Some(token) = token {
            url.query_pairs_mut().append_pair("continue", token);
        }
        self.reply(self.http.get(url))
            .await?
            .json(CREDENTIAL_REFUSED, REFUSAL)
    }
}

/// The error of a request the cluster never answered, without its URL.
///
/// The address is the customer's, so a server that cannot be reached or
/// whose certificate does not match their CA is theirs to fix; only a
/// timeout is reported as our failure.
fn unreached(error: &reqwest::Error) -> DomainError {
    if refused_by_screen(error) {
        return DomainError::invalid(message!(
            "infra-the-api-server-resolves-to-an",
            "the API server resolves to an address this deployment may not reach"
        ));
    }
    if error.is_timeout() {
        return DomainError::infra_msg("the API server did not answer in time");
    }
    DomainError::invalid(message!("infra-this-api-server-could-not-be", UNREACHABLE))
}

/// Proves a Kubernetes grant against the cluster it names.
struct KubernetesCredentialVerifier(Arc<Clusters>);

#[async_trait]
impl CredentialVerifier for KubernetesCredentialVerifier {
    async fn verify(&self, credential: &CloudCredential) -> Result<CloudIdentity, DomainError> {
        let cluster = self.0.open(credential)?;
        within(async {
            cluster.verify_token().await?;
            cluster.ensure_operator().await
        })
        .await?;
        found_identity(cluster.base.as_str())
    }
}

/// Lists the namespaces of a Kubernetes cluster.
struct KubernetesNetworkDiscovery(Arc<Clusters>);

#[async_trait]
impl NetworkDiscovery for KubernetesNetworkDiscovery {
    async fn regions(
        &self,
        credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError> {
        let cluster = self.0.open(credential)?;
        within(cluster.verify_token()).await?;
        Ok(REGIONS.to_vec())
    }

    async fn networks(
        &self,
        credential: &CloudCredential,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        let cluster = self.0.open(credential)?;
        within(cluster.namespaces(region)).await
    }
}

/// Kubernetes' verifier and discovery, reaching clusters only within the
/// deployment's upstream networks.
pub struct KubernetesCloudProviderFactory {
    clusters: Arc<Clusters>,
}

impl KubernetesCloudProviderFactory {
    /// A factory reaching clusters at public addresses, and inside
    /// `networks` too.
    #[must_use]
    pub fn new(networks: UpstreamNetworks) -> Self {
        Self {
            clusters: Arc::new(Clusters { networks }),
        }
    }
}

impl CloudProviderFactory for KubernetesCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Kubernetes
    }

    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier> {
        Arc::new(KubernetesCredentialVerifier(Arc::clone(&self.clusters)))
    }

    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery> {
        Arc::new(KubernetesNetworkDiscovery(Arc::clone(&self.clusters)))
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{bearer_token, body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::client::fixed;

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.service-account.token";

    fn token() -> CloudSecret {
        CloudSecret::new(TOKEN).unwrap()
    }

    /// A cluster at the stand-in. The screened client with the customer's
    /// CA needs a TLS server to reach, so these tests reach the plain
    /// stand-in through the fixed client and check what is asked of it.
    fn cluster<'a>(server: &MockServer, token: &'a CloudSecret) -> Cluster<'a> {
        Cluster {
            http: fixed(CALL).unwrap(),
            base: url::Url::parse(&server.uri()).unwrap(),
            token,
        }
    }

    async fn reviewing(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/apis/authentication.k8s.io/v1/selfsubjectreviews"))
            .and(bearer_token(TOKEN))
            .and(body_partial_json(
                serde_json::json!({"kind": "SelfSubjectReview"}),
            ))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn operator(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{OPERATOR}"
            )))
            .and(bearer_token(TOKEN))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// A token the cluster accepts, on a cluster with the operator, is
    /// proved.
    #[tokio::test]
    async fn a_working_token_on_a_ready_cluster_is_proved() {
        let server = MockServer::start().await;
        reviewing(&server, ResponseTemplate::new(201)).await;
        operator(&server, ResponseTemplate::new(200)).await;
        let token = token();
        let cluster = cluster(&server, &token);

        let proved = async {
            cluster.verify_token().await?;
            cluster.ensure_operator().await
        }
        .await;

        assert!(proved.is_ok());
    }

    /// A token the cluster refuses is the customer's to fix, and the error
    /// holds no token.
    #[tokio::test]
    async fn a_refused_token_is_forbidden() {
        let server = MockServer::start().await;
        reviewing(&server, ResponseTemplate::new(401)).await;
        let token = token();

        let error = cluster(&server, &token).verify_token().await.unwrap_err();

        assert!(matches!(error, DomainError::Forbidden(_)));
        assert!(!format!("{error:?} {error}").contains(TOKEN));
    }

    /// A missing database operator makes cluster verification fail with a validation error.
    #[tokio::test]
    async fn a_cluster_without_the_operator_is_refused() {
        let server = MockServer::start().await;
        operator(&server, ResponseTemplate::new(404)).await;
        let token = token();

        let result = cluster(&server, &token).ensure_operator().await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The networks offered are the cluster's namespaces.
    #[tokio::test]
    async fn networks_are_the_namespaces() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces"))
            .and(query_param("limit", "500"))
            .and(bearer_token(TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"metadata": {"name": "databases"}}, {"metadata": {"name": "apps"}}]
            })))
            .mount(&server)
            .await;
        let token = token();

        let networks = cluster(&server, &token)
            .namespaces(DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        let names: Vec<&str> = networks.iter().map(|n| n.handle().as_str()).collect();
        assert_eq!(names, vec!["databases", "apps"]);
    }

    /// Namespace pagination includes both the first page's `databases` and the next page's `apps`.
    #[tokio::test]
    async fn a_namespace_on_a_later_page_is_offered() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces"))
            .and(query_param("continue", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"metadata": {"name": "apps"}}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"metadata": {"name": "databases"}}],
                "metadata": {"continue": "page-2"}
            })))
            .mount(&server)
            .await;
        let token = token();

        let networks = cluster(&server, &token)
            .namespaces(DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        let names: Vec<&str> = networks.iter().map(|n| n.handle().as_str()).collect();
        assert_eq!(names, vec!["databases", "apps"]);
    }

    /// A Kubernetes HTTP 500 is reported as an infrastructure error.
    #[tokio::test]
    async fn a_failing_cluster_is_our_failure() {
        let server = MockServer::start().await;
        reviewing(&server, ResponseTemplate::new(500)).await;
        let token = token();

        let result = cluster(&server, &token).verify_token().await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The Kubernetes factory rejects a DigitalOcean credential as invalid input.
    #[tokio::test]
    async fn another_clouds_credential_is_refused() {
        let factory = KubernetesCloudProviderFactory::new(UpstreamNetworks::public_only());
        let token = CloudCredential::DigitalOceanToken { token: token() };

        let result = factory.credential_verifier().verify(&token).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
