//! A customer's Google Cloud project, reached over Google's APIs with the
//! service account key they handed us.
//!
//! The key signs an assertion that is exchanged at Google's own token
//! endpoint for an access token, which is sent only as a bearer header.
//! The account is proved by reading its project. The places a database
//! can live are the VPC networks that have a subnetwork in the region,
//! since Cloud SQL joins a network by its private range there.

mod assertion;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::cloud::{CloudProviderFactory, CredentialVerifier, NetworkDiscovery};
use ianua_domain::domains::organization::cloud::account::CloudIdentity;
use ianua_domain::domains::organization::cloud::credential::{
    CloudCredential, CloudIdentifier, GcpServiceAccountKey,
};
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use crate::cloud::answers::{
    CALL, CREDENTIAL_REFUSED, GRANT_REFUSED, MOST_PAGES, another_cloud, bearer, found_identity,
    found_network, reply, too_many_pages, within,
};
use crate::cloud::endpoint::CloudEndpoint;
use crate::cloud::gcp::assertion::assertion;
use crate::http::client::fixed;

/// Google's sign-in host, where [`GcpServiceAccountKey::TOKEN_URI`] lives.
const SIGN_IN: &str = "https://oauth2.googleapis.com";

/// Google's project API.
const PROJECTS: &str = "https://cloudresourcemanager.googleapis.com";

/// Google's compute API, where networks are listed.
const COMPUTE: &str = "https://compute.googleapis.com";

/// What the customer is told when Google refuses the key itself.
const KEY_REFUSAL: &str = "Google Cloud refused the service account key. Check that the key \
                           is still active and that the account has not been disabled.";

/// What the customer is told when the account may not read what we asked.
const ROLE_REFUSAL: &str = "Google Cloud refused the service account. Check that it holds the \
                            roles we asked for in its project.";

/// Every region the platform maps to a Google region.
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

/// The Google region a deployment region is served from.
fn region_code(region: DeploymentRegion) -> &'static str {
    match region {
        DeploymentRegion::UsEast1 => "us-east1",
        DeploymentRegion::UsWest2 => "us-west1",
        DeploymentRegion::CaCentral1 => "northamerica-northeast1",
        DeploymentRegion::EuWest1 => "europe-west1",
        DeploymentRegion::EuWest2 => "europe-west2",
        DeploymentRegion::EuWest3 => "europe-west9",
        DeploymentRegion::EuCentral1 => "europe-west3",
        DeploymentRegion::EuCentral2 => "europe-west6",
        DeploymentRegion::EuNorth1 => "europe-north1",
        DeploymentRegion::EuSouth1 => "europe-west8",
        DeploymentRegion::SaEast1 => "southamerica-east1",
        DeploymentRegion::ApSouth1 => "asia-south1",
        DeploymentRegion::ApNortheast1 => "asia-northeast1",
        DeploymentRegion::ApSoutheast1 => "asia-southeast1",
        DeploymentRegion::ApSoutheast2 => "australia-southeast1",
    }
}

/// `GET v1/projects/{id}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    #[serde(default)]
    lifecycle_state: String,
}

/// `GET .../regions/{r}/subnetworks`.
#[derive(Deserialize)]
struct Subnetworks {
    #[serde(default)]
    items: Vec<Subnetwork>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct Subnetwork {
    network: String,
}

/// A service account and the access token its key was exchanged for.
struct Session<'a> {
    key: &'a GcpServiceAccountKey,
    token: Secret,
}

/// One resource path under a Google API host.
#[derive(Clone, Copy)]
struct Resource<'a> {
    base: &'a str,
    segments: &'a [&'a str],
}

/// The client every Google adapter of one factory shares.
pub(crate) struct GcpApi {
    http: reqwest::Client,
    endpoint: CloudEndpoint,
}

impl GcpApi {
    /// The session `credential` opens: its key exchanged for a token.
    async fn session<'a>(
        &self,
        credential: &'a CloudCredential,
    ) -> Result<Session<'a>, DomainError> {
        let CloudCredential::GcpServiceAccount { client_email, key } = credential else {
            return Err(another_cloud("Google Cloud"));
        };
        let token = self.token(key, client_email).await?;
        Ok(Session { key, token })
    }

    /// The access token `key` of `client_email` is exchanged for.
    async fn token(
        &self,
        key: &GcpServiceAccountKey,
        client_email: &CloudIdentifier,
    ) -> Result<Secret, DomainError> {
        let signed = assertion(key, client_email, clock::now())?;
        let url = self.endpoint.url(SIGN_IN, &["token"])?;
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", signed.expose()),
        ];
        reply(self.http.post(url).form(&form))
            .await?
            .access_token(GRANT_REFUSED, KEY_REFUSAL)
    }

    /// The JSON answer from the resource, with the requested query parameters.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        session: &Session<'_>,
        resource: Resource<'_>,
        query: &[(&str, &str)],
    ) -> Result<T, DomainError> {
        let url = self
            .endpoint
            .url_with(resource.base, resource.segments, query)?;
        let request = self
            .http
            .get(url)
            .header(AUTHORIZATION, bearer(session.token.expose())?);
        reply(request).await?.json(CREDENTIAL_REFUSED, ROLE_REFUSAL)
    }

    /// The project the session's key belongs to, refused when it is not
    /// active.
    async fn project(&self, session: &Session<'_>) -> Result<CloudIdentity, DomainError> {
        let id = session.key.project_id().as_str();
        let project: Project = self
            .get(
                session,
                Resource {
                    base: PROJECTS,
                    segments: &["v1", "projects", id],
                },
                &[],
            )
            .await?;
        if project.lifecycle_state != "ACTIVE" {
            return Err(DomainError::forbidden(message!(
                "infra-the-service-account-s-project-is",
                "the service account's project is not active, so nothing can be created in it"
            )));
        }
        found_identity(id)
    }

    /// The networks with a subnetwork in `region`, each once.
    async fn networks(
        &self,
        session: &Session<'_>,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        let project = session.key.project_id().as_str();
        let segments = [
            "compute",
            "v1",
            "projects",
            project,
            "regions",
            region_code(region),
            "subnetworks",
        ];
        let mut seen: Vec<String> = Vec::new();
        let mut next: Option<String> = None;
        for _ in 0..MOST_PAGES {
            let listed = self
                .subnetworks_on(session, &segments, next.as_deref())
                .await?;
            for subnetwork in listed.items {
                if !seen.contains(&subnetwork.network) {
                    seen.push(subnetwork.network);
                }
            }
            next = listed.next_page_token.filter(|token| !token.is_empty());
            if next.is_none() {
                return networks_named(&seen, region);
            }
        }
        Err(too_many_pages("Google Cloud"))
    }

    /// One page of the subnetworks at `segments`, after `token` when a page
    /// came before.
    async fn subnetworks_on(
        &self,
        session: &Session<'_>,
        segments: &[&str],
        token: Option<&str>,
    ) -> Result<Subnetworks, DomainError> {
        let mut query = vec![("maxResults", "500")];
        if let Some(token) = token {
            query.push(("pageToken", token));
        }
        self.get(
            session,
            Resource {
                base: COMPUTE,
                segments,
            },
            &query,
        )
        .await
    }
}

/// Turns distinct network URLs into choices named by each URL's final path segment.
fn networks_named(
    networks: &[String],
    region: DeploymentRegion,
) -> Result<Vec<CloudNetwork>, DomainError> {
    networks
        .iter()
        .map(|network| {
            let name = network.rsplit('/').next().unwrap_or(network);
            found_network(network, name, region)
        })
        .collect()
}

/// Proves a Google service account key by reading its project.
struct GcpCredentialVerifier(Arc<GcpApi>);

#[async_trait]
impl CredentialVerifier for GcpCredentialVerifier {
    async fn verify(&self, credential: &CloudCredential) -> Result<CloudIdentity, DomainError> {
        within(async {
            let session = self.0.session(credential).await?;
            self.0.project(&session).await
        })
        .await
    }
}

/// Lists the networks of a Google Cloud project.
struct GcpNetworkDiscovery(Arc<GcpApi>);

#[async_trait]
impl NetworkDiscovery for GcpNetworkDiscovery {
    async fn regions(
        &self,
        credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError> {
        within(self.0.session(credential)).await?;
        Ok(REGIONS.to_vec())
    }

    async fn networks(
        &self,
        credential: &CloudCredential,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        within(async {
            let session = self.0.session(credential).await?;
            self.0.networks(&session, region).await
        })
        .await
    }
}

/// Google Cloud's verifier and discovery, over one client.
pub struct GcpCloudProviderFactory {
    api: Arc<GcpApi>,
}

impl GcpCloudProviderFactory {
    /// A factory reaching Google Cloud at `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(endpoint: CloudEndpoint) -> Result<Self, DomainError> {
        let api = GcpApi {
            http: fixed(CALL)?,
            endpoint,
        };
        Ok(Self { api: Arc::new(api) })
    }
}

impl CloudProviderFactory for GcpCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier> {
        Arc::new(GcpCredentialVerifier(Arc::clone(&self.api)))
    }

    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery> {
        Arc::new(GcpNetworkDiscovery(Arc::clone(&self.api)))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::credential::{
        CloudSecret, GcpKeyFacts, GcpKeyParts,
    };
    use wiremock::matchers::{bearer_token, body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::certificates::rsa_keys::tests::fresh_pkcs8_pem;

    const EMAIL: &str = "ianua@acme-prod.iam.gserviceaccount.com";
    const ACCESS: &str = "ya29.access-token-value";

    fn credential() -> CloudCredential {
        let pem = fresh_pkcs8_pem();
        let client_email = CloudIdentifier::new(EMAIL).unwrap();
        let parts = GcpKeyParts {
            project_id: CloudIdentifier::new("acme-prod").unwrap(),
            client_id: CloudIdentifier::new("1234567890").unwrap(),
            private_key_id: CloudIdentifier::new("key-1").unwrap(),
            private_key: CloudSecret::new(pem.as_str()).unwrap(),
        };
        let facts = GcpKeyFacts {
            key_type: "service_account",
            client_email: EMAIL,
            token_uri: GcpServiceAccountKey::TOKEN_URI,
            universe_domain: None,
        };
        let key = GcpServiceAccountKey::new(parts, &facts, &client_email).unwrap();
        CloudCredential::GcpServiceAccount { client_email, key }
    }

    fn factory(server: &MockServer) -> GcpCloudProviderFactory {
        let base = url::Url::parse(&server.uri()).unwrap();
        GcpCloudProviderFactory::new(CloudEndpoint::At(base)).unwrap()
    }

    async fn signing_in(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("jwt-bearer"))
            .and(body_string_contains("assertion="))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn token() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": ACCESS, "expires_in": 3599, "token_type": "Bearer"
        }))
    }

    async fn project(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path("/v1/projects/acme-prod"))
            .and(bearer_token(ACCESS))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// A working key is exchanged for a token, and the project it reads
    /// is the identity.
    #[tokio::test]
    async fn a_working_key_answers_its_project() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        let active = serde_json::json!({"projectId": "acme-prod", "lifecycleState": "ACTIVE"});
        project(&server, ResponseTemplate::new(200).set_body_json(active)).await;

        let identity = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap();

        assert_eq!(identity.as_str(), "acme-prod");
    }

    /// A revoked key is refused at the token endpoint with 400, which is
    /// the customer's to fix.
    #[tokio::test]
    async fn a_revoked_key_is_forbidden() {
        let server = MockServer::start().await;
        let invalid = serde_json::json!({"error": "invalid_grant"});
        signing_in(&server, ResponseTemplate::new(400).set_body_json(invalid)).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An account without the roles asked for is refused as forbidden,
    /// without the access token in the error.
    #[tokio::test]
    async fn an_account_without_its_roles_is_forbidden() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        project(&server, ResponseTemplate::new(403)).await;

        let error = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();

        assert!(matches!(error, DomainError::Forbidden(_)));
        assert!(!format!("{error:?} {error}").contains(ACCESS));
    }

    /// A truncated Google token response produces an infrastructure error without exposing the token.
    #[tokio::test]
    async fn an_unreadable_token_answer_names_no_token() {
        let server = MockServer::start().await;
        let cut = format!("{{\"access_token\": \"{ACCESS}\"");
        signing_in(&server, ResponseTemplate::new(200).set_body_string(cut)).await;

        let error = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();

        assert!(matches!(error, DomainError::Infrastructure(_)));
        assert!(!format!("{error:?} {error}").contains(ACCESS));
    }

    /// A Google HTTP 503 remains an infrastructure failure rather than a credential rejection.
    #[tokio::test]
    async fn a_failing_cloud_is_our_failure() {
        let server = MockServer::start().await;
        signing_in(&server, ResponseTemplate::new(503)).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The networks offered are those with a subnetwork in the region,
    /// each once, named by the network.
    #[tokio::test]
    async fn networks_are_those_with_a_subnetwork_in_the_region() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        let network =
            "https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/prod";
        Mock::given(method("GET"))
            .and(path(
                "/compute/v1/projects/acme-prod/regions/europe-west3/subnetworks",
            ))
            .and(query_param("maxResults", "500"))
            .and(bearer_token(ACCESS))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [
                    {"name": "a", "network": network},
                    {"name": "b", "network": network}
                ]
            })))
            .mount(&server)
            .await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].handle().as_str(), network);
        assert_eq!(networks[0].display_name().as_str(), "prod");
    }

    /// Subnetwork pagination returns `prod` from the first page and `dev` from the second.
    #[tokio::test]
    async fn a_network_on_a_later_page_is_offered() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        paginated_networks(&server).await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        let names: Vec<&str> = networks.iter().map(|n| n.display_name().as_str()).collect();
        assert_eq!(names, ["prod", "dev"]);
    }

    /// Serves prod first and dev only when the client follows the page token.
    async fn paginated_networks(server: &MockServer) {
        let at = "/compute/v1/projects/acme-prod/regions/europe-west3/subnetworks";
        let network = |name: &str| {
            format!(
                "https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/{name}"
            )
        };
        Mock::given(method("GET"))
            .and(path(at))
            .and(query_param("pageToken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"name": "b", "network": network("dev")}]
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{"name": "a", "network": network("prod")}],
                "nextPageToken": "page-2"
            })))
            .mount(server)
            .await;
    }

    /// A DigitalOcean credential fails Google validation without any HTTP request.
    #[tokio::test]
    async fn another_clouds_credential_is_refused() {
        let server = MockServer::start().await;
        let token = CloudCredential::DigitalOceanToken {
            token: CloudSecret::new("dop_v1_x").unwrap(),
        };

        let result = factory(&server).credential_verifier().verify(&token).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
