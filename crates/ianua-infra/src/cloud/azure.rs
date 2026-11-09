//! A customer's Azure subscription, reached over Azure Resource Manager
//! with the service principal they handed us.
//!
//! The principal's secret is exchanged at Microsoft's sign-in endpoint for
//! an access token, sent only as a bearer header. The account is the
//! first enabled subscription the principal sees. The places a database
//! can live are the subnets of the subscription's virtual networks in the
//! region.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::cloud::{CloudProviderFactory, CredentialVerifier, NetworkDiscovery};
use ianua_domain::domains::organization::cloud::account::CloudIdentity;
use ianua_domain::domains::organization::cloud::credential::CloudCredential;
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use crate::cloud::answers::{
    CALL, CREDENTIAL_REFUSED, GRANT_REFUSED, MOST_PAGES, another_cloud, bearer, found_identity,
    found_network, reply, too_many_pages, within,
};
use crate::cloud::endpoint::CloudEndpoint;
use crate::http::client::fixed;

/// Microsoft's sign-in host.
const SIGN_IN: &str = "https://login.microsoftonline.com";

/// Azure Resource Manager.
const MANAGEMENT: &str = "https://management.azure.com";

/// What the token may do: call Resource Manager.
const SCOPE: &str = "https://management.azure.com/.default";

/// The Resource Manager version subscriptions and locations are read in.
const SUBSCRIPTIONS_VERSION: &str = "2022-12-01";

/// The network provider version virtual networks are read in.
const NETWORKS_VERSION: &str = "2023-09-01";

/// What the customer is told when Microsoft refuses the principal.
const SECRET_REFUSAL: &str = "Azure refused the service principal. Check that the secret has \
                              not expired and that the application still exists in the \
                              directory.";

/// What the customer is told when the principal may not read what we asked.
const ROLE_REFUSAL: &str = "Azure refused the service principal. Check that it holds the role \
                            we asked for on the subscription.";

/// Every region the platform maps to an Azure location.
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

/// The Azure location a deployment region is served from.
fn region_code(region: DeploymentRegion) -> &'static str {
    match region {
        DeploymentRegion::UsEast1 => "eastus",
        DeploymentRegion::UsWest2 => "westus2",
        DeploymentRegion::CaCentral1 => "canadacentral",
        DeploymentRegion::EuWest1 => "northeurope",
        DeploymentRegion::EuWest2 => "uksouth",
        DeploymentRegion::EuWest3 => "francecentral",
        DeploymentRegion::EuCentral1 => "germanywestcentral",
        DeploymentRegion::EuCentral2 => "switzerlandnorth",
        DeploymentRegion::EuNorth1 => "swedencentral",
        DeploymentRegion::EuSouth1 => "italynorth",
        DeploymentRegion::SaEast1 => "brazilsouth",
        DeploymentRegion::ApSouth1 => "centralindia",
        DeploymentRegion::ApNortheast1 => "japaneast",
        DeploymentRegion::ApSoutheast1 => "southeastasia",
        DeploymentRegion::ApSoutheast2 => "australiaeast",
    }
}

/// The deployment region an Azure location serves, if any.
fn region_from_code(code: &str) -> Option<DeploymentRegion> {
    REGIONS
        .into_iter()
        .find(|region| region_code(*region) == code)
}

/// One page of a Resource Manager list, and where the next is when one
/// follows.
#[derive(Deserialize)]
struct Listed<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    subscription_id: String,
    #[serde(default)]
    state: String,
}

#[derive(Deserialize)]
struct Location {
    name: String,
}

#[derive(Deserialize)]
struct VirtualNetwork {
    name: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    properties: NetworkProperties,
}

#[derive(Deserialize, Default)]
struct NetworkProperties {
    #[serde(default)]
    subnets: Vec<Subnet>,
}

#[derive(Deserialize)]
struct Subnet {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    properties: SubnetProperties,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SubnetProperties {
    #[serde(default)]
    address_prefix: String,
}

/// A signed-in principal and the subscription it acts in.
struct Session {
    token: Secret,
    subscription: String,
}

/// The client every Azure adapter of one factory shares.
pub(crate) struct AzureApi {
    http: reqwest::Client,
    endpoint: CloudEndpoint,
}

impl AzureApi {
    /// The session `credential` opens: signed in, in its first enabled
    /// subscription.
    async fn session(&self, credential: &CloudCredential) -> Result<Session, DomainError> {
        let token = self.token(credential).await?;
        let listed: Vec<Subscription> = self
            .listed(&token, &["subscriptions"], SUBSCRIPTIONS_VERSION)
            .await?;
        let Some(subscription) = listed
            .into_iter()
            .find(|subscription| subscription.state.eq_ignore_ascii_case("enabled"))
        else {
            return Err(DomainError::forbidden(message!(
                "infra-this-service-principal-can-see-no",
                "this service principal can see no enabled Azure subscription; grant it a role \
                 on the subscription you want the database created in"
            )));
        };
        Ok(Session {
            token,
            subscription: subscription.subscription_id,
        })
    }

    /// The access token the principal of `credential` signs in with.
    async fn token(&self, credential: &CloudCredential) -> Result<Secret, DomainError> {
        let CloudCredential::AzureServicePrincipal {
            directory_id,
            client_id,
            secret,
        } = credential
        else {
            return Err(another_cloud("Azure"));
        };
        let url = self
            .endpoint
            .url(SIGN_IN, &[directory_id.as_str(), "oauth2", "v2.0", "token"])?;
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.expose()),
            ("scope", SCOPE),
        ];
        reply(self.http.post(url).form(&form))
            .await?
            .access_token(GRANT_REFUSED, SECRET_REFUSAL)
    }

    /// Every item of the Resource Manager list at `segments`, following
    /// its next pages. A next page is followed only on the address the
    /// first was read from, so the token is never sent anywhere else.
    async fn listed<T: serde::de::DeserializeOwned>(
        &self,
        token: &Secret,
        segments: &[&str],
        version: &str,
    ) -> Result<Vec<T>, DomainError> {
        let first = self
            .endpoint
            .url_with(MANAGEMENT, segments, &[("api-version", version)])?;
        let mut items = Vec::new();
        let mut at = first.clone();
        for _ in 0..MOST_PAGES {
            let page: Listed<T> = self.page(token, at).await?;
            items.extend(page.value);
            let Some(next) = page.next_link.filter(|link| !link.is_empty()) else {
                return Ok(items);
            };
            at = beside(&first, &next)?;
        }
        Err(too_many_pages("Azure"))
    }

    /// The JSON page at `url`.
    async fn page<T: serde::de::DeserializeOwned>(
        &self,
        token: &Secret,
        url: url::Url,
    ) -> Result<T, DomainError> {
        let request = self
            .http
            .get(url)
            .header(AUTHORIZATION, bearer(token.expose())?);
        reply(request).await?.json(CREDENTIAL_REFUSED, ROLE_REFUSAL)
    }

    /// The regions the session's subscription offers, each once.
    async fn regions(&self, session: &Session) -> Result<Vec<DeploymentRegion>, DomainError> {
        let segments = ["subscriptions", session.subscription.as_str(), "locations"];
        let listed: Vec<Location> = self
            .listed(&session.token, &segments, SUBSCRIPTIONS_VERSION)
            .await?;
        let mut regions: Vec<DeploymentRegion> = Vec::new();
        for region in listed
            .iter()
            .filter_map(|location| region_from_code(&location.name))
        {
            if !regions.contains(&region) {
                regions.push(region);
            }
        }
        Ok(regions)
    }

    /// The subnets of the session's virtual networks in `region`.
    async fn subnets(
        &self,
        session: &Session,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        let segments = [
            "subscriptions",
            session.subscription.as_str(),
            "providers",
            "Microsoft.Network",
            "virtualNetworks",
        ];
        let listed: Vec<VirtualNetwork> = self
            .listed(&session.token, &segments, NETWORKS_VERSION)
            .await?;
        let wanted = region_code(region);
        listed
            .into_iter()
            .filter(|network| network.location == wanted)
            .flat_map(|network| {
                let name = network.name;
                network
                    .properties
                    .subnets
                    .into_iter()
                    .map(move |subnet| (shown_name(&name, &subnet), subnet.id))
            })
            .map(|(shown, id)| found_network(&id, &shown, region))
            .collect()
    }
}

/// The next page `next` points at, refused unless it is on the same
/// address as `first`: Azure names it, and the token goes with it.
fn beside(first: &url::Url, next: &str) -> Result<url::Url, DomainError> {
    let next = url::Url::parse(next)
        .map_err(|_| DomainError::infra_msg("Azure named a next page that is no address"))?;
    if next.origin() != first.origin() {
        return Err(DomainError::infra_msg(
            "Azure named a next page away from Resource Manager",
        ));
    }
    Ok(next)
}

/// The name a customer sees for `subnet` of the network `network`.
fn shown_name(network: &str, subnet: &Subnet) -> String {
    match subnet.properties.address_prefix.trim() {
        "" => format!("{network} / {}", subnet.name),
        prefix => format!("{network} / {} ({prefix})", subnet.name),
    }
}

/// Proves an Azure service principal by signing it in.
struct AzureCredentialVerifier(Arc<AzureApi>);

#[async_trait]
impl CredentialVerifier for AzureCredentialVerifier {
    async fn verify(&self, credential: &CloudCredential) -> Result<CloudIdentity, DomainError> {
        let session = within(self.0.session(credential)).await?;
        found_identity(&session.subscription)
    }
}

/// Lists the subnets of an Azure subscription.
struct AzureNetworkDiscovery(Arc<AzureApi>);

#[async_trait]
impl NetworkDiscovery for AzureNetworkDiscovery {
    async fn regions(
        &self,
        credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError> {
        within(async {
            let session = self.0.session(credential).await?;
            self.0.regions(&session).await
        })
        .await
    }

    async fn networks(
        &self,
        credential: &CloudCredential,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        within(async {
            let session = self.0.session(credential).await?;
            self.0.subnets(&session, region).await
        })
        .await
    }
}

/// Azure's verifier and discovery, over one client.
pub struct AzureCloudProviderFactory {
    api: Arc<AzureApi>,
}

impl AzureCloudProviderFactory {
    /// A factory reaching Azure at `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(endpoint: CloudEndpoint) -> Result<Self, DomainError> {
        let api = AzureApi {
            http: fixed(CALL)?,
            endpoint,
        };
        Ok(Self { api: Arc::new(api) })
    }
}

impl CloudProviderFactory for AzureCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier> {
        Arc::new(AzureCredentialVerifier(Arc::clone(&self.api)))
    }

    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery> {
        Arc::new(AzureNetworkDiscovery(Arc::clone(&self.api)))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::credential::{CloudIdentifier, CloudSecret};
    use wiremock::matchers::{bearer_token, body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const SECRET: &str = "azure-client-secret-value";
    const ACCESS: &str = "eyJ.azure-access-token";

    fn credential() -> CloudCredential {
        CloudCredential::AzureServicePrincipal {
            directory_id: CloudIdentifier::new("dir-1").unwrap(),
            client_id: CloudIdentifier::new("client-1").unwrap(),
            secret: CloudSecret::new(SECRET).unwrap(),
        }
    }

    fn factory(server: &MockServer) -> AzureCloudProviderFactory {
        let base = url::Url::parse(&server.uri()).unwrap();
        AzureCloudProviderFactory::new(CloudEndpoint::At(base)).unwrap()
    }

    async fn signing_in(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/dir-1/oauth2/v2.0/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=client-1"))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn token() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token": ACCESS}))
    }

    async fn subscriptions(server: &MockServer, listed: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .and(query_param("api-version", SUBSCRIPTIONS_VERSION))
            .and(bearer_token(ACCESS))
            .respond_with(ResponseTemplate::new(200).set_body_json(listed))
            .mount(server)
            .await;
    }

    fn one_subscription() -> serde_json::Value {
        serde_json::json!({"value": [
            {"subscriptionId": "sub-disabled", "state": "Disabled"},
            {"subscriptionId": "sub-1", "state": "Enabled"}
        ]})
    }

    /// A working principal answers with its first enabled subscription,
    /// its secret sent in the form body, never in the URL.
    #[tokio::test]
    async fn a_working_principal_answers_its_subscription() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        subscriptions(&server, one_subscription()).await;

        let identity = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap();

        assert_eq!(identity.as_str(), "sub-1");
        let sent = server.received_requests().await.unwrap();
        assert!(
            sent.iter()
                .all(|request| !request.url.as_str().contains(SECRET))
        );
    }

    /// An expired secret is refused at sign-in, which is the customer's to
    /// fix, and the error holds no secret.
    #[tokio::test]
    async fn an_expired_secret_is_forbidden() {
        let server = MockServer::start().await;
        let invalid = serde_json::json!({"error": "invalid_client", "error_codes": [7000222]});
        signing_in(&server, ResponseTemplate::new(401).set_body_json(invalid)).await;

        let error = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();

        assert!(matches!(error, DomainError::Forbidden(_)));
        assert!(!format!("{error:?} {error}").contains(SECRET));
    }

    /// Resource Manager's credential rejection is forbidden and a truncated token response
    /// is an infrastructure failure; neither error exposes the access token.
    #[tokio::test]
    async fn a_refused_token_names_no_token_in_its_error() {
        let refused = MockServer::start().await;
        signing_in(&refused, token()).await;
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&refused)
            .await;
        let unreadable = MockServer::start().await;
        let cut = format!("{{\"access_token\": \"{ACCESS}\"");
        signing_in(&unreadable, ResponseTemplate::new(200).set_body_string(cut)).await;

        let forbidden = factory(&refused)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();
        let broken = factory(&unreadable)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();

        assert!(matches!(forbidden, DomainError::Forbidden(_)));
        assert!(matches!(broken, DomainError::Infrastructure(_)));
        for error in [forbidden, broken] {
            assert!(!format!("{error:?} {error}").contains(ACCESS));
        }
    }

    /// A principal with no visible enabled subscription fails verification as forbidden.
    #[tokio::test]
    async fn a_principal_without_a_subscription_is_refused() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        subscriptions(&server, serde_json::json!({"value": []})).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An Azure HTTP 500 is reported as an infrastructure failure.
    #[tokio::test]
    async fn a_failing_cloud_is_our_failure() {
        let server = MockServer::start().await;
        signing_in(&server, ResponseTemplate::new(500)).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The networks offered are the subnets of the virtual networks in the
    /// region, named with their network and range.
    #[tokio::test]
    async fn networks_are_the_subnets_in_the_region() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        subscriptions(&server, one_subscription()).await;
        Mock::given(method("GET"))
            .and(path(
                "/subscriptions/sub-1/providers/Microsoft.Network/virtualNetworks",
            ))
            .and(query_param("api-version", NETWORKS_VERSION))
            .and(bearer_token(ACCESS))
            .respond_with(ResponseTemplate::new(200).set_body_json(regional_networks()))
            .mount(&server)
            .await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        assert_eq!(networks.len(), 1);
        assert_eq!(
            networks[0].handle().as_str(),
            "/subscriptions/sub-1/x/prod/subnets/db"
        );
        assert_eq!(
            networks[0].display_name().as_str(),
            "prod / db (10.0.1.0/24)"
        );
    }

    /// Lists one Frankfurt subnet with its range and one subnet in a different region.
    fn regional_networks() -> serde_json::Value {
        serde_json::json!({"value": [
            {"name": "prod", "location": "germanywestcentral", "properties": {"subnets": [
                {"id": "/subscriptions/sub-1/x/prod/subnets/db", "name": "db",
                 "properties": {"addressPrefix": "10.0.1.0/24"}}
            ]}},
            {"name": "us", "location": "eastus", "properties": {"subnets": [
                {"id": "/subscriptions/sub-1/x/us/subnets/db", "name": "db"}
            ]}}
        ]})
    }

    /// A virtual network in Frankfurt with one subnet `subnet`.
    fn frankfurt_network(name: &str) -> serde_json::Value {
        serde_json::json!({"name": name, "location": "germanywestcentral", "properties": {
            "subnets": [{"id": format!("/subscriptions/sub-1/x/{name}/subnets/db"), "name": "db"}]
        }})
    }

    /// A same-origin next-page link is followed, returning both `prod` and `dev` networks.
    #[tokio::test]
    async fn a_network_on_a_later_page_is_offered() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        subscriptions(&server, one_subscription()).await;
        let at = "/subscriptions/sub-1/providers/Microsoft.Network/virtualNetworks";
        Mock::given(method("GET"))
            .and(path(at))
            .and(query_param("page", "2"))
            .and(bearer_token(ACCESS))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [frankfurt_network("dev")]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [frankfurt_network("prod")],
                "nextLink": format!("{}{at}?api-version={NETWORKS_VERSION}&page=2", server.uri())
            })))
            .mount(&server)
            .await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        assert_eq!(networks.len(), 2);
    }

    /// A next-page URL on another host causes an infrastructure error;
    /// the other host receives no request or access token.
    #[tokio::test]
    async fn a_next_page_on_another_host_is_refused() {
        let server = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        signing_in(&server, token()).await;
        subscriptions(&server, one_subscription()).await;
        Mock::given(method("GET"))
            .and(path(
                "/subscriptions/sub-1/providers/Microsoft.Network/virtualNetworks",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [frankfurt_network("prod")],
                "nextLink": format!("{}/steal", elsewhere.uri())
            })))
            .mount(&server)
            .await;

        let result = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert!(elsewhere.received_requests().await.unwrap().is_empty());
    }

    /// The regions offered are the subscription's locations the platform
    /// serves, each once.
    #[tokio::test]
    async fn regions_are_the_served_locations() {
        let server = MockServer::start().await;
        signing_in(&server, token()).await;
        subscriptions(&server, one_subscription()).await;
        Mock::given(method("GET"))
            .and(path("/subscriptions/sub-1/locations"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": [
                    {"name": "eastus"}, {"name": "westcentralus"}, {"name": "eastus"}
                ]})),
            )
            .mount(&server)
            .await;

        let regions = factory(&server)
            .network_discovery()
            .regions(&credential())
            .await
            .unwrap();

        assert_eq!(regions, vec![DeploymentRegion::UsEast1]);
    }
}
