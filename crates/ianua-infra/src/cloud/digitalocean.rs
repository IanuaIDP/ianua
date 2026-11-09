//! A customer's DigitalOcean account, reached over its API with the
//! personal access token they handed us, sent only as a bearer header.
//!
//! The account is proved by reading it, which also says whether it may
//! still create anything. Its places are the VPCs of a region, in the
//! datacentres the platform maps its regions to; a region DigitalOcean
//! has no datacentre for is refused rather than quietly placed elsewhere.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::cloud::{CloudProviderFactory, CredentialVerifier, NetworkDiscovery};
use ianua_domain::domains::organization::cloud::account::CloudIdentity;
use ianua_domain::domains::organization::cloud::credential::{CloudCredential, CloudSecret};
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use crate::cloud::answers::{
    CALL, CREDENTIAL_REFUSED, MOST_PAGES, another_cloud, bearer, found_identity, found_network,
    reply, too_many_pages, within,
};
use crate::cloud::endpoint::CloudEndpoint;
use crate::http::client::fixed;

/// DigitalOcean's API.
const API: &str = "https://api.digitalocean.com";

/// How many VPCs one page holds, the most DigitalOcean gives.
const PER_PAGE: usize = 200;

/// What the customer is told when DigitalOcean refuses the token.
const REFUSAL: &str = "DigitalOcean refused the token. It may have been revoked or \
                       regenerated, or lack read access to the account.";

/// The regions DigitalOcean has a datacentre for.
const SERVED: [DeploymentRegion; 10] = [
    DeploymentRegion::UsEast1,
    DeploymentRegion::UsWest2,
    DeploymentRegion::CaCentral1,
    DeploymentRegion::EuWest2,
    DeploymentRegion::EuWest3,
    DeploymentRegion::EuNorth1,
    DeploymentRegion::EuCentral1,
    DeploymentRegion::ApSouth1,
    DeploymentRegion::ApSoutheast1,
    DeploymentRegion::ApSoutheast2,
];

/// The datacentre a region is served from.
///
/// # Errors
///
/// Returns `DomainError::Validation` for a region DigitalOcean has no
/// datacentre in.
fn region_slug(region: DeploymentRegion) -> Result<&'static str, DomainError> {
    match region {
        DeploymentRegion::UsEast1 => Ok("nyc3"),
        DeploymentRegion::UsWest2 => Ok("sfo3"),
        DeploymentRegion::CaCentral1 => Ok("tor1"),
        DeploymentRegion::EuWest2 => Ok("lon1"),
        DeploymentRegion::EuWest3 | DeploymentRegion::EuNorth1 => Ok("ams3"),
        DeploymentRegion::EuCentral1 => Ok("fra1"),
        DeploymentRegion::ApSouth1 => Ok("blr1"),
        DeploymentRegion::ApSoutheast1 => Ok("sgp1"),
        DeploymentRegion::ApSoutheast2 => Ok("syd1"),
        DeploymentRegion::EuWest1
        | DeploymentRegion::EuCentral2
        | DeploymentRegion::EuSouth1
        | DeploymentRegion::SaEast1
        | DeploymentRegion::ApNortheast1 => Err(DomainError::invalid(message!(
            "infra-digitalocean-has-no-datacentre-in-this",
            "DigitalOcean has no datacentre in this region; choose another region or \
             another cloud rather than have the data placed elsewhere"
        ))),
    }
}

/// `GET /v2/account`.
#[derive(Deserialize)]
struct AccountAnswer {
    account: Account,
}

#[derive(Deserialize)]
struct Account {
    uuid: String,
    #[serde(default)]
    status: String,
}

/// `GET /v2/vpcs`.
#[derive(Deserialize)]
struct VpcsAnswer {
    #[serde(default)]
    vpcs: Vec<Vpc>,
}

#[derive(Deserialize)]
struct Vpc {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    ip_range: String,
}

/// The client every DigitalOcean adapter of one factory shares.
pub(crate) struct DigitalOceanApi {
    http: reqwest::Client,
    endpoint: CloudEndpoint,
}

impl DigitalOceanApi {
    /// The JSON answer to `GET` of `segments` with `query`, sent with the
    /// customer's token.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        token: &CloudSecret,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<T, DomainError> {
        let url = self.endpoint.url_with(API, segments, query)?;
        let request = self
            .http
            .get(url)
            .header(AUTHORIZATION, bearer(token.expose())?);
        reply(request).await?.json(CREDENTIAL_REFUSED, REFUSAL)
    }

    /// Whose account `token` opens, refused when it may create nothing.
    async fn account(&self, token: &CloudSecret) -> Result<CloudIdentity, DomainError> {
        let answer: AccountAnswer = self.get(token, &["v2", "account"], &[]).await?;
        let status = answer.account.status;
        if !status.is_empty() && !status.eq_ignore_ascii_case("active") {
            return Err(DomainError::forbidden(message!(
                "infra-this-digitalocean-account-is-not-active",
                "this DigitalOcean account is not active, so nothing can be created in it"
            )));
        }
        found_identity(&answer.account.uuid)
    }

    /// The VPCs `token` sees in `region`'s datacentre, page by page.
    async fn vpcs(
        &self,
        token: &CloudSecret,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        let wanted = region_slug(region)?;
        let mut networks = Vec::new();
        for page in 1..=MOST_PAGES {
            let vpcs = self.vpcs_on(token, page).await?;
            let last = vpcs.len() < PER_PAGE;
            for vpc in vpcs.into_iter().filter(|vpc| vpc.region == wanted) {
                networks.push(found_network(&vpc.id, &shown_name(&vpc), region)?);
            }
            if last {
                return Ok(networks);
            }
        }
        Err(too_many_pages("DigitalOcean"))
    }

    /// The VPCs on page `page` of what `token` sees.
    async fn vpcs_on(&self, token: &CloudSecret, page: usize) -> Result<Vec<Vpc>, DomainError> {
        let page = page.to_string();
        let per_page = PER_PAGE.to_string();
        let query = [("page", page.as_str()), ("per_page", per_page.as_str())];
        let answer: VpcsAnswer = self.get(token, &["v2", "vpcs"], &query).await?;
        Ok(answer.vpcs)
    }
}

/// The name a customer sees for `vpc`: its own name, or its id, with its
/// address range.
fn shown_name(vpc: &Vpc) -> String {
    let name = match vpc.name.trim() {
        "" => vpc.id.as_str(),
        named => named,
    };
    match vpc.ip_range.trim() {
        "" => name.to_owned(),
        range => format!("{name} ({range})"),
    }
}

/// The token a DigitalOcean credential carries.
fn token_of(credential: &CloudCredential) -> Result<&CloudSecret, DomainError> {
    let CloudCredential::DigitalOceanToken { token } = credential else {
        return Err(another_cloud("DigitalOcean"));
    };
    Ok(token)
}

/// Proves a DigitalOcean token by reading its account.
struct DigitalOceanCredentialVerifier(Arc<DigitalOceanApi>);

#[async_trait]
impl CredentialVerifier for DigitalOceanCredentialVerifier {
    async fn verify(&self, credential: &CloudCredential) -> Result<CloudIdentity, DomainError> {
        let token = token_of(credential)?;
        within(self.0.account(token)).await
    }
}

/// Lists the VPCs of a DigitalOcean account.
struct DigitalOceanNetworkDiscovery(Arc<DigitalOceanApi>);

#[async_trait]
impl NetworkDiscovery for DigitalOceanNetworkDiscovery {
    async fn regions(
        &self,
        credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError> {
        let token = token_of(credential)?;
        within(self.0.account(token)).await?;
        Ok(SERVED.to_vec())
    }

    async fn networks(
        &self,
        credential: &CloudCredential,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        let token = token_of(credential)?;
        within(self.0.vpcs(token, region)).await
    }
}

/// DigitalOcean's verifier and discovery, over one client.
pub struct DigitalOceanCloudProviderFactory {
    api: Arc<DigitalOceanApi>,
}

impl DigitalOceanCloudProviderFactory {
    /// A factory reaching DigitalOcean at `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(endpoint: CloudEndpoint) -> Result<Self, DomainError> {
        let api = DigitalOceanApi {
            http: fixed(CALL)?,
            endpoint,
        };
        Ok(Self { api: Arc::new(api) })
    }
}

impl CloudProviderFactory for DigitalOceanCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::DigitalOcean
    }

    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier> {
        Arc::new(DigitalOceanCredentialVerifier(Arc::clone(&self.api)))
    }

    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery> {
        Arc::new(DigitalOceanNetworkDiscovery(Arc::clone(&self.api)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::organization::cloud::credential::{ExternalId, RoleArn};
    use wiremock::matchers::{bearer_token, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const TOKEN: &str = "dop_v1_supersecrettokenvalue";

    fn credential() -> CloudCredential {
        CloudCredential::DigitalOceanToken {
            token: CloudSecret::new(TOKEN).unwrap(),
        }
    }

    fn factory(server: &MockServer) -> DigitalOceanCloudProviderFactory {
        let base = url::Url::parse(&server.uri()).unwrap();
        DigitalOceanCloudProviderFactory::new(CloudEndpoint::At(base)).unwrap()
    }

    async fn answering(route: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(route))
            .and(bearer_token(TOKEN))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn account(status: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "account": {"uuid": "b6fr89dbf6d9156cace5f3c78dc9851d957381ef", "status": status}
        }))
    }

    /// A working token answers with the account it opens, sent as a bearer
    /// header and never in the URL.
    #[tokio::test]
    async fn a_working_token_answers_its_account() {
        let server = answering("/v2/account", account("active")).await;

        let identity = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap();

        assert_eq!(
            identity.as_str(),
            "b6fr89dbf6d9156cace5f3c78dc9851d957381ef"
        );
        let sent = server.received_requests().await.unwrap();
        assert!(
            sent.iter()
                .all(|request| !request.url.as_str().contains(TOKEN))
        );
    }

    /// A revoked token is the customer's to fix, and reads as forbidden
    /// without the token in it.
    #[tokio::test]
    async fn a_refused_token_is_forbidden() {
        let server = answering("/v2/account", ResponseTemplate::new(401)).await;

        let error = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();

        assert!(matches!(error, DomainError::Forbidden(_)));
        assert!(!format!("{error:?} {error}").contains(TOKEN));
    }

    /// A locked DigitalOcean account fails verification as forbidden.
    #[tokio::test]
    async fn a_locked_account_is_refused() {
        let server = answering("/v2/account", account("locked")).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A DigitalOcean HTTP 500 is an infrastructure error, not a rejected account token.
    #[tokio::test]
    async fn a_failing_cloud_is_our_failure() {
        let server = answering("/v2/account", ResponseTemplate::new(500)).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A cloud slower than a call may take is our failure.
    #[tokio::test]
    async fn a_cloud_that_does_not_answer_in_time_is_our_failure() {
        let server = answering(
            "/v2/account",
            account("active").set_delay(CALL.saturating_add(Duration::from_secs(2))),
        )
        .await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// `count` VPCs in New York, as one page holds them.
    fn new_york_vpcs(count: usize) -> serde_json::Value {
        let vpcs: Vec<serde_json::Value> = (0..count)
            .map(|n| serde_json::json!({"id": format!("vpc-{n}"), "region": "nyc3"}))
            .collect();
        serde_json::json!({ "vpcs": vpcs })
    }

    /// The Frankfurt VPC is found on the second page after a full page of New York VPCs.
    #[tokio::test]
    async fn a_vpc_on_a_later_page_is_offered() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/vpcs"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(new_york_vpcs(PER_PAGE)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/vpcs"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vpcs": [{"id": "vpc-fra", "name": "prod", "region": "fra1"}]
            })))
            .mount(&server)
            .await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].handle().as_str(), "vpc-fra");
    }

    /// Repeated full pages beyond the listing limit return an infrastructure error instead of partial results.
    #[tokio::test]
    async fn a_listing_past_the_most_pages_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/vpcs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(new_york_vpcs(PER_PAGE)))
            .mount(&server)
            .await;

        let result = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Only the VPCs in the region's datacentre are offered, named with
    /// their address range.
    #[tokio::test]
    async fn networks_are_the_vpcs_of_the_region() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/vpcs"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "200"))
            .and(bearer_token(TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vpcs": [
                    {"id": "vpc-fra", "name": "prod", "region": "fra1", "ip_range": "10.10.0.0/20"},
                    {"id": "vpc-nyc", "name": "us", "region": "nyc3", "ip_range": "10.20.0.0/20"}
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
        assert_eq!(networks[0].handle().as_str(), "vpc-fra");
        assert_eq!(networks[0].display_name().as_str(), "prod (10.10.0.0/20)");
    }

    /// A region without a DigitalOcean datacentre is rejected before any HTTP request.
    #[tokio::test]
    async fn a_region_without_a_datacentre_is_refused() {
        let server = MockServer::start().await;

        let result = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::SaEast1)
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The DigitalOcean adapter rejects AWS role credentials as invalid input.
    #[tokio::test]
    async fn another_clouds_credential_is_refused() {
        let server = MockServer::start().await;
        let aws = CloudCredential::AwsAssumeRole {
            role_arn: RoleArn::new("arn:aws:iam::123456789012:role/Ianua").unwrap(),
            external_id: ExternalId::new("abcdefghijklmnopqrstuvwxyz012345").unwrap(),
        };

        let result = factory(&server).credential_verifier().verify(&aws).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
