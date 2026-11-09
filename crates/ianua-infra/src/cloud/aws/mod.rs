//! A customer's AWS account, reached by assuming the role they made for us.
//!
//! The platform's own keys assume the role under the external id the
//! customer placed in its trust policy, for fifteen minutes; everything
//! else is asked as that session. The account is proved by asking whose
//! it is. The places a database can live are the account's RDS subnet
//! groups that RDS can actually use.
//!
//! The role is made by `ianua-connect.yaml` beside this module, the
//! CloudFormation template the platform publishes for customers to run.

mod account;
mod replies;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::cloud::{CloudProviderFactory, CredentialVerifier, NetworkDiscovery};
use ianua_domain::domains::organization::cloud::account::CloudIdentity;
use ianua_domain::domains::organization::cloud::credential::CloudCredential;
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::cloud::answers::{CALL, found_identity, found_network, within};
use crate::cloud::aws::account::{AwsAccounts, Purpose};
use crate::cloud::endpoint::CloudEndpoint;
use crate::http::client::fixed;

/// Every region the platform maps to an AWS region.
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

/// The platform's own AWS keys, which assume customers' roles.
///
/// The deployment's configuration hands them in; a role's trust policy
/// names the account they belong to.
pub struct AwsPlatformCredentials {
    /// The access key id, which is not secret.
    pub access_key_id: String,
    /// Signs requests that assume customer roles; excluded from debug output.
    pub secret_access_key: Secret,
    /// The session token, when the keys are themselves temporary.
    pub session_token: Option<Secret>,
}

impl std::fmt::Debug for AwsPlatformCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsPlatformCredentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// Proves an AWS role by assuming it and asking whose account it is.
struct AwsCredentialVerifier(Arc<AwsAccounts>);

#[async_trait]
impl CredentialVerifier for AwsCredentialVerifier {
    async fn verify(&self, credential: &CloudCredential) -> Result<CloudIdentity, DomainError> {
        let account = within(async {
            let session = self.0.session(credential, Purpose::Verify).await?;
            self.0.account_of(&session).await
        })
        .await?;
        found_identity(&account)
    }
}

/// Lists the regions and database subnet groups of an AWS account.
struct AwsNetworkDiscovery(Arc<AwsAccounts>);

#[async_trait]
impl NetworkDiscovery for AwsNetworkDiscovery {
    async fn regions(
        &self,
        credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError> {
        let codes = within(async {
            let session = self.0.session(credential, Purpose::Discover).await?;
            self.0.region_codes(&session).await
        })
        .await?;
        Ok(REGIONS
            .into_iter()
            .filter(|region| codes.iter().any(|code| code == region.code()))
            .collect())
    }

    async fn networks(
        &self,
        credential: &CloudCredential,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        let groups = within(async {
            let session = self.0.session(credential, Purpose::Discover).await?;
            self.0.subnet_groups(&session, region.code()).await
        })
        .await?;
        groups
            .iter()
            .filter(|group| group.holds_a_database())
            .map(|group| found_network(&group.name, &group.shown_name(), region))
            .collect()
    }
}

/// AWS's verifier and discovery, over one client holding the platform's
/// keys.
pub struct AwsCloudProviderFactory {
    accounts: Arc<AwsAccounts>,
}

impl AwsCloudProviderFactory {
    /// A factory assuming roles with `platform`'s keys, reaching AWS at
    /// `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(
        platform: AwsPlatformCredentials,
        endpoint: CloudEndpoint,
    ) -> Result<Self, DomainError> {
        let accounts = AwsAccounts {
            http: fixed(CALL)?,
            platform,
            endpoint,
        };
        Ok(Self {
            accounts: Arc::new(accounts),
        })
    }
}

impl CloudProviderFactory for AwsCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }

    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier> {
        Arc::new(AwsCredentialVerifier(Arc::clone(&self.accounts)))
    }

    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery> {
        Arc::new(AwsNetworkDiscovery(Arc::clone(&self.accounts)))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::credential::{ExternalId, RoleArn};
    use wiremock::matchers::{body_string_contains, header, header_regex, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const EXTERNAL_ID: &str = "abcdefghijklmnopqrstuvwxyz012345";
    const PLATFORM_SECRET: &str = "platform-secret-access-key";
    const SESSION_SECRET: &str = "session-secret-access-key";
    const SESSION_TOKEN: &str = "session-token-value";

    fn credential() -> CloudCredential {
        CloudCredential::AwsAssumeRole {
            role_arn: RoleArn::new("arn:aws:iam::123456789012:role/Ianua").unwrap(),
            external_id: ExternalId::new(EXTERNAL_ID).unwrap(),
        }
    }

    fn factory(server: &MockServer) -> AwsCloudProviderFactory {
        let platform = AwsPlatformCredentials {
            access_key_id: "AKIAPLATFORM".to_owned(),
            secret_access_key: Secret::new(PLATFORM_SECRET),
            session_token: None,
        };
        let base = url::Url::parse(&server.uri()).unwrap();
        AwsCloudProviderFactory::new(platform, CloudEndpoint::At(base)).unwrap()
    }

    fn assumed() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!(
            "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
             <AccessKeyId>ASIASESSION</AccessKeyId>\
             <SecretAccessKey>{SESSION_SECRET}</SecretAccessKey>\
             <SessionToken>{SESSION_TOKEN}</SessionToken>\
             </Credentials></AssumeRoleResult></AssumeRoleResponse>"
        ))
    }

    async fn assuming(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("Action=AssumeRole"))
            .and(body_string_contains("RoleSessionName=ianua-"))
            .and(body_string_contains(format!("ExternalId={EXTERNAL_ID}")))
            .and(header_regex(
                "authorization",
                "^AWS4-HMAC-SHA256 Credential=AKIAPLATFORM/[0-9]{8}/us-east-1/sts/aws4_request, \
                 SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$",
            ))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn as_session(server: &MockServer, action: &str, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains(format!("Action={action}")))
            .and(header("x-amz-security-token", SESSION_TOKEN))
            .and(header_regex(
                "authorization",
                "^AWS4-HMAC-SHA256 Credential=ASIASESSION/.*SignedHeaders=content-type;host;\
                 x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$",
            ))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn identity() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(
            "<GetCallerIdentityResponse><GetCallerIdentityResult>\
             <Account>123456789012</Account></GetCallerIdentityResult>\
             </GetCallerIdentityResponse>",
        )
    }

    /// A working role is assumed with the platform's signed keys and
    /// answers the account it opens, asked as the session it granted.
    #[tokio::test]
    async fn a_working_role_answers_its_account() {
        let server = MockServer::start().await;
        assuming(&server, assumed()).await;
        as_session(&server, "GetCallerIdentity", identity()).await;

        let account = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap();

        assert_eq!(account.as_str(), "123456789012");
    }

    /// AWS request URLs omit the external ID and action parameters;
    /// request headers contain neither the platform nor temporary signing secret.
    #[tokio::test]
    async fn no_secret_travels_in_a_url_or_header() {
        let server = MockServer::start().await;
        assuming(&server, assumed()).await;
        as_session(&server, "GetCallerIdentity", identity()).await;

        factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap();

        for request in server.received_requests().await.unwrap() {
            let url = request.url.as_str();
            assert!(!url.contains(EXTERNAL_ID) && !url.contains("Action="));
            let headers = format!("{:?}", request.headers);
            assert!(!headers.contains(PLATFORM_SECRET) && !headers.contains(SESSION_SECRET));
        }
    }

    /// A trust policy that does not name us is the customer's to fix, and
    /// the error holds neither the external id nor a key.
    #[tokio::test]
    async fn a_role_that_refuses_us_is_forbidden() {
        let server = MockServer::start().await;
        let denied = "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>";
        assuming(&server, ResponseTemplate::new(403).set_body_string(denied)).await;

        let error = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await
            .unwrap_err();

        assert!(matches!(error, DomainError::Forbidden(_)));
        let shown = format!("{error:?} {error}");
        assert!(!shown.contains(EXTERNAL_ID) && !shown.contains(PLATFORM_SECRET));
    }

    /// An AWS HTTP 500 returns an infrastructure error rather than rejecting the customer's role.
    #[tokio::test]
    async fn a_failing_cloud_is_our_failure() {
        let server = MockServer::start().await;
        assuming(&server, ResponseTemplate::new(500)).await;

        let result = factory(&server)
            .credential_verifier()
            .verify(&credential())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The regions offered are the account's enabled regions the platform
    /// serves.
    #[tokio::test]
    async fn regions_are_the_enabled_ones_the_platform_serves() {
        let server = MockServer::start().await;
        assuming(&server, assumed()).await;
        let regions = "<DescribeRegionsResponse><regionInfo>\
                       <item><regionName>eu-central-1</regionName></item>\
                       <item><regionName>me-central-1</regionName></item>\
                       <item><regionName>us-east-1</regionName></item>\
                       </regionInfo></DescribeRegionsResponse>";
        as_session(
            &server,
            "DescribeRegions",
            ResponseTemplate::new(200).set_body_string(regions),
        )
        .await;

        let found = factory(&server)
            .network_discovery()
            .regions(&credential())
            .await
            .unwrap();

        assert_eq!(
            found,
            vec![DeploymentRegion::UsEast1, DeploymentRegion::EuCentral1]
        );
    }

    /// Only subnet groups RDS can place a database in are offered, named
    /// by their description and VPC.
    #[tokio::test]
    async fn networks_are_the_usable_subnet_groups() {
        let server = MockServer::start().await;
        assuming(&server, assumed()).await;
        let groups = "<DescribeDBSubnetGroupsResponse><DescribeDBSubnetGroupsResult>\
            <DBSubnetGroups>\
            <DBSubnetGroup><DBSubnetGroupName>prod-db</DBSubnetGroupName>\
            <DBSubnetGroupDescription>Production</DBSubnetGroupDescription>\
            <VpcId>vpc-1</VpcId><SubnetGroupStatus>Complete</SubnetGroupStatus><Subnets>\
            <Subnet><SubnetAvailabilityZone><Name>eu-central-1a</Name></SubnetAvailabilityZone></Subnet>\
            <Subnet><SubnetAvailabilityZone><Name>eu-central-1b</Name></SubnetAvailabilityZone></Subnet>\
            </Subnets></DBSubnetGroup>\
            <DBSubnetGroup><DBSubnetGroupName>one-zone</DBSubnetGroupName>\
            <VpcId>vpc-2</VpcId><SubnetGroupStatus>Complete</SubnetGroupStatus><Subnets>\
            <Subnet><SubnetAvailabilityZone><Name>eu-central-1a</Name></SubnetAvailabilityZone></Subnet>\
            </Subnets></DBSubnetGroup>\
            </DBSubnetGroups></DescribeDBSubnetGroupsResult></DescribeDBSubnetGroupsResponse>";
        as_session(
            &server,
            "DescribeDBSubnetGroups",
            ResponseTemplate::new(200).set_body_string(groups),
        )
        .await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].handle().as_str(), "prod-db");
        assert_eq!(networks[0].display_name().as_str(), "Production (vpc-1)");
    }

    /// A usable subnet group named `name`, in two zones, as RDS lists it.
    fn usable_group(name: &str) -> String {
        format!(
            "<DBSubnetGroup><DBSubnetGroupName>{name}</DBSubnetGroupName>\
             <VpcId>vpc-1</VpcId><SubnetGroupStatus>Complete</SubnetGroupStatus><Subnets>\
             <Subnet><SubnetAvailabilityZone><Name>eu-central-1a</Name></SubnetAvailabilityZone></Subnet>\
             <Subnet><SubnetAvailabilityZone><Name>eu-central-1b</Name></SubnetAvailabilityZone></Subnet>\
             </Subnets></DBSubnetGroup>"
        )
    }

    /// Following the pagination marker includes both `prod-db` and the later `dev-db` subnet group.
    #[tokio::test]
    async fn a_subnet_group_on_a_later_page_is_offered() {
        let server = MockServer::start().await;
        assuming(&server, assumed()).await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("Marker=page-2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(subnet_page(&usable_group("dev-db"), "")),
            )
            .mount(&server)
            .await;
        as_session(
            &server,
            "DescribeDBSubnetGroups",
            ResponseTemplate::new(200).set_body_string(subnet_page(
                &usable_group("prod-db"),
                "<Marker>page-2</Marker>",
            )),
        )
        .await;

        let networks = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await
            .unwrap();

        let handles: Vec<&str> = networks.iter().map(|n| n.handle().as_str()).collect();
        assert_eq!(handles, ["prod-db", "dev-db"]);
    }

    /// Wraps subnet groups and an optional continuation marker in the RDS page envelope.
    fn subnet_page(groups: &str, marker: &str) -> String {
        format!(
            "<DescribeDBSubnetGroupsResponse><DescribeDBSubnetGroupsResult>\
             <DBSubnetGroups>{groups}</DBSubnetGroups>{marker}\
             </DescribeDBSubnetGroupsResult></DescribeDBSubnetGroupsResponse>"
        )
    }

    /// A role that may not list subnet groups is the customer's to fix.
    #[tokio::test]
    async fn a_role_without_its_permissions_is_forbidden() {
        let server = MockServer::start().await;
        assuming(&server, assumed()).await;
        let denied = "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>";
        as_session(
            &server,
            "DescribeDBSubnetGroups",
            ResponseTemplate::new(403).set_body_string(denied),
        )
        .await;

        let result = factory(&server)
            .network_discovery()
            .networks(&credential(), DeploymentRegion::EuCentral1)
            .await;

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
