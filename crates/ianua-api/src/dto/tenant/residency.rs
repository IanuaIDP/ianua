//! Where a tenant's data lives: chosen when it is provisioned, reported
//! back with the tenant.
//!
//! Clouds and regions are spelled here as they are in URLs (`aws`,
//! `eu-central-1`), so a body never spells them differently from the paths
//! beside it.

use ianua_domain::domains::tenant::compliance::DataResidency;
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudProvider, DeploymentRegion, IsolationLevel, NetworkHandle, NetworkPlacement, Placement,
    TenantResidency,
};
use ianua_domain::message;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Every region ianua serves.
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

/// Every cloud ianua drives.
const CLOUDS: [CloudProvider; 5] = [
    CloudProvider::Aws,
    CloudProvider::Gcp,
    CloudProvider::Azure,
    CloudProvider::DigitalOcean,
    CloudProvider::Kubernetes,
];

/// Where a tenant's data should live, as chosen over the wire.
///
/// The isolation level rides along with the placement because the two are
/// only valid in certain combinations, and the domain refuses the rest.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ResidencyBody {
    /// Our infrastructure, in a region you pick.
    Platform {
        /// Which of our regions, as `eu-central-1`. Omit for the deployment
        /// default.
        #[serde(default)]
        region: Option<String>,
        /// How far from other tenants. Omit for a shared database.
        #[serde(default)]
        #[schema(value_type = Option<String>)]
        isolation: Option<IsolationLevel>,
    },
    /// Your cloud account: we provision and administer, you own and pay.
    CustomerCloud {
        /// `aws`, `gcp`, `azure`, `digitalocean` or `kubernetes`, spelled as
        /// in the URLs.
        provider: String,
        /// As `eu-central-1`.
        region: String,
        /// How far from other tenants.
        #[schema(value_type = String)]
        isolation: IsolationLevel,
        /// Which of your networks to deploy into: a handle from the
        /// discovery endpoint, never typed by hand. Omit it to have us build
        /// a hardened network instead.
        #[serde(default)]
        network: Option<String>,
    },
    /// A database you already run. We create no infrastructure.
    CustomerDatabase {
        /// How far from other tenants.
        #[schema(value_type = String)]
        isolation: IsolationLevel,
    },
}

impl ResidencyBody {
    /// Where `body` says the tenant's data lives, or the platform's shared
    /// database in `default_region` when it says nothing.
    ///
    /// # Errors
    ///
    /// A validation error for a cloud, region or network that names
    /// nothing, or a placement and isolation level that contradict each
    /// other.
    pub(crate) fn residency(
        body: Option<Self>,
        default_region: DeploymentRegion,
    ) -> Result<TenantResidency, ApiError> {
        let Some(body) = body else {
            return Ok(TenantResidency::shared_on_platform(default_region));
        };
        let (placement, isolation) = body.placement(default_region)?;
        TenantResidency::new(placement, isolation).map_err(ApiError::validation)
    }

    /// Where this body places the tenant's data and how far from other
    /// tenants, filling in `default_region` and shared isolation where it
    /// is silent.
    fn placement(
        self,
        default_region: DeploymentRegion,
    ) -> Result<(Placement, IsolationLevel), ApiError> {
        match self {
            Self::Platform { region, isolation } => Ok((
                Placement::Platform {
                    region: region
                        .as_deref()
                        .map(parse_region)
                        .transpose()?
                        .unwrap_or(default_region),
                },
                isolation.unwrap_or(IsolationLevel::Shared),
            )),
            Self::CustomerCloud {
                provider,
                region,
                isolation,
                network,
            } => Ok((
                Placement::CustomerCloud {
                    provider: parse_provider(&provider)?,
                    region: parse_region(&region)?,
                    network: network_placement(network)?,
                },
                isolation,
            )),
            Self::CustomerDatabase { isolation } => Ok((Placement::CustomerDatabase, isolation)),
        }
    }
}

/// Where a tenant's data lives, as reported back.
///
/// A flat shape rather than a mirror of [`ResidencyBody`]: a caller reading
/// this wants to display it, so there is one field per thing worth showing
/// and nothing to match on.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ResidencyResponse {
    /// `platform`, `customer_cloud` or `customer_database`.
    pub kind: &'static str,
    /// How far this tenant's data is kept from other tenants'.
    #[schema(schema_with = crate::dto::schemas::isolation_level)]
    pub isolation: IsolationLevel,
    /// Which cloud, for a tenant in the customer's own account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<&'static str>,
    /// Where geographically, in its URL spelling. Absent for a database the
    /// customer supplied: they chose where it runs and never told us.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<&'static str>,
    /// The jurisdiction that region sits in, which is what a contract
    /// names.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = crate::dto::schemas::data_residency)]
    pub data_residency: Option<DataResidency>,
    /// The network handle, once one has been settled on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Whether we still have to build the network before provisioning.
    pub network_pending: bool,
}

impl From<&TenantResidency> for ResidencyResponse {
    fn from(residency: &TenantResidency) -> Self {
        let isolation = residency.isolation();
        match residency.placement() {
            Placement::Platform { region } => Self {
                region: Some(region.code()),
                data_residency: Some(region.data_residency()),
                ..Self::placement("platform", isolation)
            },
            Placement::CustomerCloud {
                provider,
                region,
                network,
            } => Self {
                kind: "customer_cloud",
                isolation,
                provider: Some(provider.as_str()),
                region: Some(region.code()),
                data_residency: Some(region.data_residency()),
                network: network.handle().map(|handle| handle.as_str().to_owned()),
                network_pending: network.needs_building(),
            },
            Placement::CustomerDatabase => Self::placement("customer_database", isolation),
        }
    }
}

impl ResidencyResponse {
    /// Names a placement before adding any cloud, region or managed-network details.
    fn placement(kind: &'static str, isolation: IsolationLevel) -> Self {
        Self {
            kind,
            isolation,
            provider: None,
            region: None,
            data_residency: None,
            network: None,
            network_pending: false,
        }
    }
}

/// The region `code` names, such as `eu-central-1`.
fn parse_region(code: &str) -> Result<DeploymentRegion, ApiError> {
    let code = code.to_ascii_lowercase();
    REGIONS
        .into_iter()
        .find(|region| region.code() == code)
        .ok_or_else(|| {
            ApiError::validation(message!(
                "api-unknown-region",
                format!("unknown region '{code}'")
            ))
        })
}

/// The cloud `name` names, such as `aws`. The refusal names the accepted
/// spellings, so a caller who wrote `amazon` learns the word we use.
fn parse_provider(name: &str) -> Result<CloudProvider, ApiError> {
    let name = name.to_ascii_lowercase();
    CLOUDS
        .into_iter()
        .find(|cloud| cloud.as_str() == name)
        .ok_or_else(|| {
            ApiError::validation(message!(
                "api-unknown-cloud-expected-aws-gcp-azure-2",
                format!(
                    "unknown cloud '{name}': expected aws, gcp, azure, digitalocean or kubernetes"
                )
            ))
        })
}

/// The customer's network named by `handle`, or one we build when none is
/// named.
fn network_placement(handle: Option<String>) -> Result<NetworkPlacement, ApiError> {
    let Some(handle) = handle else {
        return Ok(NetworkPlacement::Provision);
    };
    NetworkHandle::new(handle)
        .map(NetworkPlacement::Existing)
        .map_err(ApiError::validation)
}
