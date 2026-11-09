//! Where a tenant's resources are created: the cloud, the region, the isolation and the network.

use crate::domains::tenant::compliance::DataResidency;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{Fact, Label};

/// A cloud vendor whose account a tenant's infrastructure can be created in.
///
/// Each variant has an adapter that provisions Postgres there. A vendor with
/// no adapter does not belong here, because choosing it would be a promise we
/// cannot keep.
///
/// There is no "self-hosted" variant, because that is the lack of a
/// provider. A customer running their own database is
/// [`Placement::CustomerDatabase`], and a tenant on our hardware is
/// [`Placement::Platform`]. A `SelfHosted` value would allow a
/// `Placement::CustomerCloud` that names no cloud to build in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CloudProvider {
    /// Amazon Web Services, using RDS for PostgreSQL.
    Aws,
    /// Google Cloud Platform, using Cloud SQL for PostgreSQL.
    Gcp,
    /// Microsoft Azure, using Azure Database for PostgreSQL.
    Azure,
    /// DigitalOcean, using Managed Databases.
    DigitalOcean,

    /// The customer's own Kubernetes cluster, using the CloudNativePG
    /// operator.
    ///
    /// It sits beside the clouds because an organization connects one
    /// credential per provider, and this is one of them. It is not a cloud
    /// like the other four. Kubernetes usually runs on one of them.
    Kubernetes,
}

impl CloudProvider {
    /// A short, stable name for logs and the audit trail.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::DigitalOcean => "digitalocean",
            Self::Kubernetes => "kubernetes",
        }
    }
}

/// Geographic region for data residency and latency.
///
/// The adapters turn each one into the provider's own region code, for
/// example `UsEast1` into `us-east-1` on AWS or `eastus` on Azure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeploymentRegion {
    /// US East (Virginia).
    UsEast1,
    /// US West (Oregon).
    UsWest2,
    /// Canada Central (Montreal).
    CaCentral1,
    /// EU West (Ireland).
    EuWest1,
    /// EU West (London). This is the United Kingdom, not the EU.
    EuWest2,
    /// EU West (Paris).
    EuWest3,
    /// EU Central (Frankfurt).
    EuCentral1,
    /// EU Central (Zurich). This is Switzerland, not the EU.
    EuCentral2,
    /// EU North (Stockholm).
    EuNorth1,
    /// EU South (Milan).
    EuSouth1,
    /// South America (São Paulo).
    SaEast1,
    /// Asia Pacific (Mumbai).
    ApSouth1,
    /// Asia Pacific (Tokyo).
    ApNortheast1,
    /// Asia Pacific (Sydney).
    ApSoutheast2,
    /// Asia Pacific (Singapore).
    ApSoutheast1,
}

/// How the tenant's data is isolated from other tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IsolationLevel {
    /// A shared database, with rows kept apart by their `tenant_id` column.
    /// It costs least and suits most tenants.
    Shared,

    /// A schema of its own inside a shared database instance. Stronger
    /// isolation at a moderate cost.
    DedicatedSchema,

    /// A database instance of its own. Full isolation at a higher cost.
    DedicatedInstance,

    /// A cluster of its own, database and compute both. The strongest
    /// isolation, for regulated industries.
    DedicatedCluster,
}

impl DeploymentRegion {
    /// The region's code, as the API and AWS both write it, such as
    /// `eu-west-1`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::UsEast1 => "us-east-1",
            Self::UsWest2 => "us-west-2",
            Self::CaCentral1 => "ca-central-1",
            Self::EuWest1 => "eu-west-1",
            Self::EuWest2 => "eu-west-2",
            Self::EuWest3 => "eu-west-3",
            Self::EuCentral1 => "eu-central-1",
            Self::EuCentral2 => "eu-central-2",
            Self::EuNorth1 => "eu-north-1",
            Self::EuSouth1 => "eu-south-1",
            Self::SaEast1 => "sa-east-1",
            Self::ApSouth1 => "ap-south-1",
            Self::ApNortheast1 => "ap-northeast-1",
            Self::ApSoutheast1 => "ap-southeast-1",
            Self::ApSoutheast2 => "ap-southeast-2",
        }
    }

    /// The jurisdiction this region sits in.
    ///
    /// This links the promise in a tenant's
    /// [`CompliancePosture`](crate::domains::tenant::compliance::CompliancePosture)
    /// to the place its rows end up. It is worked out, not stored, so the two
    /// cannot disagree.
    #[must_use]
    pub fn data_residency(self) -> DataResidency {
        match self {
            Self::UsEast1 | Self::UsWest2 => DataResidency::Us,
            Self::CaCentral1 => DataResidency::Canada,
            Self::EuWest1 | Self::EuWest3 | Self::EuCentral1 | Self::EuNorth1 | Self::EuSouth1 => {
                DataResidency::Eu
            }
            Self::EuWest2 => DataResidency::Uk,
            Self::EuCentral2 => DataResidency::Switzerland,
            Self::SaEast1 => DataResidency::Brazil,
            Self::ApSouth1 => DataResidency::India,
            Self::ApNortheast1 => DataResidency::Japan,
            Self::ApSoutheast1 => DataResidency::Singapore,
            Self::ApSoutheast2 => DataResidency::Australia,
        }
    }
}

/// Whose hardware a tenant's data sits on.
///
/// [`IsolationLevel`] answers a different question: how far the data is
/// kept from other tenants. Only some pairs of answers make sense, and
/// [`TenantResidency`](crate::domains::tenant::provisioning::infrastructure::TenantResidency)
/// refuses the rest.
// Not `Copy`: `CustomerCloud` carries a `NetworkHandle`, which owns a
// String. A placement is decided once and read many times, so the accessors
// below hand out references rather than copies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Placement {
    /// Our infrastructure, in a region the customer picks. This is the
    /// common case, and the only one that needs nothing else from the
    /// customer.
    Platform {
        /// Where we run it for them.
        region: DeploymentRegion,
    },

    /// Their cloud account. We create and run the resources. They own them
    /// and pay for them.
    CustomerCloud {
        /// Which cloud their account is with.
        provider: CloudProvider,
        /// Region within their account.
        region: DeploymentRegion,
        /// Which network inside that account the database sits in.
        ///
        /// It is chosen per tenant, though the account is per organization,
        /// because production and staging may need different networks. With
        /// it here, the provisioner works from the placement alone. A
        /// deployment-wide setting would name a network in our own account.
        network: NetworkPlacement,
    },

    /// A database they already run and hand us a connection to. We create
    /// no infrastructure at all.
    CustomerDatabase,
}

text_value! {
    /// A place inside a customer's cloud account where a database can live.
    ///
    /// Only the cloud that issued it can read it. Examples are an AWS DB
    /// subnet group name, an Azure delegated subnet id or a DigitalOcean VPC
    /// uuid. The application layer stores it and hands it back, and never
    /// parses it. So one type works for every cloud.
    pub struct NetworkHandle;
}

impl TextValue for NetworkHandle {
    const FIELD: &'static str = "network";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=Self::MAX_LEN).no_control_chars()
    }
}

impl NetworkHandle {
    /// Longest handle any provider issues, with room to spare.
    const MAX_LEN: usize = 512;
}

/// Which network a tenant's database goes into.
///
/// The two answers are different requests, not one optional field. Naming a
/// network asks us to use one that exists. [`Self::Provision`] asks us to
/// build one. If "build one" were "no network chosen", a form left blank
/// would look like an order to create infrastructure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NetworkPlacement {
    /// Use a network the customer already has, chosen from discovery.
    Existing(NetworkHandle),

    /// Build a hardened network for them, and record its handle once it
    /// exists.
    ///
    /// Customers with an empty account choose this. We then control the
    /// layout: private subnets, no public path to the database, and a CIDR we
    /// picked so a tunnel cannot collide with it.
    Provision,
}

impl NetworkPlacement {
    /// The network to deploy into, or `None` when it still has to be built.
    #[must_use]
    pub fn handle(&self) -> Option<&NetworkHandle> {
        match self {
            Self::Existing(handle) => Some(handle),
            Self::Provision => None,
        }
    }

    /// Whether provisioning must create the network before the database.
    #[must_use]
    pub fn needs_building(&self) -> bool {
        matches!(self, Self::Provision)
    }
}

/// A network offered back to the customer to choose from.
///
/// Discovery returns the handle we will use and the name the customer gave
/// the network. They pick by a name they know, not an id they would have to
/// look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudNetwork {
    handle: NetworkHandle,
    display_name: Label,
    region: DeploymentRegion,
}

impl CloudNetwork {
    /// Records a network found in a customer's account.
    #[must_use]
    pub fn new(handle: NetworkHandle, display_name: Label, region: DeploymentRegion) -> Self {
        Self {
            handle,
            display_name,
            region,
        }
    }

    /// The handle to deploy against.
    #[must_use]
    pub fn handle(&self) -> &NetworkHandle {
        &self.handle
    }

    /// The name the customer knows this network by.
    #[must_use]
    pub fn display_name(&self) -> &Label {
        &self.display_name
    }

    /// Where it is.
    #[must_use]
    pub fn region(&self) -> DeploymentRegion {
        self.region
    }
}

impl Placement {
    /// Whether the customer, rather than the platform, owns the hardware.
    #[must_use]
    pub fn is_customer_owned(&self) -> bool {
        !matches!(self, Self::Platform { .. })
    }

    /// The region this placement targets, where one applies.
    ///
    /// It is unknown for [`Placement::CustomerDatabase`]. The customer's
    /// connection string decides, and we never learn where it leads.
    #[must_use]
    pub fn region(&self) -> Fact<DeploymentRegion> {
        match self {
            Self::Platform { region } | Self::CustomerCloud { region, .. } => Fact::Known(*region),
            Self::CustomerDatabase => Fact::Unknown,
        }
    }
}
