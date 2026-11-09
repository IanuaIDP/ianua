//! Tenant infrastructure: where a tenant's data lives.
//!
//! These types say what the tenant asked for. The adapters read them and
//! create the real databases; the tenant's setup
//! ([`crate::domains::tenant::setup`]) tracks how far that got.

mod placement;

pub use placement::*;

use crate::domains::tenant::compliance::{DataResidency, Residency};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Fact;

/// Where a tenant's data lives, as a single validated decision.
///
/// Pairs a [`Placement`] with an [`IsolationLevel`]. The constructor refuses
/// pairs that cannot both be true, so no later layer checks them again. A
/// tenant on its own hardware shares no table or schema with anybody.
///
/// It cannot be changed. Moving a tenant is a data migration with its own
/// lifecycle, not a field update.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "TenantResidencyWire"))]
pub struct TenantResidency {
    placement: Placement,
    isolation: IsolationLevel,
}

/// A residency as it arrives, before [`TenantResidency::new`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct TenantResidencyWire {
    placement: Placement,
    isolation: IsolationLevel,
}

#[cfg(feature = "serde")]
impl TryFrom<TenantResidencyWire> for TenantResidency {
    type Error = DomainError;

    /// A residency read from storage or an API body is refused when its
    /// placement and isolation contradict each other, as one built in code is.
    fn try_from(wire: TenantResidencyWire) -> Result<Self, Self::Error> {
        Self::new(wire.placement, wire.isolation)
    }
}

impl TenantResidency {
    /// Pairs a placement with an isolation level.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the placement is customer-owned but
    ///   the isolation level shares a database or schema with other tenants.
    pub fn new(placement: Placement, isolation: IsolationLevel) -> Result<Self, DomainError> {
        let shares_platform_hardware = matches!(
            isolation,
            IsolationLevel::Shared | IsolationLevel::DedicatedSchema
        );

        if placement.is_customer_owned() && shares_platform_hardware {
            return Err(DomainError::invalid(message!(
                "tenant-a-tenant-on-customer-owned-infrastructure",
                "a tenant on customer-owned infrastructure cannot share a database or schema \
                 with other tenants; choose a dedicated instance or cluster"
            )));
        }

        Ok(Self {
            placement,
            isolation,
        })
    }

    /// The arrangement every tenant starts on: our infrastructure, shared
    /// database, in `region`.
    #[must_use]
    pub fn shared_on_platform(region: DeploymentRegion) -> Self {
        Self {
            placement: Placement::Platform { region },
            isolation: IsolationLevel::Shared,
        }
    }

    /// Whose hardware this is.
    #[must_use]
    pub fn placement(&self) -> &Placement {
        &self.placement
    }

    /// How far this tenant's data is kept from other tenants'.
    #[must_use]
    pub fn isolation(&self) -> IsolationLevel {
        self.isolation
    }

    /// Whether this arrangement needs a database of its own provisioned.
    ///
    /// `Shared` and `DedicatedSchema` live on infrastructure that already
    /// exists. The other two do not.
    #[must_use]
    pub fn needs_dedicated_database(&self) -> bool {
        matches!(
            self.isolation,
            IsolationLevel::DedicatedInstance | IsolationLevel::DedicatedCluster
        )
    }

    /// Whether provisioning needs something from the customer first, such as
    /// a connection string or access to their cloud account.
    #[must_use]
    pub fn needs_customer_input(&self) -> bool {
        self.placement.is_customer_owned()
    }

    /// Refuses a placement that breaks the tenant's declared residency, and
    /// says how far the residency was checked.
    ///
    /// A tenant promises its data stays in the EU and is then placed in
    /// Virginia. Neither value shows the problem alone, only the pair does.
    ///
    /// [`Residency::Anywhere`] means no constraint, so any region meets it. A
    /// customer's own database is accepted as
    /// [`ResidencyAssurance::DeclaredByCustomer`]. We never learn where their
    /// connection string leads, so the promise is theirs and must never show
    /// as one we checked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the placement's region lies outside
    ///   the required jurisdiction. The message names both.
    pub fn satisfies_declared_residency(
        &self,
        required: Residency,
    ) -> Result<ResidencyAssurance, DomainError> {
        let Residency::Within(required) = required else {
            return Ok(ResidencyAssurance::NotRequired);
        };
        let Fact::Known(region) = self.placement.region() else {
            return Ok(ResidencyAssurance::DeclaredByCustomer(required));
        };

        if region.data_residency() == required {
            return Ok(ResidencyAssurance::Verified(required));
        }

        Err(DomainError::invalid(message!(
            "tenant-stores-data-in-but-this-tenant",
            format!(
                "{region:?} stores data in {:?}, but this tenant requires {required:?}",
                region.data_residency()
            )
        )))
    }
}

/// How far a tenant's data residency was checked.
///
/// A dashboard or compliance report shows this next to the jurisdiction. It
/// tells a residency the platform checked apart from one the customer
/// declared for a database only they can locate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencyAssurance {
    /// The tenant declared no jurisdiction.
    NotRequired,
    /// The platform checked that the data sits in a region inside this
    /// jurisdiction.
    Verified(DataResidency),
    /// The tenant declared this jurisdiction for its own database. The
    /// platform cannot see where that database is, so this is the
    /// customer's word.
    DeclaredByCustomer(DataResidency),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Label;

    /// A tenant on our infrastructure in Frankfurt asks for each of the four
    /// isolation levels. All four are accepted.
    #[test]
    fn platform_placement_accepts_every_isolation_level() {
        let region = DeploymentRegion::EuCentral1;

        for isolation in [
            IsolationLevel::Shared,
            IsolationLevel::DedicatedSchema,
            IsolationLevel::DedicatedInstance,
            IsolationLevel::DedicatedCluster,
        ] {
            let residency = TenantResidency::new(Placement::Platform { region }, isolation);
            assert!(
                residency.is_ok(),
                "{isolation:?} should be valid on platform"
            );
        }
    }

    /// A tenant on its own database asks for shared or schema isolation. Both
    /// are refused, since it cannot share a table or schema with our other
    /// customers.
    #[test]
    fn customer_owned_placement_refuses_shared_isolation() {
        for isolation in [IsolationLevel::Shared, IsolationLevel::DedicatedSchema] {
            let result = TenantResidency::new(Placement::CustomerDatabase, isolation);
            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{isolation:?} should be refused off-platform, got {result:?}"
            );
        }
    }

    /// A tenant in its own AWS account in Ireland asks for a dedicated
    /// instance. It is accepted, needs the customer's input first, needs its
    /// own database and reads its region as known.
    #[test]
    fn customer_cloud_accepts_dedicated_isolation() {
        let residency = TenantResidency::new(
            Placement::CustomerCloud {
                provider: CloudProvider::Aws,
                region: DeploymentRegion::EuWest1,
                network: NetworkPlacement::Existing(NetworkHandle::new("ianua-db").unwrap()),
            },
            IsolationLevel::DedicatedInstance,
        )
        .unwrap();

        assert!(residency.needs_customer_input());
        assert!(residency.needs_dedicated_database());
        assert_eq!(
            residency.placement().region(),
            Fact::Known(DeploymentRegion::EuWest1)
        );
    }

    /// The arrangement every tenant starts on is shared isolation on our
    /// infrastructure. It needs nothing from the customer and no database of
    /// its own.
    #[test]
    fn the_default_is_shared_on_our_own_infrastructure() {
        let residency = TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1);

        assert_eq!(residency.isolation(), IsolationLevel::Shared);
        assert!(!residency.needs_customer_input());
        assert!(!residency.needs_dedicated_database());
    }

    /// A tenant hands us a connection string to its own database. Its region
    /// reads as unknown, since the string says nothing about where it lands.
    #[test]
    fn a_customer_database_has_no_region_of_ours() {
        assert_eq!(Placement::CustomerDatabase.region(), Fact::Unknown);
    }

    /// Frankfurt and Ireland map to the EU, Virginia and Oregon to the US,
    /// and Tokyo to Japan.
    #[test]
    fn every_region_maps_to_a_bloc() {
        assert_eq!(
            DeploymentRegion::EuCentral1.data_residency(),
            DataResidency::Eu
        );
        assert_eq!(
            DeploymentRegion::EuWest1.data_residency(),
            DataResidency::Eu
        );
        assert_eq!(
            DeploymentRegion::UsEast1.data_residency(),
            DataResidency::Us
        );
        assert_eq!(
            DeploymentRegion::UsWest2.data_residency(),
            DataResidency::Us
        );
        assert_eq!(
            DeploymentRegion::ApNortheast1.data_residency(),
            DataResidency::Japan
        );
    }

    /// London and Zurich have `eu-` region codes but map to the UK and
    /// Switzerland, not the EU. Montreal maps to Canada.
    #[test]
    fn regions_outside_the_eu_are_not_reported_as_eu() {
        assert_eq!(
            DeploymentRegion::EuWest2.data_residency(),
            DataResidency::Uk,
            "London is not the EU, whatever its region code says"
        );
        assert_eq!(
            DeploymentRegion::EuCentral2.data_residency(),
            DataResidency::Switzerland,
            "Zurich is adequate, not European"
        );
        assert_eq!(
            DeploymentRegion::CaCentral1.data_residency(),
            DataResidency::Canada
        );
    }

    /// Placements in London, Zurich and Tokyo fail an EU residency requirement.
    #[test]
    fn an_eu_requirement_refuses_every_merely_adequate_jurisdiction() {
        for region in [
            DeploymentRegion::EuWest2,
            DeploymentRegion::EuCentral2,
            DeploymentRegion::ApNortheast1,
        ] {
            let residency =
                TenantResidency::new(Placement::Platform { region }, IsolationLevel::Shared)
                    .unwrap();

            assert!(
                residency
                    .satisfies_declared_residency(Residency::Within(DataResidency::Eu))
                    .is_err(),
                "{region:?} has an EU adequacy decision but does not sit in the EU"
            );
        }
    }

    /// Each of the fifteen regions is checked against its own jurisdiction.
    /// Every one passes, so no region maps somewhere it cannot meet.
    #[test]
    fn every_region_names_a_jurisdiction_we_can_be_held_to() {
        for region in [
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
        ] {
            let residency =
                TenantResidency::new(Placement::Platform { region }, IsolationLevel::Shared)
                    .unwrap();

            assert!(
                residency
                    .satisfies_declared_residency(Residency::Within(region.data_residency()))
                    .is_ok(),
                "{region:?} must satisfy its own jurisdiction"
            );
        }
    }

    /// A placement in Virginia fails validation against an EU residency
    /// requirement.
    #[test]
    fn a_region_outside_the_declared_bloc_is_refused() {
        let residency = TenantResidency::shared_on_platform(DeploymentRegion::UsEast1);

        let result = residency.satisfies_declared_residency(Residency::Within(DataResidency::Eu));

        assert!(
            matches!(result, Err(DomainError::Validation(_))),
            "{result:?}"
        );
    }

    /// A tenant that requires EU residency is placed in Frankfurt. It is
    /// accepted.
    #[test]
    fn a_region_inside_the_declared_bloc_is_accepted() {
        let residency = TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1);

        assert!(
            residency
                .satisfies_declared_residency(Residency::Within(DataResidency::Eu))
                .is_ok()
        );
    }

    /// A tenant with no residency requirement is placed in Singapore. It is
    /// accepted.
    #[test]
    fn no_declaration_accepts_any_region() {
        let residency = TenantResidency::shared_on_platform(DeploymentRegion::ApSoutheast1);

        assert!(
            residency
                .satisfies_declared_residency(Residency::Anywhere)
                .is_ok()
        );
    }

    /// A tenant on its own database declares EU residency. It is accepted as
    /// the customer's word, never as verified, since we never learn where
    /// the connection string leads.
    #[test]
    fn a_customer_database_is_accepted_as_declared_by_the_customer() {
        let residency = TenantResidency::new(
            Placement::CustomerDatabase,
            IsolationLevel::DedicatedInstance,
        )
        .unwrap();

        let assurance = residency
            .satisfies_declared_residency(Residency::Within(DataResidency::Eu))
            .unwrap();

        assert_eq!(
            assurance,
            ResidencyAssurance::DeclaredByCustomer(DataResidency::Eu)
        );
    }

    /// A tenant we placed in Frankfurt reads as verified for EU residency,
    /// and as not required when it declares none.
    #[test]
    fn a_region_the_platform_placed_is_verified() {
        let residency = TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1);

        assert_eq!(
            residency
                .satisfies_declared_residency(Residency::Within(DataResidency::Eu))
                .unwrap(),
            ResidencyAssurance::Verified(DataResidency::Eu)
        );
        assert_eq!(
            residency
                .satisfies_declared_residency(Residency::Anywhere)
                .unwrap(),
            ResidencyAssurance::NotRequired
        );
    }

    /// On our infrastructure, shared and schema isolation need no database
    /// of their own. A dedicated instance or cluster does.
    #[test]
    fn only_dedicated_tiers_need_a_database_provisioned() {
        let region = DeploymentRegion::UsEast1;
        let placement = Placement::Platform { region };

        for (isolation, expected) in [
            (IsolationLevel::Shared, false),
            (IsolationLevel::DedicatedSchema, false),
            (IsolationLevel::DedicatedInstance, true),
            (IsolationLevel::DedicatedCluster, true),
        ] {
            let residency = TenantResidency::new(placement.clone(), isolation).unwrap();
            assert_eq!(
                residency.needs_dedicated_database(),
                expected,
                "{isolation:?}"
            );
        }
    }

    /// AWS, GCP, Azure and DigitalOcean are each written to JSON and read
    /// back as the same provider.
    #[cfg(feature = "serde")]
    #[test]
    fn every_cloud_provider_reads_back_from_json() {
        for p in [
            CloudProvider::Aws,
            CloudProvider::Gcp,
            CloudProvider::Azure,
            CloudProvider::DigitalOcean,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let restored: CloudProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(p, restored);
        }
    }

    /// Each of the four isolation levels is written to JSON and read back as
    /// the same level.
    #[cfg(feature = "serde")]
    #[test]
    fn every_isolation_level_reads_back_from_json() {
        for i in [
            IsolationLevel::Shared,
            IsolationLevel::DedicatedSchema,
            IsolationLevel::DedicatedInstance,
            IsolationLevel::DedicatedCluster,
        ] {
            let json = serde_json::to_string(&i).unwrap();
            let restored: IsolationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(i, restored);
        }
    }

    /// The starting residency in Frankfurt is written to JSON. It matches,
    /// character for character, the shape a database migration writes.
    #[cfg(feature = "serde")]
    #[test]
    fn the_default_residency_serialises_to_the_shape_the_migration_writes() {
        let json = serde_json::to_string(&TenantResidency::shared_on_platform(
            DeploymentRegion::EuCentral1,
        ))
        .unwrap();

        assert_eq!(
            json,
            r#"{"placement":{"Platform":{"region":"EuCentral1"}},"isolation":"Shared"}"#
        );
    }

    /// A dedicated cluster in a customer's GCP account in Tokyo, with a
    /// network still to build, is written to JSON and read back equal.
    /// Provisioning and pool lookups depend on that.
    #[cfg(feature = "serde")]
    #[test]
    fn a_residency_reads_back_from_json() {
        let residency = TenantResidency::new(
            Placement::CustomerCloud {
                provider: CloudProvider::Gcp,
                region: DeploymentRegion::ApNortheast1,
                network: NetworkPlacement::Provision,
            },
            IsolationLevel::DedicatedCluster,
        )
        .unwrap();

        let json = serde_json::to_string(&residency).unwrap();
        let restored: TenantResidency = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, residency);
    }

    /// A stored residency puts a customer's own database on shared
    /// isolation. Reading it back is refused, as building it in code is.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_residency_sharing_a_customers_database_is_refused() {
        let json = r#"{"placement":"CustomerDatabase","isolation":"Shared"}"#;

        assert!(serde_json::from_str::<TenantResidency>(json).is_err());
    }

    /// `vpc-0a1b2c3d` reads from JSON and writes back the same. An empty
    /// handle and one with a line break are refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_network_handle_read_from_json_is_validated() {
        let handle: NetworkHandle = serde_json::from_str("\"vpc-0a1b2c3d\"").unwrap();

        assert_eq!(serde_json::to_string(&handle).unwrap(), "\"vpc-0a1b2c3d\"");
        assert!(serde_json::from_str::<NetworkHandle>("\"\"").is_err());
        assert!(serde_json::from_str::<NetworkHandle>("\"vpc\\n0a1b\"").is_err());
    }

    /// Discovery finds `vpc-0a1b2c3d`, named "Production VPC". The network
    /// keeps both, so the adapter deploys into the handle the customer picked
    /// by name.
    #[test]
    fn a_discovered_network_carries_the_handle_and_the_name_the_customer_knows() {
        let network = CloudNetwork::new(
            NetworkHandle::new("vpc-0a1b2c3d").unwrap(),
            Label::new("name", "Production VPC").unwrap(),
            DeploymentRegion::EuCentral1,
        );

        assert_eq!(network.handle().as_str(), "vpc-0a1b2c3d");
        assert_eq!(network.display_name().as_str(), "Production VPC");
    }

    /// A chosen network gives its handle and needs no building. A network to
    /// be built has no handle yet and needs building.
    #[test]
    fn choosing_a_network_is_told_apart_from_asking_for_one_to_be_built() {
        let chosen = NetworkPlacement::Existing(NetworkHandle::new("vpc-0a1b2c3d").unwrap());

        assert_eq!(
            chosen.handle().map(NetworkHandle::as_str),
            Some("vpc-0a1b2c3d")
        );
        assert!(!chosen.needs_building());

        assert!(NetworkPlacement::Provision.handle().is_none());
        assert!(NetworkPlacement::Provision.needs_building());
    }
}
