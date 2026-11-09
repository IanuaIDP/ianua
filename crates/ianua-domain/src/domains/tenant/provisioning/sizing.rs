//! How large a tenant's dedicated database is.
//!
//! The size follows from the isolation level the customer's plan allows. The
//! customer is never asked. Someone buying an identity provider cannot know
//! whether they need a `db.r6g.xlarge`, and would sometimes pick wrong.
//!
//! A [`DatabaseSizing`] names no cloud provider. It says how much machine a
//! tenant gets. Each cloud adapter turns that into its own names, such as
//! `db.r6g.large`, `db-custom-4-16384` or `Standard_D4s_v3`.

use crate::domains::tenant::provisioning::infrastructure::IsolationLevel;
use crate::message;
use crate::shared::errors::DomainError;

/// How much machine a tenant's database gets.
///
/// There are three fixed steps, one for each kind of database an isolation
/// level gives a tenant: none of its own, a dedicated instance or a
/// dedicated cluster. Any size in between would need a price of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DatabaseTier {
    /// Shared with other tenants. No dedicated machine exists.
    Shared,

    /// A tenant that paid to be alone on a dedicated instance.
    Standard,

    /// A tenant whose isolation is a regulatory requirement rather than a
    /// preference, and whose load usually matches.
    Large,
}

/// The smallest storage each tier starts with, in gibibytes.
///
/// Every cloud we use grows storage on demand, so only the starting size
/// matters. Too little means an outage during the first import. Too much
/// bills the customer for empty disk on day one.
const fn storage_floor(tier: DatabaseTier) -> u32 {
    match tier {
        DatabaseTier::Shared => 0,
        DatabaseTier::Standard => 100,
        DatabaseTier::Large => 500,
    }
}

/// The size of one tenant's database, decided by what they bought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "DatabaseSizingWire"))]
pub struct DatabaseSizing {
    tier: DatabaseTier,
    storage_gib: u32,
}

/// A sizing as it arrives, before its storage is checked against the tier's
/// minimum and the maximum.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct DatabaseSizingWire {
    tier: DatabaseTier,
    storage_gib: u32,
}

#[cfg(feature = "serde")]
impl TryFrom<DatabaseSizingWire> for DatabaseSizing {
    type Error = DomainError;

    /// A sizing read from storage goes through
    /// [`with_storage_gib`](DatabaseSizing::with_storage_gib), so it meets the
    /// same minimum and maximum as one decided in code.
    fn try_from(wire: DatabaseSizingWire) -> Result<Self, Self::Error> {
        let at_floor = Self {
            tier: wire.tier,
            storage_gib: storage_floor(wire.tier),
        };
        at_floor.with_storage_gib(wire.storage_gib)
    }
}

impl DatabaseSizing {
    /// The sizing a tenant at this isolation level is owed.
    ///
    /// It reads the isolation level, not the plan.
    /// [`crate::domains::organization::billing::plan::PlanLimits::permits_residency`]
    /// already refuses an isolation level the plan does not cover. So at
    /// provisioning the isolation level is what the tenant paid for. Reading
    /// the plan again here could give a different answer.
    #[must_use]
    pub fn for_isolation(isolation: IsolationLevel) -> Self {
        let tier = match isolation {
            IsolationLevel::Shared | IsolationLevel::DedicatedSchema => DatabaseTier::Shared,
            IsolationLevel::DedicatedInstance => DatabaseTier::Standard,
            IsolationLevel::DedicatedCluster => DatabaseTier::Large,
        };

        Self {
            tier,
            storage_gib: storage_floor(tier),
        }
    }

    /// Raises the starting storage for a tenant that needs more.
    ///
    /// This is the one sizing choice an operator makes by hand, for example
    /// for a migrating customer whose directory is already bigger than the
    /// tier's minimum. Customers cannot make it. It can only grow the
    /// storage, because a database below the minimum fails on import.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the size is below this tier's
    ///   minimum.
    /// - [`DomainError::Validation`] when the size is beyond what any cloud we
    ///   use will allocate.
    pub fn with_storage_gib(self, storage_gib: u32) -> Result<Self, DomainError> {
        /// Every cloud we use refuses more than this. A bigger request is far
        /// likelier to be a typo than a real directory.
        const MAX_STORAGE_GIB: u32 = 65_536;

        let floor = storage_floor(self.tier);
        if storage_gib < floor {
            return Err(DomainError::invalid(message!(
                "tenant-starts-at-gib-gib-would-fail",
                format!(
                    "{:?} starts at {floor} GiB; {storage_gib} GiB would fail on first import",
                    self.tier
                )
            )));
        }

        if storage_gib > MAX_STORAGE_GIB {
            return Err(DomainError::invalid(message!(
                "tenant-gib-is-beyond-the-gib-ceiling",
                format!("{storage_gib} GiB is beyond the {MAX_STORAGE_GIB} GiB ceiling")
            )));
        }

        Ok(Self {
            storage_gib,
            ..self
        })
    }

    /// How much machine this tenant gets.
    #[must_use]
    pub fn tier(&self) -> DatabaseTier {
        self.tier
    }

    /// Starting storage, in gibibytes.
    #[must_use]
    pub fn storage_gib(&self) -> u32 {
        self.storage_gib
    }

    /// Whether a machine has to be created at all.
    #[must_use]
    pub fn needs_a_machine(&self) -> bool {
        self.tier != DatabaseTier::Shared
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant on shared isolation is sized. It gets the shared tier, no
    /// machine of its own and no storage of its own.
    #[test]
    fn a_shared_tenant_gets_no_machine() {
        let sizing = DatabaseSizing::for_isolation(IsolationLevel::Shared);

        assert_eq!(sizing.tier(), DatabaseTier::Shared);
        assert!(!sizing.needs_a_machine());
        assert_eq!(sizing.storage_gib(), 0);
    }

    /// A tenant with a dedicated schema is sized. No machine is created,
    /// since the schema lives in a database that already exists.
    #[test]
    fn a_dedicated_schema_still_gets_no_machine_of_its_own() {
        let sizing = DatabaseSizing::for_isolation(IsolationLevel::DedicatedSchema);

        assert!(
            !sizing.needs_a_machine(),
            "a dedicated schema lives inside a database that already exists"
        );
    }

    /// A tenant with a dedicated instance gets a standard machine starting at
    /// 100 GiB.
    #[test]
    fn a_dedicated_instance_gets_a_standard_machine() {
        let sizing = DatabaseSizing::for_isolation(IsolationLevel::DedicatedInstance);

        assert_eq!(sizing.tier(), DatabaseTier::Standard);
        assert!(sizing.needs_a_machine());
        assert_eq!(sizing.storage_gib(), 100);
    }

    /// A dedicated cluster gets a higher tier and more storage than a
    /// dedicated instance.
    #[test]
    fn a_dedicated_cluster_gets_more_than_an_instance() {
        let instance = DatabaseSizing::for_isolation(IsolationLevel::DedicatedInstance);
        let cluster = DatabaseSizing::for_isolation(IsolationLevel::DedicatedCluster);

        assert!(cluster.tier() > instance.tier());
        assert!(cluster.storage_gib() > instance.storage_gib());
    }

    /// An operator raises a migrating customer's standard database to
    /// 400 GiB. The storage grows and the tier stays standard.
    #[test]
    fn storage_can_be_raised_for_a_migrating_customer() {
        let sizing = DatabaseSizing::for_isolation(IsolationLevel::DedicatedInstance)
            .with_storage_gib(400)
            .unwrap();

        assert_eq!(sizing.storage_gib(), 400);
        assert_eq!(sizing.tier(), DatabaseTier::Standard);
    }

    /// An operator asks for 5 GiB on a standard database, which starts at
    /// 100. It is refused, since the first import would fail.
    #[test]
    fn storage_cannot_be_dropped_below_the_floor() {
        let err =
            DatabaseSizing::for_isolation(IsolationLevel::DedicatedInstance).with_storage_gib(5);

        assert!(matches!(err, Err(DomainError::Validation(_))));
    }

    /// An operator asks for a million GiB on a cluster. It is refused as more
    /// than any cloud we use will allocate.
    #[test]
    fn an_implausible_storage_request_is_refused() {
        let err = DatabaseSizing::for_isolation(IsolationLevel::DedicatedCluster)
            .with_storage_gib(1_000_000);

        assert!(matches!(err, Err(DomainError::Validation(_))));
    }

    /// On a standard database, 100 and 65,536 GiB are accepted. One below
    /// the minimum and one above the maximum are refused.
    #[test]
    fn the_floor_and_the_ceiling_are_both_sizes_you_may_ask_for() {
        let standard = DatabaseSizing::for_isolation(IsolationLevel::DedicatedInstance);

        assert!(
            standard.with_storage_gib(100).is_ok(),
            "the floor is allowed"
        );
        assert!(standard.with_storage_gib(99).is_err());

        assert!(
            standard.with_storage_gib(65_536).is_ok(),
            "the ceiling is allowed"
        );
        assert!(standard.with_storage_gib(65_537).is_err());
    }

    /// A stored sizing says standard with 5 GiB. Reading it back is refused,
    /// so storage never skips the minimum.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_sizing_below_its_tiers_floor_is_refused() {
        let json = r#"{"tier":"Standard","storage_gib":5}"#;

        assert!(serde_json::from_str::<DatabaseSizing>(json).is_err());
    }

    /// A cluster sizing raised to 800 GiB is written to JSON and read back.
    /// It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_valid_sizing_round_trips_through_json() {
        let sizing = DatabaseSizing::for_isolation(IsolationLevel::DedicatedCluster)
            .with_storage_gib(800)
            .unwrap();

        let json = serde_json::to_string(&sizing).unwrap();
        let restored: DatabaseSizing = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, sizing);
    }

    /// Every isolation level is sized. Between them they pick every tier, so
    /// no tier exists that no tenant can be given.
    #[test]
    fn every_tier_is_picked_by_some_isolation_level() {
        let picked: Vec<DatabaseTier> = [
            IsolationLevel::Shared,
            IsolationLevel::DedicatedSchema,
            IsolationLevel::DedicatedInstance,
            IsolationLevel::DedicatedCluster,
        ]
        .into_iter()
        .map(|isolation| DatabaseSizing::for_isolation(isolation).tier())
        .collect();

        for tier in [
            DatabaseTier::Shared,
            DatabaseTier::Standard,
            DatabaseTier::Large,
        ] {
            assert!(picked.contains(&tier), "{tier:?} is never picked");
        }
    }

    /// Each isolation level is sized twice. Both answers match, so a retried
    /// provisioning run asks for the same machine.
    #[test]
    fn sizing_is_the_same_for_the_same_isolation_every_time() {
        for isolation in [
            IsolationLevel::Shared,
            IsolationLevel::DedicatedSchema,
            IsolationLevel::DedicatedInstance,
            IsolationLevel::DedicatedCluster,
        ] {
            assert_eq!(
                DatabaseSizing::for_isolation(isolation),
                DatabaseSizing::for_isolation(isolation),
                "a retried provisioning run must ask for the same machine"
            );
        }
    }
}
