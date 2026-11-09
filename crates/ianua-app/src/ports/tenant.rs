//! Tenant-specific ports.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::tenant::clone::{ClonePart, TenantClone};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudProvider, IsolationLevel, TenantResidency,
};
use ianua_domain::domains::tenant::provisioning::sizing::DatabaseSizing;
use ianua_domain::domains::tenant::setup::TenantSetup;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::domains::tenant::teardown::TenantTeardown;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{OrgUserId, OrganizationId, TenantCloneId, TenantId, TenantSlug};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};

define_sort_field! {
    /// Field a tenant listing can be ordered by.
    pub enum TenantSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by display name.
        DisplayName => "display_name",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<TenantSortField> for Tenant {
    fn sort_key(&self, field: TenantSortField) -> SortKey {
        match field {
            TenantSortField::CreatedAt => self.created_at().into(),
            TenantSortField::UpdatedAt => self.updated_at().into(),
            TenantSortField::DisplayName => self.display_name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving tenants.
#[async_trait]
pub trait TenantStore: Send + Sync {
    /// Finds a tenant by its globally unique ID.
    ///
    /// Returns an owned aggregate so load-mutate-save use cases can modify it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError>;

    /// Finds a tenant by slug within a specific organization.
    ///
    /// This is the only slug lookup: tenant slugs are unique only per
    /// organization, so a bare-slug lookup could return the wrong org's
    /// tenant, or one of several. Returns an `Arc` because this is the per-request read-only
    /// resolution path (scope extractor, login), cache hits hand out a
    /// pointer clone instead of copying the whole aggregate each request.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_slug_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<Option<Arc<Tenant>>, DomainError>;

    /// Whether a tenant of `organization_id` already has `slug`. Another
    /// organization's tenant under the same slug does not count: slugs are
    /// unique only within an organization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn slug_exists_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<bool, DomainError>;

    /// Lists tenants in an organization with optional status filter, ordering,
    /// and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_organization(
        &self,
        organization_id: &OrganizationId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError>;

    /// Lists the tenants an org user has been granted, with optional status
    /// filter, ordering, and pagination.
    ///
    /// This is a Member's whole view of the organization: a tenant they hold
    /// no grant in must not appear, whichever organization it belongs to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_granted_to_org_user(
        &self,
        org_user_id: &OrgUserId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError>;

    /// Lists all tenants with optional status filter, ordering, and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_all(
        &self,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError>;

    /// Archived tenants whose grace ended at or before `now`, oldest
    /// archive first, at most `limit` of them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_past_grace(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError>;

    /// At most `size` tenants whose id comes after `after`, in id order,
    /// whatever their status; from the first tenant when `after` is `None`.
    ///
    /// How a sweep walks every tenant: it passes back the last id it was
    /// given, so each batch starts where the last ended and only one batch
    /// is ever held. A tenant made during the walk is reached if its id
    /// comes after the batch being read. An empty answer ends the walk.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn batch_after(
        &self,
        after: Option<TenantId>,
        size: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError>;

    /// Counts the organization's tenants, other than deleted ones, whose
    /// database is placed in the customer's own `provider` cloud
    /// (`Placement::CustomerCloud`), in one query.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn count_in_cloud(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<u64, DomainError>;

    /// Saves a new or updated tenant.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when another tenant of the same
    ///   organization already has its slug.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, tenant: &Tenant) -> Result<(), DomainError>;
}

/// Everything provisioning needs to know about one tenant's database.
///
/// Carries the whole residency, not just the isolation level. The isolation
/// level answers "how far from other tenants" and says nothing about *whose
/// hardware*, so a port that took only isolation could not tell a tenant
/// bound for the customer's own AWS account from one bound for ours, and the
/// implementation had no choice but to fall back on a deployment-wide default.
/// That is exactly how a customer who asked for their own cloud got a database
/// on our server instead.
///
/// The sizing travels with it because the plan has already been consulted:
/// deciding it here rather than in the adapter keeps "how much machine did
/// they pay for" a domain question, and keeps `db.r6g.large` out of it.
pub struct ProvisionDatabaseRequest {
    /// Whose hardware, where, and how isolated.
    pub residency: TenantResidency,
    /// How much machine, derived from what they bought.
    pub sizing: DatabaseSizing,
}

impl ProvisionDatabaseRequest {
    /// The request for a tenant whose plan has already been checked.
    #[must_use]
    pub fn for_residency(residency: TenantResidency) -> Self {
        let sizing = DatabaseSizing::for_isolation(residency.isolation());
        Self { residency, sizing }
    }

    /// The isolation level, for implementations that branch on it alone.
    #[must_use]
    pub fn isolation(&self) -> IsolationLevel {
        self.residency.isolation()
    }
}

/// Dyn-safe port for provisioning a tenant's data store.
///
/// The app layer calls this during tenant lifecycle transitions.
/// The infra layer implements it based on the tenant's isolation level:
///
/// - **Shared**: row-level isolation in existing tables (no-op on provision)
/// - **DedicatedSchema**: a schema per tenant within the platform database
/// - **DedicatedInstance**: separate database per organization
/// - **DedicatedCluster**: separate database per tenant (may be cross-account)
///
/// The implementation orchestrates infrastructure creation (local or in a
/// customer's cloud account), runs schema migrations and registers
/// connection endpoints.
#[async_trait]
pub trait TenantDatabaseProvisioner: Send + Sync {
    /// Provisions the data store for a newly created tenant.
    ///
    /// For `Shared` this is a no-op. For dedicated isolation levels,
    /// this creates the infrastructure (database, schema, or external
    /// resources), runs migrations, and registers the connection
    /// endpoint so the pool resolver can route queries.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if provisioning fails
    /// at any step. The tenant's setup retries its database step, and
    /// fails the setup once the step's tries are spent.
    async fn provision(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        request: &ProvisionDatabaseRequest,
    ) -> Result<ProvisionedEndpoint, DomainError>;

    /// Migrates a tenant's data from one isolation level to another.
    ///
    /// The tenant must be suspended before calling this. The Postgres
    /// implementation only provisions the target store; it does not yet
    /// copy tenant data across or clean up the source.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if `from` and the target isolation
    /// level are the same, and `DomainError::Infrastructure` if provisioning
    /// the target fails. The caller should not resume the tenant until the
    /// migration completes successfully or is explicitly rolled back.
    async fn migrate_isolation(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        from: IsolationLevel,
        to: &ProvisionDatabaseRequest,
    ) -> Result<ProvisionedEndpoint, DomainError>;

    /// Tears down tenant-specific data store resources.
    ///
    /// The tenant's teardown calls it last, once its data is removed and
    /// its audit trail moved. For `Shared` this is a no-op. For dedicated
    /// levels, drops the schema or decommissions the database and its
    /// network link, and stops routing the tenant to it. A store removed
    /// already is not an error, so a retry is safe.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if teardown fails.
    async fn teardown(
        &self,
        tenant_id: &TenantId,
        organization_id: &OrganizationId,
        isolation: IsolationLevel,
    ) -> Result<(), DomainError>;
}

/// Result of a successful provisioning or migration.
///
/// Contains the connection details the pool resolver needs to
/// route queries to this tenant's data store.
#[derive(Debug, Clone)]
pub enum ProvisionedEndpoint {
    /// Shared database, no dedicated endpoint, uses the platform pool.
    Shared,

    /// Dedicated schema within the platform database.
    Schema {
        /// The schema name (e.g. `org_<uuid>`).
        schema_name: String,
    },

    /// A separate database (local or cross-account).
    Dedicated {
        /// Connection URL for the database. It carries the password, so it
        /// is held as a secret.
        connection_url: Secret,
        /// Maximum pool connections for this endpoint.
        max_connections: u32,
    },
}

/// The version of a tenant's setup as it was read: the time it last
/// changed.
///
/// A setup's first steps run as parallel jobs, and each marks its own step
/// done. A setup saved over a version that moved on would undo the other's
/// mark: the signing key and the starting roles finishing at once would
/// leave one of them not done, activation never ready, and the tenant
/// provisioning for good. So every change to a stored setup goes through
/// [`TenantSetupStore::save_unchanged_since`] with the version it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupVersion(OffsetDateTime);

impl SetupVersion {
    /// The version `setup` is at. Only a setup read back from the store
    /// names a version the store can compare: a setup changed in memory
    /// carries a time the store has not kept.
    #[must_use]
    pub fn of(setup: &TenantSetup) -> Self {
        Self(setup.updated_at())
    }

    /// The version a store kept a setup at: `changed_at`, the time the
    /// setup last changed as the store wrote it.
    #[must_use]
    pub fn stored(changed_at: OffsetDateTime) -> Self {
        Self(changed_at)
    }

    /// The time the setup last changed at this version.
    #[must_use]
    pub fn changed_at(self) -> OffsetDateTime {
        self.0
    }
}

/// Dyn-safe port for keeping each tenant's setup.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): a setup is kept with the
/// platform's records of its tenant, since it runs before a tenant with a
/// database of its own has that database.
#[async_trait]
pub trait TenantSetupStore: Send + Sync {
    /// The setup of `tenant_id`, or `None` when it has none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find(&self, tenant_id: &TenantId) -> Result<Option<TenantSetup>, DomainError>;

    /// The setups of the requested tenants, read together in no guaranteed
    /// order. Tenants without a stored setup are omitted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read.
    async fn find_many(&self, tenant_ids: &[TenantId]) -> Result<Vec<TenantSetup>, DomainError>;

    /// Saves a new setup. A change to a stored one goes through
    /// [`save_unchanged_since`](Self::save_unchanged_since), so it cannot
    /// undo a change made since it was read.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the tenant has a setup already, which
    ///   stays as it is: of two starts at once, the first one's is kept.
    /// - `DomainError::Infrastructure` when it cannot be written.
    async fn save(&self, setup: &TenantSetup) -> Result<(), DomainError>;

    /// Saves `setup` only when the stored setup is still at `read`, the
    /// version the caller read before changing it, and gives back the
    /// version it is stored at now.
    ///
    /// The check and the write are one statement, and every write moves
    /// the version on, so of two changes read from one version only the
    /// first is kept. The setup must already be stored.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the stored setup changed since
    ///   `read`, or is gone.
    /// - `DomainError::Infrastructure` when it cannot be written.
    async fn save_unchanged_since(
        &self,
        setup: &TenantSetup,
        read: SetupVersion,
    ) -> Result<SetupVersion, DomainError>;
}

/// The version of a deleted tenant's teardown as it was read: the time it
/// last changed.
///
/// A teardown's first steps, the data removed and the audit trail moved,
/// run as parallel jobs. A teardown saved over a version that moved on
/// would undo the other's mark, and the database step waiting on both
/// would never be ready. So every change to a stored teardown goes through
/// [`TenantTeardownStore::save_unchanged_since`] with the version it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeardownVersion(OffsetDateTime);

impl TeardownVersion {
    /// The version `teardown` is at. Only a teardown read back from the
    /// store names a version the store can compare.
    #[must_use]
    pub fn of(teardown: &TenantTeardown) -> Self {
        Self(teardown.updated_at())
    }

    /// The version a store kept a teardown at: `changed_at`, the time it
    /// last changed as the store wrote it.
    #[must_use]
    pub fn stored(changed_at: OffsetDateTime) -> Self {
        Self(changed_at)
    }

    /// The time the teardown last changed at this version.
    #[must_use]
    pub fn changed_at(self) -> OffsetDateTime {
        self.0
    }
}

/// Dyn-safe port for keeping each deleted tenant's teardown.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): a teardown is kept with
/// the platform's records of its tenant, since it outlives a database of
/// the tenant's own.
#[async_trait]
pub trait TenantTeardownStore: Send + Sync {
    /// The teardown of `tenant_id`, or `None` when it has none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find(&self, tenant_id: &TenantId) -> Result<Option<TenantTeardown>, DomainError>;

    /// Saves a new teardown. A change to a stored one goes through
    /// [`save_unchanged_since`](Self::save_unchanged_since), so it cannot
    /// undo a change made since it was read.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the tenant has a teardown already,
    ///   which stays as it is: of two starts at once, the first one's is
    ///   kept.
    /// - `DomainError::Infrastructure` when it cannot be written.
    async fn save(&self, teardown: &TenantTeardown) -> Result<(), DomainError>;

    /// Saves `teardown` only when the stored teardown is still at `read`,
    /// the version the caller read before changing it, and gives back the
    /// version it is stored at now. The check and the write are one
    /// statement, and every write moves the version on. The teardown must
    /// already be stored.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the stored teardown changed since
    ///   `read`, or is gone.
    /// - `DomainError::Infrastructure` when it cannot be written.
    async fn save_unchanged_since(
        &self,
        teardown: &TenantTeardown,
        read: TeardownVersion,
    ) -> Result<TeardownVersion, DomainError>;
}

/// Dyn-safe port for removing a deleted tenant's data.
#[async_trait]
pub trait TenantDataPurger: Send + Sync {
    /// Removes every row `tenant_id` holds, wherever it lives, but its audit
    /// trail, which is kept for as long as its retention says, the
    /// platform's own record of the tenant, its setup and teardown, and its
    /// queued jobs, which end on their own once what they work on is gone.
    /// Removing what is gone already removes nothing, so a retry is safe.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a database does not
    /// answer. What was removed before stays removed.
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError>;
}

/// Dyn-safe port for removing a deleted tenant's files.
#[async_trait]
pub trait TenantFilePurger: Send + Sync {
    /// Removes every file `tenant_id` holds outside the databases: its logo
    /// and its people's data exports. Its audit log exports stay, kept and
    /// removed with the trail they copy. Removing what is gone already
    /// removes nothing, so a retry is safe.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the files cannot be
    /// removed. What was removed before stays removed.
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError>;
}

/// Dyn-safe port for removing a deleted tenant's memory texts and vectors,
/// wherever the vector store keeps them.
#[async_trait]
pub trait TenantMemoryPurger: Send + Sync {
    /// Removes every text and vector `tenant_id`'s memories keep. Removing
    /// what is gone already removes nothing, so a retry is safe.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store fails. What was
    /// removed before stays removed.
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError>;
}

/// Dyn-safe port for keeping copies of one tenant's setup into another.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): a clone spans two
/// tenants of one organization, and the worker that runs it reads it by id
/// alone.
#[async_trait]
pub trait TenantCloneStore: Send + Sync {
    /// The clone `id`, or `None` when there is none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row breaks a rule the clone keeps.
    async fn find_by_id(&self, id: &TenantCloneId) -> Result<Option<TenantClone>, DomainError>;

    /// Whether a clone into `target` is still copying.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn copying_into(&self, target: &TenantId) -> Result<bool, DomainError>;

    /// Saves a new or updated clone.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, clone: &TenantClone) -> Result<(), DomainError>;
}

/// Dyn-safe port copying one part of a tenant's setup into another tenant
/// of its organization, as a step of a clone.
///
/// The tenant's own settings are copied through the tenant itself
/// ([`Tenant::copy_settings_from`]) and never reach this port. The adapter
/// copies the records of every other part, and never users, sessions,
/// signing keys or secrets: roles come without who holds them, and OAuth
/// applications without their secrets. Copying a part again replaces what
/// the first copy wrote, so a worker that stopped half-way copies it again
/// safely.
#[async_trait]
pub trait ClonePartCopier: Send + Sync {
    /// Copies `part` of `clone`'s source tenant into its target.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` for [`ClonePart::Settings`], which
    /// the tenant copies itself, and `DomainError::Infrastructure` when the
    /// copy fails; nothing of the part is left half-written.
    async fn copy(&self, clone: &TenantClone, part: ClonePart) -> Result<(), DomainError>;
}
