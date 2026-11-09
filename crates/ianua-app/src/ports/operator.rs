//! Operator-specific ports.

use async_trait::async_trait;
use ianua_domain::domains::operator::api_key::OperatorApiKey;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::operator::impersonation::ImpersonationGrant;
use ianua_domain::domains::operator::status::OperatorStatus;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, ImpersonationGrantId, KeyPrefix, OperatorId, TenantId, UserId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};

/// Which operators a listing keeps.
pub struct OperatorFilter {
    /// Only operators of this status. `None` keeps every status.
    pub status: Option<OperatorStatus>,
}

impl OperatorFilter {
    /// No filter: every operator.
    #[must_use]
    pub fn all() -> Self {
        Self { status: None }
    }

    /// Whether `operator` is one the filter keeps.
    #[must_use]
    pub fn admits(&self, operator: &Operator) -> bool {
        self.status.is_none_or(|status| operator.status() == status)
    }
}

define_sort_field! {
    /// Field an operator listing can be ordered by.
    pub enum OperatorSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by email address.
        Email => "email",
        /// Order by account status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<OperatorSortField> for Operator {
    fn sort_key(&self, field: OperatorSortField) -> SortKey {
        match field {
            OperatorSortField::CreatedAt => self.created_at().into(),
            OperatorSortField::Email => self.email().as_str().into(),
            OperatorSortField::Status => operator_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word an operator's status sorts by, as it is stored.
fn operator_status_word(status: OperatorStatus) -> &'static str {
    match status {
        OperatorStatus::Active => "active",
        OperatorStatus::Disabled => "disabled",
    }
}

/// Dyn-safe port for persisting and retrieving operators.
#[async_trait]
pub trait OperatorStore: Send + Sync {
    /// Finds an operator by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &OperatorId) -> Result<Option<Operator>, DomainError>;

    /// Finds an operator by email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_email(&self, email: &Email) -> Result<Option<Operator>, DomainError>;

    /// One page of the operators `filter` keeps, in `sort` order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the page's cursor was made for
    /// another order, or `DomainError::Infrastructure` on lookup failure.
    async fn list(
        &self,
        filter: &OperatorFilter,
        sort: &SortOrder<OperatorSortField>,
        page: &PageRequest,
    ) -> Result<Page<Operator>, DomainError>;

    /// Whether any operator exists at all, of any status.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn any_exists(&self) -> Result<bool, DomainError>;

    /// Saves a new or updated operator.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another operator signs in with
    /// the address, or `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, operator: &Operator) -> Result<(), DomainError>;
}

/// Dyn-safe port for persisting and retrieving impersonation grants.
#[async_trait]
pub trait ImpersonationGrantStore: Send + Sync {
    /// Finds a grant by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(
        &self,
        id: &ImpersonationGrantId,
    ) -> Result<Option<ImpersonationGrant>, DomainError>;

    /// Finds an active grant for an operator targeting a specific user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_active(
        &self,
        operator_id: &OperatorId,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<ImpersonationGrant>, DomainError>;

    /// Saves a new or updated grant. A revoked grant is final: a save over
    /// it changes nothing and is refused, so a copy read before the
    /// revocation never makes it live again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the stored grant was revoked
    /// already or is another operator's, or `DomainError::Infrastructure`
    /// on persistence failure.
    async fn save(&self, grant: &ImpersonationGrant) -> Result<(), DomainError>;

    /// Revokes all active grants for an operator. Returns how many went.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_all_for_operator(&self, operator_id: &OperatorId) -> Result<u64, DomainError>;
}

/// Dyn-safe port for persisting operator API keys.
#[async_trait]
pub trait OperatorKeyStore: Send + Sync {
    /// Finds a key by its visible prefix.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_prefix(
        &self,
        prefix: &KeyPrefix,
    ) -> Result<Option<OperatorApiKey>, DomainError>;

    /// Every key an operator holds, revoked or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_operator(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Vec<OperatorApiKey>, DomainError>;

    /// Saves a new or changed key. A revoked key is final: a save over it
    /// changes nothing and is refused, so a copy read before the revocation
    /// never makes it work again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the stored key was revoked
    /// already or its prefix is another operator's, or
    /// `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, key: &OperatorApiKey) -> Result<(), DomainError>;

    /// Writes `keys`, all of `operator_id`'s and all just revoked together,
    /// as revoked at the time each was, in one step: every one of them
    /// while every one is still in force, or none. Storage locks the keys
    /// before it writes, so a revocation landing meanwhile turns the whole
    /// step down and nothing is half written.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when a key of `keys` is not revoked.
    /// - `DomainError::Conflict` when a key of `keys` was revoked meanwhile,
    ///   is gone, or is another operator's; none was written.
    /// - `DomainError::Infrastructure` on persistence failure.
    async fn revoke_together(
        &self,
        operator_id: &OperatorId,
        keys: &[OperatorApiKey],
    ) -> Result<(), DomainError>;
}
