//! Relationships on the objects of a tenant's app: who holds which relation
//! on which object, and which object sits under which.

use async_trait::async_trait;
use ianua_domain::domains::authorization::relationship::{
    ObjectRef, RelationLink, RelationSubject, Relationship,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::RelationshipId;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order relationships are listed in: newest first.
    pub enum RelationshipSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<RelationshipSortField> for Relationship<ResolvedTenant> {
    fn sort_key(&self, field: RelationshipSortField) -> SortKey {
        match field {
            RelationshipSortField::CreatedAt => self.created_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Which of a tenant's relationships a listing shows, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationshipFilter {
    /// Every relationship.
    All,
    /// Those about this object.
    OnObject(ObjectRef),
    /// Those naming this subject as the holder of a relation.
    HeldBy(RelationSubject),
}

/// Dyn-safe port for persisting and retrieving relationships.
#[async_trait]
pub trait RelationshipStore: Send + Sync + TenantScoped {
    /// Finds a relationship by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RelationshipId,
    ) -> Result<Option<Relationship<ResolvedTenant>>, DomainError>;

    /// Finds the relationship saying `link` about `object`, if one was
    /// written, so the same fact is never stored twice.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_same(
        &self,
        tenant_id: &ScopedTenant,
        object: &ObjectRef,
        link: &RelationLink,
    ) -> Result<Option<Relationship<ResolvedTenant>>, DomainError>;

    /// The relationships `filter` keeps, newest first, one page of them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: &RelationshipFilter,
        page: &PageRequest,
    ) -> Result<Page<Relationship<ResolvedTenant>>, DomainError>;

    /// Every relationship about `object` and about each object it sits
    /// under, following parents at most `depth` steps up: what an access
    /// check on `object` reads.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_chain(
        &self,
        tenant_id: &ScopedTenant,
        object: &ObjectRef,
        depth: usize,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError>;

    /// The union of the relationships about `objects` and their ancestors,
    /// following each root at most `depth` steps, read together. A shared
    /// ancestor's relationships are returned only once.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find_chains(
        &self,
        tenant_id: &ScopedTenant,
        objects: &[ObjectRef],
        depth: usize,
    ) -> Result<Vec<Relationship<ResolvedTenant>>, DomainError>;

    /// Saves a new relationship.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the relationship cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        relationship: &Relationship<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes a relationship.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the relationship cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &RelationshipId,
    ) -> Result<(), DomainError>;
}
