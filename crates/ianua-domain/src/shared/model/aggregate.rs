use time::OffsetDateTime;

/// What every aggregate root has: an id, a creation time and a last-change time.
///
/// Code that works on any aggregate, such as audit logging or caching, reads
/// these three without knowing the concrete type.
pub trait Aggregate {
    /// The type of the aggregate's unique identifier.
    type Id;

    /// The aggregate's unique identifier.
    fn id(&self) -> &Self::Id;

    /// When this aggregate was created.
    fn created_at(&self) -> OffsetDateTime;

    /// When this aggregate was last modified.
    fn updated_at(&self) -> OffsetDateTime;
}
