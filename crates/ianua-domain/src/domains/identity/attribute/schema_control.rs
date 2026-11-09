//! Who may declare and change the tenant's custom attributes.
//!
//! The schema decides what every user may hold and who sees it. Sam may only
//! view users. Without a check, he declares a `clearance_level` the
//! policies then read, or archives the attribute a review depends on.
//! Changing the schema needs the right to update users, the right the
//! attribute routes ask for. Authorization knows what a person holds and
//! answers. Identity sits below authorization, so it names only this rule.

use crate::domains::identity::attribute::resolved::AttributeClearance;
use crate::domains::identity::sealed::Sealed;
use crate::shared::errors::DomainError;

/// Whether the person acting may change the tenant's attribute schema, and
/// how much of it they may see.
pub trait SchemaControlCheck: Sealed {
    /// Refuses unless the person acting may change the schema.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold the right to
    ///   update users.
    fn ensure_may_change_schema(&self) -> Result<(), DomainError>;

    /// How much of a user's attributes the person acting may see, worked
    /// out from what they hold, never the caller's word.
    fn clearance(&self) -> AttributeClearance;
}
