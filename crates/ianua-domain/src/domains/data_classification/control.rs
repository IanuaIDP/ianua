//! Who may change how the tenant's response fields are classified.
//!
//! A classification rule decides whether the proxy hides a field before the
//! response reaches the caller. So making a rule set, and adding or removing
//! a rule, names who makes it and needs the right for it.

use crate::domains::data_classification::sealed::Sealed;
use crate::shared::errors::DomainError;

/// Whether the person acting may change the tenant's classification rules.
///
/// Sam may only view the rules. Without this check, he removes the rule
/// that masks `user.ssn`, and every response carries it in the clear.
/// Authorization knows what the person holds and answers with
/// [`TenantAuthority`](crate::domains::authorization::authority::TenantAuthority).
/// Classification sits below authorization, so it names only this rule.
pub trait ClassificationControlCheck: Sealed {
    /// Refuses unless the person acting may change classification rules.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not.
    fn ensure_may_change_rules(&self) -> Result<(), DomainError>;
}
