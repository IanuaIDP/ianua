//! People and agents checking an agent: approvals and independent review.

pub mod approval;
/// Where an approval stands: pending, approved, denied, expired, or consumed
/// once the one action it allowed has run.
pub mod approval_status;
pub mod review;
