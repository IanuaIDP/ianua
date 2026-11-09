//! What identity handlers take from a request beyond the shared callers:
//! visitors following emailed links, a user listing's filters and order,
//! and the support impersonation a request acts through.

pub mod impersonation;
pub mod user_listing;
pub mod visitors;
