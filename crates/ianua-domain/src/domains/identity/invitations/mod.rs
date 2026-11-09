//! Invitations to join a tenant.

/// The invitation aggregate: an offer to join a tenant, sent to an email
/// address.
pub mod invitation;
/// The role an invitation gives, and the rules for who may offer it.
pub mod invited_role;
/// The offer every invitation carries: its link, expiry and answer.
pub mod offer;
/// How an invitation's link reached the invitee, and what accepting it
/// shows about the address.
pub mod route;
/// Where an invitation stands: pending until accepted, declined, expired or
/// revoked.
pub mod status;
