//! Organization domain events.

/// Events about members signing in to the management plane and the credentials they use.
pub mod access;
/// Events about the organization's subscription, trial and payments.
pub mod billing;
/// Events about the organization's own look.
pub mod branding;
/// Events about an organization's connections to its cloud accounts.
pub mod cloud;
/// Events about invitations to join an organization.
pub mod invitations;
/// Events about the people who administer an organization.
pub mod members;
/// Events about the organization itself: creation, status, names and plan.
pub mod organization;
/// Events about a member's consent and the erasure of their data.
pub mod privacy;
