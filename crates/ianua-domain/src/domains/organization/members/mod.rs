//! The people who administer an organization and what they may reach.

pub mod account_control;
pub mod account_now;
/// Who acts on the organization plane, and what they act through.
pub mod control;
/// Magic-link invitations for org users to join an organization.
pub mod invitation;
pub mod linked_identity;
pub mod membership;
mod org_password;
pub mod org_user;
mod org_user_authority;
/// What a stored member row must keep before it is rebuilt.
mod org_user_row;
/// Organization-level user lifecycle.
pub mod org_user_status;
/// The organization's members as they stand now, so a change keeps an owner.
pub mod owners;
pub mod permission;
pub mod privacy;
pub mod reach;
pub mod reopened;
pub mod tenant_authority;
pub mod tenant_grant;
