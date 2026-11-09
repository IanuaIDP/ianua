//! Organization use cases: the organization's lifecycle, its members and
//! invitations, how members sign in and prove who they are, its API keys
//! and cloud accounts. Its audit log is read in the audit context.

/// API keys that act for the organization.
pub mod api_keys;
mod attributed;
/// What the organization pays for: its plan, its subscription and its payments.
pub mod billing;
/// How the organization's own dashboard and mail look.
pub mod branding;
/// Connecting the organization's own cloud accounts.
pub mod cloud_accounts;
/// The organization's own identity provider, its members' company directory.
pub mod identity_providers;
/// Bringing people into the organization: invitations, welcome mail and address verification.
pub mod invitations;
/// The organization itself: creating it, changing it, and moving it through its lifecycle.
pub mod lifecycle;
mod link_mail;
mod lookup;
mod mail_labels;
/// The organization's members: their accounts, roles, tenant access and linked identities.
pub mod members;
/// Members' second factors: authenticator apps and recovery codes.
pub mod mfa;
/// Members' passkeys: registering, managing and signing in with them.
pub mod passkeys;
pub(crate) mod password_breach;
/// Members who forgot their password setting a new one through a mailed link.
pub mod password_reset;
/// Members' consent records and their requests to be erased.
pub mod privacy;
/// How members sign in and stay signed in: passwords, sessions, devices and tenants.
pub mod sign_in;
mod sign_in_record;
/// Who takes a platform action on an organization: a member or an operator.
pub mod steward;
