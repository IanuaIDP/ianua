/// How organization members and machines sign in to the management plane.
pub mod access;
/// What an organization pays for: its plan, its subscription and the catalog of plans.
pub mod billing;
/// How the organization's own dashboard and mail look.
pub mod branding;
/// An organization's connections to its own cloud accounts.
pub mod cloud;
/// Organization domain events.
pub mod events;
/// The proof that an organization was just founded, which makes its first owner.
pub mod founding;
/// The organization itself: creating it, changing its status and its contact details.
pub mod lifecycle;
/// The people who administer an organization and what they may reach.
pub mod members;
/// A sign-up waiting for its founder to prove their mailbox.
pub mod signup;
/// Slugs kept for the platform's own hosts.
pub mod slugs;
/// Organization lifecycle: active, suspended, closed.
pub mod status;
