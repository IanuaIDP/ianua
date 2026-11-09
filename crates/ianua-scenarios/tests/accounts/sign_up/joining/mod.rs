//! People joining what exists: Pat registering through a tenant's public
//! form and proving the mailbox, Uma invited into the organization and Pat
//! into the tenant, both from the mailed link, and the same without a
//! mail server, where the link is handed over. Every account is used
//! afterwards, by its own sign-in, and reaches only what is its own.
//!
//! - `self_signup`: Pat's public form, its mailbox proof, and what the
//!   pending account can and cannot do before and after.
//! - `member_invitations`: Uma invited into the organization: the offered
//!   role and nothing more, expiry, resend, revoke, decline, the sender's
//!   current authority, and who may invite.
//! - `user_invitations`: Pat invited into the tenant: the same, with the
//!   sender's current tenant grants.
//! - `offline`: joining without a mail server: the public form refused,
//!   invitations handed to their sender and joined without a mailbox
//!   claimed.
//! - `policies`: the admission matrix behind the public form, the
//!   stronger assurances, password rules, and a policy changed while a
//!   proof is pending.

mod member_invitations;
mod offline;
mod policies;
mod self_signup;
mod support;
mod user_invitations;
