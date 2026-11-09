//! Ann runs her company itself: she changes its profile, suspends it,
//! lets it go on again and closes it; she pays for it, connects clouds of
//! its own and sends its notifications outside the app; and she looks
//! after what her colleagues' mailboxes prove. A change shows at once to
//! every member, whoever lacks the right is refused with nothing changed
//! and nothing recorded, and a change the trail cannot record happens not
//! even in part. Sam's company is never touched by any of it.
//!
//! - `profile`: the profile changed whole or in part, an unchanged or
//!   bad form, and who may change it.
//! - `lifecycle`: suspending, letting go on again and closing, and who
//!   may do which.
//! - `rollback`: a profile change and a closure the trail cannot record.
//! - `billing`: the plans on sale, the bill and what is used, the plan an
//!   operator arranges, the checkout, and the notices a payment provider
//!   posts.
//! - `cloud`: the clouds a company connects and the role template it reads.
//! - `destinations`: the outside places its notifications are posted to.
//! - `factors`: whether a member has a second factor.
//! - `invitations`: what a mailed invitation link is worth, and renewing
//!   one that ran out.
//! - `key_ends`: a company key with an end, stopping at its exact second.
//! - `mailboxes`: another proof of a mailbox, a move made for a colleague,
//!   a welcome, and the links a move leaves behind.

#![cfg(test)]

mod billing;
mod cloud;
mod destinations;
mod factors;
mod invitations;
mod key_ends;
mod lifecycle;
mod mailboxes;
mod profile;
mod rollback;
mod support;
