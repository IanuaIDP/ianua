//! A forgotten password reset by a link mailed to the member alone.
//! Whoever asks for it is answered alike; the link is worth something
//! until it is spent, once, or until it expires; the new password must
//! meet the rules in force now, and the reset ends every session the
//! member held. A member with an authenticator app must answer it before
//! the mailbox alone replaces the password, and a link reset nobody's
//! standing. Every refused step leaves the password, the session and the
//! link as they were.
//!
//! - `mail`: a forgotten password reset by mail, ending every session;
//!   with an authenticator app, the reset needs its code.
//! - `expiry`: a link one second before, at and after its deadline, and
//!   a fresh link after an expired one.
//! - `factor`: a reset without the phone's fresh code changes nothing.
//! - `interruption`: a reset refused by a failed audit write changes
//!   nothing and its link still works after a restart.
//! - `policy`: a removed member's link recreates no account; a link obeys
//!   the password rules in force when it is followed.
//! - `purposes`: a sign-in link resets no password and a reset link signs
//!   nobody in; each still does what it was sent for.
//! - `races`: two resets through one link change the password once.
//! - `resends`: a resent link waits for the cooldown and replaces the old
//!   one.
//! - `standing`: a reset neither unlocks a locked member nor reactivates a
//!   deactivated one.
//! - `support`: Max's reset link, the access everyone has after a reset,
//!   the one password change the trail holds, and a reset request.

mod expiry;
mod factor;
mod interruption;
mod mail;
mod policy;
mod purposes;
mod races;
mod resends;
mod standing;
mod support;
