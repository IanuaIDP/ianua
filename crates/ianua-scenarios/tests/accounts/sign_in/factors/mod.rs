//! A member's second factor at sign-in: the code an authenticator app
//! shows, the factor an organization requires before anyone is let in,
//! passkeys with and without an address, and what happens to a sign-in
//! when a factor is given up, turned off, reset or recovered. Every
//! refusal is followed by the sign-in that still works, so a refused step
//! is shown to have broken nothing.
//!
//! - `codes`: a code is spent once; guessing codes locks the factor.
//! - `enrollment`: a required factor lets nobody in until its code or
//!   passkey is confirmed, and a deployment without mail still asks for
//!   one.
//! - `interruption`: a code or recovery code refused by a failed audit
//!   write is still good after the platform restarts, and is spent once.
//! - `lifecycle`: a setup given up, a factor turned off or kept on by
//!   policy, a lost factor reset by the owner or recovered with a printed
//!   code.
//! - `member`: Max's authenticator and printout, the sign-in that owes
//!   them and the colleagues who keep their access, shared by the
//!   scenarios about him.
//! - `passkeys`: a passkey signs in with no password, once; relayed,
//!   copied, removed, borrowed and moved answers are refused; a challenge
//!   obeys policy and expiry; a passkey meets a two-factor baseline.
//! - `policy`: a sign-in waiting for its mailbox or its factor answers the
//!   policy in force now, not the one when it began.

mod codes;
mod enrollment;
mod interruption;
mod lifecycle;
pub(crate) mod member;
mod passkeys;
mod policy;
