//! A person looking after their own account, on both planes: Pat in her
//! tenant and Max in his organization. Each changes their profile, moves
//! to another mailbox, changes a password or a factor, looks after their
//! devices and sessions, links accounts, and decides on consent, exports
//! and erasure. After every change the old proofs are tried again and the
//! person's own access is read once more.
//!
//! - `choices`: a language and time zone picked from the lists anyone may
//!   read; one not on the list is refused.
//! - `profile`: a language, time zone or name change moves nothing else:
//!   not the rest of the preferences, not the account's rights.
//! - `email`: a move to another mailbox is confirmed only from the new
//!   mailbox and called off only from the old; a password change kills a
//!   pending move; a held factor is owed afresh; the old address signs in
//!   no more.
//! - `security`: a changed password puts other devices out and keeps this
//!   one; a refused change leaves everything; a factor turned off, a
//!   passkey removed and a new printout of recovery codes.
//! - `devices`: a remembered laptop skips the code until Pat forgets it;
//!   only Pat, with her factor proved, remembers or forgets it.
//! - `sessions`: signing out everywhere else, ending one session, another
//!   holder's session id, and whose sign-ins each holder reads.
//! - `rotation`: a refreshed session retires the token it came from; a
//!   replayed old token ends Pat's sessions and nobody else's; Uma cannot
//!   spend Pat's token.
//! - `identities`: Pat links her two accounts at one address and switches
//!   between them; a shared mailbox, a made-up or ended session, or a
//!   different address links nothing; unlinking stops the switch.
//! - `federation`: Pat's first sign-in through a real provider links her
//!   account; she confirms the link again and removes it; a provider that
//!   did not prove the address, or claims an administrator, links nothing.
//! - `factors`: codes mailed and texted, a lost phone replaced with a
//!   recovery code, a half-set-up authenticator across a restart, a
//!   temporary password set by Tess, and risk and assurance thresholds.
//! - `privacy`: consent purpose by purpose, exports downloaded once, and
//!   erasure called off, held, carried out or refused.

#![cfg(test)]

mod choices;
mod devices;
mod email;
mod factors;
mod federation;
mod identities;
mod privacy;
mod profile;
mod rotation;
mod security;
mod sessions;
mod support;
