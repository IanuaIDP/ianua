//! A printed recovery code standing in for a lost phone at sign-in. A code
//! finishes one sign-in and is spent; it is its own member's, refused on
//! anyone else's sign-in without being spent; it shares the phone's lock
//! against guessing; a used-up printout leaves the phone in force; a code
//! or phone answers one live sign-in of its own company only; and a new
//! printout, which takes the password and a fresh code, kills every old
//! code.
//!
//! - `spending`: a code is good once, belongs to its member, and two
//!   sends at once finish the sign-in once.
//! - `lock`: guessing codes and recovery codes share one lock that lifts
//!   in time; a used-up printout keeps the phone required; a sign-in still
//!   owing its factor cannot replace the printout.
//! - `answers`: a code sent to another company's address, to a sign-in
//!   the owner ended, or twice at once, finishes nothing it should not.
//! - `replacements`: a new printout kills every old code; a refused
//!   replacement leaves every old code good.
//! - `support`: the sign-in a recovery code finishes, the factor answers
//!   the trail counts, and the secrets a record must not hold.

mod answers;
mod lock;
mod replacements;
mod spending;
mod support;
