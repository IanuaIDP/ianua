//! Getting back in after losing something: the password, reset by a link
//! mailed to the member alone, worth something until it is spent once and
//! judged by the policy, standing and factor in force when it is followed;
//! and the phone, stood in for by a printed recovery code that is good
//! once, shares the factor's lock, and is replaced only with fresh proof.
//! Every refused step is followed by the sign-in that still works.
//!
//! - `codes`: recovery codes at sign-in: spent once, each member's own,
//!   locked with the factor, answering one live sign-in, and replaced as
//!   a whole printout.
//! - `reset`: a forgotten password reset by mail: the link's lifetime,
//!   purpose, cooldown and single use, the factor and policy it obeys,
//!   the member's standing, competing resets and a failed audit write.

mod codes;
mod reset;
