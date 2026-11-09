//! Pat, a tenant user, and the sign-in steps the member scenarios do not
//! reach: her reset link read before she types, replaced and spent, the
//! code a reset asks for when her factor is mailed or texted, what the
//! sign-in page and her security page offer, a passkey added while her
//! sign-in waits for one and one that signs her in naming nobody, a setup
//! given up, and a frozen session lifted only by a code from her own
//! factor.
//!
//! - `reset_links`: a link reads as valid with its rules, spent, expired or
//!   worthless without being spent; a resend waits out its cooldown and
//!   retires the old link.
//! - `reset_codes`: a mailed or texted code is the second proof of a reset;
//!   a wrong one changes nothing; a forged link or an app factor gets none.
//! - `options`: what the sign-in page offers and what Pat may set up,
//!   holds and owes, read by nobody else.
//! - `passkeys`: a discoverable sign-in, a passkey set up as the factor a
//!   waiting sign-in owes, and renaming one.
//! - `enrollment`: a setup given up on the right proof starts over.
//! - `resume`: a frozen session lifted by a code from its own factor, and
//!   nobody else's.

mod enrollment;
mod options;
mod passkeys;
mod reset_codes;
mod reset_links;
mod resume;
mod support;
