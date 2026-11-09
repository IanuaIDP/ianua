//! Pat's second factors in the tenant, each proved where it is delivered
//! before it counts, and what the tenant's rules make of a sign-in that
//! is half way through.
//!
//! - `codes`: a code mailed or texted proves its mailbox or number, and
//!   then answers only the sign-in it was sent for.
//! - `recovery`: a recovery code lets Pat replace her lost phone before
//!   she is let in, under a tenant that requires a factor.
//! - `interruption`: an authenticator half set up survives a restart and
//!   a failed audit write, and is confirmed once.
//! - `password_change`: a temporary password Tess set is replaced only
//!   with Pat's own phone, and once.
//! - `policy`: a code is refused once the tenant demands hardware and
//!   accepted once it relents; a low risk threshold asks for the mailbox,
//!   and a low denial threshold turns Pat away until it is raised.

mod codes;
mod interruption;
mod password_change;
mod policy;
mod recovery;
