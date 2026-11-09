//! A member's sessions as the company runs them, and the devices a
//! member remembers. Who sees and ends another member's session; what a
//! locked, deactivated or suspended account's session is worth; where a
//! session may move; how long it lives idle and in all; and when a
//! remembered device skips the second factor.
//!
//! - `members`: who sees who is signed in and who may end another
//!   member's session; a locked or deactivated member is out at once and
//!   answers like a wrong guess; a member with no tenant signs in alone
//!   and moves in once granted; naming a tenant at sign-in needs its
//!   grant; a lock midway through a sign-in spoils its mailed link.
//! - `suspension`: a suspended company ends its sessions and waiting
//!   sign-ins; the owner signs in afresh to lift it, and the member needs
//!   a fresh sign-in after.
//! - `devices`: only a sign-in that proved a factor may remember a
//!   device; from then on the password alone opens a session there, while
//!   any other device is asked for the factor; a forgotten device is asked
//!   again at once; a device secret needs the right password.
//! - `isolation`: a remembered device is listed and forgotten by its
//!   member alone; a session moves into a tenant only with a grant, and a
//!   refused move keeps the session it had.
//! - `lifetime`: a session idle too long or alive too long reads nothing
//!   until a fresh sign-in; a waiting sign-in cannot be finished after its
//!   deadline; the boundaries hold to the second.
//! - `trust`: remembered devices obey the company's limit, a changed
//!   password, their age and their account.

mod devices;
mod isolation;
mod lifetime;
mod members;
mod suspension;
mod trust;
