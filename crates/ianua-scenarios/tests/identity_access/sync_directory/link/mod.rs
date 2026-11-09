//! The link itself, as Tess keeps it: the token that opens exactly one
//! tenant's directory, a link paused and switched back on, and what the
//! endpoint does with the people it makes.
//!
//! - `tokens`: a token opens only its own tenant; no token, a wrong one, a
//!   wrong scheme and an unknown tenant are all refused alike.
//! - `pausing`: only Tess pauses a link, a paused link refuses its token,
//!   switched back on the same token works again, and the link's status
//!   tells it all and no secret.
//! - `settings`: a role with built-in power is never given automatically,
//!   a harmless one is and stays protected while named; people may wait
//!   for their own mailbox or be sent in switched off.

mod pausing;
mod settings;
mod tokens;
