//! Traffic the gateway carries rather than decides: a WebSocket kept open
//! through it, bodies moved a piece at a time and held to a limit, a person
//! held to a request count, and what the gateway answers when what it
//! relies on has gone away or an app hangs. Whatever is unavailable, a
//! request is refused rather than let through undecided.
//!
//! - `sockets`: Pat talks to an app over WebSocket, the app verifying her
//!   name at the handshake; nobody signed in gets a handshake through, an
//!   app whose answers are inspected refuses the switch, and her open
//!   socket closes when she is suspended or taken out of the route's group
//!   while a colleague's stays open.
//! - `bodies`: an upload reaches the app while it is still being sent and
//!   a download reaches the client while it is still being written; a body
//!   past the limit is refused and the app never gets it whole.
//! - `limits`: each person is held to their own count, told when to come
//!   back, and let in again in the next window; a counter that cannot be
//!   reached refuses rather than counts nothing.
//! - `outages`: while the database is out nobody's session can be checked,
//!   so nobody is let in, until it comes back.
//! - `crowding`: requests hung on a stuck app hold nobody else up.

mod bodies;
mod crowding;
mod limits;
mod outages;
mod sockets;
