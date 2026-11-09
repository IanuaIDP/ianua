//! Hearing about what happened: a tenant user's inbox and a company
//! member's inbox, the unread count on the bell, notices read one at a
//! time or all at once, and the channel each person chooses per category.
//!
//! - `audit_streams`: the tenant's audit records streamed to Acme's
//!   collector, its credential never read back, private addresses refused
//!   and a silent collector noted against the stream.
//! - `bus`: the rest of the tenant's message bus: schemas, a topic's
//!   settings and end, subscriptions, signed pushes and agent channels.
//! - `inbox`: Pat finds a role given and taken back in her tenant inbox,
//!   reads one notice and then all; only she can mark them, Uma is told
//!   nothing about Pat, and reading leaves no audit record.
//! - `live`: the bell's WebSocket: Pat and Ann each hear their own notice
//!   as it happens and Uma hears nothing of it; a stream is refused to
//!   anyone who may not read that inbox and closes once Pat signs out.
//! - `messages`: the courier's service pulls each order once through the
//!   tenant's message bus; a refused order is set aside and replayed; a
//!   paused subscription or topic stops the flow; nobody without the right
//!   publishes or pulls.
//! - `members`: Ann hears in her company inbox of a change Tess made in a
//!   tenant and reads it; Max cannot mark her notices.
//! - `preferences`: Pat switches notices about roles off yet still hears
//!   of her own; Ann switches them off and hears no more; nobody else
//!   changes either choice.
//! - `webhooks`: Tess subscribes Acme's server, is shown its secret once,
//!   addresses inside the deployment are refused, each attempt is kept,
//!   and she pauses, rotates and deletes; nobody without the right can.

#![cfg(test)]

mod audit_streams;
mod bus;
mod inbox;
mod live;
mod members;
mod messages;
mod preferences;
mod support;
mod webhooks;
