//! Services that carry messages: chat, mail and texts.
//!
//! - `discord`: the bot's token is checked before it is kept, and a run
//!   posts a message that pings nobody and starts a thread from it; the
//!   server picked for the form is never sent.
//! - `gmail`: the grant is exchanged for a token before it is kept, and a
//!   run sends a whole email in `raw` and stars the message sent.
//! - `mailgun`: the key is checked before it is kept, and a run mails a
//!   report as Mailgun's form, one `to` per recipient.
//! - `slack`: the bot token is checked before it is kept, and a run posts
//!   to a channel through it; a message Slack refuses with success and
//!   `"ok": false` fails the run.
//! - `teams`: the grant is exchanged for a token, kept and reused, and a
//!   run posts to a channel and replies in its thread.
//! - `telegram`: the bot's token is part of the address and nowhere else,
//!   and a run sends a message and pins it.
//! - `twilio`: the account's SID and token are checked before they are
//!   kept, and a run texts the person on call at the account's own place.

mod discord;
mod gmail;
mod mailgun;
mod slack;
mod teams;
mod telegram;
mod twilio;
