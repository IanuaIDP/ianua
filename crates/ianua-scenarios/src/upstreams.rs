//! Real apps behind the gateway, each started for one scenario on a port of
//! loopback and stopped when dropped:
//!
//! - [`Echo`]: answers every request with what reached it, and checks the
//!   gateway's `X-Ianua-Assertion` against the keys the tenant publishes,
//!   reporting who the gateway says the caller is.
//! - [`Hanging`]: takes every request and never answers.
//! - [`Failing`]: drops every connection before answering.
//! - [`CannedApp`]: answers each path it knows with a fixed answer, such as
//!   a JSON record full of personal fields.
//! - [`OutsideService`]: takes one account's credential and counts what
//!   reached it, the service a workflow delivers to.
//! - [`LetterEmbeddings`]: an embedding server speaking OpenAI's
//!   embeddings API, its vectors counting letters.
//! - [`Pipe`]: takes bodies and gives them a piece at a time, showing
//!   the gateway holds none of them whole.
//! - [`SocketApp`]: speaks WebSocket, answering every message it hears.
//! - [`OutsideReceiver`]: a customer's own HTTPS service at a public-looking
//!   name under a private authority, which webhooks, streams and
//!   integrations are posted to.
//!
//! Each keeps what reached it, so a scenario can say that a refused request
//! never got there.

pub mod assertion;
mod canned;
mod echo;
mod embeddings;
mod outside;
mod pipe;
mod receiver;
mod serving;
mod silent;
mod socket;

pub use assertion::{AssertedCaller, AssertionCheck};
pub use canned::{Canned, CannedApp, Received};
pub use echo::{ASSERTION_HEADER, Arrival, Echo, KEY_SET_PATH};
pub use embeddings::{Embedded, LETTER_VECTOR_SIZE, LetterEmbeddings};
pub use outside::{OUTSIDE_CREDENTIAL, OutsideService};
pub use pipe::{DownloadSizes, Pipe, Uploaded, digest_of, pattern};
pub use receiver::OutsideReceiver;
pub use silent::{Failing, Hanging};
pub use socket::SocketApp;
