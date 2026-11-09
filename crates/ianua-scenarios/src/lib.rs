//! The end-to-end scenarios' harness: the real platform started in the
//! test's own process, and everything a scenario needs to drive it from
//! outside, the way a customer's client would.
//!
//! The platform starts through the server's own composition root, from
//! settings, over a database cloned from the migrated template and the
//! shared cache and bus servers. It is reached only over the wire: HTTPS
//! through a TLS ingress, JSON in this crate's own types, cookies and
//! bearer tokens. Its mail lands in an SMTP receiver here and its texts in
//! a Twilio-shaped receiver here, so a scenario reads the links and codes
//! a person would.
//!
//! - [`stack`]: starting and stopping the platform for a [`stack::Profile`].
//! - [`net`]: the HTTP client each actor uses.
//! - [`wire`]: the requests and answers, and [`wire::Answer`].
//! - [`mail`] and [`sms`]: the receivers of the platform's mail and texts.
//! - [`api`]: typed calls by area, each a [`api::Request`].
//! - [`actors`]: who acts, each with their own client and credentials.
//! - [`authenticators`]: a person's own devices: an authenticator app, a
//!   passkey, recovery codes.
//! - [`world`]: a fresh organization, its tenant and twin, and the cast.
//! - [`agent`]: agents as an LLM SDK runs them, and the scripted model.
//! - [`upstreams`]: real apps behind the gateway, reporting what reached
//!   them.
//! - [`systems`]: a company's own databases in containers, for Protected
//!   data steps.
//! - [`services`]: outside apps people sign in to through the platform,
//!   checking its answers with code of their own.
//! - [`ldap`]: an application's LDAP client to the tenant directory.
//! - [`routes`]: a service, pipeline and route made through the API, and
//!   awaited until the gateway serves them.
//! - [`expect`]: the checks every step uses.
//! - [`memory`]: every byte the platform holds, counted, each test's
//!   report, and the check that a step repeated leaks nothing.
//!
//! Anything asynchronous is awaited with [`expect::eventually`], never
//! slept for.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod actors;
pub mod agent;
pub mod api;
pub mod authenticators;
pub mod automation;
pub mod clock;
pub mod expect;
pub(crate) mod inbox;
pub mod ldap;
pub mod mail;
pub mod memory;
pub mod net;
pub mod providers;
pub mod routes;
pub mod services;
pub mod sms;
pub mod stack;
pub mod systems;
pub mod upstreams;
pub mod wire;
pub mod world;
