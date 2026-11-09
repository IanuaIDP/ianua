//! What every integration a workflow's action steps call is built on.
//!
//! An integration is one outside service, such as GitHub or Slack, in a
//! crate of its own beside this one. Each implements [`Integration`]: how
//! it presents itself, the operations it declares to the workflow domain
//! and how it explains them, checking an account's credential, and the
//! call; and, where its service allows, signing in to connect an account
//! ([`connect`]) and the events a workflow may start on ([`events`]), whose
//! deliveries are proven with [`signature`]. A step reaching a system
//! behind a stream route, such as a company's own database, is handed a
//! connection the platform opened through the gateway and the login to
//! sign in with instead ([`data`]). The platform installs the ones
//! a deployment wants and finds a step's integration by its key; it opens
//! the account's credential itself and hands it only to an operation that
//! acts through an account.
//!
//! It works as the integrations' SDK. A REST service is mostly described
//! rather than written: [`rest`] makes a whole integration from a profile,
//! a table of steps, how an account reaches the service, and the request
//! that proves a credential, and checks the steps against the rules and
//! against the service's published API description. Below that sit the
//! parts it is built from, for a service that needs its own: writing a
//! profile and guides as text ([`describe`]), reading a step's arguments
//! ([`arguments`]), the address of a service ([`ServiceEndpoint`]), a
//! client that follows no redirect ([`client`]), and turning an answer into
//! a step's outcome ([`answer`]).

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

pub mod answer;
pub mod arguments;
mod client;
pub mod connect;
pub mod data;
pub mod describe;
mod endpoint;
pub mod events;
pub mod form;
mod integration;
pub mod picture;
pub mod rest;
pub mod signature;

pub use client::{ServiceReach, client, client_reaching};
pub use endpoint::ServiceEndpoint;
pub use integration::{Called, Checked, Integration, Renewed};
