//! What goes over the wire, in this crate's own types: the requests a
//! scenario sends, the answers it reads, and [`Answer`] around each.
//!
//! None of these is the API's own type. Each says what a scenario relies
//! on, so a change to the API's JSON breaks a scenario as it would break a
//! customer's client. Fields a scenario does not read are left out and
//! ignored when they come.

pub mod account;
pub mod activity;
pub mod agents;
mod answer;
pub mod api_keys;
pub mod app_sign_in;
pub mod attributes;
pub mod audit;
pub mod audit_streams;
pub mod billing;
pub mod branding;
pub mod classification;
pub mod cloud;
pub mod connections;
pub mod consumers;
pub mod control_access;
pub mod crypto;
pub mod destinations;
pub mod directory;
pub mod domains;
mod exchange;
pub mod factors;
pub mod federation;
pub mod gateway;
pub mod memories;
pub mod messaging;
pub mod notifications;
pub mod oauth;
pub mod onboarding;
pub mod operators;
pub mod organization;
mod page;
pub mod people;
pub mod policies;
mod problem;
pub mod registration;
pub mod roles;
pub mod routing;
pub mod saml_apps;
pub mod sandboxes;
pub mod sign_in;
pub mod signals;
pub mod tenant_sign_in;
pub mod tenants;
pub mod webhooks;
pub mod workflows;

pub use answer::Answer;
pub(crate) use answer::Arrived;
pub use exchange::Exchange;
pub(crate) use exchange::{Received, Sent};
/// HTTP response statuses with standard names and readable failure messages.
pub use http::StatusCode as Status;
pub use page::Page;
pub use problem::Problem;
