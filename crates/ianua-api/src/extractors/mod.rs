//! What handlers take from a request: who is calling, the path, the query,
//! the body.
//!
//! Extractors read and parse. They check no permission: that is the app's.

pub(crate) mod time;

pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod calendar;
pub mod callers;
pub mod document;
pub mod federation;
pub mod form;
pub mod identity;
pub(crate) mod input_state;
pub mod json;
pub mod language;
pub(crate) mod listing;
pub mod messaging;
pub mod metrics_window;
pub mod oauth;
pub mod operator;
pub mod organization;
pub mod pagination;
pub mod paths;
pub mod public_tenant;
pub mod query;
pub mod realtime;
pub mod scim;
pub mod scim_filter;
pub mod signals;
pub mod sort;
pub mod tenant;
pub mod workflows;
