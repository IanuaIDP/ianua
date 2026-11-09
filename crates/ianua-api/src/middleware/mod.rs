//! Axum middleware: tenant resolution, authentication, request metadata.
pub mod access_log;
pub(crate) mod answer_floor;
pub mod auth;
pub mod client_ip;
pub mod ip_rate_limit;
pub mod rate_limit;
pub mod request_metrics;
pub(crate) mod security_headers;
pub mod sign_in_admission;
pub mod unit_of_work;
pub mod user_rate_limit;
pub mod wording;
