//! OAuth requests, read the way clients and browsers send them.
//!
//! Clients send forms (`application/x-www-form-urlencoded`) and name
//! themselves in the body or in an `Authorization: Basic` header; browsers
//! bring an authorization or sign-out request in the query string; apps
//! present access and registration tokens as `Bearer`. Each is read here
//! into what the app's use case takes, and a request that cannot be read is
//! answered in the protocol's own error shape.

pub mod authorization;
pub mod bearer;
pub mod client;
pub mod device;
pub mod dpop;
pub mod form;
pub mod logout;
pub mod pushed;
pub mod token;
pub mod tokens;
