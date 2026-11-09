//! What the stages that look at a request before it is forwarded decide:
//! the web application firewall, CORS, the client fingerprint, the country
//! fence and MCP calls.
//!
//! An adapter reads the request (its text, its headers, its body, the TLS
//! hello) into the plain values these take. What those values come to is
//! decided here, so every gateway decides alike and each rule is tested
//! without a request in sight.

pub mod cors;
pub mod fingerprint;
pub mod geo_fence;
pub mod mcp;
pub mod waf;
