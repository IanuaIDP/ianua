//! `ianua-connector`: the small program a tenant runs inside its own
//! network, so a private service is reachable through the ianua gateway
//! without opening any inbound port.
//!
//! The connector dials out. It enrolls once with the one-time code an
//! admin was shown, holding a key it made itself and never sends; the
//! platform's connector authority signs a certificate for that key that
//! lasts a day, and the connector asks for the next one well before it
//! ends. With it, the connector opens one mutual TLS link to every address
//! the gateway's name resolves to and holds each open as HTTP/2, with the
//! gateway as the client. The gateway sends `CONNECT host:port` down a
//! link for each connection it needs; the connector dials the target only
//! when its allow list names it, and carries the bytes both ways unread.
//! Anything the list does not name, private addresses included, is
//! refused and never dialled.
//!
//! The connector holds no platform secret and refuses to start with one.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod api;
pub mod backoff;
pub mod config;
pub mod dial;
pub mod error;
pub mod link;
pub mod relay;
pub mod renewal;
pub mod serve;
pub mod state;
pub mod targets;
pub mod tls;

pub use serve::{Serving, run, serving};
