//! Stream routes: ports below HTTP, one listener per route.
//!
//! The HTTP side owns one listener and routes each request on its host and
//! path. Here the port is the routing key, so every stream route gets its
//! own socket, opened when the route appears and closed when it goes. The
//! [`StreamSupervisor`] keeps the bound ports equal to the routes the
//! directory lists, and the follower asks it to look again through the
//! [`StreamReload`] it hands out.
//!
//! Every connection is decided by the application before a byte moves. The
//! credential the wire carried, a client certificate the handshake
//! verified or the token a signed-in tunnel's `CONNECT` carries, is named
//! by
//! [`IdentifyStreamCallerUseCase`](ianua_app::use_cases::routing::stream_routes::IdentifyStreamCallerUseCase),
//! and
//! [`AdmitStreamConnectionUseCase`](ianua_app::use_cases::routing::stream_routes::AdmitStreamConnectionUseCase)
//! checks the route's server-name restriction and who it lets in. Anything
//! but an explicit admission, an error or a late answer included, closes
//! the connection. Every outbound dial has a timeout, every spliced stream
//! an idle timeout, every route a ceiling on what it carries at once, and a
//! stream opened with a credential closes when the credential expires; a
//! tunnel's token is checked again while it lasts. Each connection leaves
//! one record naming the route, who was on it, the decision and its
//! reason, never the bytes.
//!
//! What the wire can prove decides what a route can be: raw TCP, TLS
//! passthrough and UDP know no one, so they are public ports; a port that
//! ends TLS can name a certificate's consumer; the signed-in tunnel names
//! a person or a consumer by token. A route that ends TLS, the tunnel
//! included, is left unbound when the gateway was given nothing to end TLS
//! with: an unbound port refuses everyone.

mod admission;
mod backend;
mod listener;
mod route;
mod sni;
mod splice;
mod supervisor;
mod terminated;
mod tunnel;
mod udp;
mod workflow;

pub(crate) use route::TunnelChecks;
pub use supervisor::StreamPorts;
pub(crate) use supervisor::{StreamReload, StreamSettings, StreamSources, StreamSupervisor};
pub(crate) use workflow::DataEntry;
