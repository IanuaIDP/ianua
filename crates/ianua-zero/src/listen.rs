//! Where connections come in.
//!
//! The accept loops for HTTP and HTTPS ([`Listener`]) take each connection
//! under a permit ([`ConnectionPermits`]), read its opening within a
//! timeout (a PROXY protocol header only from a trusted ingress,
//! [`ProxyProtocol`]), end TLS with the certificate served for the name
//! the client asked for ([`CertificateTable`]) and the client-certificate
//! verification of the tenant behind it ([`ClientAuthTable`]), and hand the
//! connection to the [`Handler`] the caller supplies, with what was learned
//! on the way ([`ConnectionFacts`]: the client, the name asked for, the
//! verified client certificate, the JA4 fingerprint). Port 80 answers
//! HTTP-01 challenges and sends everything else to HTTPS
//! ([`AcmeResponder`]). A stream route's port ends TLS through
//! [`StreamTls`], held to the tenant whose port it is, with the same
//! certificates and client-certificate verification. The listeners inside
//! the deployment's network, the connector and internal ones, speak
//! [`InternalTls`]: one certificate of the platform's served, and on all but
//! the runner listener a client certificate of one authority required.
//!
//! Nothing here decides about a request. What is refused here is refused
//! about the connection: a header from a peer not trusted to send one, a
//! name no certificate is served for, a client certificate the tenant's
//! authorities did not sign, an opening or a handshake that took too long.
//! The tables are filled and kept current by the caller.

mod acme;
mod activity;
mod certificates;
mod client_auth;
mod connection;
mod handler;
mod hello;
mod internal_tls;
mod ja4;
mod listener;
mod permits;
mod proxy_header;
mod rewind;
mod stream_tls;
mod tls;

pub(crate) use acme::AcmeResponder;
pub(crate) use certificates::{CertificateTable, PlatformCertificate};
pub(crate) use client_auth::{ClientAuthTable, TenantMtls};
#[cfg(test)]
pub(crate) use connection::ConnectionParts;
pub(crate) use connection::{ClientCertificate, ConnectionFacts, HostCheck};
pub(crate) use handler::{BodyError, Handler, HttpLimits};
pub(crate) use internal_tls::{
    InternalTls, ListenerPem, MutualTlsError, ServedPem, server_config as mutual_server_config,
    server_only_config,
};
pub(crate) use ja4::Ja4;
pub(crate) use listener::{ListenLimits, Listener, Transport};
pub(crate) use permits::ConnectionPermits;
pub(crate) use proxy_header::ProxyProtocol;
#[cfg(test)]
pub(crate) use stream_tls::fixtures as stream_tls_fixtures;
pub(crate) use stream_tls::{StreamHandshake, StreamTls, StreamTlsSources, TerminatedStream};
pub(crate) use tls::{ServedNames, TlsSources, TlsTerminator};
