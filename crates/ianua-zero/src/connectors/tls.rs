//! The TLS the connector listener speaks: mutual TLS, a client certificate
//! required of every connector and checked against the connector authority
//! alone, and HTTP/2 as the only protocol.

use std::sync::Arc;

use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::CryptoProvider;

use crate::listen::{ListenerPem, MutualTlsError, mutual_server_config};

/// The only protocol a link speaks.
pub(super) const LINK_PROTOCOL: &[u8] = b"h2";

/// The connector listener's TLS on `provider`, as `pem` describes it.
///
/// # Errors
///
/// Any [`MutualTlsError`].
pub(crate) fn server_config(
    provider: &Arc<CryptoProvider>,
    pem: &ListenerPem,
) -> Result<Arc<ServerConfig>, MutualTlsError> {
    mutual_server_config(provider, pem, &[LINK_PROTOCOL])
}
