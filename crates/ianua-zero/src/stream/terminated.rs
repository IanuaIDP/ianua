//! A port that ends TLS: the handshake, the caller its client certificate
//! names, the route's answer, then the decrypted stream spliced to the
//! backend.
//!
//! The handshake is held to the tenant whose port it is: its names, its
//! certificates and, on a mutual-TLS route, its authorities. A certificate
//! the handshake verified is named by the application: its consumer, or an
//! unnamed certificate when no consumer holds it. A connection presenting
//! none is nobody. The route then says whether that caller may pass, and a
//! stream opened with a consumer's certificate closes when the certificate
//! stops working.

use std::net::SocketAddr;

use ianua_app::use_cases::routing::stream_routes::{
    IdentifiedStreamCaller, StreamConnectionCaller, StreamCredential,
};
use ianua_domain::types::{DomainName, Expiry};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use super::admission::{Gate, Shut};
use super::route::{ConnectionRecord, ServedRoute};
use super::splice::{expiring, splice};
use crate::listen::{ClientCertificate, StreamHandshake, TerminatedStream};

/// Ends TLS on one connection as `asked` says, decides it, then splices it
/// to a backend or closes it.
pub(super) async fn carry(
    route: &ServedRoute,
    client: TcpStream,
    peer: SocketAddr,
    asked: StreamHandshake,
) {
    let mut record = route.record(peer);
    let (mut stream, expiry) = match admitted(route, &mut record, client, asked).await {
        Ok(admitted) => admitted,
        Err(shut) => {
            record.report_refusal(shut);
            return;
        }
    };
    let mut backend = match route.dial().await {
        Ok(dialled) => dialled,
        Err(failure) => {
            record.unreachable(&failure);
            return;
        }
    };
    let (outcome, counts) = splice(
        &mut stream,
        &mut backend.stream,
        route.idle_limit(),
        expiring(expiry),
    )
    .await;
    record.report_close(&backend.authority, outcome, counts);
}

/// The decrypted stream of a connection the route admits, and when the
/// credential it was admitted on stops working.
///
/// # Errors
///
/// - The [`Shut`] of a refused handshake, a credential that named no one,
///   or a caller the route does not let in.
async fn admitted(
    route: &ServedRoute,
    record: &mut ConnectionRecord<'_>,
    client: TcpStream,
    asked: StreamHandshake,
) -> Result<(TlsStream<TcpStream>, Expiry), Shut> {
    let TerminatedStream {
        stream,
        server_name,
        client_certificate,
    } = route.terminate(client, asked).await?;
    record.record_server_name(Some(server_name.clone()));
    let named = caller_of(route, server_name.clone(), client_certificate).await?;
    record.record_caller(named.caller.clone());
    if let Gate::Closed(shut) = route.gate(Some(server_name), named.caller).await {
        return Err(shut);
    }
    Ok((stream, named.expiry))
}

/// Who the certificate the handshake made of names: its holder, as the
/// application names them, or nobody when none was verified.
async fn caller_of(
    route: &ServedRoute,
    server_name: DomainName,
    certificate: ClientCertificate,
) -> Result<IdentifiedStreamCaller, Shut> {
    let ClientCertificate::Verified(fingerprint) = certificate else {
        return Ok(IdentifiedStreamCaller {
            caller: StreamConnectionCaller::Nobody,
            expiry: Expiry::Never,
        });
    };
    route
        .identify(server_name, StreamCredential::Certificate(fingerprint))
        .await
}
