//! What Mallory finds at the gateway's own door, below HTTP: it speaks
//! only current TLS, a plain-text request gets no page, a client that
//! sends its request slowly to hold a connection open is cut off, and a
//! connection opened for one name is never used for another.

use std::sync::Arc;
use std::time::Duration;

use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// How long the gateway waits for a request's head, set short here.
const HEADER_WAIT_SECONDS: &str = "2";

/// Past the header wait, by when a slow client has been cut off.
const CUT_OFF_BY: Duration = Duration::from_secs(6);

/// How long a refused connection is given to say so.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// A TLS 1.0 ClientHello offering one old cipher suite and nothing newer,
/// as a client that never moved past it sends it.
const TLS_1_0_HELLO: [u8; 50] = [
    0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0x00, 0x00, 0x29, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
];

/// The type a TLS record carrying a handshake message has.
const HANDSHAKE_RECORD: u8 = 0x16;

/// Mallory cannot negotiate TLS 1.0. The gateway alerts or closes without
/// sending a handshake, and a current TLS client still connects afterwards.
#[tokio::test]
async fn the_gateway_never_agrees_to_old_tls() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut mallory = TcpStream::connect(stack.gateway())
        .await
        .expect("the gateway takes the connection");

    mallory
        .write_all(&TLS_1_0_HELLO)
        .await
        .expect("the hello is sent");
    let mut answer = [0_u8; 1];
    let read = timeout(ANSWER_WITHIN, mallory.read(&mut answer))
        .await
        .expect("the gateway answers or closes in time");

    let agreed = matches!(read, Ok(1) if answer[0] == HANDSHAKE_RECORD);
    assert!(!agreed, "the gateway went on with a TLS 1.0 handshake");
    gateway_still_accepts_tls(&stack).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory receives no HTTP page after sending plaintext to the TLS port.
/// The connection ends promptly and a current TLS client remains usable.
#[tokio::test]
async fn a_plain_text_request_gets_no_page() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut mallory = TcpStream::connect(stack.gateway())
        .await
        .expect("the gateway takes the connection");
    let host = format!("shop.{}", stack.apps_domain());

    mallory
        .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .expect("the request is sent");
    let mut answer = Vec::new();
    let _closed = timeout(ANSWER_WITHIN, mallory.read_to_end(&mut answer))
        .await
        .expect("the plaintext connection ends in time");

    assert!(
        !answer.starts_with(b"HTTP/"),
        "a plain-text request got a page: {}",
        String::from_utf8_lossy(&answer)
    );
    gateway_still_accepts_tls(&stack).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory cannot hold a connection indefinitely with incomplete headers.
/// The configured head timeout closes it while a fresh TLS client still connects.
#[tokio::test]
async fn a_client_sending_its_request_slowly_is_cut_off() {
    let stack = Stack::start(
        Profile::standard().with("GATEWAY_HEADER_TIMEOUT_SECONDS", HEADER_WAIT_SECONDS),
    )
    .await
    .expect("the stack starts");
    let host = format!("shop.{}", stack.apps_domain());
    let mut mallory = tls_to_gateway(&stack, &host).await;

    mallory
        .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n").as_bytes())
        .await
        .expect("the start of the head is sent");
    let cut_off = timeout(CUT_OFF_BY, send_slow_headers(&mut mallory)).await;

    assert!(
        cut_off.is_ok(),
        "a client still sending its head after {CUT_OFF_BY:?} was not cut off"
    );
    gateway_still_accepts_tls(&stack).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Keeps extending the incomplete head until the gateway closes the connection.
async fn send_slow_headers(mallory: &mut TlsStream<TcpStream>) {
    loop {
        if mallory.write_all(b"X-Slow: 1\r\n").await.is_err() {
            return;
        }
        let mut answer = [0_u8; 512];
        if let Ok(Ok(0) | Err(_)) =
            timeout(Duration::from_millis(500), mallory.read(&mut answer)).await
        {
            return;
        }
    }
}

/// Mallory opens TLS for her own host and requests another host. The
/// gateway returns a misdirected request and fresh TLS connections still work.
#[tokio::test]
async fn a_connection_opened_for_one_name_is_never_used_for_another() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let own = format!("mallory.{}", stack.apps_domain());
    let other = format!("shop.{}", stack.apps_domain());
    let mut mallory = tls_to_gateway(&stack, &own).await;

    mallory
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {other}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("the request is sent");
    let mut answer = Vec::new();
    timeout(ANSWER_WITHIN, mallory.read_to_end(&mut answer))
        .await
        .expect("the misdirected request ends in time")
        .expect("the refusal is read");

    let status_line = String::from_utf8_lossy(&answer)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    assert!(
        status_line.split_whitespace().nth(1) == Some(Status::MISDIRECTED_REQUEST.as_str()),
        "a request for another name than the connection's was not misdirected: {status_line:?}"
    );
    gateway_still_accepts_tls(&stack).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A TLS connection to the gateway for `name`, trusting the stack's test
/// authority as a client of the stack does.
async fn tls_to_gateway(stack: &Stack, name: &str) -> TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    let certificate = CertificateDer::from_pem_slice(stack.root_certificate_pem().as_bytes())
        .expect("the test authority's certificate reads");
    roots
        .add(certificate)
        .expect("the test authority is a root");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(name.to_owned()).expect("a server name");
    let tcp = TcpStream::connect(stack.gateway())
        .await
        .expect("the gateway takes the connection");
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .expect("the TLS handshake with the gateway completes")
}

/// Confirms a refused connection did not stop the gateway accepting current TLS.
async fn gateway_still_accepts_tls(stack: &Stack) {
    let host = format!("shop.{}", stack.apps_domain());
    timeout(ANSWER_WITHIN, tls_to_gateway(stack, &host))
        .await
        .expect("a fresh TLS connection completes in time");
}
