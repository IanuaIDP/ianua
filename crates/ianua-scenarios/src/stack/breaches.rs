//! A stand-in of the Pwned Passwords range service, so the platform's
//! password breach check runs without the internet and a scenario can
//! show a breached password refused.
//!
//! The platform asks through its real breach checker, pointed here by
//! `PASSWORD_BREACH_URL`. The stand-in answers the one call the checker
//! makes, `GET /range/{prefix}`, as the service does: the first five hex
//! characters of a password's SHA-1, in either case, answered with one
//! `SUFFIX:COUNT` line for each hash it knows under that prefix and a few
//! padding lines of count 0, as `text/plain`. A prefix that is not five
//! hex characters is `Status::BAD_REQUEST`, any other path `Status::NOT_FOUND`, any other method `Status::METHOD_NOT_ALLOWED`.
//! It knows [`BREACHED_PASSWORDS`] and nothing else, so every password a
//! scenario makes up reads as clean.

use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Method, Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ianua_boot::shutdown::Shutdown;
use sha1::{Digest as _, Sha1};
use tokio::net::TcpListener;

use crate::wire::Status;

/// Passwords the stand-in lists as breached, each strong enough for the
/// platform's own password rules and on no list of common passwords, so
/// the breach check is the only thing that refuses them.
pub const BREACHED_PASSWORDS: [&str; 3] = [
    "Velvet Quarry Lantern 7319",
    "Marble Kettle Orchid 4826",
    "Cobalt Meadow Parsnip 5502",
];

/// How often each breached password was seen, as the service counts it.
const TIMES_SEEN: [u64; 3] = [1_204, 87, 9_315];

/// How many hex characters a range's prefix holds.
const PREFIX_CHARS: usize = 5;

/// The padding lines every answer carries, of count 0, as the service
/// pads an answer when asked: suffixes no SHA-1 of a listed password ends
/// in.
const PADDING: [&str; 3] = [
    "0000000000000000000000000000000000A",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0",
    "123456789ABCDEF0123456789ABCDEF0123",
];

/// The stand-in of the range service, listening on a port of loopback.
pub(crate) struct Breaches {
    address: SocketAddr,
}

impl fmt::Debug for Breaches {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Breaches")
            .field("address", &self.address)
            .finish()
    }
}

impl Breaches {
    /// A stand-in listening on a port of loopback until `shutdown` stops
    /// it.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub(crate) async fn open(shutdown: &Shutdown) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        serve(listener, Arc::new(Listed::known()), shutdown);
        Ok(Self { address })
    }

    /// The service's address, for `PASSWORD_BREACH_URL`.
    #[must_use]
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

/// The hashes the stand-in knows, upper-case hex SHA-1, each with how often
/// it was seen.
struct Listed {
    hashes: Vec<(String, u64)>,
}

impl Listed {
    /// The hashes of [`BREACHED_PASSWORDS`].
    fn known() -> Self {
        let hashes = BREACHED_PASSWORDS
            .iter()
            .zip(TIMES_SEEN)
            .map(|(password, seen)| (sha1_hex(password), seen))
            .collect();
        Self { hashes }
    }

    /// The service's answer for `prefix`: a line for each hash under it,
    /// then the padding. `None` when `prefix` is not five hex characters.
    fn range(&self, prefix: &str) -> Option<String> {
        let valid = prefix.len() == PREFIX_CHARS && prefix.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid {
            return None;
        }
        let prefix = prefix.to_ascii_uppercase();
        let found = self.hashes.iter().filter_map(|(hash, seen)| {
            let suffix = hash.strip_prefix(prefix.as_str())?;
            Some(format!("{suffix}:{seen}"))
        });
        let padding = PADDING.iter().map(|suffix| format!("{suffix}:0"));
        Some(found.chain(padding).collect::<Vec<_>>().join("\r\n"))
    }
}

/// The SHA-1 of `password`, in upper-case hex as the service writes it.
fn sha1_hex(password: &str) -> String {
    Sha1::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// Takes connections on `listener` until `shutdown` stops it, each served
/// as a task of its own.
fn serve(listener: TcpListener, listed: Arc<Listed>, shutdown: &Shutdown) {
    let tasks = shutdown.clone();
    shutdown.spawn_until_stopped(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let listed = Arc::clone(&listed);
            tasks.spawn_until_stopped(async move {
                let service = service_fn(move |request| answered(request, Arc::clone(&listed)));
                let served = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                if let Err(error) = served {
                    tracing::debug!(%error, "a connection to the breach stand-in ended early");
                }
            });
        }
    });
}

/// The answer to one call: the range asked for, or the refusal.
async fn answered(
    request: Request<Incoming>,
    listed: Arc<Listed>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if *request.method() != Method::GET {
        return Ok(text(
            Status::METHOD_NOT_ALLOWED,
            "Method not allowed".to_owned(),
        ));
    }
    let Some(prefix) = request.uri().path().strip_prefix("/range/") else {
        return Ok(text(Status::NOT_FOUND, "Not found".to_owned()));
    };
    let Some(range) = listed.range(prefix) else {
        return Ok(text(
            Status::BAD_REQUEST,
            "The hash prefix was not in a valid format".to_owned(),
        ));
    };
    Ok(text(Status::OK, range))
}

/// `body` as a plain-text answer with `status`.
fn text(status: Status, body: String) -> Response<Full<Bytes>> {
    let mut answer = Response::new(Full::new(Bytes::from(body)));
    *answer.status_mut() = status;
    answer
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-1 of `password` split where the service splits it.
    fn split(password: &str) -> (String, String) {
        let hash = sha1_hex(password);
        let (prefix, suffix) = hash.split_at(PREFIX_CHARS);
        (prefix.to_owned(), suffix.to_owned())
    }

    /// The hash is the upper-case SHA-1 the service lists a password
    /// under.
    #[test]
    fn the_hash_is_upper_case_sha1() {
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    /// Each breached password's range lists its suffix with how often it
    /// was seen, asked in either case.
    #[test]
    fn a_breached_password_is_listed_with_its_count() {
        let listed = Listed::known();

        for (password, seen) in BREACHED_PASSWORDS.iter().zip(TIMES_SEEN) {
            let (prefix, suffix) = split(password);
            let range = listed.range(&prefix.to_ascii_lowercase()).unwrap();

            assert!(
                range.lines().any(|line| line == format!("{suffix}:{seen}")),
                "{password}"
            );
        }
    }

    /// A password the stand-in does not know reads as clean: its range
    /// holds only padding, of count 0.
    #[test]
    fn an_unlisted_password_reads_clean() {
        let (prefix, suffix) = split("Scenario harbour lantern meadow 1234");

        let range = Listed::known().range(&prefix).unwrap();

        assert!(range.lines().all(|line| line.ends_with(":0")));
        assert!(!range.contains(&suffix));
    }

    /// Empty, wrong-length and non-hexadecimal prefixes return no range.
    #[test]
    fn a_prefix_that_is_not_five_hex_characters_is_refused() {
        let listed = Listed::known();

        for prefix in ["", "ABCD", "ABCDEF", "ABCDG", "../.."] {
            assert!(listed.range(prefix).is_none(), "{prefix:?}");
        }
    }
}
