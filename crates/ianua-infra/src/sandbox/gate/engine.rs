//! The Docker Engine API, spoken over its local socket: the few calls the
//! gate makes to run one container and remove it.
//!
//! Each call opens a connection of its own, so a call that hangs holds
//! nothing else up, and each is held to a time. A container's streams are
//! attached before it starts, so nothing it writes is missed, and read as
//! the engine frames them: standard output and standard error apart.

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_TYPE, HOST, UPGRADE};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::net::UnixStream;

use crate::sandbox::output::Memory;

/// How long one call to the engine may take, but a pull.
const CALL_WITHIN: Duration = Duration::from_secs(30);

/// The most bytes of an answer the engine gives that are read.
const MOST_ANSWERED: usize = 8 * 1024 * 1024;

/// The label every container the gate starts carries.
pub(super) const SANDBOX_LABEL: (&str, &str) = ("ianua.io/sandbox", "code");

/// What a call came to.
struct Called {
    status: StatusCode,
    body: Bytes,
}

/// The engine behind one socket.
pub(super) struct Engine {
    socket: PathBuf,
}

impl Engine {
    /// The engine listening on `socket`.
    pub(super) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// Makes container `name` as `spec` describes, pulling its image once
    /// when the engine does not hold it, within `pull_within`; its id.
    pub(super) async fn create(
        &self,
        name: &str,
        spec: &Value,
        pull_within: Duration,
    ) -> Result<String, String> {
        let path = format!("/containers/create?name={name}");
        let made = self.call(Method::POST, &path, Some(spec)).await?;
        let made = match made.status {
            StatusCode::NOT_FOUND => {
                let image = text_at(spec, "Image").unwrap_or_default();
                tokio::time::timeout(pull_within, self.pull(image, None))
                    .await
                    .map_err(|_| {
                        format!("the image was not pulled within {}s", pull_within.as_secs())
                    })??;
                self.call(Method::POST, &path, Some(spec)).await?
            }
            _ => made,
        };
        let created = expect(made, StatusCode::CREATED, "the container was not made")?;
        let id = serde_json::from_slice::<Value>(&created)
            .ok()
            .and_then(|made| text_at(&made, "Id").map(str::to_owned));
        id.ok_or_else(|| "the engine named no container".to_owned())
    }

    /// Attaches to container `id`'s input and output, before it starts.
    pub(super) async fn attach(&self, id: &str) -> Result<TokioIo<Upgraded>, String> {
        let mut sender = self.connected().await?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "http://docker/containers/{id}/attach?stream=1&stdin=1&stdout=1&stderr=1"
            ))
            .header(HOST, "docker")
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "tcp")
            .body(Full::new(Bytes::new()))
            .map_err(|error| format!("the attach could not be asked: {error}"))?;
        let response = tokio::time::timeout(CALL_WITHIN, sender.send_request(request))
            .await
            .map_err(|_| "the engine did not answer the attach in time".to_owned())?
            .map_err(|error| format!("the attach failed: {error}"))?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(format!(
                "the engine refused the attach: {}",
                response.status()
            ));
        }
        let upgraded = hyper::upgrade::on(response)
            .await
            .map_err(|error| format!("the attach was not opened: {error}"))?;
        Ok(TokioIo::new(upgraded))
    }

    /// Starts container `id`.
    pub(super) async fn start(&self, id: &str) -> Result<(), String> {
        let started = self
            .call(Method::POST, &format!("/containers/{id}/start"), None)
            .await?;
        expect(
            started,
            StatusCode::NO_CONTENT,
            "the container was not started",
        )
        .map(drop)
    }

    /// Container `id`'s exit status, once it has ended.
    pub(super) async fn wait(&self, id: &str) -> Result<Option<i32>, String> {
        let waited = self
            .call(Method::POST, &format!("/containers/{id}/wait"), None)
            .await?;
        let waited = expect(waited, StatusCode::OK, "the container's end was not read")?;
        let status = serde_json::from_slice::<Value>(&waited)
            .ok()
            .and_then(|waited| waited.get("StatusCode").and_then(Value::as_i64))
            .and_then(|status| i32::try_from(status).ok());
        Ok(status)
    }

    /// Whether the kernel killed container `id` for its memory.
    pub(super) async fn memory(&self, id: &str) -> Memory {
        let inspected = self
            .call(Method::GET, &format!("/containers/{id}/json"), None)
            .await;
        let killed = inspected
            .ok()
            .and_then(|inspected| serde_json::from_slice::<Value>(&inspected.body).ok())
            .and_then(|inspected| {
                inspected
                    .get("State")
                    .and_then(|state| state.get("OOMKilled"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false);
        match killed {
            true => Memory::OverItsLimit,
            false => Memory::WithinItsLimit,
        }
    }

    /// Kills container `id`, which outlived its time.
    pub(super) async fn kill(&self, id: &str) {
        if let Err(why) = self
            .call(Method::POST, &format!("/containers/{id}/kill"), None)
            .await
        {
            tracing::warn!(%why, container = %id, "a code container could not be killed");
        }
    }

    /// Removes container `id`, running or not, with its anonymous volumes.
    pub(super) async fn remove(&self, id: &str) {
        let removed = self
            .call(
                Method::DELETE,
                &format!("/containers/{id}?force=true&v=true"),
                None,
            )
            .await;
        let gone = removed.is_ok_and(|removed| {
            matches!(
                removed.status,
                StatusCode::NO_CONTENT | StatusCode::NOT_FOUND
            )
        });
        if !gone {
            tracing::warn!(container = %id, "a code container could not be removed");
        }
    }

    /// The ids of every container the gate started, left by a gate that
    /// stopped mid-run.
    pub(super) async fn leftovers(&self) -> Result<Vec<String>, String> {
        let filter = format!(r#"{{"label":["{}={}"]}}"#, SANDBOX_LABEL.0, SANDBOX_LABEL.1);
        let query: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("all", "true")
            .append_pair("filters", &filter)
            .finish();
        let listed = self
            .call(Method::GET, &format!("/containers/json?{query}"), None)
            .await?;
        let listed = expect(listed, StatusCode::OK, "the containers were not listed")?;
        let listed = serde_json::from_slice::<Vec<Value>>(&listed)
            .map_err(|error| format!("the containers' list is unreadable: {error}"))?;
        Ok(listed
            .iter()
            .filter_map(|container| text_at(container, "Id").map(str::to_owned))
            .collect())
    }

    /// Pulls `image`, with `login` as the engine's `X-Registry-Auth` when
    /// there is one, reading the engine's progress to its end.
    pub(super) async fn pull(&self, image: &str, login: Option<&str>) -> Result<(), String> {
        let query: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("fromImage", image)
            .finish();
        let mut sender = self.connected().await?;
        let mut request = request(Method::POST, &format!("/images/create?{query}"), None)?;
        if let Some(login) = login {
            let value = http::HeaderValue::from_str(login)
                .map_err(|_| "the registry login is no header value".to_owned())?;
            request.headers_mut().insert("x-registry-auth", value);
        }
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("the pull failed: {error}"))?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MOST_ANSWERED)
            .collect()
            .await
            .map_err(|error| format!("the pull's progress was not read: {error}"))?
            .to_bytes();
        match (status, pull_error(&body)) {
            (StatusCode::OK, None) => Ok(()),
            (_, Some(why)) => Err(format!("the image was not pulled: {why}")),
            (status, None) => Err(format!("the image was not pulled: {status}")),
        }
    }

    /// Calls the engine at `path` with `body`, within a time.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Called, String> {
        let called = tokio::time::timeout(CALL_WITHIN, async {
            let mut sender = self.connected().await?;
            let response = sender
                .send_request(request(method, path, body)?)
                .await
                .map_err(|error| format!("the engine call failed: {error}"))?;
            let status = response.status();
            let body = Limited::new(response.into_body(), MOST_ANSWERED)
                .collect()
                .await
                .map_err(|error| format!("the engine's answer was not read: {error}"))?
                .to_bytes();
            Ok(Called { status, body })
        });
        called
            .await
            .unwrap_or_else(|_| Err("the engine did not answer in time".to_owned()))
    }

    /// A connection to the engine, driven in the background until its
    /// answer, or its attached streams, are done with.
    async fn connected(&self) -> Result<http1::SendRequest<Full<Bytes>>, String> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|error| format!("the engine's socket could not be reached: {error}"))?;
        let (sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| format!("the engine did not shake hands: {error}"))?;
        tokio::spawn(async move {
            if let Err(error) = connection.with_upgrades().await {
                tracing::debug!(%error, "a connection to the engine ended");
            }
        });
        Ok(sender)
    }
}

/// A request to the engine at `path`, with `body` as JSON.
fn request(
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Request<Full<Bytes>>, String> {
    let body = body.map(Value::to_string).unwrap_or_default();
    Request::builder()
        .method(method)
        .uri(format!("http://docker{path}"))
        .header(HOST, "docker")
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| format!("the engine call could not be made: {error}"))
}

/// `called`'s body when it came back `wanted`, or why not, after `what`.
fn expect(called: Called, wanted: StatusCode, what: &str) -> Result<Bytes, String> {
    if called.status == wanted {
        return Ok(called.body);
    }
    let said = serde_json::from_slice::<Value>(&called.body)
        .ok()
        .and_then(|said| text_at(&said, "message").map(str::to_owned))
        .unwrap_or_default();
    Err(format!("{what}: {} {said}", called.status))
}

/// The text at `field` of `value`, when it holds one.
fn text_at<'v>(value: &'v Value, field: &str) -> Option<&'v str> {
    value.get(field).and_then(Value::as_str)
}

/// What a container wrote to standard output, at most `most_answer` bytes
/// and one more, and the last `most_errors` bytes of standard error, read
/// from the engine's frames until they end.
///
/// # Errors
///
/// When the stream fails before its end.
pub(super) async fn demuxed(
    mut reader: impl AsyncRead + Unpin,
    most_answer: usize,
    most_errors: usize,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut answer = Vec::new();
    let mut errors = Vec::new();
    loop {
        let mut header = [0_u8; 8];
        match reader.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok((answer, errors));
            }
            Err(error) => return Err(error),
        }
        let [stream, _, _, _, size @ ..] = header;
        let mut frame = Vec::new();
        (&mut reader)
            .take(u64::from(u32::from_be_bytes(size)))
            .read_to_end(&mut frame)
            .await?;
        match stream {
            1 => keep_first(&mut answer, &frame, most_answer.saturating_add(1)),
            2 => keep_last(&mut errors, &frame, most_errors),
            _ => {}
        }
    }
}

/// `held` with as much of `frame` as fits within `most`.
fn keep_first(held: &mut Vec<u8>, frame: &[u8], most: usize) {
    let room = most.saturating_sub(held.len());
    held.extend_from_slice(frame.get(..room.min(frame.len())).unwrap_or_default());
}

/// `held` with `frame`, keeping only its last `most` bytes.
fn keep_last(held: &mut Vec<u8>, frame: &[u8], most: usize) {
    held.extend_from_slice(frame);
    let over = held.len().saturating_sub(most);
    held.drain(..over);
}

/// The error a pull's progress reports, the engine writing one JSON value
/// per line; `None` when it reports none.
fn pull_error(progress: &[u8]) -> Option<String> {
    String::from_utf8_lossy(progress)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|line| text_at(&line, "error").map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(stream: u8, body: &[u8]) -> Vec<u8> {
        let mut framed = vec![stream, 0, 0, 0];
        framed.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(body);
        framed
    }

    /// Standard output and standard error are read apart from the engine's
    /// frames, in order.
    #[tokio::test]
    async fn the_streams_are_read_apart() {
        let framed = [
            frame(2, b"making a slug\n"),
            frame(1, br#"{"slug":"#),
            frame(1, br#""fix"}"#),
        ]
        .concat();

        let (answer, errors) = demuxed(framed.as_slice(), 64, 64).await.unwrap();

        assert_eq!(answer, br#"{"slug":"fix"}"#);
        assert_eq!(errors, b"making a slug\n");
    }

    /// An answer is held to its bound and one byte more, and of the errors
    /// only their end is kept, however much the code writes.
    #[tokio::test]
    async fn each_stream_is_held_within_its_bound() {
        let framed = [
            frame(1, &[b'x'; 100]),
            frame(2, b"first"),
            frame(2, b"the end"),
        ]
        .concat();

        let (answer, errors) = demuxed(framed.as_slice(), 10, 7).await.unwrap();

        assert_eq!(answer.len(), 11);
        assert_eq!(errors, b"the end");
    }
}
