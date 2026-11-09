//! The one Twilio call the stand-in answers: creating a message.

use std::convert::Infallible;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Response};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;

use super::{Text, TwilioAccount};
use crate::inbox::Inbox;
use crate::stack::secrets;
use crate::wire::Status;

/// The largest form taken.
const LARGEST_FORM: usize = 64 * 1024;

/// What the stand-in checks each call against, and where it files the
/// texts.
pub(super) struct Desk {
    messages_path: String,
    authorization: String,
    inbox: Inbox<Text>,
}

impl Desk {
    /// The desk taking calls for `account`, filing texts in `inbox`.
    pub(super) fn new(account: &TwilioAccount, inbox: Inbox<Text>) -> Self {
        let login = STANDARD.encode(format!("{}:{}", account.sid, account.auth_token));
        Self {
            messages_path: format!("/2010-04-01/Accounts/{}/Messages.json", account.sid),
            authorization: format!("Basic {login}"),
            inbox,
        }
    }
}

/// Takes connections on `listener` until `shutdown` stops it, each served
/// as a task of its own.
pub(super) fn serve(listener: TcpListener, desk: Desk, shutdown: &Shutdown) {
    let desk = Arc::new(desk);
    let tasks = shutdown.clone();
    shutdown.spawn_until_stopped(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let desk = Arc::clone(&desk);
            tasks.spawn_until_stopped(async move {
                let service = service_fn(move |request| answered(request, Arc::clone(&desk)));
                let served = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                if let Err(error) = served {
                    tracing::debug!(%error, "a connection to the Twilio stand-in ended early");
                }
            });
        }
    });
}

/// Why a call was refused, as Twilio would answer it.
struct Refusal {
    status: Status,
    message: &'static str,
}

impl Refusal {
    fn new(status: Status, message: &'static str) -> Self {
        Self { status, message }
    }

    /// The refusal as Twilio's error body.
    fn answer(&self) -> Response<Full<Bytes>> {
        let body = serde_json::json!({
            "code": self.status.as_u16(),
            "message": self.message,
            "status": self.status.as_u16(),
        });
        json(self.status, &body)
    }
}

/// The answer to one call: the message created and filed, or the refusal.
async fn answered(
    request: Request<Incoming>,
    desk: Arc<Desk>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let text = match text_of(request, &desk).await {
        Ok(text) => text,
        Err(refusal) => return Ok(refusal.answer()),
    };
    let to = text.to.clone();
    desk.inbox.deliver(&to, text).await;
    let created = serde_json::json!({
        "sid": format!("SM{}", secrets::hex(16)),
        "to": to,
        "status": "queued",
    });
    Ok(json(Status::CREATED, &created))
}

/// The text a call asks to create, once it is the messages call of the
/// right account with its credentials and its fields.
async fn text_of(request: Request<Incoming>, desk: &Desk) -> Result<Text, Refusal> {
    ensure_messages_call(&request, desk)?;
    ensure_signed_in(&request, desk)?;
    let form = form_of(request).await?;
    let field = |name: &str| {
        form.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let Some(to) = field("To") else {
        return Err(Refusal::new(
            Status::BAD_REQUEST,
            "A 'To' phone number is required.",
        ));
    };
    let Some(body) = field("Body") else {
        return Err(Refusal::new(
            Status::BAD_REQUEST,
            "A message body is required.",
        ));
    };
    let Some(sender) = field("From").or_else(|| field("MessagingServiceSid")) else {
        return Err(Refusal::new(
            Status::BAD_REQUEST,
            "A 'From' phone number or a Messaging Service is required.",
        ));
    };
    Ok(Text { to, sender, body })
}

/// Refuses anything but a `POST` to the account's messages.
fn ensure_messages_call(request: &Request<Incoming>, desk: &Desk) -> Result<(), Refusal> {
    if request.uri().path() != desk.messages_path {
        return Err(Refusal::new(
            Status::NOT_FOUND,
            "The requested resource was not found.",
        ));
    }
    if *request.method() != Method::POST {
        return Err(Refusal::new(
            Status::METHOD_NOT_ALLOWED,
            "Method not allowed.",
        ));
    }
    Ok(())
}

/// Refuses a call without the account's credentials.
fn ensure_signed_in(request: &Request<Incoming>, desk: &Desk) -> Result<(), Refusal> {
    let given = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if given != Some(desk.authorization.as_str()) {
        return Err(Refusal::new(Status::UNAUTHORIZED, "Authenticate"));
    }
    Ok(())
}

/// The form a call carries, read up to the largest taken.
async fn form_of(request: Request<Incoming>) -> Result<Vec<(String, String)>, Refusal> {
    let encoded = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
    if !encoded {
        return Err(Refusal::new(
            Status::UNSUPPORTED_MEDIA_TYPE,
            "The body must be form encoded.",
        ));
    }
    let collected = Limited::new(request.into_body(), LARGEST_FORM)
        .collect()
        .await
        .map_err(|_| Refusal::new(Status::PAYLOAD_TOO_LARGE, "The body is too large."))?;
    let bytes = collected.to_bytes();
    Ok(url::form_urlencoded::parse(&bytes).into_owned().collect())
}

/// `body` as a JSON answer with `status`.
fn json(status: Status, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let mut answer = Response::new(Full::new(Bytes::from(body.to_string())));
    *answer.status_mut() = status;
    answer.headers_mut().insert(
        CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    answer
}
