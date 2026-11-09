//! Refusals answered in gRPC's own terms.
//!
//! A gRPC client reads neither a page nor a JSON body: it reads
//! `grpc-status` and `grpc-message`, and an HTTP error status alone reaches
//! it as an opaque `UNKNOWN` or `UNAVAILABLE`. So a caller that sends
//! `application/grpc`, or gRPC-web's `application/grpc-web` and
//! `application/grpc-web-text`, is refused with a trailers-only answer:
//! HTTP 200, its own content type, no body, and the code and message in
//! the headers. Over HTTP/2 an answer with no body ends its stream on the
//! headers, which is gRPC's trailers-only response; gRPC-web clients read
//! the status from the headers of an empty answer the same way.
//!
//! The code is chosen from the refusal's status, the closest gRPC has for
//! what the gateway meant. The message is the refusal's generic code and
//! the request's reference, never the reason behind it.
//!
//! gRPC-web itself passes through untouched: it is ordinary HTTP/1.1 or
//! HTTP/2 with the trailers framed in the body, and the gateway streams
//! both ways and keeps trailers.

use http::HeaderMap;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use http_body_util::Full;
use hyper::body::Bytes;
use ianua_app::ports::pages::ErrorPage;
use ianua_domain::types::DenialStatus;

use crate::respond::error_page::Response;

/// The header gRPC reads a call's code from.
pub(crate) const GRPC_STATUS: &str = "grpc-status";

/// The header gRPC reads a call's message from.
pub(crate) const GRPC_MESSAGE: &str = "grpc-message";

/// The gRPC wire a caller speaks, read from the content type it sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrpcWire {
    /// gRPC over HTTP/2, `application/grpc` and its `+proto` forms.
    Grpc,
    /// gRPC-web in binary, `application/grpc-web` and its `+proto` forms.
    Web,
    /// gRPC-web in base64 text, `application/grpc-web-text`.
    WebText,
}

impl GrpcWire {
    /// The wire the request sending `headers` speaks, or `None` when it is
    /// no gRPC call.
    #[must_use]
    pub(crate) fn of(headers: &HeaderMap) -> Option<Self> {
        let sent = headers.get(CONTENT_TYPE)?.to_str().ok()?;
        Self::from_content_type(sent)
    }

    /// The wire a content type of `sent` names. The type is compared
    /// without its parameters and in any case.
    fn from_content_type(sent: &str) -> Option<Self> {
        let media = sent.split(';').next()?.trim().to_ascii_lowercase();
        let (base, _) = media.split_once('+').unwrap_or((media.as_str(), ""));
        match base {
            "application/grpc" => Some(Self::Grpc),
            "application/grpc-web" => Some(Self::Web),
            "application/grpc-web-text" => Some(Self::WebText),
            _ => None,
        }
    }

    /// The content type the answer is sent with.
    fn content_type(self) -> &'static str {
        match self {
            Self::Grpc => "application/grpc",
            Self::Web => "application/grpc-web",
            Self::WebText => "application/grpc-web-text",
        }
    }
}

/// A gRPC status code, as `grpc-status` carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrpcCode {
    /// `INVALID_ARGUMENT`, 3.
    InvalidArgument,
    /// `DEADLINE_EXCEEDED`, 4.
    DeadlineExceeded,
    /// `NOT_FOUND`, 5.
    NotFound,
    /// `PERMISSION_DENIED`, 7.
    PermissionDenied,
    /// `RESOURCE_EXHAUSTED`, 8.
    ResourceExhausted,
    /// `INTERNAL`, 13.
    Internal,
    /// `UNAVAILABLE`, 14.
    Unavailable,
    /// `UNAUTHENTICATED`, 16.
    Unauthenticated,
}

impl GrpcCode {
    /// The code closest to what a refusal with `status` means. A status
    /// with no closer code is `INTERNAL`, never `OK`.
    #[must_use]
    pub(crate) fn of(status: DenialStatus) -> Self {
        match status.code() {
            400 | 405 | 411 | 414 | 415 | 431 => Self::InvalidArgument,
            401 => Self::Unauthenticated,
            403 => Self::PermissionDenied,
            404 => Self::NotFound,
            408 | 504 => Self::DeadlineExceeded,
            413 | 429 => Self::ResourceExhausted,
            421 | 502 | 503 => Self::Unavailable,
            _ => Self::Internal,
        }
    }

    /// The number `grpc-status` carries.
    #[must_use]
    pub(crate) fn number(self) -> u8 {
        match self {
            Self::InvalidArgument => 3,
            Self::DeadlineExceeded => 4,
            Self::NotFound => 5,
            Self::PermissionDenied => 7,
            Self::ResourceExhausted => 8,
            Self::Internal => 13,
            Self::Unavailable => 14,
            Self::Unauthenticated => 16,
        }
    }
}

/// The trailers-only answer refusing a `wire` call as `page` says.
#[must_use]
pub(crate) fn grpc_refusal(wire: GrpcWire, page: &ErrorPage) -> Response {
    let code = GrpcCode::of(page.status);
    let message = format!("{} (reference {})", page.kind.code(), page.reference);
    let built = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(CONTENT_TYPE, wire.content_type())
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(GRPC_STATUS, code.number().to_string())
        .header(GRPC_MESSAGE, message)
        .body(Full::new(Bytes::new()));
    built.unwrap_or_else(|_| internal(wire))
}

/// The bare `INTERNAL` answer, should the refusal itself not build.
fn internal(wire: GrpcWire) -> Response {
    let mut bare = http::Response::new(Full::new(Bytes::new()));
    let headers = bare.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        http::HeaderValue::from_static(wire.content_type()),
    );
    headers.insert(GRPC_STATUS, http::HeaderValue::from_static("13"));
    bare
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use http_body_util::BodyExt;
    use ianua_app::ports::pages::ErrorPageKind;
    use ianua_domain::types::CorrelationId;

    use super::*;

    fn sending(content_type: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers
    }

    #[test]
    fn a_grpc_call_is_known_by_its_content_type() {
        for (sent, wire) in [
            ("application/grpc", GrpcWire::Grpc),
            ("application/grpc+proto", GrpcWire::Grpc),
            ("Application/GRPC; charset=utf-8", GrpcWire::Grpc),
            ("application/grpc-web", GrpcWire::Web),
            ("application/grpc-web+proto", GrpcWire::Web),
            ("application/grpc-web-text", GrpcWire::WebText),
            ("application/grpc-web-text+proto", GrpcWire::WebText),
        ] {
            assert_eq!(GrpcWire::of(&sending(sent)), Some(wire), "{sent}");
        }
    }

    #[test]
    fn anything_else_is_no_grpc_call() {
        for sent in ["application/json", "application/grpcx", "text/html", ""] {
            assert_eq!(GrpcWire::of(&sending(sent)), None, "{sent}");
        }
        assert_eq!(GrpcWire::of(&HeaderMap::new()), None);
    }

    /// Every refusal maps to a failing code: none ever reads as `OK`.
    #[test]
    fn every_refusal_is_a_failing_code() {
        for kind in ErrorPageKind::ALL {
            assert_ne!(GrpcCode::of(kind.status()).number(), 0, "{kind:?}");
        }
        assert_eq!(
            GrpcCode::of(DenialStatus::TOO_MANY_REQUESTS),
            GrpcCode::ResourceExhausted
        );
        assert_eq!(
            GrpcCode::of(DenialStatus::UNAUTHORIZED),
            GrpcCode::Unauthenticated
        );
        assert_eq!(
            GrpcCode::of(DenialStatus::FORBIDDEN),
            GrpcCode::PermissionDenied
        );
    }

    /// Sam's gRPC call is refused for a missing permission. He gets a
    /// trailers-only answer: 200, no body, `PERMISSION_DENIED` and the
    /// generic code with the reference.
    #[tokio::test]
    async fn a_refused_grpc_call_reads_permission_denied() {
        let page = ErrorPage::new(ErrorPageKind::Forbidden, CorrelationId::new());

        let answer = grpc_refusal(GrpcWire::Grpc, &page);

        assert_eq!(answer.status(), http::StatusCode::OK);
        assert_eq!(answer.headers()[CONTENT_TYPE], "application/grpc");
        assert_eq!(answer.headers()[GRPC_STATUS], "7");
        assert_eq!(
            answer.headers()[GRPC_MESSAGE],
            format!("forbidden (reference {})", page.reference).as_str()
        );
        let body = answer.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    /// A gRPC-web caller is answered in its own content type.
    #[test]
    fn a_grpc_web_call_is_answered_as_grpc_web() {
        let page = ErrorPage::new(ErrorPageKind::TooManyRequests, CorrelationId::new());

        let answer = grpc_refusal(GrpcWire::WebText, &page);

        assert_eq!(answer.headers()[CONTENT_TYPE], "application/grpc-web-text");
        assert_eq!(answer.headers()[GRPC_STATUS], "8");
    }
}
