//! The backend's answer on its way to the client.
//!
//! The body streams: each frame is passed on as it arrives and none is
//! kept. An ordinary answer is held to the gateway's response deadline, so
//! a backend that starts to answer and then trickles cannot hold a
//! connection forever. A long-lived one, server-sent events or a stream
//! the route marks, is meant to stay open, so it is held to an idle limit
//! instead: it may last as long as it keeps sending, and is cut off once it
//! goes quiet for longer. When a response stage will read the answer, it is
//! held to the inspection limit too, so a stage is never handed more than
//! it was built to read. A body that breaks any of these ends in an error
//! rather than quietly short.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use http::{Response, StatusCode, header};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use tokio::time::{Instant, Sleep};

use super::error::ForwardError;
use super::headers;
use super::pool::Lease;
use super::target::{ResponseInspection, ResponseSpan};

/// The media type of server-sent events, whose answer is long-lived by
/// nature.
const EVENT_STREAM: &str = "text/event-stream";

/// Why a backend's answer stopped short.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyError {
    /// It ran past the limit the pipeline inspects.
    #[error("the backend's answer is longer than the pipeline inspects")]
    TooLong,
    /// It was not done by the gateway's response deadline.
    #[error("the backend's answer took longer than the gateway allows")]
    TimedOut,
    /// A long-lived answer sent nothing for longer than the gateway allows.
    #[error("the backend's long-lived answer went quiet")]
    WentQuiet,
    /// The backend broke it off.
    #[error("the backend's answer broke off")]
    Broken(#[source] hyper::Error),
}

/// What an answer's time is held to.
#[derive(Debug, Clone, Copy)]
pub(super) struct Timing {
    /// When an ordinary answer must be done.
    pub(super) deadline: Instant,
    /// The longest a long-lived answer may send nothing.
    pub(super) idle: Duration,
    /// Whether the route marks its answers long-lived.
    pub(super) span: ResponseSpan,
}

/// How an answer's time is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pace {
    /// Done by this instant, whatever it sends.
    Deadline(Instant),
    /// Never quiet for longer than this.
    Idle(Duration),
}

impl Pace {
    /// When the answer is cut off if nothing changes.
    fn first_limit(self) -> Instant {
        match self {
            Self::Deadline(at) => at,
            Self::Idle(idle) => Instant::now() + idle,
        }
    }

    /// Moves the limit on after a frame arrived, for an answer held to its
    /// silences.
    fn reset_after_frame(self, limit: Pin<&mut Sleep>) {
        let Self::Idle(idle) = self else {
            return;
        };
        limit.reset(Instant::now() + idle);
    }

    /// The error of an answer cut off at its limit.
    fn ran_out(self) -> BodyError {
        match self {
            Self::Deadline(_) => BodyError::TimedOut,
            Self::Idle(_) => BodyError::WentQuiet,
        }
    }
}

/// A backend's answer, streamed and held to its bounds.
pub(crate) struct ResponseBody {
    inner: Inner,
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseBody").finish_non_exhaustive()
    }
}

/// What a body is.
enum Inner {
    /// Nothing, as after a protocol switch.
    Empty,
    /// A backend's answer, arriving.
    Streaming(Streaming),
}

/// A backend's answer and what holds it.
struct Streaming {
    body: Incoming,
    pace: Pace,
    cut_off: Pin<Box<Sleep>>,
    limit: Option<u64>,
    read: u64,
    _lease: Lease,
}

impl ResponseBody {
    /// A body with nothing in it.
    pub(super) fn empty() -> Self {
        Self {
            inner: Inner::Empty,
        }
    }

    /// `body`, kept to `pace` and at most `limit` bytes, keeping its
    /// backend counted as busy until it is done with.
    fn streaming(body: Incoming, limit: Option<u64>, pace: Pace, lease: Lease) -> Self {
        Self {
            inner: Inner::Streaming(Streaming {
                body,
                pace,
                cut_off: Box::pin(tokio::time::sleep_until(pace.first_limit())),
                limit,
                read: 0,
                _lease: lease,
            }),
        }
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match &mut self.get_mut().inner {
            Inner::Empty => Poll::Ready(None),
            Inner::Streaming(streaming) => streaming.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Inner::Empty => true,
            Inner::Streaming(streaming) => streaming.body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Inner::Empty => SizeHint::with_exact(0),
            Inner::Streaming(streaming) => streaming.body.size_hint(),
        }
    }
}

impl Streaming {
    /// The next frame, unless the answer's time ran out first.
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.cut_off.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(self.pace.ran_out())));
        }
        match ready!(Pin::new(&mut self.body).poll_frame(cx)) {
            Some(Ok(frame)) => {
                self.pace.reset_after_frame(self.cut_off.as_mut());
                Poll::Ready(Some(self.admit(frame)))
            }
            Some(Err(error)) => Poll::Ready(Some(Err(BodyError::Broken(error)))),
            None => Poll::Ready(None),
        }
    }

    /// `frame`, unless it carries the body past its limit.
    fn admit(&mut self, frame: Frame<Bytes>) -> Result<Frame<Bytes>, BodyError> {
        let size = frame.data_ref().map_or(0, Bytes::len);
        self.read = self
            .read
            .saturating_add(u64::try_from(size).unwrap_or(u64::MAX));
        let Some(limit) = self.limit else {
            return Ok(frame);
        };
        if self.read > limit {
            return Err(BodyError::TooLong);
        }
        Ok(frame)
    }
}

/// The client's answer from the backend's `response`.
///
/// The connection headers go. An answer that declares a body longer than
/// an inspecting pipeline reads is refused before any of it is read, and
/// one that switches protocols unasked is refused outright. The body is
/// kept to `timing`: to its idle limit when it is long-lived, to the
/// deadline otherwise.
///
/// # Errors
///
/// - [`ForwardError::UnexpectedSwitch`] when the backend answered `101`.
/// - [`ForwardError::ResponseTooLarge`] when the declared length is past
///   the inspection limit.
pub(super) fn answer(
    response: Response<Incoming>,
    lease: Lease,
    inspection: ResponseInspection,
    timing: Timing,
) -> Result<Response<ResponseBody>, ForwardError> {
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Err(ForwardError::UnexpectedSwitch);
    }
    let limit = inspection.limit();
    if declares_more_than(&response, limit) {
        return Err(ForwardError::ResponseTooLarge);
    }
    let pace = pace_of(&response, timing);
    let (mut parts, body) = response.into_parts();
    headers::strip_hop_by_hop(&mut parts.headers);
    let body = ResponseBody::streaming(body, limit, pace, lease);
    Ok(Response::from_parts(parts, body))
}

/// How `response`'s time is kept: by its silences when the route marks it
/// long-lived or it streams server-sent events, by the deadline otherwise.
fn pace_of<B>(response: &Response<B>, timing: Timing) -> Pace {
    let span = if streams_events(response) {
        ResponseSpan::LongLived
    } else {
        timing.span
    };
    match span {
        ResponseSpan::LongLived => Pace::Idle(timing.idle),
        ResponseSpan::Bounded => Pace::Deadline(timing.deadline),
    }
}

/// Whether `response` declares server-sent events.
fn streams_events<B>(response: &Response<B>) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(EVENT_STREAM))
}

/// Whether `response` declares a body longer than `limit`.
fn declares_more_than<B>(response: &Response<B>, limit: Option<u64>) -> bool {
    let Some(limit) = limit else {
        return false;
    };
    response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|length| length > limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaring(length: &str) -> Response<()> {
        Response::builder()
            .header(header::CONTENT_LENGTH, length)
            .body(())
            .unwrap()
    }

    #[test]
    fn a_declared_length_past_the_limit_is_caught_before_reading() {
        assert!(declares_more_than(&declaring("2048"), Some(1_024)));
        assert!(!declares_more_than(&declaring("1024"), Some(1_024)));
    }

    #[test]
    fn a_streamed_answer_has_no_limit() {
        assert!(!declares_more_than(&declaring("999999999"), None));
    }

    fn typed(content_type: &str) -> Response<()> {
        Response::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(())
            .unwrap()
    }

    fn timing(span: ResponseSpan) -> Timing {
        Timing {
            deadline: Instant::now() + Duration::from_secs(60),
            idle: Duration::from_secs(5),
            span,
        }
    }

    /// Server-sent events stay open as long as they keep sending, so they
    /// are held to their silences, whatever the route says.
    #[test]
    fn server_sent_events_are_held_to_their_silences() {
        let events = typed("Text/Event-Stream; charset=utf-8");

        let pace = pace_of(&events, timing(ResponseSpan::Bounded));

        assert_eq!(pace, Pace::Idle(Duration::from_secs(5)));
    }

    /// A chunked stream the route marks long-lived is held the same way.
    #[test]
    fn a_marked_stream_is_held_to_its_silences() {
        let pace = pace_of(
            &typed("application/x-ndjson"),
            timing(ResponseSpan::LongLived),
        );

        assert_eq!(pace, Pace::Idle(Duration::from_secs(5)));
    }

    /// An ordinary JSON answer selects the fixed response deadline rather than an idle limit.
    #[test]
    fn an_ordinary_answer_is_held_to_the_deadline() {
        let timing = timing(ResponseSpan::Bounded);

        let pace = pace_of(&typed("application/json"), timing);

        assert_eq!(pace, Pace::Deadline(timing.deadline));
    }

    #[test]
    fn an_empty_body_ends_at_once() {
        let body = ResponseBody::empty();

        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }
}
