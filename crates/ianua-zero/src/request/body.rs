//! Reading the start of a request body before deciding on it, while every
//! byte still streams on to the upstream.
//!
//! The pipeline says how much it needs ([`BodyNeed`]): usually nothing, and
//! the body is never touched. When a stage must see it, the gateway reads
//! at most that many bytes, whatever `Content-Length` claims (a declared
//! length is exactly what a caller dodging a scan would lie about), and
//! hands back a body that replays them before the rest of the stream. The
//! whole body is never held in memory.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::HeaderMap;
use hyper::body::{Body, Bytes, Frame, SizeHint};
use ianua_domain::domains::proxy::request::body::{BodyExtent, BodyNeed};

/// How much the gateway sets aside up front for a prefix, whatever the cap.
/// A small body never reserves a large cap's worth of memory.
const FIRST_RESERVE: usize = 64 * 1024;

/// What the gateway read of a body before deciding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyRead {
    /// Nothing asked for the body, so none of it was read.
    Unread,
    /// The first bytes, up to the pipeline's cap.
    Read {
        /// The bytes read.
        prefix: Bytes,
        /// Whether they are all of the body.
        extent: BodyExtent,
    },
}

/// A body after its peek: what was read, and the body to forward, which
/// replays it first.
pub(crate) struct Peeked<B> {
    read: BodyRead,
    body: PrefixThenBody<B>,
}

impl<B> Peeked<B> {
    /// What was read before deciding.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn read(&self) -> &BodyRead {
        &self.read
    }

    /// What was read, and the whole body to forward.
    #[must_use]
    pub(crate) fn into_parts(self) -> (BodyRead, PrefixThenBody<B>) {
        (self.read, self.body)
    }
}

/// Why a body could not be peeked.
#[derive(Debug)]
pub(crate) enum PeekError<E> {
    /// The client's body failed while the prefix was read.
    Body(E),
    /// The client did not send the prefix within the deadline.
    TimedOut,
}

impl<E> std::fmt::Display for PeekError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Body(_) => "the request body failed while it was read",
            Self::TimedOut => "the request body was not sent in time",
        })
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PeekError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(error) => Some(error),
            Self::TimedOut => None,
        }
    }
}

/// Reads as much of `body` as `need` asks, within `deadline`, and returns
/// it beside a body that still yields every byte.
///
/// With [`BodyNeed::Nothing`] nothing is read and the body streams as it
/// came.
///
/// # Errors
///
/// - [`PeekError::Body`] when the client's body fails during the read.
/// - [`PeekError::TimedOut`] when the prefix is not in by `deadline`; a
///   client trickling bytes must not hold the request open.
pub(crate) async fn peek<B>(
    body: B,
    need: BodyNeed,
    deadline: Duration,
) -> Result<Peeked<B>, PeekError<B::Error>>
where
    B: Body<Data = Bytes> + Unpin,
{
    let BodyNeed::Prefix(cap) = need else {
        return Ok(Peeked {
            read: BodyRead::Unread,
            body: PrefixThenBody::passing(body),
        });
    };
    let cap = usize::try_from(cap.get()).unwrap_or(usize::MAX);
    tokio::time::timeout(deadline, read_prefix(body, cap))
        .await
        .map_err(|_| PeekError::TimedOut)?
        .map_err(PeekError::Body)
}

/// Reads up to `cap` bytes of `body`, keeping any trailers it passes.
async fn read_prefix<B>(mut body: B, cap: usize) -> Result<Peeked<B>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut prefix = Prefix::new(cap);
    while prefix.room() > 0 {
        let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        else {
            return Ok(prefix.whole());
        };
        let leftover = prefix.take(frame?);
        if !leftover.is_empty() {
            return Ok(prefix.cut(leftover, body));
        }
    }
    Ok(prefix.cut(Bytes::new(), body))
}

/// The bytes read so far, and any trailers passed on the way.
struct Prefix {
    cap: usize,
    collected: Vec<u8>,
    trailers: Option<HeaderMap>,
}

impl Prefix {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            collected: Vec::with_capacity(cap.min(FIRST_RESERVE)),
            trailers: None,
        }
    }

    fn room(&self) -> usize {
        self.cap - self.collected.len()
    }

    /// Takes what fits of `frame`, returning what does not.
    ///
    /// A trailers frame carries no data; it is kept to be sent after the
    /// body, since gRPC puts `grpc-status` there.
    fn take(&mut self, frame: Frame<Bytes>) -> Bytes {
        let mut data = match frame.into_data() {
            Ok(data) => data,
            Err(other) => {
                self.keep_trailers(other);
                return Bytes::new();
            }
        };
        let leftover = data.split_off(data.len().min(self.room()));
        self.collected.extend_from_slice(&data);
        leftover
    }

    /// Keeps `frame` when it carries trailers.
    fn keep_trailers(&mut self, frame: Frame<Bytes>) {
        let Ok(trailers) = frame.into_trailers() else {
            return;
        };
        self.trailers = Some(trailers);
    }

    /// The body ended within the cap: the prefix is all of it.
    fn whole<B>(self) -> Peeked<B> {
        let prefix = Bytes::from(self.collected);
        Peeked {
            read: BodyRead::Read {
                prefix: prefix.clone(),
                extent: BodyExtent::Whole,
            },
            body: PrefixThenBody::replaying(prefix, Bytes::new(), None, self.trailers),
        }
    }

    /// The cap was reached: `leftover` of the last frame and the rest of
    /// `body` follow the prefix.
    fn cut<B>(self, leftover: Bytes, body: B) -> Peeked<B> {
        let prefix = Bytes::from(self.collected);
        Peeked {
            read: BodyRead::Read {
                prefix: prefix.clone(),
                extent: BodyExtent::Prefix,
            },
            body: PrefixThenBody::replaying(prefix, leftover, Some(body), self.trailers),
        }
    }
}

/// A body that yields the bytes a peek read, then the rest of the stream,
/// then any trailers the peek passed over.
pub(crate) struct PrefixThenBody<B> {
    pending: VecDeque<Bytes>,
    inner: Option<B>,
    trailers: Option<HeaderMap>,
}

impl<B> PrefixThenBody<B> {
    /// `body` as it came, nothing read ahead.
    fn passing(body: B) -> Self {
        Self {
            pending: VecDeque::new(),
            inner: Some(body),
            trailers: None,
        }
    }

    /// `prefix`, then `leftover`, then `inner`, then `trailers`.
    fn replaying(
        prefix: Bytes,
        leftover: Bytes,
        inner: Option<B>,
        trailers: Option<HeaderMap>,
    ) -> Self {
        let pending = [prefix, leftover]
            .into_iter()
            .filter(|chunk| !chunk.is_empty())
            .collect();
        Self {
            pending,
            inner,
            trailers,
        }
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for PrefixThenBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(chunk) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if let Some(inner) = self.inner.as_mut() {
            match Pin::new(inner).poll_frame(cx) {
                Poll::Ready(None) => {}
                other => return other,
            }
            self.inner = None;
        }
        Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_empty()
            && self.trailers.is_none()
            && self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        let pending: u64 = self.pending.iter().map(|chunk| chunk.len() as u64).sum();
        if self.trailers.is_some() {
            let mut hint = SizeHint::new();
            hint.set_lower(pending);
            return hint;
        }
        let Some(inner) = &self.inner else {
            return SizeHint::with_exact(pending);
        };
        let inner = inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(pending + inner.lower());
        if let Some(upper) = inner.upper() {
            hint.set_upper(pending + upper);
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http_body_util::{BodyExt, StreamBody};
    use ianua_domain::domains::proxy::request::body::ByteCap;
    use proptest::prelude::*;

    use super::*;

    const DEADLINE: Duration = Duration::from_secs(5);

    fn body_of(chunks: Vec<&'static str>) -> impl Body<Data = Bytes, Error = Infallible> + Unpin {
        StreamBody::new(futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|chunk| Ok(Frame::data(Bytes::from_static(chunk.as_bytes())))),
        ))
    }

    fn with_trailers(
        chunks: Vec<&'static str>,
    ) -> impl Body<Data = Bytes, Error = Infallible> + Unpin {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        let data = chunks
            .into_iter()
            .map(|chunk| Ok(Frame::data(Bytes::from_static(chunk.as_bytes()))));
        StreamBody::new(futures_util::stream::iter(
            data.chain(std::iter::once(Ok(Frame::trailers(trailers)))),
        ))
    }

    fn prefix(bytes: u64) -> BodyNeed {
        BodyNeed::Prefix(ByteCap::new(bytes).unwrap())
    }

    async fn all_of<B>(body: B) -> Vec<u8>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    /// A four-byte peek returns only the requested prefix while forwarding
    /// every byte of the three-chunk body in order.
    #[tokio::test]
    async fn the_cap_is_respected_and_the_rest_streams() {
        let sent = body_of(vec!["0123456789", "abcdef", "rest"]);

        let peeked = peek(sent, prefix(4), DEADLINE).await.unwrap();

        let (read, body) = peeked.into_parts();
        assert_eq!(
            read,
            BodyRead::Read {
                prefix: Bytes::from_static(b"0123"),
                extent: BodyExtent::Prefix,
            }
        );
        assert_eq!(all_of(body).await, b"0123456789abcdefrest");
    }

    #[tokio::test]
    async fn a_body_shorter_than_the_cap_is_read_whole() {
        let peeked = peek(body_of(vec!["hello", " world"]), prefix(100), DEADLINE)
            .await
            .unwrap();

        let (read, body) = peeked.into_parts();
        assert_eq!(
            read,
            BodyRead::Read {
                prefix: Bytes::from_static(b"hello world"),
                extent: BodyExtent::Whole,
            }
        );
        assert_eq!(all_of(body).await, b"hello world");
    }

    #[tokio::test]
    async fn a_body_nothing_needs_is_not_read() {
        let peeked = peek(body_of(vec!["abc"]), BodyNeed::Nothing, DEADLINE)
            .await
            .unwrap();

        assert_eq!(peeked.read(), &BodyRead::Unread);
        assert_eq!(all_of(peeked.into_parts().1).await, b"abc");
    }

    /// gRPC puts `grpc-status` in trailers; a peek that walked past them
    /// would leave the client waiting for a status that never comes.
    #[tokio::test]
    async fn trailers_survive_the_peek() {
        for need in [prefix(3), prefix(100)] {
            let peeked = peek(with_trailers(vec!["12345", "67890"]), need, DEADLINE)
                .await
                .unwrap();

            let collected = peeked.into_parts().1.collect().await.unwrap();
            assert_eq!(collected.trailers().unwrap()["grpc-status"], "0");
            assert_eq!(collected.to_bytes(), Bytes::from_static(b"1234567890"));
        }
    }

    /// A client that sends headers and then nothing does not hold the
    /// request past the deadline.
    #[tokio::test]
    async fn a_client_that_never_sends_the_body_times_out() {
        let silent = StreamBody::new(futures_util::stream::pending::<
            Result<Frame<Bytes>, Infallible>,
        >());

        let peeked = peek(silent, prefix(10), Duration::from_millis(20)).await;

        assert!(matches!(peeked, Err(PeekError::TimedOut)));
    }

    /// Peeks `chunks` with a cap of `cap` and forwards the rest.
    fn peeked_and_forwarded(chunks: Vec<Vec<u8>>, cap: u64) -> (BodyRead, Vec<u8>) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let frames = chunks
            .into_iter()
            .map(|chunk| Ok::<_, Infallible>(Frame::data(Bytes::from(chunk))));
        let body = StreamBody::new(futures_util::stream::iter(frames));
        runtime.block_on(async {
            let peeked = peek(body, prefix(cap), DEADLINE).await.unwrap();
            let (read, body) = peeked.into_parts();
            (read, all_of(body).await)
        })
    }

    fn any_chunks() -> impl Strategy<Value = Vec<Vec<u8>>> {
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..20), 0..8)
    }

    proptest! {
        /// Whatever the cap and however the body is split, the prefix is the
        /// body's start and never longer than the cap, it is called whole
        /// only when it is, and the forwarded body is every byte in order.
        #[test]
        fn every_byte_is_forwarded_and_the_prefix_never_passes_the_cap(
            chunks in any_chunks(),
            cap in 1u64..64,
        ) {
            let sent: Vec<u8> = chunks.concat();

            let (read, forwarded) = peeked_and_forwarded(chunks, cap);

            let BodyRead::Read { prefix: head, extent } = read else {
                return Err(TestCaseError::fail("a prefix was asked for"));
            };
            prop_assert!(head.len() as u64 <= cap);
            prop_assert_eq!(&head[..], &sent[..head.len()]);
            if extent == BodyExtent::Whole {
                prop_assert_eq!(head.len(), sent.len());
            }
            if (sent.len() as u64) < cap {
                prop_assert_eq!(extent, BodyExtent::Whole);
            }
            prop_assert_eq!(forwarded, sent);
        }
    }
}
