//! Moving bytes between two sockets, and stopping when nothing moves.
//!
//! The copying is `tokio::io::copy_bidirectional`. What this adds is the
//! idle bound: a stream that carries nothing for the route's idle timeout
//! is closed, while one that keeps carrying bytes runs as long as it does.
//! Without it, a silent stream holds a file descriptor, a backend
//! connection and a decision made long ago, whose grant may be revoked by
//! now.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ianua_domain::types::Expiry;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio::time::Instant;

/// How a spliced stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpliceOutcome {
    /// One side closed and the other was told.
    Closed,
    /// Nothing moved either way for the idle timeout.
    IdleTimeout,
    /// The copy failed.
    Failed,
    /// The credential it was opened with expired.
    Expired,
    /// Its caller no longer holds: the credential was withdrawn, or the
    /// route no longer lets them in, or that could not be told in time.
    CallerLost,
}

impl SpliceOutcome {
    /// A short, stable reason for the record.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::IdleTimeout => "idle_timeout",
            Self::Failed => "failed",
            Self::Expired => "credential_expired",
            Self::CallerLost => "caller_lost",
        }
    }
}

/// Bytes moved each way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SpliceCounts {
    /// From the client to the backend.
    pub(super) to_backend: u64,
    /// From the backend to the client.
    pub(super) to_client: u64,
}

/// Copies between `client` and `backend` until one closes, the copy fails,
/// nothing moves either way for `idle`, or `held` ends with the outcome it
/// gives: a stream held to a credential closes when the credential does.
pub(super) async fn splice<C, B>(
    client: &mut C,
    backend: &mut B,
    idle: Duration,
    held: impl Future<Output = SpliceOutcome>,
) -> (SpliceOutcome, SpliceCounts)
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity::new();
    let mut client = Watched::new(client, &activity);
    let mut backend = Watched::new(backend, &activity);
    tokio::select! {
        copied = copy_bidirectional(&mut client, &mut backend) => outcome_of(&copied),
        () = activity.wait_for_idle(idle) => (SpliceOutcome::IdleTimeout, SpliceCounts::default()),
        ended = held => (ended, SpliceCounts::default()),
    }
}

/// What holds a stream that only its ends and its idle time close.
pub(super) async fn unheld() -> SpliceOutcome {
    std::future::pending().await
}

/// What holds a stream opened with a credential that stops working at
/// `expiry`: it ends then, and never for one that does not expire.
pub(super) async fn expiring(expiry: Expiry) -> SpliceOutcome {
    let Some(at) = expiry.instant() else {
        return unheld().await;
    };
    let left = Duration::try_from(at - OffsetDateTime::now_utc()).unwrap_or(Duration::ZERO);
    tokio::time::sleep(left).await;
    SpliceOutcome::Expired
}

/// The outcome a finished copy comes to.
fn outcome_of(copied: &io::Result<(u64, u64)>) -> (SpliceOutcome, SpliceCounts) {
    let Ok((to_backend, to_client)) = copied else {
        return (SpliceOutcome::Failed, SpliceCounts::default());
    };
    let counts = SpliceCounts {
        to_backend: *to_backend,
        to_client: *to_client,
    };
    (SpliceOutcome::Closed, counts)
}

/// When bytes last moved, either way.
struct Activity {
    start: Instant,
    last_millis: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    /// Notes that bytes moved now.
    fn touch(&self) {
        let millis = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    /// When bytes last moved.
    fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last_millis.load(Ordering::Relaxed))
    }

    /// Done once nothing has moved for `idle`.
    async fn wait_for_idle(&self, idle: Duration) {
        loop {
            let deadline = self.last() + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// A socket whose reads are noted in an [`Activity`].
struct Watched<'a, S> {
    inner: S,
    activity: &'a Activity,
}

impl<'a, S> Watched<'a, S> {
    fn new(inner: S, activity: &'a Activity) -> Self {
        Self { inner, activity }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.activity.touch();
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn copies_both_ways_until_close() {
        let (mut client, mut client_far) = duplex(64);
        let (mut backend, mut backend_far) = duplex(64);
        let spliced = tokio::spawn(async move {
            splice(
                &mut client_far,
                &mut backend_far,
                Duration::from_secs(5),
                unheld(),
            )
            .await
        });

        client.write_all(b"ping").await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut seen = Vec::new();
        backend.read_to_end(&mut seen).await.expect("read");
        backend.shutdown().await.expect("shutdown");
        let (outcome, counts) = spliced.await.expect("the splice ends");

        assert_eq!(seen, b"ping");
        assert_eq!(outcome, SpliceOutcome::Closed);
        assert_eq!(counts.to_backend, 4);
    }

    #[tokio::test]
    async fn a_silent_stream_is_closed_at_the_idle_timeout() {
        let (_client, mut client_far) = duplex(64);
        let (_backend, mut backend_far) = duplex(64);

        let (outcome, _) = splice(
            &mut client_far,
            &mut backend_far,
            Duration::from_millis(30),
            unheld(),
        )
        .await;

        assert_eq!(outcome, SpliceOutcome::IdleTimeout);
    }

    /// A stream with bytes waiting returns caller-lost when the future
    /// holding it resolves with that outcome.
    #[tokio::test]
    async fn a_stream_closes_when_what_holds_it_ends() {
        let (mut client, mut client_far) = duplex(64);
        let (_backend, mut backend_far) = duplex(64);
        client.write_all(b"busy").await.expect("write");

        let (outcome, _) = splice(
            &mut client_far,
            &mut backend_far,
            Duration::from_secs(5),
            async { SpliceOutcome::CallerLost },
        )
        .await;

        assert_eq!(outcome, SpliceOutcome::CallerLost);
    }

    /// A stream whose credential expires before its idle deadline returns
    /// the expired outcome.
    #[tokio::test]
    async fn a_stream_closes_when_its_credential_expires() {
        let (_client, mut client_far) = duplex(64);
        let (_backend, mut backend_far) = duplex(64);
        let soon = Expiry::At(OffsetDateTime::now_utc() + time::Duration::milliseconds(100));

        let (outcome, _) = splice(
            &mut client_far,
            &mut backend_far,
            Duration::from_secs(5),
            expiring(soon),
        )
        .await;

        assert_eq!(outcome, SpliceOutcome::Expired);
    }

    /// The idle bound is on silence, not on the stream's age: a stream that
    /// keeps carrying bytes outlives many idle windows.
    #[tokio::test]
    async fn a_busy_stream_outlives_the_idle_timeout() {
        let (mut client, mut client_far) = duplex(64);
        let (mut backend, mut backend_far) = duplex(64);
        let spliced = tokio::spawn(async move {
            splice(
                &mut client_far,
                &mut backend_far,
                Duration::from_millis(80),
                unheld(),
            )
            .await
        });

        let mut byte = [0u8; 1];
        for _ in 0..10 {
            client.write_all(b"x").await.expect("write");
            backend.read_exact(&mut byte).await.expect("read");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(!spliced.is_finished(), "a busy stream was closed as idle");

        client.shutdown().await.expect("shutdown");
        backend.shutdown().await.expect("shutdown");
        let (outcome, counts) = spliced.await.expect("the splice ends");
        assert_eq!(outcome, SpliceOutcome::Closed);
        assert_eq!(counts.to_backend, 10);
    }
}
