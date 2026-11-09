//! How long a connection has moved no bytes.
//!
//! A client that opens a connection and then sends nothing, or trickles a
//! byte now and then, holds a permit for as long as it likes unless
//! something notices. Every byte read or written is noted here, and a
//! connection quiet for longer than its limit is closed. Upgraded tunnels
//! run over the same stream, so their traffic counts too.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// When a connection last moved a byte.
#[derive(Debug)]
pub(crate) struct Clock {
    opened: Instant,
    last_moved_ms: AtomicU64,
}

impl Clock {
    fn started() -> Self {
        Self {
            opened: Instant::now(),
            last_moved_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        self.last_moved_ms
            .store(whole_millis(self.opened.elapsed()), Ordering::Relaxed);
    }

    fn quiet_for(&self) -> Duration {
        let last_moved = Duration::from_millis(self.last_moved_ms.load(Ordering::Relaxed));
        self.opened.elapsed().saturating_sub(last_moved)
    }

    /// Done once the connection has moved nothing for `limit`.
    pub(crate) async fn quiet(&self, limit: Duration) {
        loop {
            let quiet = self.quiet_for();
            if quiet >= limit {
                return;
            }
            tokio::time::sleep(limit - quiet).await;
        }
    }
}

fn whole_millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// A stream whose every byte moved is noted on its [`Clock`].
#[derive(Debug)]
pub(crate) struct Tracked<S> {
    inner: S,
    clock: Arc<Clock>,
}

/// `inner`, tracked, and the clock it moves.
pub(crate) fn track<S>(inner: S) -> (Tracked<S>, Arc<Clock>) {
    let clock = Arc::new(Clock::started());
    let tracked = Tracked {
        inner,
        clock: Arc::clone(&clock),
    };
    (tracked, clock)
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.clock.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            this.clock.touch();
        }
        poll
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const SHORT: Duration = Duration::from_millis(50);

    /// A connection that moves nothing is quiet once its limit has passed.
    #[tokio::test]
    async fn a_connection_moving_nothing_goes_quiet() {
        let (near, _far) = tokio::io::duplex(64);
        let (_tracked, clock) = track(near);

        let quiet = tokio::time::timeout(Duration::from_secs(1), clock.quiet(SHORT)).await;

        assert!(quiet.is_ok());
    }

    /// Bytes read put the quiet back to nothing.
    #[tokio::test]
    async fn a_byte_read_resets_the_quiet() {
        let (near, mut far) = tokio::io::duplex(64);
        let (mut tracked, clock) = track(near);
        tokio::time::sleep(SHORT).await;

        far.write_all(b"x").await.unwrap();
        let mut byte = [0_u8; 1];
        tracked.read_exact(&mut byte).await.unwrap();

        assert!(clock.quiet_for() < SHORT);
    }

    /// Bytes written put the quiet back to nothing.
    #[tokio::test]
    async fn a_byte_written_resets_the_quiet() {
        let (near, _far) = tokio::io::duplex(64);
        let (mut tracked, clock) = track(near);
        tokio::time::sleep(SHORT).await;

        tracked.write_all(b"x").await.unwrap();

        assert!(clock.quiet_for() < SHORT);
    }
}
