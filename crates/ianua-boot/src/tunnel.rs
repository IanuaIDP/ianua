//! A tunnel's bytes, carried both ways unread until either side closes, a
//! side fails, or nothing moves for the idle time. The connector relays
//! the gateway's connections to a target through one, and the egress
//! gateway a service's connections to a destination.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The most bytes read in one go from either side.
const CHUNK: usize = 16 * 1024;

/// How a tunnel ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// A side closed it.
    Closed,
    /// Nothing moved for the idle time.
    Idle,
    /// A side failed.
    Failed,
}

impl Ended {
    /// A short, stable word for the log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Idle => "idle",
            Self::Failed => "failed",
        }
    }
}

/// Which side a read came from, and what it read.
enum Read {
    /// The side that opened the tunnel.
    Near(std::io::Result<usize>),
    /// The side it reaches.
    Far(std::io::Result<usize>),
}

/// What one step of a tunnel did.
enum Moved {
    /// A side sent this many bytes on.
    Bytes,
    /// A side closed.
    Closed,
    /// A side failed.
    Failed,
}

/// Carries bytes between `near`, the side that opened the tunnel, and
/// `far`, the side it reaches, until the tunnel ends, each step held to
/// `idle`. When one side closes, the other is told it will get no more.
pub async fn splice<N, F>(near: &mut N, far: &mut F, idle: Duration) -> Ended
where
    N: AsyncRead + AsyncWrite + Unpin,
    F: AsyncRead + AsyncWrite + Unpin,
{
    let mut from_near = vec![0_u8; CHUNK];
    let mut from_far = vec![0_u8; CHUNK];
    loop {
        let step = tokio::time::timeout(idle, async {
            let read = tokio::select! {
                read = near.read(&mut from_near) => Read::Near(read),
                read = far.read(&mut from_far) => Read::Far(read),
            };
            match read {
                Read::Near(read) => carried(read, &from_near, &mut *far).await,
                Read::Far(read) => carried(read, &from_far, &mut *near).await,
            }
        })
        .await;
        match step {
            Ok(Moved::Bytes) => {}
            Ok(Moved::Closed) => {
                let _ = near.shutdown().await;
                let _ = far.shutdown().await;
                return Ended::Closed;
            }
            Ok(Moved::Failed) => return Ended::Failed,
            Err(_) => return Ended::Idle,
        }
    }
}

/// Sends what `read` brought in `buffer` on to `to`.
async fn carried<W: AsyncWrite + Unpin>(
    read: std::io::Result<usize>,
    buffer: &[u8],
    to: &mut W,
) -> Moved {
    match read {
        Ok(0) => Moved::Closed,
        Ok(count) => match to.write_all(&buffer[..count]).await {
            Ok(()) => Moved::Bytes,
            Err(_) => Moved::Failed,
        },
        Err(_) => Moved::Failed,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    /// Bytes cross both ways, and the tunnel ends when a side closes.
    #[tokio::test]
    async fn bytes_cross_both_ways_until_a_side_closes() {
        let (mut near, mut near_end) = duplex(64);
        let (mut far, mut far_end) = duplex(64);
        let tunnel = tokio::spawn(async move {
            splice(&mut near_end, &mut far_end, Duration::from_secs(5)).await
        });

        near.write_all(b"ping").await.unwrap();
        let mut heard = [0_u8; 4];
        far.read_exact(&mut heard).await.unwrap();
        far.write_all(b"pong").await.unwrap();
        let mut answered = [0_u8; 4];
        near.read_exact(&mut answered).await.unwrap();
        drop(near);

        assert_eq!(&heard, b"ping");
        assert_eq!(&answered, b"pong");
        assert_eq!(tunnel.await.unwrap(), Ended::Closed);
    }

    /// A tunnel with both ends silent ends as idle after its idle time.
    #[tokio::test]
    async fn a_silent_tunnel_is_closed() {
        let (_near, mut near_end) = duplex(64);
        let (_far, mut far_end) = duplex(64);

        let ended = splice(&mut near_end, &mut far_end, Duration::from_millis(50)).await;

        assert_eq!(ended, Ended::Idle);
    }
}
