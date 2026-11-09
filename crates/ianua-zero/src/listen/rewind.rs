//! A stream that gives back the bytes already read from it.
//!
//! The opening of a connection is read before anyone knows what it is: the
//! first bytes are checked for a PROXY protocol signature, and the TLS
//! ClientHello is read whole to be fingerprinted. Whatever was read and is
//! not ours to keep is handed on first, so the next reader sees the
//! connection from where it really starts.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream read from its start again: the bytes already taken off it come
/// first, then the stream itself.
#[derive(Debug)]
pub(crate) struct Rewind<S> {
    taken: Vec<u8>,
    given: usize,
    inner: S,
}

impl<S> Rewind<S> {
    /// `inner`, with `taken` given back before anything read from it.
    pub(crate) fn new(taken: Vec<u8>, inner: S) -> Self {
        Self {
            taken,
            given: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let rest = &this.taken[this.given..];
        if rest.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let count = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..count]);
        this.given += count;
        if this.given == this.taken.len() {
            this.taken = Vec::new();
            this.given = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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

    /// The bytes taken come back first, then the rest of the stream, with
    /// nothing lost or repeated between them.
    #[tokio::test]
    async fn the_taken_bytes_come_back_before_the_stream() {
        let rest = std::io::Cursor::new(b"\x01rest".to_vec());
        let mut stream = Rewind::new(b"\x16\x03".to_vec(), rest);

        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();

        assert_eq!(read, b"\x16\x03\x01rest");
    }

    /// A reader with less room than was taken gets it over several reads.
    #[tokio::test]
    async fn the_taken_bytes_survive_a_small_reader() {
        let mut stream = Rewind::new(b"abc".to_vec(), std::io::Cursor::new(b"d".to_vec()));

        let mut first = [0_u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();

        assert_eq!(&first, b"ab");
        assert_eq!(rest, b"cd");
    }

    /// Writing goes straight to the stream underneath.
    #[tokio::test]
    async fn writes_reach_the_stream() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut stream = Rewind::new(b"taken".to_vec(), near);

        stream.write_all(b"answer").await.unwrap();
        let mut written = [0_u8; 6];
        far.read_exact(&mut written).await.unwrap();

        assert_eq!(&written, b"answer");
    }
}
