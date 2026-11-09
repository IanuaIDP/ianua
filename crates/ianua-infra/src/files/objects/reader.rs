//! A kept object read as it arrives, never more of it than the store said
//! it holds.
//!
//! A task reads the answer's body a chunk at a time and hands each chunk
//! on through a channel of a few chunks, so a slow reader slows the
//! download instead of the body piling up in memory. A body longer than
//! the store said, or cut short, ends in an error rather than a file that
//! quietly differs. Dropping the reader drops the download.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// How many chunks wait between the download and its reader.
const WAITING_CHUNKS: usize = 4;

/// The body of one kept object, read as it arrives.
pub(super) struct BodyReader {
    chunks: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
}

impl BodyReader {
    /// The body of `response`, which holds `length` bytes, read in a task
    /// of its own.
    pub(super) fn spawn(response: reqwest::Response, length: u64) -> Self {
        let (sender, chunks) = mpsc::channel(WAITING_CHUNKS);
        tokio::spawn(feed(response, length, sender));
        Self {
            chunks,
            current: Bytes::new(),
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.current.is_empty() {
                let taken = self.current.len().min(buf.remaining());
                let chunk = self.current.split_to(taken);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match ready!(self.chunks.poll_recv(cx)) {
                Some(Ok(chunk)) => self.current = chunk,
                Some(Err(error)) => return Poll::Ready(Err(error)),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// Hands the body of `response` to `sender` a chunk at a time, ending in
/// an error when it holds more or fewer than `length` bytes, and stopping
/// once nobody reads.
async fn feed(
    mut response: reqwest::Response,
    length: u64,
    sender: mpsc::Sender<io::Result<Bytes>>,
) {
    let mut read: u64 = 0;
    loop {
        let chunk = match next_chunk(&mut response).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                let _ = sender.send(Err(error)).await;
                return;
            }
        };
        read = read.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if read > length {
            let _ = sender.send(Err(differs())).await;
            return;
        }
        if sender.send(Ok(chunk)).await.is_err() {
            return;
        }
    }
    if read < length {
        let _ = sender.send(Err(differs())).await;
    }
}

/// The next chunk of `response`'s body, or `None` at its end.
async fn next_chunk(response: &mut reqwest::Response) -> io::Result<Option<Bytes>> {
    response
        .chunk()
        .await
        .map_err(|error| io::Error::other(error.without_url()))
}

/// The error of a body that is not as long as the store said.
fn differs() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the kept file is not as long as the object store said",
    )
}
