//! A file written to the object store a part at a time, which appears
//! whole under its name or not at all.
//!
//! What is written is held until it makes a part of [`PART_BYTES`], the
//! least every store takes for any part but the last. A file that never
//! fills one is sent in one `PUT` when it is finished. A longer one
//! becomes a multipart upload: started when its first part is full, sent
//! a part at a time, and finished with the list of its parts. The store
//! shows nothing under the name until it is finished.
//!
//! An upload that fails, or is dropped before it is finished, is aborted,
//! so its parts are not kept. One a crash left behind is aborted by the
//! next attempt at the same file.

use std::mem;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ianua_domain::shared::errors::DomainError;
use reqwest::Method;
use reqwest::header::ETAG;

use crate::files::objects::calls::{Bucket, Call, text_of, unless_gone};
use crate::files::objects::documents::{
    NO_SUCH_UPLOAD, Part, completion, ensure_completed, upload_id,
};
use crate::files::store::FileUpload;

/// How many bytes each part but the last holds: 8 MiB, above the 5 MiB
/// every store asks of a part.
pub(super) const PART_BYTES: usize = 8_388_608;

/// The most parts an upload holds, the most every store takes.
const MOST_PARTS: usize = 10_000;

/// What is logged when an unfinished upload could not be aborted.
const NOT_ABORTED: &str =
    "an unfinished upload was not aborted; the next attempt at its file clears it";

/// Where an upload stands.
enum Progress {
    /// Nothing is sent yet; what is written fits in one request.
    Held,
    /// A multipart upload is under way.
    Parts(Multipart),
    /// Finished, failed or aborted: nothing more is taken.
    Ended,
}

/// A multipart upload under way: its id and the parts sent.
struct Multipart {
    upload_id: String,
    parts: Vec<Part>,
}

/// One file being written to the object store.
pub(super) struct ObjectUpload {
    bucket: Arc<Bucket>,
    key: String,
    held: Vec<u8>,
    progress: Progress,
}

impl ObjectUpload {
    /// The file `key` in `bucket`, nothing written yet.
    pub(super) fn new(bucket: Arc<Bucket>, key: String) -> Self {
        Self {
            bucket,
            key,
            held: Vec::new(),
            progress: Progress::Held,
        }
    }

    /// Refuses a write to an upload that has ended.
    fn ensure_open(&self) -> Result<(), DomainError> {
        if matches!(self.progress, Progress::Ended) {
            return Err(DomainError::infra_msg("the upload has ended"));
        }
        Ok(())
    }

    /// Sends `part` as the next part, starting the multipart upload first
    /// when it is the first.
    async fn send_part(&mut self, part: Bytes) -> Result<(), DomainError> {
        if matches!(self.progress, Progress::Held) {
            let upload_id = start(&self.bucket, &self.key).await?;
            self.progress = Progress::Parts(Multipart {
                upload_id,
                parts: Vec::new(),
            });
        }
        let Progress::Parts(multipart) = &mut self.progress else {
            return Err(DomainError::infra_msg("the upload has ended"));
        };
        let number = multipart.parts.len().saturating_add(1);
        if number > MOST_PARTS {
            return Err(DomainError::infra_msg(
                "the file is longer than the object store keeps",
            ));
        }
        let sent = Sent {
            key: &self.key,
            upload_id: &multipart.upload_id,
            number,
        };
        let tag = upload_part(&self.bucket, &sent, part).await?;
        multipart.parts.push(Part { number, tag });
        Ok(())
    }

    /// Makes the file whole: one `PUT` when it was held, or its last part
    /// and the list of its parts.
    async fn complete(&mut self) -> Result<(), DomainError> {
        let rest = Bytes::from(mem::take(&mut self.held));
        if matches!(self.progress, Progress::Held) {
            return put_whole(&self.bucket, &self.key, rest).await;
        }
        if !rest.is_empty() {
            self.send_part(rest).await?;
        }
        let Progress::Parts(multipart) = &self.progress else {
            return Err(DomainError::infra_msg("the upload has ended"));
        };
        finish_parts(&self.bucket, &self.key, multipart).await
    }

    /// Aborts the multipart upload under way, if there is one, and ends
    /// the upload.
    async fn abandon(&mut self) {
        let Progress::Parts(multipart) = mem::replace(&mut self.progress, Progress::Ended) else {
            return;
        };
        if let Err(error) = abort(&self.bucket, &self.key, &multipart.upload_id).await {
            tracing::warn!(%error, "{NOT_ABORTED}");
        }
    }
}

#[async_trait]
impl FileUpload for ObjectUpload {
    async fn write(&mut self, bytes: &[u8]) -> Result<(), DomainError> {
        self.ensure_open()?;
        self.held.extend_from_slice(bytes);
        while self.held.len() >= PART_BYTES {
            let rest = self.held.split_off(PART_BYTES);
            let part = Bytes::from(mem::replace(&mut self.held, rest));
            if let Err(error) = self.send_part(part).await {
                self.abandon().await;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<(), DomainError> {
        self.ensure_open()?;
        let finished = self.complete().await;
        if finished.is_err() {
            self.abandon().await;
        }
        self.progress = Progress::Ended;
        finished
    }
}

/// Aborts an upload dropped before it was finished, in a task of its own
/// as a drop cannot wait. Should the abort be lost, the next attempt at
/// the file clears it.
impl Drop for ObjectUpload {
    fn drop(&mut self) {
        let Progress::Parts(multipart) = mem::replace(&mut self.progress, Progress::Ended) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let bucket = Arc::clone(&self.bucket);
        let key = mem::take(&mut self.key);
        runtime.spawn(async move {
            if let Err(error) = abort(&bucket, &key, &multipart.upload_id).await {
                tracing::warn!(%error, "{NOT_ABORTED}");
            }
        });
    }
}

/// One part being sent: the file, the upload and the part's number.
struct Sent<'a> {
    key: &'a str,
    upload_id: &'a str,
    number: usize,
}

/// Keeps `body` whole as the object `key`, in one request.
async fn put_whole(bucket: &Bucket, key: &str, body: Bytes) -> Result<(), DomainError> {
    let call = Call {
        body,
        ..Call::to(Method::PUT, key, &[])
    };
    bucket.succeeded(call).await.map(drop)
}

/// Starts a multipart upload of `key`, answering its id.
async fn start(bucket: &Bucket, key: &str) -> Result<String, DomainError> {
    let response = bucket
        .succeeded(Call::to(Method::POST, key, &[("uploads", "")]))
        .await?;
    upload_id(&text_of(response).await?)
}

/// Sends `body` as the part `sent` names, answering the tag the store
/// gave it.
async fn upload_part(bucket: &Bucket, sent: &Sent<'_>, body: Bytes) -> Result<String, DomainError> {
    let number = sent.number.to_string();
    let query = [
        ("partNumber", number.as_str()),
        ("uploadId", sent.upload_id),
    ];
    let call = Call {
        body,
        ..Call::to(Method::PUT, sent.key, &query)
    };
    let response = bucket.succeeded(call).await?;
    response
        .headers()
        .get(ETAG)
        .and_then(|tag| tag.to_str().ok())
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| DomainError::infra_msg("the object store took a part without a tag"))
}

/// Finishes the multipart upload of `key` from its parts.
async fn finish_parts(
    bucket: &Bucket,
    key: &str,
    multipart: &Multipart,
) -> Result<(), DomainError> {
    let query = [("uploadId", multipart.upload_id.as_str())];
    let call = Call {
        headers: &[("content-type", "application/xml")],
        body: Bytes::from(completion(&multipart.parts)),
        ..Call::to(Method::POST, key, &query)
    };
    let response = bucket.succeeded(call).await?;
    ensure_completed(&text_of(response).await?)
}

/// Aborts the multipart upload `upload_id` of `key`, its parts dropped.
/// Aborting one already gone succeeds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the store does not abort it.
pub(super) async fn abort(bucket: &Bucket, key: &str, upload_id: &str) -> Result<(), DomainError> {
    let query = [("uploadId", upload_id)];
    let response = bucket.send(Call::to(Method::DELETE, key, &query)).await?;
    unless_gone(response, NO_SUCH_UPLOAD).await
}
