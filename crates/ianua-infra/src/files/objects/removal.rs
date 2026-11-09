//! Removing everything kept under one folder of the bucket: the uploads
//! left unfinished there, then every object, a page at a time.
//!
//! Each page of a listing is removed in one batch delete, signed with the
//! body's MD5 as every store asks of one. A store without batch deletes,
//! such as Google Cloud Storage's XML API, refuses the batch, and its
//! objects are then removed one at a time, a few at once. A store that
//! does not list unfinished uploads has none to clear.
//!
//! Removing what is gone already succeeds, so a removal cut short by a
//! crash or a timeout is finished by running it again. One that reaches
//! the most pages it reads fails, having removed what it reached, and
//! goes on from there when run again.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::{TryStreamExt as _, stream};
use ianua_domain::shared::errors::DomainError;
use md5::{Digest as _, Md5};
use reqwest::Method;

use crate::files::objects::calls::{Bucket, Call, refusal, refused, text_of, unless_gone};
use crate::files::objects::documents::{
    Listed, NO_SUCH_KEY, Pending, delete_failures, delete_request, listed, pending,
};
use crate::files::objects::uploads::abort;

/// How many entries one page of a listing holds, the most a batch delete
/// takes.
const PAGE: &str = "1000";

/// The most pages one removal reads of each listing.
const MOST_PAGES: usize = 100;

/// How many objects are removed at once when the store takes them only
/// one at a time.
const AT_ONCE: usize = 8;

/// The statuses a store answers a request it does not serve with.
const NOT_SERVED: [u16; 3] = [400, 405, 501];

/// Removes every object and unfinished upload whose key starts with
/// `prefix`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the store cannot be listed,
/// refuses a removal, or holds more than one removal reaches.
pub(super) async fn remove_under(bucket: &Bucket, prefix: &str) -> Result<(), DomainError> {
    abort_pending(bucket, prefix).await?;
    remove_objects(bucket, prefix).await
}

/// Aborts every upload left unfinished under `prefix`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the store cannot be listed,
/// refuses an abort, or holds more than one removal reaches.
pub(super) async fn abort_pending(bucket: &Bucket, prefix: &str) -> Result<(), DomainError> {
    let mut after: Option<(String, String)> = None;
    for _ in 0..MOST_PAGES {
        let Some(page) = pending_page(bucket, prefix, after.as_ref()).await? else {
            return Ok(());
        };
        abort_all(bucket, &page).await?;
        after = page.next;
        if after.is_none() {
            return Ok(());
        }
    }
    Err(too_many())
}

/// Aborts each upload on `page`.
async fn abort_all(bucket: &Bucket, page: &Pending) -> Result<(), DomainError> {
    for (key, upload_id) in &page.uploads {
        abort(bucket, key, upload_id).await?;
    }
    Ok(())
}

/// One page of the uploads unfinished under `prefix`, after the key and
/// upload id `after` names, or `None` from a store that does not list
/// them.
async fn pending_page(
    bucket: &Bucket,
    prefix: &str,
    after: Option<&(String, String)>,
) -> Result<Option<Pending>, DomainError> {
    let mut query = vec![("uploads", ""), ("prefix", prefix), ("max-uploads", PAGE)];
    if let Some((key, upload_id)) = after {
        query.extend([
            ("key-marker", key.as_str()),
            ("upload-id-marker", upload_id.as_str()),
        ]);
    }
    let response = bucket.send(Call::to(Method::GET, "", &query)).await?;
    if NOT_SERVED.contains(&response.status().as_u16()) {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(DomainError::infra(refusal(response).await));
    }
    pending(&text_of(response).await?).map(Some)
}

/// Removes every object under `prefix`, a page at a time.
async fn remove_objects(bucket: &Bucket, prefix: &str) -> Result<(), DomainError> {
    let mut token: Option<String> = None;
    for _ in 0..MOST_PAGES {
        let page = listed_page(bucket, prefix, token.as_deref()).await?;
        remove_batch(bucket, &page.keys).await?;
        token = page.next;
        if token.is_none() {
            return Ok(());
        }
    }
    Err(too_many())
}

/// One page of the objects under `prefix`, from the page `token` asks
/// for.
async fn listed_page(
    bucket: &Bucket,
    prefix: &str,
    token: Option<&str>,
) -> Result<Listed, DomainError> {
    let mut query = vec![("list-type", "2"), ("max-keys", PAGE), ("prefix", prefix)];
    query.extend(token.map(|token| ("continuation-token", token)));
    let response = bucket.succeeded(Call::to(Method::GET, "", &query)).await?;
    listed(&text_of(response).await?)
}

/// Removes `keys` in one batch delete, or one at a time from a store that
/// takes no batch.
async fn remove_batch(bucket: &Bucket, keys: &[String]) -> Result<(), DomainError> {
    if keys.is_empty() {
        return Ok(());
    }
    let body = delete_request(keys);
    let digest = STANDARD.encode(Md5::digest(body.as_bytes()));
    let call = Call {
        headers: &[
            ("content-md5", digest.as_str()),
            ("content-type", "application/xml"),
        ],
        body: Bytes::from(body),
        ..Call::to(Method::POST, "", &[("delete", "")])
    };
    let response = bucket.send(call).await?;
    if NOT_SERVED.contains(&response.status().as_u16()) {
        return remove_each(bucket, keys).await;
    }
    if !response.status().is_success() {
        return Err(DomainError::infra(refusal(response).await));
    }
    let failures = delete_failures(&text_of(response).await?)?;
    let Some(code) = failures.first() else {
        return Ok(());
    };
    Err(DomainError::infra(refused(200, code)))
}

/// Removes `keys` one at a time, [`AT_ONCE`] of them at once.
async fn remove_each(bucket: &Bucket, keys: &[String]) -> Result<(), DomainError> {
    stream::iter(keys.iter().map(Ok::<&String, DomainError>))
        .try_for_each_concurrent(AT_ONCE, |key| remove_one(bucket, key))
        .await
}

/// Removes the object `key`. Removing one already gone succeeds.
async fn remove_one(bucket: &Bucket, key: &str) -> Result<(), DomainError> {
    let response = bucket.send(Call::to(Method::DELETE, key, &[])).await?;
    unless_gone(response, NO_SUCH_KEY).await
}

/// The failure of a removal that reached the most pages it reads.
fn too_many() -> DomainError {
    DomainError::infra_msg(
        "more is kept under one folder than one removal reaches; what it reached is removed, \
         and running it again goes on",
    )
}
