//! The memories' texts kept in a vector server instead of pgvector: any
//! server speaking Qdrant's REST API, at `VECTOR_STORE_URL`, for a
//! deployment whose memories outgrow an exact search inside Postgres.
//!
//! A collection holds vectors of one length, so the texts of every memory
//! whose vectors are `n` long live in the collection `ianua_memories_<n>`,
//! made the first time one is kept, searched by cosine. Each point carries
//! its tenant and memory, and every read, count and deletion is filtered
//! by both, so one tenant never reaches another's texts. The memories
//! themselves stay in Postgres.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::tenant::TenantMemoryPurger;
use ianua_app::ports::workflows::MemoryEntries;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::memory::entry::{
    Embedding, EntryPage, FoundCount, FoundEntry, KeptEntry, MemoryEntry, MemoryText, NextPage,
    PageStart,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{MemoryEntryId, MemoryId, TenantId};
use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use url::Url;

use crate::http::client::{body_within, fixed};

/// The start of every collection's name.
const COLLECTION_PREFIX: &str = "ianua_memories_";

/// The most an answer of the server may hold.
const MOST_ANSWER_BYTES: usize = 4 * 1024 * 1024;

/// Where the vector server answers, and the key it takes. The key never
/// prints.
#[derive(Clone)]
pub struct VectorServer {
    /// Its address, such as `http://vectors:6333`.
    pub url: Url,
    /// The key it takes in `api-key`, if any.
    pub api_key: Option<Secret>,
}

impl std::fmt::Debug for VectorServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorServer")
            .field("url", &self.url.as_str())
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The memories' texts kept in a vector server.
pub struct VectorMemoryEntries {
    server: VectorServer,
    client: reqwest::Client,
}

impl TenantScoped for VectorMemoryEntries {}

impl VectorMemoryEntries {
    /// Texts kept at `server`, each call held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(server: VectorServer, timeout: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            server,
            client: fixed(timeout)?,
        })
    }

    /// The answer to `method` on `path` with `body`, read as JSON.
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, DomainError> {
        let mut address = self.server.url.clone();
        let (route, query) = path
            .split_once('?')
            .map_or((path, None), |(route, query)| (route, Some(query)));
        address.set_path(route);
        address.set_query(query);
        let mut request = self.client.request(method, address);
        if let Some(key) = &self.server.api_key {
            let mut value = HeaderValue::from_str(key.expose())
                .map_err(|_| DomainError::infra_msg("the vector server's key cannot be sent"))?;
            value.set_sensitive(true);
            request = request.header(HeaderName::from_static("api-key"), value);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(DomainError::infra)?;
        let status = response.status();
        let bytes = body_within(response, MOST_ANSWER_BYTES).await?;
        if !status.is_success() {
            return Err(DomainError::infra_msg(format!(
                "the vector server answered {}",
                status.as_u16()
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| DomainError::infra_msg("the vector server's answer does not read"))
    }

    /// Makes the collection for vectors of `size` numbers, with its tenant
    /// and memory indexed, unless it is there.
    async fn ensure_collection(&self, size: usize) -> Result<String, DomainError> {
        let name = format!("{COLLECTION_PREFIX}{size}");
        let path = format!("/collections/{name}");
        let exists = self
            .call(reqwest::Method::GET, &format!("{path}/exists"), None)
            .await?;
        if exists.pointer("/result/exists").and_then(Value::as_bool) == Some(true) {
            return Ok(name);
        }
        let made = json!({ "vectors": { "size": size, "distance": "Cosine" } });
        self.call(reqwest::Method::PUT, &path, Some(made)).await?;
        for field in ["tenant_id", "memory_id"] {
            let index = json!({ "field_name": field, "field_schema": "keyword" });
            self.call(
                reqwest::Method::PUT,
                &format!("{path}/index?wait=true"),
                Some(index),
            )
            .await?;
        }
        Ok(name)
    }

    /// The names of every collection of memories.
    async fn collections(&self) -> Result<Vec<String>, DomainError> {
        let listed = self
            .call(reqwest::Method::GET, "/collections", None)
            .await?;
        let names = listed
            .pointer("/result/collections")
            .and_then(Value::as_array)
            .map(|collections| {
                collections
                    .iter()
                    .filter_map(|collection| collection.get("name").and_then(Value::as_str))
                    .filter(|name| name.starts_with(COLLECTION_PREFIX))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(names)
    }
}

/// The filter keeping a call to `tenant`'s points, and to `memory`'s when
/// one is named.
fn owned_by(tenant: &ScopedTenant, memory: Option<&MemoryId>) -> Value {
    let mut must =
        vec![json!({ "key": "tenant_id", "match": { "value": tenant.as_uuid().to_string() } })];
    if let Some(memory) = memory {
        must.push(
            json!({ "key": "memory_id", "match": { "value": memory.as_uuid().to_string() } }),
        );
    }
    json!({ "must": must })
}

/// One point a search found.
#[derive(Deserialize)]
struct FoundPoint {
    score: f32,
    payload: FoundPayload,
}

/// What a found point carries.
#[derive(Deserialize)]
struct FoundPayload {
    entry_id: uuid::Uuid,
    text: String,
    exposure: String,
    kept_at: i64,
}

/// One page a scroll read.
#[derive(Deserialize)]
struct ScrolledPage {
    points: Vec<ScrolledPoint>,
    next_page_offset: Option<uuid::Uuid>,
}

/// One point a scroll read.
#[derive(Deserialize)]
struct ScrolledPoint {
    payload: FoundPayload,
}

impl ScrolledPage {
    /// The page of texts it holds, their values checked again.
    fn into_page(self) -> Result<EntryPage, DomainError> {
        let entries = self
            .points
            .into_iter()
            .map(|point| point.payload.into_kept())
            .collect::<Result<_, _>>()?;
        let next = self.next_page_offset.map_or(NextPage::Done, |id| {
            NextPage::At(MemoryEntryId::from_uuid(id))
        });
        Ok(EntryPage { entries, next })
    }
}

impl FoundPayload {
    /// The kept text the payload holds, its values checked again.
    fn into_kept(self) -> Result<KeptEntry, DomainError> {
        Ok(KeptEntry {
            id: MemoryEntryId::from_uuid(self.entry_id),
            text: MemoryText::new(self.text).map_err(|_| {
                DomainError::infra_msg("the vector server holds a text that does not read")
            })?,
            exposure: DataClassLevel::from_stored(&self.exposure)?,
            kept_at: OffsetDateTime::from_unix_timestamp(self.kept_at).map_err(|_| {
                DomainError::infra_msg("the vector server holds a time that does not read")
            })?,
        })
    }
}

/// The `result` of a vector server's `answer`, read as `T`, or `unread`
/// when it does not read.
fn result_of<T: serde::de::DeserializeOwned>(
    mut answer: Value,
    unread: &'static str,
) -> Result<T, DomainError> {
    let result = answer
        .get_mut("result")
        .map(Value::take)
        .unwrap_or_default();
    serde_json::from_value(result).map_err(|_| DomainError::infra_msg(unread))
}

/// A scroll through `memory` of `tenant`'s points in id order, at most
/// `limit`, from `start`, payloads only.
fn scroll_body(tenant: &ScopedTenant, memory: &MemoryId, start: PageStart, limit: u8) -> Value {
    let offset = match start {
        PageStart::First => Value::Null,
        PageStart::At(entry) => json!(entry.as_uuid().to_string()),
    };
    json!({
        "filter": owned_by(tenant, Some(memory)),
        "limit": limit,
        "offset": offset,
        "with_payload": true,
        "with_vector": false,
    })
}

impl FoundPoint {
    /// The entry the point holds, its values checked again.
    fn into_found(self) -> Result<FoundEntry, DomainError> {
        let kept = self.payload.into_kept()?;
        Ok(FoundEntry {
            id: kept.id,
            text: kept.text,
            exposure: kept.exposure,
            similarity: self.score,
            kept_at: kept.kept_at,
        })
    }
}

#[async_trait]
impl MemoryEntries for VectorMemoryEntries {
    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        entry: &MemoryEntry,
    ) -> Result<(), DomainError> {
        let collection = self
            .ensure_collection(entry.embedding().values().len())
            .await?;
        let point = json!({ "points": [{
            "id": entry.id().as_uuid().to_string(),
            "vector": entry.embedding().values(),
            "payload": {
                "tenant_id": tenant_id.as_uuid().to_string(),
                "memory_id": memory.as_uuid().to_string(),
                "entry_id": entry.id().as_uuid().to_string(),
                "text": entry.text().as_str(),
                "exposure": entry.exposure().as_str(),
                "kept_at": entry.created_at().unix_timestamp(),
            },
        }]});
        self.call(
            reqwest::Method::PUT,
            &format!("/collections/{collection}/points?wait=true"),
            Some(point),
        )
        .await?;
        Ok(())
    }

    async fn find_similar(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        near: &Embedding,
        count: FoundCount,
    ) -> Result<Vec<FoundEntry>, DomainError> {
        let collection = self.ensure_collection(near.values().len()).await?;
        let search = json!({
            "vector": near.values(),
            "limit": count.get(),
            "filter": owned_by(tenant_id, Some(memory)),
            "with_payload": true,
        });
        let answer = self
            .call(
                reqwest::Method::POST,
                &format!("/collections/{collection}/points/search"),
                Some(search),
            )
            .await?;
        let points: Vec<FoundPoint> =
            result_of(answer, "the vector server's search does not read")?;
        points.into_iter().map(FoundPoint::into_found).collect()
    }

    /// A memory's points sit in the one collection of its vectors' length,
    /// so the first collection holding any of them holds them all.
    async fn page(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        start: PageStart,
        limit: u8,
    ) -> Result<EntryPage, DomainError> {
        let scroll = scroll_body(tenant_id, memory, start, limit);
        for collection in self.collections().await? {
            let answer = self
                .call(
                    reqwest::Method::POST,
                    &format!("/collections/{collection}/points/scroll"),
                    Some(scroll.clone()),
                )
                .await?;
            let page: ScrolledPage = result_of(answer, "the vector server's scroll does not read")?;
            if !page.points.is_empty() {
                return page.into_page();
            }
        }
        Ok(EntryPage {
            entries: Vec::new(),
            next: NextPage::Done,
        })
    }

    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let mut total: u64 = 0;
        for collection in self.collections().await? {
            let counted = self
                .call(
                    reqwest::Method::POST,
                    &format!("/collections/{collection}/points/count"),
                    Some(json!({ "filter": owned_by(tenant_id, None), "exact": true })),
                )
                .await?;
            total = total.saturating_add(
                counted
                    .pointer("/result/count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
        }
        Ok(total)
    }

    async fn forget_all(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
    ) -> Result<(), DomainError> {
        for collection in self.collections().await? {
            self.call(
                reqwest::Method::POST,
                &format!("/collections/{collection}/points/delete?wait=true"),
                Some(json!({ "filter": owned_by(tenant_id, Some(memory)) })),
            )
            .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl TenantMemoryPurger for VectorMemoryEntries {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        let filter = json!({ "must": [
            { "key": "tenant_id", "match": { "value": tenant_id.as_uuid().to_string() } }
        ]});
        for collection in self.collections().await? {
            self.call(
                reqwest::Method::POST,
                &format!("/collections/{collection}/points/delete?wait=true"),
                Some(json!({ "filter": filter })),
            )
            .await?;
        }
        Ok(())
    }
}
