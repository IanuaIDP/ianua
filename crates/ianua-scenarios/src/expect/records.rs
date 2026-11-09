//! The records the gateway kept of the requests a step sent, read through
//! the tenant's request search as someone who may read it.

use super::eventually;
use crate::api::TenantPath;
use crate::net::Client;
use crate::wire::Page;
use crate::wire::gateway::RequestRecord;

/// The most records one read asks for.
const PAGE: &str = "100";

/// A tenant's request records, read by one of its administrators.
pub struct Records<'a> {
    reader: &'a Client,
    search: String,
}

impl<'a> Records<'a> {
    /// The records of `tenant`, read by `reader`.
    #[must_use]
    pub fn of_tenant(reader: &'a Client, tenant: &TenantPath) -> Self {
        Self {
            reader,
            search: tenant.at("/gateway/requests"),
        }
    }

    /// Every record kept of a request to exactly `path`, newest first, up
    /// to a hundred.
    ///
    /// # Panics
    ///
    /// When the records cannot be read.
    pub async fn of_path(&self, path: &str) -> Vec<RequestRecord> {
        let read = format!("{}?limit={PAGE}", self.search);
        self.reader
            .get::<Page<RequestRecord>>(&read)
            .await
            .ok()
            .items
            .into_iter()
            .filter(|record| record.path == path)
            .collect()
    }

    /// The record of a request to `path`, once the gateway has written
    /// one; records are written in batches, so it is awaited.
    ///
    /// # Panics
    ///
    /// When none comes within [`eventually`]'s patience.
    pub async fn recorded(&self, path: &str) -> RequestRecord {
        self.recorded_where(path, "any", |_| true).await
    }

    /// The newest record of a request to `path` that `matches`, described
    /// as `which`, once the gateway has written one.
    ///
    /// # Panics
    ///
    /// When none comes within [`eventually`]'s patience.
    pub async fn recorded_where(
        &self,
        path: &str,
        which: &str,
        matches: impl Fn(&RequestRecord) -> bool,
    ) -> RequestRecord {
        let what = format!("the gateway's record of {which} request to {path}");
        let matches = &matches;
        eventually(&what, || async move {
            self.of_path(path)
                .await
                .into_iter()
                .find(|record| matches(record))
        })
        .await
    }
}
