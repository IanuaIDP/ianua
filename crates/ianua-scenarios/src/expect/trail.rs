//! The audit trail a step must leave, read through the organization's
//! audit log as a member who may read it.

use std::collections::HashSet;

use url::form_urlencoded;

use super::eventually;
use crate::net::Client;
use crate::wire::Page;
use crate::wire::audit::AuditEntry;

/// The most records one read asks for.
const PAGE: &str = "100";

/// An organization's audit trail, read by one of its members.
pub struct Trail<'a> {
    reader: &'a Client,
    log: String,
}

impl<'a> Trail<'a> {
    /// The trail of the organization `org_slug`, read by `reader`, who
    /// may read its audit log.
    #[must_use]
    pub fn of_organization(reader: &'a Client, org_slug: &str) -> Self {
        Self {
            reader,
            log: format!("/api/v1/organizations/{org_slug}/audit-log"),
        }
    }

    /// The records whose type starts with `event_type`, newest first, up to
    /// a hundred.
    ///
    /// # Panics
    ///
    /// When the log cannot be read.
    pub async fn entries(&self, event_type: &str) -> Vec<AuditEntry> {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("event_type", event_type)
            .append_pair("limit", PAGE)
            .finish();
        let path = format!("{}?{query}", self.log);
        self.reader.get::<Page<AuditEntry>>(&path).await.ok().items
    }

    /// How many records of exactly `event_type` the trail holds now, up to
    /// a hundred: a step's count before, to compare with its count after.
    ///
    /// # Panics
    ///
    /// When the log cannot be read.
    pub async fn count(&self, event_type: &str) -> usize {
        self.entries(event_type)
            .await
            .iter()
            .filter(|entry| entry.event_type == event_type)
            .count()
    }

    /// The record of type `event_type`, once the trail holds one.
    ///
    /// # Panics
    ///
    /// When none comes within [`eventually`]'s patience, or the log cannot
    /// be read.
    pub async fn recorded(&self, event_type: &str) -> AuditEntry {
        let what = format!("{event_type} in the audit trail");
        eventually(&what, || self.first_of(event_type)).await
    }

    /// The ids of every record the trail holds now, up to a hundred: what
    /// a step saw before it acted, to tell the records it raises from them.
    ///
    /// # Panics
    ///
    /// When the log cannot be read.
    pub async fn ids(&self) -> HashSet<String> {
        self.entries("")
            .await
            .into_iter()
            .map(|entry| entry.id)
            .collect()
    }

    /// The record of exactly `event_type` whose id is not in `seen`, once
    /// the trail holds one: what a step raised, told from what was there
    /// before it.
    ///
    /// # Panics
    ///
    /// When none comes within [`eventually`]'s patience, or the log cannot
    /// be read.
    pub async fn recorded_after(&self, seen: &HashSet<String>, event_type: &str) -> AuditEntry {
        let what = format!("a new {event_type} in the audit trail");
        eventually(&what, || self.first_after(seen, event_type)).await
    }

    /// Fails when the trail holds a record of exactly `event_type` whose
    /// id is not in `seen`: a refused step records nothing it refused.
    ///
    /// # Panics
    ///
    /// When such a record is there, or the log cannot be read.
    pub async fn nothing_after(&self, seen: &HashSet<String>, event_type: &str) {
        let fresh = self.first_after(seen, event_type).await;
        assert!(fresh.is_none(), "a refused step recorded {event_type}");
    }

    /// The newest record of exactly `event_type`, if any.
    async fn first_of(&self, event_type: &str) -> Option<AuditEntry> {
        self.entries(event_type)
            .await
            .into_iter()
            .find(|entry| entry.event_type == event_type)
    }

    /// The newest record of exactly `event_type` not in `seen`, if any.
    async fn first_after(&self, seen: &HashSet<String>, event_type: &str) -> Option<AuditEntry> {
        self.entries(event_type)
            .await
            .into_iter()
            .find(|entry| entry.event_type == event_type && !seen.contains(&entry.id))
    }
}
