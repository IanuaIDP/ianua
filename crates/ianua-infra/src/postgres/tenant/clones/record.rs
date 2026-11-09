//! A clone as its row holds it: read back into the aggregate, and written
//! out from it. Its state is kept as a word, with the failure and the end
//! beside it when it has them.

use ianua_domain::domains::tenant::clone::{ClonePart, CloneState, TenantClone, TenantCloneRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantCloneId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CLONE: Stored = Stored("tenant clone");

/// A clone as it is read. The store's checked queries fill it.
pub(super) struct CloneRecord {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) source_tenant_id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) parts: Vec<String>,
    pub(super) copied: Vec<String>,
    pub(super) state: String,
    pub(super) failure: Option<String>,
    pub(super) ended_at: Option<OffsetDateTime>,
    pub(super) started_at: OffsetDateTime,
}

impl CloneRecord {
    /// The clone the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, the
    /// state and its failure or end disagree, or the row breaks a rule the
    /// clone keeps.
    pub(super) fn into_clone(self) -> Result<TenantClone, DomainError> {
        let state = self.state_of()?;
        TenantClone::reconstitute(TenantCloneRow {
            id: TenantCloneId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            source: TenantId::from_uuid(self.source_tenant_id),
            target: TenantId::from_uuid(self.tenant_id),
            parts: parts_of(&self.parts)?,
            copied: parts_of(&self.copied)?,
            state,
            started_at: self.started_at,
        })
    }

    /// Where the clone is, from its word, its failure and its end.
    fn state_of(&self) -> Result<CloneState, DomainError> {
        match (self.state.as_str(), self.ended_at, self.failure.as_deref()) {
            ("copying", None, None) => Ok(CloneState::Copying),
            ("completed", Some(at), None) => Ok(CloneState::Completed { at }),
            ("failed", Some(at), Some(reason)) => Ok(CloneState::Failed {
                at,
                reason: CLONE.choice(reason)?,
            }),
            _ => Err(DomainError::corrupt_row(
                CLONE.0,
                "a state that disagrees with its failure or its end",
            )),
        }
    }
}

fn parts_of(words: &[String]) -> Result<Vec<ClonePart>, DomainError> {
    words.iter().map(|word| CLONE.choice(word)).collect()
}

/// A clone's columns, as they are written.
pub(super) struct CloneColumns {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) source_tenant_id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) parts: Vec<String>,
    pub(super) copied: Vec<String>,
    pub(super) state: &'static str,
    pub(super) failure: Option<&'static str>,
    pub(super) ended_at: Option<OffsetDateTime>,
    pub(super) started_at: OffsetDateTime,
}

impl CloneColumns {
    /// The columns `clone` is written as.
    pub(super) fn of(clone: &TenantClone) -> Self {
        let words = |parts: &[ClonePart]| parts.iter().map(|part| part.word().to_owned()).collect();
        let (state, failure, ended_at) = match clone.state() {
            CloneState::Copying => ("copying", None, None),
            CloneState::Completed { at } => ("completed", None, Some(at)),
            CloneState::Failed { at, reason } => ("failed", Some(reason.word()), Some(at)),
        };
        Self {
            id: *clone.id().as_uuid(),
            tenant_id: *clone.target().as_uuid(),
            source_tenant_id: *clone.source().as_uuid(),
            organization_id: *clone.organization_id().as_uuid(),
            parts: words(clone.parts()),
            copied: words(clone.copied()),
            state,
            failure,
            ended_at,
            started_at: clone.started_at(),
        }
    }
}
