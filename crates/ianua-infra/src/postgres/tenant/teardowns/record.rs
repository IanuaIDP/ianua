//! A teardown as its row holds it: read back into the aggregate, and
//! written out from it. Its steps are kept as words, in the order planned
//! and done.

use ianua_domain::domains::tenant::teardown::{TeardownStep, TenantTeardown, TenantTeardownRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::model::steps::RunFailure;
use ianua_domain::types::{TenantId, UntrustedText};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const TEARDOWN: Stored = Stored("tenant teardown");

/// A teardown as it is read. The store's checked queries fill it.
pub(super) struct TeardownRecord {
    pub(super) tenant_id: Uuid,
    pub(super) planned: Vec<String>,
    pub(super) done: Vec<String>,
    pub(super) failed_step: Option<String>,
    pub(super) failed_reason: Option<String>,
    pub(super) started_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl TeardownRecord {
    /// The teardown the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a step's word is unknown,
    /// the failure is half kept, or the row breaks a rule the teardown
    /// keeps.
    pub(super) fn into_teardown(self) -> Result<TenantTeardown, DomainError> {
        let failed = match (self.failed_step, self.failed_reason) {
            (Some(step), Some(why)) => RunFailure::FailedAt {
                step: TEARDOWN.choice(&step)?,
                why: UntrustedText::record(&why),
            },
            (None, None) => RunFailure::NotFailed,
            (Some(_), None) | (None, Some(_)) => {
                return Err(DomainError::corrupt_row(
                    TEARDOWN.0,
                    "a failure kept by half",
                ));
            }
        };
        TenantTeardown::reconstitute(TenantTeardownRow {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            planned: steps_of(&self.planned)?,
            done: steps_of(&self.done)?,
            failed,
            started_at: self.started_at,
            updated_at: self.updated_at,
        })
    }
}

fn steps_of(words: &[String]) -> Result<Vec<TeardownStep>, DomainError> {
    words.iter().map(|word| TEARDOWN.choice(word)).collect()
}

/// A teardown's columns, as they are written.
pub(super) struct TeardownColumns {
    pub(super) tenant_id: Uuid,
    pub(super) planned: Vec<String>,
    pub(super) done: Vec<String>,
    pub(super) failed_step: Option<String>,
    pub(super) failed_reason: Option<String>,
    pub(super) started_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl TeardownColumns {
    /// The columns `teardown` is written as.
    pub(super) fn of(teardown: &TenantTeardown) -> Self {
        let words =
            |steps: &[TeardownStep]| steps.iter().map(|step| step.word().to_owned()).collect();
        let failure = teardown.failure();
        Self {
            tenant_id: *teardown.tenant_id().as_uuid(),
            planned: words(&teardown.planned()),
            done: words(teardown.done()),
            failed_step: failure.map(|(step, _)| step.word().to_owned()),
            failed_reason: failure.map(|(_, why)| why.as_str().to_owned()),
            started_at: teardown.created_at(),
            updated_at: teardown.updated_at(),
        }
    }
}
