//! A setup as its row holds it: read back into the aggregate, and written
//! out from it. Its steps are kept as words, in the order planned and done.

use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup, TenantSetupRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::model::steps::RunFailure;
use ianua_domain::types::{TenantId, UntrustedText};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SETUP: Stored = Stored("tenant setup");

/// A setup as it is read. The store's checked queries fill it.
pub(super) struct SetupRecord {
    pub(super) tenant_id: Uuid,
    pub(super) planned: Vec<String>,
    pub(super) done: Vec<String>,
    pub(super) failed_step: Option<String>,
    pub(super) failed_reason: Option<String>,
    pub(super) started_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SetupRecord {
    /// The setup the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a step's word is unknown,
    /// the failure is half kept, or the row breaks a rule the setup keeps.
    pub(super) fn into_setup(self) -> Result<TenantSetup, DomainError> {
        let failed = match (self.failed_step, self.failed_reason) {
            (Some(step), Some(why)) => RunFailure::FailedAt {
                step: SETUP.choice(&step)?,
                why: UntrustedText::record(&why),
            },
            (None, None) => RunFailure::NotFailed,
            (Some(_), None) | (None, Some(_)) => {
                return Err(DomainError::corrupt_row(SETUP.0, "a failure kept by half"));
            }
        };
        TenantSetup::reconstitute(TenantSetupRow {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            planned: steps_of(&self.planned)?,
            done: steps_of(&self.done)?,
            failed,
            started_at: self.started_at,
            updated_at: self.updated_at,
        })
    }
}

fn steps_of(words: &[String]) -> Result<Vec<SetupStep>, DomainError> {
    words.iter().map(|word| SETUP.choice(word)).collect()
}

/// A setup's columns, as they are written.
pub(super) struct SetupColumns {
    pub(super) tenant_id: Uuid,
    pub(super) planned: Vec<String>,
    pub(super) done: Vec<String>,
    pub(super) failed_step: Option<String>,
    pub(super) failed_reason: Option<String>,
    pub(super) started_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SetupColumns {
    /// The columns `setup` is written as.
    pub(super) fn of(setup: &TenantSetup) -> Self {
        let words = |steps: &[SetupStep]| steps.iter().map(|step| step.word().to_owned()).collect();
        let failure = setup.failure();
        Self {
            tenant_id: *setup.tenant_id().as_uuid(),
            planned: words(&setup.planned()),
            done: words(setup.done()),
            failed_step: failure.map(|(step, _)| step.word().to_owned()),
            failed_reason: failure.map(|(_, why)| why.as_str().to_owned()),
            started_at: setup.created_at(),
            updated_at: setup.updated_at(),
        }
    }
}
