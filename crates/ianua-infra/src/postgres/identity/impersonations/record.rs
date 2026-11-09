//! A support impersonation as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::identity::impersonation::state::{
    ImpersonationConsent, ImpersonationState, ImpersonationStatus, ImpersonationWindow,
};
use ianua_domain::domains::identity::impersonation::{
    SupportImpersonation, SupportImpersonationRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SupportImpersonationId, Text, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const IMPERSONATION: Stored = Stored("support impersonation");

/// An impersonation as it is read. The store's checked queries fill it.
pub(super) struct ImpersonationRecord {
    pub(super) id: Uuid,
    pub(super) admin_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) reason: String,
    pub(super) window_minutes: i32,
    pub(super) consent: String,
    pub(super) status: String,
    pub(super) since: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
}

impl ImpersonationRecord {
    /// The impersonation the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// impersonation keeps.
    pub(super) fn into_impersonation(
        self,
    ) -> Result<SupportImpersonation<ResolvedTenant>, DomainError> {
        let minutes = u32::try_from(self.window_minutes).map_err(DomainError::infra)?;
        let status: ImpersonationStatus = IMPERSONATION.choice(&self.status)?;
        SupportImpersonation::reconstitute(SupportImpersonationRow {
            id: SupportImpersonationId::from_uuid(self.id),
            admin: UserId::from_uuid(self.admin_id),
            user_id: UserId::from_uuid(self.user_id),
            reason: IMPERSONATION.value("reason", Text::new("reason", self.reason))?,
            window: ImpersonationWindow::minutes(minutes).map_err(|_| {
                DomainError::corrupt_row(IMPERSONATION.0, "a window no impersonation has")
            })?,
            consent: IMPERSONATION.choice::<ImpersonationConsent>(&self.consent)?,
            state: ImpersonationState::from_stored(status, self.since)?,
            requested_at: self.requested_at,
        })
    }
}

/// An impersonation's columns, as they are written.
pub(super) struct ImpersonationColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) admin_id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) reason: &'a str,
    pub(super) window_minutes: i32,
    pub(super) consent: &'static str,
    pub(super) status: &'static str,
    pub(super) since: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
}

impl<'a> ImpersonationColumns<'a> {
    /// The columns `impersonation` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its window does not fit
    /// the column, which no window the domain allows does.
    pub(super) fn of(
        impersonation: &'a SupportImpersonation<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: impersonation.id().as_uuid(),
            admin_id: impersonation.admin().as_uuid(),
            user_id: impersonation.user_id().as_uuid(),
            reason: impersonation.reason().as_str(),
            window_minutes: i32::try_from(impersonation.window().as_minutes())
                .map_err(DomainError::infra)?,
            consent: impersonation.consent().word(),
            status: impersonation.status().word(),
            since: impersonation.state().since(),
            requested_at: impersonation.requested_at(),
        })
    }
}
