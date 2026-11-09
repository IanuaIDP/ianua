//! A delegation request as its row holds it: read back into the aggregate,
//! and written out from it. What it asks for and the limits it asks for
//! are each one JSON value, as a delegation keeps them.

use ianua_domain::domains::agents::authority::delegation_request::{
    DelegationReason, DelegationRequest, DelegationRequestRow, RequestState,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, DelegationId, DelegationRequestId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::agents::requests::words::RequestStateKind;
use crate::postgres::authorization::principals::{HumanColumns, human_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const REQUEST: Stored = Stored("delegation request");

const GRANTED: Kept = Kept {
    entity: REQUEST.0,
    column: "granted",
    shape: 1,
};

const LIMITS: Kept = Kept {
    entity: REQUEST.0,
    column: "limits",
    shape: 1,
};

/// A request as it is read. The store's checked queries fill it.
pub(super) struct RequestRecord {
    pub(super) id: Uuid,
    pub(super) agent_id: Uuid,
    pub(super) asked_of_kind: String,
    pub(super) asked_of_id: Uuid,
    pub(super) asked_of_person: String,
    pub(super) granted: Value,
    pub(super) limits: Value,
    pub(super) reason: String,
    pub(super) state: String,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) decided_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl RequestRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the state misses what it needs, or
    /// the row breaks a rule the request keeps.
    pub(super) fn into_request(self) -> Result<DelegationRequest<ResolvedTenant>, DomainError> {
        let state = self.state()?;
        DelegationRequest::reconstitute(DelegationRequestRow {
            id: DelegationRequestId::from_uuid(self.id),
            agent_id: AgentId::from_uuid(self.agent_id),
            asked_of: human_from(
                REQUEST,
                &self.asked_of_kind,
                self.asked_of_id,
                self.asked_of_person,
            )?,
            granted: GRANTED.open(self.granted)?,
            constraints: LIMITS.open(self.limits)?,
            reason: REQUEST.value("reason", DelegationReason::new(self.reason))?,
            state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            updated_at: self.updated_at,
        })
    }

    /// Where the request stands, from its state word and the columns
    /// beside it.
    fn state(&self) -> Result<RequestState, DomainError> {
        let kind = REQUEST.choice::<RequestStateKind>(&self.state)?;
        match (kind, self.delegation_id, self.decided_at) {
            (RequestStateKind::Pending, None, None) => Ok(RequestState::Pending),
            (RequestStateKind::Approved, Some(delegation), Some(at)) => {
                Ok(RequestState::Approved {
                    delegation_id: DelegationId::from_uuid(delegation),
                    at,
                })
            }
            (RequestStateKind::Denied, None, Some(at)) => Ok(RequestState::Denied { at }),
            (_, _, _) => Err(DomainError::corrupt_row(
                REQUEST.0,
                "a state its columns contradict",
            )),
        }
    }
}

/// A request's columns, as they are written.
pub(super) struct RequestColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) agent_id: &'a Uuid,
    pub(super) asked_of: HumanColumns<'a>,
    pub(super) granted: Value,
    pub(super) limits: Value,
    pub(super) reason: &'a str,
    pub(super) state: &'static str,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) decided_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> RequestColumns<'a> {
    /// The columns `request` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when what it asks for or its
    /// limits cannot be written out as JSON.
    pub(super) fn of(request: &'a DelegationRequest<ResolvedTenant>) -> Result<Self, DomainError> {
        let state = request.state();
        Ok(Self {
            id: request.id().as_uuid(),
            agent_id: request.agent_id().as_uuid(),
            asked_of: HumanColumns::of(request.asked_of()),
            granted: GRANTED.seal(request.granted())?,
            limits: LIMITS.seal(request.constraints())?,
            reason: request.reason().as_str(),
            state: RequestStateKind::from(state).word(),
            delegation_id: became(state),
            decided_at: state.decided_at(),
            created_at: request.created_at(),
            expires_at: request.expires_at(),
            updated_at: request.updated_at(),
        })
    }
}

/// The delegation an approved request became.
fn became(state: RequestState) -> Option<Uuid> {
    match state {
        RequestState::Approved { delegation_id, .. } => Some(*delegation_id.as_uuid()),
        RequestState::Pending | RequestState::Denied { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, DelegationConstraints,
    };
    use ianua_domain::types::Seconds;
    use serde_json::json;

    use super::*;

    /// What a request asks for is written in the shape pinned here, and a
    /// row in that shape reads back the same.
    #[test]
    fn what_a_request_asks_for_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "http": [],
            "messaging": [],
            "resources": [],
            "mcp": {"classed_tools": [], "resources": [], "prompts": []},
        }});

        assert_eq!(GRANTED.seal(&CapabilitySet::empty()).unwrap(), stored);
        let read: CapabilitySet = GRANTED.open(stored.clone()).unwrap();
        assert_eq!(GRANTED.seal(&read).unwrap(), stored);
    }

    /// The limits a request asks for are written in the shape pinned here,
    /// and a row in that shape reads back the same.
    #[test]
    fn the_limits_a_request_asks_for_are_stored_in_their_pinned_shape() {
        let limits = DelegationConstraints::new(Seconds::new(600), 1).unwrap();
        let stored = json!({"v": 1, "value": {
            "ttl_seconds": 600,
            "max_depth": 1,
            "task": null,
            "budget": "unrestricted",
            "intent": "unrestricted",
            "resource_scope": "unrestricted",
            "apps": "no_apps",
            "approval": "not_required",
            "binding": "bearer",
            "max_data_class": "unrestricted",
            "template": "unrestricted",
        }});

        assert_eq!(LIMITS.seal(&limits).unwrap(), stored);
        let read: DelegationConstraints = LIMITS.open(stored.clone()).unwrap();
        assert_eq!(LIMITS.seal(&read).unwrap(), stored);
    }
}
