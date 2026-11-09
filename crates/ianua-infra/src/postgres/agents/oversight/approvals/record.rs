//! An approval request and the people behind its delegation as their rows
//! hold them: read back into the aggregate, and written out from it.

use std::collections::HashMap;

use ianua_domain::domains::agents::authority::delegation::ActingUnder;
use ianua_domain::domains::agents::execution::run::{PendingCallRef, ToolCall};
use ianua_domain::domains::agents::oversight::approval::{
    ActionParties, Approval, ApprovalAction, ApprovalOrigin, ApprovalRequest, ApprovalRequestRow,
    ApprovalState, StoredApprovalOrigin, StoredDecision, StoredRunOrigin,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    ActionClass, AgentId, AgentRunId, ApprovalId, DeclaredAction, DelegationId, Human, Initiator,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::agents::run::chains::{depth_of, origin_from};
use crate::postgres::agents::run::initiators::{InitiatorColumns, initiator_from};
use crate::postgres::authorization::principals::{HumanColumns, human_from, maybe_human_from};
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const APPROVAL: Stored = Stored("approval request");

/// A request as it is read, without the people behind its delegation. The
/// store's checked queries fill it.
pub(super) struct ApprovalRecord {
    pub(super) id: Uuid,
    pub(super) agent_id: Uuid,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) requested_by_kind: String,
    pub(super) requested_by_id: Uuid,
    pub(super) requested_by_person: Option<String>,
    pub(super) run_id: Option<Uuid>,
    pub(super) pending_tool: Option<String>,
    pub(super) pending_arguments: Option<String>,
    pub(super) pending_at_step: Option<i32>,
    pub(super) run_exposure: Option<String>,
    pub(super) chain_depth: Option<i16>,
    pub(super) owner_kind: String,
    pub(super) owner_id: Uuid,
    pub(super) owner_person: String,
    pub(super) action_class: Option<String>,
    pub(super) action: String,
    pub(super) status: String,
    pub(super) first_by_kind: Option<String>,
    pub(super) first_by_id: Option<Uuid>,
    pub(super) first_by_person: Option<String>,
    pub(super) first_at: Option<OffsetDateTime>,
    pub(super) decided_by_kind: Option<String>,
    pub(super) decided_by_id: Option<Uuid>,
    pub(super) decided_by_person: Option<String>,
    pub(super) decided_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// One person behind the delegation a request's action uses, as read.
pub(super) struct DelegatorRecord {
    pub(super) approval_id: Uuid,
    pub(super) account_kind: String,
    pub(super) account_id: Uuid,
    pub(super) person: String,
}

/// `delegators`, read in order of request and place, grouped by the
/// request they stand behind, each request's in order.
pub(super) fn delegators_by_request(
    delegators: Vec<DelegatorRecord>,
) -> HashMap<Uuid, Vec<DelegatorRecord>> {
    let mut grouped: HashMap<Uuid, Vec<DelegatorRecord>> = HashMap::new();
    for delegator in delegators {
        grouped
            .entry(delegator.approval_id)
            .or_default()
            .push(delegator);
    }
    grouped
}

impl ApprovalRecord {
    /// The request the record holds with `delegators`, in the order the
    /// request names them, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, part of its run, an approval or the
    /// decision is missing, or the row breaks a rule the request keeps.
    pub(super) fn into_approval(
        mut self,
        delegators: Vec<DelegatorRecord>,
    ) -> Result<ApprovalRequest<ResolvedTenant>, DomainError> {
        let origin = self.origin()?;
        let parties = self.parties(delegators)?;
        let state = self.state()?;
        let declared = self.action_class.as_deref().map(ActionClass::from_stored);
        let delegation = self.delegation_id.map(DelegationId::from_uuid);
        ApprovalRequest::reconstitute(ApprovalRequestRow {
            id: ApprovalId::from_uuid(self.id),
            agent_id: AgentId::from_uuid(self.agent_id),
            delegation_id: ActingUnder::from_stored(delegation),
            origin,
            parties,
            action_class: DeclaredAction::from_stored(declared.transpose()?),
            action: APPROVAL.value("action", ApprovalAction::new(self.action))?,
            state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            updated_at: self.updated_at,
        })
    }

    /// Where the request came from: opened by hand by its requester, or
    /// raised by its run, which started the run.
    fn origin(&mut self) -> Result<StoredApprovalOrigin, DomainError> {
        let person = self.requested_by_person.take();
        let requester = initiator_from(
            APPROVAL,
            &self.requested_by_kind,
            self.requested_by_id,
            person,
        )?;
        let Some(run_id) = self.run_id else {
            return Ok(StoredApprovalOrigin::Opened(requester));
        };
        Ok(StoredApprovalOrigin::Run(StoredRunOrigin {
            run_id: AgentRunId::from_uuid(run_id),
            agent_id: AgentId::from_uuid(self.agent_id),
            started_by: requester,
            pending_call: self.held_call()?,
            exposure: self.run_exposure()?,
            chain: origin_from(APPROVAL, self.chain_depth)?,
        }))
    }

    /// The call the request's run paused on.
    fn held_call(&self) -> Result<PendingCallRef, DomainError> {
        let (Some(tool), Some(arguments), Some(at_step)) = (
            self.pending_tool.as_deref(),
            self.pending_arguments.as_deref(),
            self.pending_at_step,
        ) else {
            return Err(DomainError::corrupt_row(
                APPROVAL.0,
                "a run with no held call",
            ));
        };
        let call = APPROVAL.value("held call", ToolCall::new(tool, arguments))?;
        let at_step = u32::try_from(at_step)
            .map_err(|_| DomainError::corrupt_row(APPROVAL.0, "a call held at no step"))?;
        Ok(PendingCallRef::new(call, at_step))
    }

    /// What the request's run had read when it paused.
    fn run_exposure(&self) -> Result<DataClassLevel, DomainError> {
        let Some(exposure) = self.run_exposure.as_deref() else {
            return Err(DomainError::corrupt_row(
                APPROVAL.0,
                "a run with no exposure",
            ));
        };
        DataClassLevel::from_stored(exposure)
    }

    /// The agent's owner, which this takes from the record, and
    /// `delegators`.
    fn parties(&mut self, delegators: Vec<DelegatorRecord>) -> Result<ActionParties, DomainError> {
        let person = std::mem::take(&mut self.owner_person);
        let owner = human_from(APPROVAL, &self.owner_kind, self.owner_id, person)?;
        let delegators = delegators
            .into_iter()
            .map(|delegator| {
                human_from(
                    APPROVAL,
                    &delegator.account_kind,
                    delegator.account_id,
                    delegator.person,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ActionParties::from_stored(owner, delegators))
    }

    /// Where the request stands, with the approvals and decision this
    /// takes from the record.
    fn state(&mut self) -> Result<ApprovalState, DomainError> {
        let first = maybe_human_from(
            APPROVAL,
            self.first_by_kind.take(),
            self.first_by_id,
            self.first_by_person.take(),
        )?;
        let decider = maybe_human_from(
            APPROVAL,
            self.decided_by_kind.take(),
            self.decided_by_id,
            self.decided_by_person.take(),
        )?;
        let decision =
            approval_from(decider, self.decided_at)?.map_or(StoredDecision::Undecided, |decided| {
                StoredDecision::Decided {
                    by: decided.by,
                    at: decided.at,
                }
            });
        let first = approval_from(first, self.first_at)?;
        ApprovalState::from_stored(APPROVAL.choice(&self.status)?, first, decision)
    }
}

/// An approval a person and a time make, both or neither.
fn approval_from(
    by: Option<Human>,
    at: Option<OffsetDateTime>,
) -> Result<Option<Approval>, DomainError> {
    match (by, at) {
        (None, None) => Ok(None),
        (Some(by), Some(at)) => Ok(Some(Approval { by, at })),
        (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
            APPROVAL.0,
            "an approval with no person or no time",
        )),
    }
}

/// A person's three columns, or none of them, as they are written.
pub(super) struct MaybeHumanColumns<'a> {
    pub(super) kind: Option<&'static str>,
    pub(super) id: Option<Uuid>,
    pub(super) person: Option<&'a str>,
}

impl<'a> MaybeHumanColumns<'a> {
    /// The columns `human` is written to, empty when there is none.
    fn of(human: Option<&'a Human>) -> Self {
        let columns = human.map(HumanColumns::of);
        Self {
            kind: columns.as_ref().map(|columns| columns.kind),
            id: columns.as_ref().map(|columns| columns.id),
            person: columns.map(|columns| columns.person),
        }
    }
}

/// The run columns of a request: the run, the call it paused on, what it
/// had read and where it came from, all empty for one opened by hand.
pub(super) struct RunOriginColumns<'a> {
    pub(super) run_id: Option<Uuid>,
    pub(super) pending_tool: Option<&'a str>,
    pub(super) pending_arguments: Option<&'a str>,
    pub(super) pending_at_step: Option<i32>,
    pub(super) exposure: Option<&'static str>,
    pub(super) chain_depth: Option<i16>,
}

impl<'a> RunOriginColumns<'a> {
    /// The run columns `origin` is written to.
    fn of(origin: &'a ApprovalOrigin) -> Result<Self, DomainError> {
        let ApprovalOrigin::Run(run) = origin else {
            return Ok(Self {
                run_id: None,
                pending_tool: None,
                pending_arguments: None,
                pending_at_step: None,
                exposure: None,
                chain_depth: None,
            });
        };
        let at_step = i32::try_from(run.pending_call().at_step()).map_err(DomainError::infra)?;
        Ok(Self {
            run_id: Some(*run.run_id().as_uuid()),
            pending_tool: Some(run.pending_call().tool()),
            pending_arguments: Some(run.pending_call().arguments()),
            pending_at_step: Some(at_step),
            exposure: Some(run.exposure().as_str()),
            chain_depth: depth_of(run.chain()),
        })
    }
}

/// A request's columns, as they are written.
pub(super) struct ApprovalColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) agent_id: &'a Uuid,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) requested_by: InitiatorColumns<'a>,
    pub(super) run: RunOriginColumns<'a>,
    pub(super) owner: HumanColumns<'a>,
    pub(super) action_class: Option<&'static str>,
    pub(super) action: &'a str,
    pub(super) status: &'static str,
    pub(super) first_by: MaybeHumanColumns<'a>,
    pub(super) first_at: Option<OffsetDateTime>,
    pub(super) decided_by: MaybeHumanColumns<'a>,
    pub(super) decided_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) delegators: DelegatorColumns,
}

impl<'a> ApprovalColumns<'a> {
    /// The columns `approval` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the step its run paused
    /// at, or the number of people behind it, is past what a column holds.
    pub(super) fn of(approval: &'a ApprovalRequest<ResolvedTenant>) -> Result<Self, DomainError> {
        let first = approval.first_approval();
        let decided = decided(approval.state());
        Ok(Self {
            id: approval.id().as_uuid(),
            agent_id: approval.agent_id().as_uuid(),
            delegation_id: approval
                .delegation_id()
                .delegation()
                .map(|id| *id.as_uuid()),
            requested_by: InitiatorColumns::of(requester_of(approval.origin())),
            run: RunOriginColumns::of(approval.origin())?,
            owner: HumanColumns::of(approval.parties().owner()),
            action_class: approval.action_class().stored().map(ActionClass::as_str),
            action: approval.action().as_str(),
            status: approval.status().word(),
            first_by: MaybeHumanColumns::of(first.map(|first| &first.by)),
            first_at: first.map(|first| first.at),
            decided_by: MaybeHumanColumns::of(decided.map(|(by, _)| by)),
            decided_at: decided.map(|(_, at)| at),
            created_at: approval.created_at(),
            expires_at: approval.expires_at(),
            updated_at: approval.updated_at(),
            delegators: DelegatorColumns::of(approval.parties().delegators())?,
        })
    }
}

/// Who put a request's action there: who opened it, or who started its run.
fn requester_of(origin: &ApprovalOrigin) -> &Initiator {
    match origin {
        ApprovalOrigin::Opened(by) => by,
        ApprovalOrigin::Run(run) => run.started_by(),
    }
}

/// Who decided a request and when: the person whose approval granted it,
/// or who denied or withdrew it.
fn decided(state: &ApprovalState) -> Option<(&Human, OffsetDateTime)> {
    match state {
        ApprovalState::Approved { approval, .. } | ApprovalState::Consumed { approval, .. } => {
            Some((&approval.by, approval.at))
        }
        ApprovalState::Denied { decision, .. } | ApprovalState::Withdrawn { decision, .. } => {
            Some((decision.decider(), decision.at()))
        }
        ApprovalState::Pending(_) | ApprovalState::Expired(_) => None,
    }
}

/// The people behind a request's delegation, one list per column and one
/// place per person, as one statement writes them.
pub(super) struct DelegatorColumns {
    pub(super) places: Vec<i16>,
    pub(super) kinds: Vec<String>,
    pub(super) ids: Vec<Uuid>,
    pub(super) persons: Vec<String>,
}

impl DelegatorColumns {
    /// The columns `delegators` are written to, in their order.
    fn of(delegators: &[Human]) -> Result<Self, DomainError> {
        let places = (0..delegators.len())
            .map(|place| i16::try_from(place).map_err(DomainError::infra))
            .collect::<Result<_, _>>()?;
        let columns: Vec<HumanColumns<'_>> = delegators.iter().map(HumanColumns::of).collect();
        Ok(Self {
            places,
            kinds: columns.iter().map(|human| human.kind.to_owned()).collect(),
            ids: columns.iter().map(|human| human.id).collect(),
            persons: columns
                .iter()
                .map(|human| human.person.to_owned())
                .collect(),
        })
    }
}
