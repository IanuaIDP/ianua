//! An access request as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::authorization::access_request::{
    AccessRequest, AccessRequestRow, AccessRequestStatus, AskedAccess, RequestAnswer,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AccessRequestId, GroupId, Human, Lifetime, RoleId, Text};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{HumanColumns, human_from, maybe_human_from};
use crate::postgres::foundation::stored::Stored;

const ACCESS_REQUEST: Stored = Stored("access request");

/// The word of a request for a role.
const ROLE: &str = "role";

/// The word of a request for a place in a group.
const GROUP: &str = "group";

/// A request as it is read. The store's checked queries fill it.
pub(super) struct AccessRequestRecord {
    pub(super) id: Uuid,
    pub(super) requester_kind: String,
    pub(super) requester_id: Uuid,
    pub(super) requester_person: String,
    pub(super) asked: String,
    pub(super) asked_id: Uuid,
    pub(super) reason: String,
    pub(super) length_seconds: i64,
    pub(super) status: String,
    pub(super) approver_kind: Option<String>,
    pub(super) approver_id: Option<Uuid>,
    pub(super) approver_person: Option<String>,
    pub(super) answered_at: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
}

impl AccessRequestRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the request
    /// keeps.
    pub(super) fn into_request(self) -> Result<AccessRequest<ResolvedTenant>, DomainError> {
        let approver = maybe_human_from(
            ACCESS_REQUEST,
            self.approver_kind,
            self.approver_id,
            self.approver_person,
        )?;
        AccessRequest::reconstitute(AccessRequestRow {
            id: AccessRequestId::from_uuid(self.id),
            requester: human_from(
                ACCESS_REQUEST,
                &self.requester_kind,
                self.requester_id,
                self.requester_person,
            )?,
            asked: asked_from(&self.asked, self.asked_id)?,
            reason: ACCESS_REQUEST.value("reason", Text::new("reason", self.reason))?,
            length: ACCESS_REQUEST.value("length", Lifetime::seconds(self.length_seconds))?,
            status: AccessRequestStatus::from_stored(&self.status)?,
            answer: answer_from(approver, self.answered_at)?,
            requested_at: self.requested_at,
        })
    }
}

/// What a word and an id say was asked for.
fn asked_from(word: &str, id: Uuid) -> Result<AskedAccess, DomainError> {
    match word {
        ROLE => Ok(AskedAccess::Role(RoleId::from_uuid(id))),
        GROUP => Ok(AskedAccess::Group(GroupId::from_uuid(id))),
        _ => Err(DomainError::corrupt_row(
            ACCESS_REQUEST.0,
            "asks for something unknown",
        )),
    }
}

/// The answer an approver and a time say, or none when both are empty.
fn answer_from(
    approver: Option<Human>,
    at: Option<OffsetDateTime>,
) -> Result<RequestAnswer, DomainError> {
    match (approver, at) {
        (None, None) => Ok(RequestAnswer::Unanswered),
        (Some(approver), Some(at)) => Ok(RequestAnswer::By { approver, at }),
        (_, _) => Err(DomainError::corrupt_row(
            ACCESS_REQUEST.0,
            "an answer with no approver or no time",
        )),
    }
}

/// A request's columns, as they are written.
pub(super) struct AccessRequestColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) requester: HumanColumns<'a>,
    pub(super) asked: &'static str,
    pub(super) asked_id: Uuid,
    pub(super) reason: &'a str,
    pub(super) length_seconds: i64,
    pub(super) status: &'static str,
    pub(super) approver: Option<HumanColumns<'a>>,
    pub(super) answered_at: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
}

impl<'a> AccessRequestColumns<'a> {
    /// The columns `request` is written to.
    pub(super) fn of(request: &'a AccessRequest<ResolvedTenant>) -> Self {
        let (asked, asked_id) = match request.asked() {
            AskedAccess::Role(role) => (ROLE, *role.as_uuid()),
            AskedAccess::Group(group) => (GROUP, *group.as_uuid()),
        };
        let (approver, answered_at) = match request.answer() {
            RequestAnswer::Unanswered => (None, None),
            RequestAnswer::By { approver, at } => (Some(HumanColumns::of(approver)), Some(*at)),
        };
        Self {
            id: request.id().as_uuid(),
            requester: HumanColumns::of(request.requester()),
            asked,
            asked_id,
            reason: request.reason().as_str(),
            length_seconds: request.length().whole_seconds(),
            status: request.status().as_str(),
            approver,
            answered_at,
            requested_at: request.requested_at(),
        }
    }
}
