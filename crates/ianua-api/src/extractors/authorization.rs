//! Reading the filters of the authorization listings out of the query
//! string: which access requests, access reviews, relationships and
//! decision records a listing keeps.
//!
//! Nothing here decides whether the caller may see what a filter keeps;
//! the app does.

use ianua_app::ports::authorization::{
    AccessRequestFilter, AccessReviewFilter, DecisionFilter, RelationshipFilter, Verdict,
};
use ianua_domain::domains::authorization::policy::version::PolicyVersion;
use ianua_domain::domains::authorization::relationship::{ObjectRef, RelationSubject};
use ianua_domain::message;
use ianua_domain::types::{Label, PrincipalRef};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::principal::PrincipalKind;
use crate::dto::authorization::relationships::{SubjectKind, object_ref};
use crate::error::ApiError;

/// The status an access request listing narrows to.
#[derive(Clone, Copy, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestStatusParam {
    /// Requests still waiting for an answer.
    Pending,
}

/// Which access requests a listing keeps: `?status=pending`, or
/// `?asked_by_kind=user&asked_by_id=…`, or every one when neither is given.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AccessRequestQuery {
    /// `pending` keeps only those still waiting for an answer.
    status: Option<RequestStatusParam>,
    /// The kind of account that asked, with `asked_by_id`.
    asked_by_kind: Option<PrincipalKind>,
    /// The account that asked, with `asked_by_kind`.
    asked_by_id: Option<Uuid>,
}

impl AccessRequestQuery {
    /// The filter the query names.
    ///
    /// # Errors
    ///
    /// A validation error when it names both a status and an asker, or half
    /// an asker.
    pub(crate) fn filter(&self) -> Result<AccessRequestFilter, ApiError> {
        let asker = principal(self.asked_by_kind, self.asked_by_id, "asked_by")?;
        match (self.status, asker) {
            (None, None) => Ok(AccessRequestFilter::All),
            (Some(RequestStatusParam::Pending), None) => Ok(AccessRequestFilter::Pending),
            (None, Some(asker)) => Ok(AccessRequestFilter::AskedBy(asker)),
            (Some(_), Some(_)) => Err(ApiError::validation(message!(
                "api-filter-by-status-or-by-asker",
                "filter by status or by asker, not both"
            ))),
        }
    }
}

/// The status an access review listing narrows to.
#[derive(Clone, Copy, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReviewStatusParam {
    /// Reviews whose reviewers are still deciding.
    Open,
}

/// Which access reviews a listing keeps: `?status=open`, or every one.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AccessReviewQuery {
    /// `open` keeps only those reviewers are still deciding.
    status: Option<ReviewStatusParam>,
}

impl AccessReviewQuery {
    /// The filter the query names.
    #[must_use]
    pub(crate) fn filter(&self) -> AccessReviewFilter {
        match self.status {
            None => AccessReviewFilter::All,
            Some(ReviewStatusParam::Open) => AccessReviewFilter::Open,
        }
    }
}

/// Which relationships a listing keeps: those about one object
/// (`?object_type=…&object_key=…`), those one subject holds
/// (`?subject_kind=…&subject_id=…`), or every one.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RelationshipQuery {
    /// The object's resource type, with `object_key`.
    object_type: Option<String>,
    /// The object's key in the tenant's app, with `object_type`.
    object_key: Option<String>,
    /// The kind of subject holding a relation, with `subject_id`.
    subject_kind: Option<SubjectKind>,
    /// The subject holding a relation, with `subject_kind`.
    subject_id: Option<Uuid>,
}

impl RelationshipQuery {
    /// The filter the query names.
    ///
    /// # Errors
    ///
    /// A validation error when it names both an object and a subject, half
    /// of either, or an object that is not valid.
    pub(crate) fn filter(&self) -> Result<RelationshipFilter, ApiError> {
        match (self.object()?, self.subject()?) {
            (None, None) => Ok(RelationshipFilter::All),
            (Some(object), None) => Ok(RelationshipFilter::OnObject(object)),
            (None, Some(subject)) => Ok(RelationshipFilter::HeldBy(subject)),
            (Some(_), Some(_)) => Err(ApiError::validation(message!(
                "api-filter-by-object-or-by-subject",
                "filter by object or by subject, not both"
            ))),
        }
    }

    /// The object the query names, if any.
    fn object(&self) -> Result<Option<ObjectRef>, ApiError> {
        match (&self.object_type, &self.object_key) {
            (None, None) => Ok(None),
            (Some(resource_type), Some(key)) => object_ref(resource_type, key).map(Some),
            _ => Err(ApiError::validation(message!(
                "api-object-type-and-object-key-go",
                "object_type and object_key go together"
            ))),
        }
    }

    /// The subject the query names, if any.
    fn subject(&self) -> Result<Option<RelationSubject>, ApiError> {
        match (self.subject_kind, self.subject_id) {
            (None, None) => Ok(None),
            (Some(kind), Some(id)) => Ok(Some(kind.with_id(id))),
            _ => Err(ApiError::validation(message!(
                "api-subject-kind-and-subject-id-go",
                "subject_kind and subject_id go together"
            ))),
        }
    }
}

/// How a recorded decision went.
#[derive(Clone, Copy, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerdictParam {
    /// Let through.
    Allowed,
    /// Refused.
    Denied,
    /// Let through only after a stronger sign-in or a proof.
    Challenged,
}

impl From<VerdictParam> for Verdict {
    fn from(param: VerdictParam) -> Self {
        match param {
            VerdictParam::Allowed => Self::Allowed,
            VerdictParam::Denied => Self::Denied,
            VerdictParam::Challenged => Self::Challenged,
        }
    }
}

/// Which decision records a search keeps; every part given must hold.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct DecisionQuery {
    /// The kind of subject decided about, with `subject_id`.
    subject_kind: Option<PrincipalKind>,
    /// The subject decided about, with `subject_kind`.
    subject_id: Option<Uuid>,
    /// `allowed`, `denied` or `challenged`.
    verdict: Option<VerdictParam>,
    /// The number of the policy version that decided.
    policy_version: Option<u32>,
    /// The name of the policy rule that decided.
    rule: Option<String>,
    /// Only decisions made at or after this time (RFC 3339).
    #[serde(default, with = "time::serde::rfc3339::option")]
    since: Option<OffsetDateTime>,
}

impl DecisionQuery {
    /// The filter the query names.
    ///
    /// # Errors
    ///
    /// A validation error for half a subject, version 0, or a rule name
    /// that is not valid.
    pub(crate) fn filter(&self) -> Result<DecisionFilter, ApiError> {
        Ok(DecisionFilter {
            subject: principal(self.subject_kind, self.subject_id, "subject")?,
            verdict: self.verdict.map(Verdict::from),
            policy_version: self
                .policy_version
                .map(PolicyVersion::parse)
                .transpose()
                .map_err(ApiError::validation)?,
            rule: self
                .rule
                .as_deref()
                .map(|rule| Label::new("rule", rule))
                .transpose()
                .map_err(ApiError::validation)?,
            since: self.since,
        })
    }
}

/// The principal a `<prefix>_kind` and `<prefix>_id` pair names, if any.
fn principal(
    kind: Option<PrincipalKind>,
    id: Option<Uuid>,
    prefix: &str,
) -> Result<Option<PrincipalRef>, ApiError> {
    match (kind, id) {
        (None, None) => Ok(None),
        (Some(kind), Some(id)) => Ok(Some(kind.with_id(id))),
        _ => Err(ApiError::validation(message!(
            "api-kind-and-id-go-together",
            format!("{prefix}_kind and {prefix}_id go together")
        ))),
    }
}
