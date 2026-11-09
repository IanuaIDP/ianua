//! SCIM request parsing: the directory calling, which page, filter and
//! order a listing asks for, the version a directory already holds, and a
//! body read in SCIM's terms. Every refusal answers in SCIM's error format.

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::header::{AUTHORIZATION, IF_NONE_MATCH};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::ScimCaller;
use ianua_app::error::AppError;
use ianua_app::listing::SortDirection;
use ianua_app::ports::federation::{ScimQuery, ScimUserSort, ScimWindow};
use ianua_app::use_cases::scim::{groups, users};
use ianua_domain::shared::security::secret::Secret;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::dto::scim::FilterMatch;
use crate::error::ApiError;
use crate::error::scim::ScimApiError;
use crate::extractors::json::Json;
use crate::extractors::public_tenant::PublicTenant;
use crate::extractors::query::Query;
use crate::extractors::scim_filter::{FilterExpr, group_attribute, user_attribute};
use crate::state::ApiState;

/// The page size when a provider does not say.
const DEFAULT_PAGE: u64 = 100;

/// A directory calling the SCIM service of the tenant the path names, with
/// whatever bearer token it sent. Whether the token is the tenant's is the
/// use case's question.
pub(crate) struct ScimDirectory {
    /// The tenant, and the token the directory came with.
    pub caller: ScimCaller,
    /// Records what the directory changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for ScimDirectory {
    type Rejection = ScimApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = bearer_token(parts);
        let tenant = PublicTenant::from_request_parts(parts, state)
            .await
            .map_err(as_unknown_directory)?;
        Ok(Self {
            caller: ScimCaller::new(tenant.tenant, bearer),
            auditor: tenant.auditor,
        })
    }
}

/// A tenant the path names that is missing or closed, answered as a token
/// that is not the tenant's.
///
/// Only a directory holding the tenant's token has any use for its SCIM
/// service. Without this, Mallory, holding no token, tries tenant names and
/// learns from a `404` which ones exist.
fn as_unknown_directory(refused: ApiError) -> ScimApiError {
    match refused.0 {
        AppError::Internal(_) => ScimApiError::from(refused),
        _ => ScimApiError::from(AppError::Unauthenticated),
    }
}

/// The token in an `Authorization: Bearer` header, the scheme read in any
/// case, or `None` when the request carries none.
fn bearer_token(parts: &Parts) -> Option<Secret> {
    let header = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| Secret::new(token.trim()))
}

/// A listing's `filter`, `sortBy`, `sortOrder`, `startIndex` and `count`.
pub(crate) struct ScimListQuery {
    page: ScimWindow,
    /// The 1-based index of the first result, echoed in the response.
    pub start_index: u64,
    filter: Option<FilterExpr>,
    sort: Option<(String, SortDirection)>,
}

/// The listing's query string, as sent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawListQuery {
    filter: Option<String>,
    start_index: Option<u64>,
    count: Option<u64>,
    sort_by: Option<String>,
    sort_order: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for ScimListQuery {
    type Rejection = ScimApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<RawListQuery>::from_request_parts(parts, state).await?;
        let start_index = raw.start_index.unwrap_or(1).max(1);
        let direction = sort_direction(raw.sort_order.as_deref())?;
        Ok(Self {
            page: ScimWindow::new(start_index, raw.count.unwrap_or(DEFAULT_PAGE)),
            start_index,
            filter: raw.filter.as_deref().map(FilterExpr::parse).transpose()?,
            sort: raw
                .sort_by
                .map(|attribute| (attribute.to_ascii_lowercase(), direction)),
        })
    }
}

/// The direction `sortOrder` names: ascending when absent.
fn sort_direction(order: Option<&str>) -> Result<SortDirection, ScimApiError> {
    match order.map(str::to_ascii_lowercase).as_deref() {
        None | Some("ascending") => Ok(SortDirection::Asc),
        Some("descending") => Ok(SortDirection::Desc),
        Some(other) => Err(ScimApiError::invalid_value(format!(
            "sortOrder is ascending or descending, not {other}"
        ))),
    }
}

impl ScimListQuery {
    /// The user listing asked for, and whether its filter can match anyone.
    ///
    /// A filter on an attribute this service does not keep matches nobody:
    /// a provider looking a user up that way is told there is none and goes
    /// on to create it. The listing still runs, on one entry, so the
    /// directory's token is checked before anything is answered.
    ///
    /// # Errors
    ///
    /// `invalidValue` if `sortBy` names an attribute this service does not
    /// keep.
    pub(crate) fn users(&self) -> Result<(users::ListScimRequest, FilterMatch), ScimApiError> {
        let sort = self.user_sort()?;
        let (filter, matches) = self.picked(user_attribute);
        let request = users::ListScimRequest {
            filter,
            sort,
            page: self.page_for(matches),
        };
        Ok((request, matches))
    }

    /// The group listing asked for, and whether its filter can match
    /// anyone, read as [`users`](Self::users) reads it.
    ///
    /// # Errors
    ///
    /// `invalidValue` if the listing names a `sortBy`: groups are listed in
    /// one order.
    pub(crate) fn groups(&self) -> Result<(groups::ListScimRequest, FilterMatch), ScimApiError> {
        if self.sort.is_some() {
            return Err(ScimApiError::invalid_value(
                "groups are listed in one order; sortBy is not read for them",
            ));
        }
        let (filter, matches) = self.picked(group_attribute);
        let request = groups::ListScimRequest {
            filter,
            page: self.page_for(matches),
        };
        Ok((request, matches))
    }

    /// The query the filter makes over the attributes `attribute` knows:
    /// everything when there is no filter, and nobody when it can match
    /// nothing.
    fn picked<A>(&self, attribute: fn(&str) -> Option<A>) -> (ScimQuery<A>, FilterMatch) {
        let Some(filter) = &self.filter else {
            return (ScimQuery::All, FilterMatch::Readable);
        };
        filter
            .resolve(attribute)
            .map_or((ScimQuery::All, FilterMatch::Nobody), |query| {
                (query, FilterMatch::Readable)
            })
    }

    /// The order users are listed in: as stored when no `sortBy` is given.
    fn user_sort(&self) -> Result<ScimUserSort, ScimApiError> {
        let Some((attribute, direction)) = &self.sort else {
            return Ok(ScimUserSort::Default);
        };
        user_attribute(attribute)
            .map(|known| ScimUserSort::By(known, *direction))
            .ok_or_else(|| {
                ScimApiError::invalid_value(format!("users are not sorted by {attribute}"))
            })
    }

    /// The page to read: the one asked for, or a single entry when the
    /// answer is empty anyway.
    fn page_for(&self, matches: FilterMatch) -> ScimWindow {
        match matches {
            FilterMatch::Readable => self.page,
            FilterMatch::Nobody => ScimWindow::single(),
        }
    }
}

/// The versions a directory says it already holds, from `If-None-Match`.
/// Absent, it holds none.
pub(crate) struct IfNoneMatch(Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for IfNoneMatch {
    type Rejection = ScimApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let held = parts
            .headers
            .get(IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok(Self(held))
    }
}

impl IfNoneMatch {
    /// Whether the directory already holds `version`: the header names it,
    /// weakly compared, or is `*`.
    #[must_use]
    pub(crate) fn holds(&self, version: &str) -> bool {
        let Some(held) = &self.0 else {
            return false;
        };
        let wanted = version.trim_start_matches("W/");
        held.split(',')
            .map(str::trim)
            .any(|tag| tag == "*" || tag.trim_start_matches("W/") == wanted)
    }
}

/// A JSON body a provider sent, as `application/scim+json` or
/// `application/json`. A body that is not one is an `invalidValue`, whose
/// detail never quotes the body.
pub(crate) struct ScimBody<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for ScimBody<T> {
    type Rejection = ScimApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(body) = Json::<T>::from_request(req, state).await?;
        Ok(Self(body))
    }
}
