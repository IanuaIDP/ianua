//! List filters, ordering and cursor paging read through the usual query
//! extractors, preserving their validation errors and order.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::listing::{PageRequest, SortField, SortOrder};
use serde::de::DeserializeOwned;

use crate::extractors::pagination::Paging;
use crate::extractors::query::{Query, QueryRefusal};
use crate::extractors::sort::SortQuery;

/// A list's filter parameters followed by its checked cursor and limit.
pub(crate) struct PageQuery<T> {
    /// The endpoint's filter parameters.
    pub query: T,
    /// Where the page begins and how many rows it may contain.
    pub page: PageRequest,
}

impl<S, T> FromRequestParts<S> for PageQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(query) = Query::<T>::from_request_parts(parts, state).await?;
        let Paging(page) = Paging::from_request_parts(parts, state).await?;
        Ok(Self { query, page })
    }
}

/// A list's checked ordering followed by its cursor and limit.
pub(crate) struct SortedPage<F: SortField> {
    /// The fields and directions used to order the page.
    pub sort: SortOrder<F>,
    /// Where the page begins and how many rows it may contain.
    pub page: PageRequest,
}

impl<S, F> FromRequestParts<S> for SortedPage<F>
where
    S: Send + Sync,
    F: SortField + Send,
{
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let SortQuery(sort) = SortQuery::<F>::from_request_parts(parts, state).await?;
        let Paging(page) = Paging::from_request_parts(parts, state).await?;
        Ok(Self { sort, page })
    }
}

/// A list query read in filter, ordering and pagination order.
pub(crate) struct ListingQuery<T, F: SortField> {
    /// The endpoint's filter parameters.
    pub query: T,
    /// The fields and directions used to order the page.
    pub sort: SortOrder<F>,
    /// Where the page begins and how many rows it may contain.
    pub page: PageRequest,
}

impl<S, T, F> FromRequestParts<S> for ListingQuery<T, F>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
    F: SortField + Send,
{
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(query) = Query::<T>::from_request_parts(parts, state).await?;
        let SortedPage { sort, page } = SortedPage::<F>::from_request_parts(parts, state).await?;
        Ok(Self { query, sort, page })
    }
}
