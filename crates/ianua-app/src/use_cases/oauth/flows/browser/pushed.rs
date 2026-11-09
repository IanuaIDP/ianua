//! The pushed request behind a browser's `request_uri` at the consent
//! step: read and used in memory, then used up in storage once, when a
//! code is issued.

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::pushed_request::{PushedParameters, PushedRequest};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

use crate::error::{AppError, OrInternal};
use crate::ports::oauth::PushedRequestStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::oauth::flows::BrowserParameters;
use crate::use_cases::oauth::lookup::existing_pushed_request;

/// Where the request's parameters came from.
pub(in crate::use_cases::oauth::flows) enum Source {
    /// The browser carried them.
    Carried,
    /// They were pushed; this request, just used in memory, is used up in
    /// storage when a code is issued.
    Pushed(Box<PushedRequest<ResolvedTenant>>),
}

/// Uses up a pushed request in storage, once: of two browsers coming with
/// one `request_uri`, only one gets a code.
///
/// # Errors
///
/// - `AppError::Domain` when another browser used it first.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::oauth::flows) async fn ensure_pushed_used_once(
    store: &dyn PushedRequestStore,
    tenant: &ScopedTenant,
    source: &Source,
) -> Result<(), AppError> {
    let Source::Pushed(pushed) = source else {
        return Ok(());
    };
    if store.redeem(tenant, pushed).await.or_internal()? {
        return Ok(());
    }
    Err(AppError::Domain(DomainError::invalid(message!(
        "oauth-this-request-uri-was-used-already",
        "this request_uri was used already"
    ))))
}

/// The parameters `parameters` stand for, with where they came from. A
/// pushed request is used in memory here, for `client`.
///
/// # Errors
///
/// - `AppError::NotFound` when no pushed request has the `request_uri`.
/// - `AppError::Domain` when it was pushed by another client, ran out, or
///   was used already.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::oauth::flows) async fn parameters_of(
    store: &dyn PushedRequestStore,
    tenant: &ScopedTenant,
    client: &OAuthClient<ResolvedTenant>,
    parameters: BrowserParameters,
) -> Result<(PushedParameters, Source), AppError> {
    let uri = match parameters {
        BrowserParameters::Carried(carried) => return Ok((carried, Source::Carried)),
        BrowserParameters::Pushed(uri) => uri,
    };
    let mut pushed = existing_pushed_request(store, tenant, &uri).await?;
    let parameters = pushed
        .redeem(client, clock::now())
        .map_err(|refusal| AppError::from_domain(DomainError::from(refusal)))?;
    Ok((parameters, Source::Pushed(Box::new(pushed))))
}
