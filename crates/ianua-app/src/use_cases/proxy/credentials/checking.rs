//! What every check of a request's credential reads: the request as it
//! arrived, and the readers every kind of caller shares.

use ianua_domain::domains::proxy::request::context::RouteRequirements;
use ianua_domain::domains::proxy::request::cross_site::{CookieRequest, CsrfEcho, PageOrigin};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Fact, Issuer};

use crate::context::QuotaCharge;
use crate::ports::authentication::PresentedTokens;
use crate::ports::authorization::AccessRecordStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::oauth::sender::DpopHeader;
use crate::use_cases::proxy::credentials::outcome::Refusal;
use crate::use_cases::proxy::credentials::presented::RequestTarget;

/// A request at the gateway while its credential is checked.
pub(crate) struct Checking<'a> {
    /// The tenant it targets.
    pub tenant: &'a ScopedTenant,
    /// Where it was sent.
    pub target: &'a RequestTarget,
    /// What its route asks of it.
    pub route: &'a RouteRequirements,
    /// Reads the tokens the tenant signed.
    pub tokens: &'a dyn PresentedTokens,
    /// What callers hold, from the tenant's records.
    pub records: &'a dyn AccessRecordStore,
    /// Whether a consumer signing in is counted against its quota.
    pub charge: QuotaCharge,
}

impl Checking<'_> {
    /// The issuer the route holds tokens to.
    ///
    /// # Errors
    ///
    /// - [`Refusal::WrongIssuer`] while the route has none: no token is
    ///   taken unchecked for want of an issuer to hold it to.
    pub(crate) fn issuer(&self) -> Result<&Issuer, Refusal> {
        match &self.route.expected_issuer {
            Fact::Known(issuer) => Ok(issuer),
            Fact::Unknown => Err(Refusal::WrongIssuer),
        }
    }

    /// Refuses a cookie-authenticated request that a page of `origin` could
    /// have forged: one that changes something must come from the cookie's
    /// own site or echo the CSRF cookie. A session cookie trusts no page, so
    /// its requests are checked as coming from elsewhere.
    ///
    /// # Errors
    ///
    /// - [`Refusal::CrossSite`] when the request may be forged.
    pub(crate) fn ensure_not_forged(
        &self,
        origin: PageOrigin,
        echo: CsrfEcho,
    ) -> Result<(), Refusal> {
        let request = CookieRequest {
            method: self.target.method,
            origin,
            echo,
        };
        request.ensure_not_forged().map_err(|_| Refusal::CrossSite)
    }
}

/// A bearer token, with the `DPoP` proof the request sent beside it.
pub(crate) struct Bearer {
    /// The raw credential to authenticate alongside its sender proof.
    pub token: Secret,
    /// The request's `DPoP` header.
    pub dpop: DpopHeader,
}
