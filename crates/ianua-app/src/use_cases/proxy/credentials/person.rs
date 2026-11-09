//! A person's credential: a token the tenant signed for them, issued under
//! an app session or an OAuth grant, or the app session cookie of the host
//! they signed in on.
//!
//! Whatever the credential, the person must still be able to sign in, and
//! what it was issued under must still stand: deactivating Ann, ending her
//! session or revoking her grant stops her credential on the next request,
//! not when it runs out.

use std::sync::Arc;

use ianua_domain::domains::oauth::grants::access_token::TokenSubject;
use ianua_domain::domains::oauth::grants::token_binding::SenderBinding;
use ianua_domain::domains::proxy::access::question::DpopBinding;
use ianua_domain::domains::proxy::request::context::{Caller, UserSignIn};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Expiry, Fact, PrincipalRef, TrustedDeviceId, UserId};

use crate::error::AppError;
use crate::ports::authentication::{
    AppSessionCheck, AppSessionClaim, AppSessionToken, ExpectedSession, IssuedUnder, PersonToken,
};
use crate::ports::identity::UserStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query as _;
use crate::use_cases::oauth::flows::{PresentedAccessToken, ResolveAccessTokenUseCase};
use crate::use_cases::oauth::sender::SenderEvidence;
use crate::use_cases::proxy::credentials::checking::{Bearer, Checking};
use crate::use_cases::proxy::credentials::held::{claims_of, held_by};
use crate::use_cases::proxy::credentials::outcome::{Identification, Refusal, proven, read};
use crate::use_cases::proxy::credentials::presented::AppSessionCookie;

/// The ports checking that what stands behind a person's credential still
/// does.
#[derive(ianua_macros::Fakes)]
pub struct PersonPorts {
    /// Where accounts are kept, to see the person may still sign in.
    pub user_store: Arc<dyn UserStore>,
    /// Whether an app session is still live.
    pub app_sessions: Arc<dyn AppSessionCheck>,
    /// Resolves an OAuth access token to the grant behind it, while it
    /// stands, with the proof of the key it may be bound to.
    pub grants: Arc<ResolveAccessTokenUseCase>,
}

/// The person a token the tenant signed names, once what it was issued
/// under still stands.
///
/// # Errors
///
/// - [`Refusal::UnknownSubject`] or [`Refusal::Inactive`] when the person
///   is not there or may no longer sign in.
/// - [`Refusal::Revoked`] when the app session ended, or the grant no
///   longer stands.
/// - [`Refusal::Invalid`] when the token names another person than its
///   session or grant.
/// - [`Refusal::Unavailable`] when a check fails.
pub(crate) async fn by_token(
    ports: &PersonPorts,
    checking: &Checking<'_>,
    person: PersonToken,
    bearer: Bearer,
) -> Result<Identification, Refusal> {
    ensure_may_sign_in(ports, checking.tenant, &person.user_id).await?;
    let device = signed_in_from(person.issued_under);
    let (sign_in, binding) = ensure_issued_under_stands(ports, checking, bearer, &person).await?;
    let principal = PrincipalRef::User(person.user_id);
    let held = held_by(checking.records, checking.tenant, principal).await?;
    let mut claims = claims_of(&held);
    claims.scopes = person.scopes;
    claims.current_aal = person.assurance;
    claims.asserted = Fact::Known(person.claims);
    claims.signed_in_from = device;
    let caller = Caller::User {
        user_id: person.user_id,
        sign_in,
    };
    Ok(proven(
        caller,
        Expiry::At(person.expires_at),
        held,
        claims,
        binding,
    ))
}

/// The person an app session cookie names on its host, once the request
/// shows it was not forged by another site and the session is still live.
///
/// # Errors
///
/// - [`Refusal::CrossSite`] when a request that changes something came
///   from another site without a CSRF proof.
/// - The reader's refusals, as [`Refusal`] maps them, and
///   [`Refusal::WrongIssuer`] while the route holds tokens to no issuer.
/// - [`Refusal::UnknownSubject`], [`Refusal::Inactive`] or
///   [`Refusal::Revoked`] as for a token.
/// - [`Refusal::Unavailable`] when a check fails.
pub(crate) async fn by_app_session(
    ports: &PersonPorts,
    checking: &Checking<'_>,
    cookie: AppSessionCookie,
) -> Result<Identification, Refusal> {
    checking.ensure_not_forged(cookie.origin, cookie.csrf)?;
    let expected = ExpectedSession {
        issuer: checking.issuer()?,
        audience: &cookie.audience,
        host: &cookie.host,
        owner: &cookie.owner,
    };
    let session = session_named(checking, &cookie.token, expected).await?;
    let user_id = session.claim.user_id;
    ensure_may_sign_in(ports, checking.tenant, &user_id).await?;
    ensure_session_live(ports, checking.tenant, &session.claim, &user_id).await?;
    let principal = PrincipalRef::User(user_id);
    let held = held_by(checking.records, checking.tenant, principal).await?;
    let mut claims = claims_of(&held);
    claims.current_aal = session.assurance;
    claims.signed_in_from = session.claim.signed_in_from;
    let caller = Caller::User {
        user_id,
        sign_in: UserSignIn::Session(session.claim.session_id),
    };
    Ok(proven(
        caller,
        Expiry::At(session.expires_at),
        held,
        claims,
        DpopBinding::Unbound,
    ))
}

/// What `person`'s token was issued under, as it stands now: the session
/// it was issued in, still live, or the grant behind it, still standing
/// with the key it is bound to.
///
/// # Errors
///
/// - [`Refusal::Revoked`] when the session ended or the grant was revoked.
/// - [`Refusal::DpopMismatch`] when a bound token comes without its key's
///   proof.
/// - [`Refusal::Unavailable`] when a check fails.
async fn ensure_issued_under_stands(
    ports: &PersonPorts,
    checking: &Checking<'_>,
    bearer: Bearer,
    person: &PersonToken,
) -> Result<(UserSignIn, DpopBinding), Refusal> {
    match person.issued_under {
        IssuedUnder::AppSession(claim) => {
            ensure_session_live(ports, checking.tenant, &claim, &person.user_id).await?;
            Ok((UserSignIn::Session(claim.session_id), DpopBinding::Unbound))
        }
        IssuedUnder::Grant => {
            let binding = ensure_grant_stands(ports, checking, bearer, &person.user_id).await?;
            Ok((UserSignIn::Token, binding))
        }
    }
}

/// The session `token` names, read against what `expected` says of it.
///
/// # Errors
///
/// - The reader's refusals, as [`Refusal`] maps them.
/// - [`Refusal::Unavailable`] when the reading fails.
async fn session_named(
    checking: &Checking<'_>,
    token: &Secret,
    expected: ExpectedSession<'_>,
) -> Result<AppSessionToken, Refusal> {
    let reading = checking
        .tokens
        .read_app_session(checking.tenant, token, expected)
        .await
        .map_err(Refusal::unavailable)?;
    read(reading)
}

/// The trusted device the session behind a token was signed in from. A
/// grant's access token is held by an app's server, not by the person's
/// device, so it names none.
fn signed_in_from(issued_under: IssuedUnder) -> Fact<TrustedDeviceId> {
    match issued_under {
        IssuedUnder::AppSession(claim) => claim.signed_in_from,
        IssuedUnder::Grant => Fact::Unknown,
    }
}

/// Refuses a person who is not there or may no longer sign in, so
/// deactivating or locking them stops their credential at once.
///
/// # Errors
///
/// - [`Refusal::UnknownSubject`] when the tenant has no such person.
/// - [`Refusal::Inactive`] when they may not sign in now.
/// - [`Refusal::Unavailable`] when the account cannot be read.
pub(super) async fn ensure_may_sign_in(
    ports: &PersonPorts,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<(), Refusal> {
    let account = ports
        .user_store
        .find_by_id(tenant, user_id)
        .await
        .map_err(Refusal::unavailable)?
        .ok_or(Refusal::UnknownSubject)?;
    if !account.can_authenticate() {
        return Err(Refusal::Inactive);
    }
    Ok(())
}

/// Refuses a credential whose app session ended, or names another person
/// than `user_id`.
///
/// # Errors
///
/// - [`Refusal::Invalid`] when the session's person is not `user_id`.
/// - [`Refusal::Revoked`] when the session is not live.
/// - [`Refusal::Unavailable`] when the session cannot be read.
async fn ensure_session_live(
    ports: &PersonPorts,
    tenant: &ScopedTenant,
    claim: &AppSessionClaim,
    user_id: &UserId,
) -> Result<(), Refusal> {
    if claim.user_id != *user_id {
        return Err(Refusal::Invalid);
    }
    let live = ports
        .app_sessions
        .is_live(tenant, claim)
        .await
        .map_err(Refusal::unavailable)?;
    if !live {
        return Err(Refusal::Revoked);
    }
    Ok(())
}

/// Whether an OAuth access token is bound to a `DPoP` key the request
/// proved it holds; refuses one whose grant no longer stands, was
/// presented without the key it is bound to, or names another person than
/// `user_id`.
///
/// # Errors
///
/// - [`Refusal::Revoked`] when the token's record is gone, revoked or run
///   out, its client was revoked, or it lacks its key's proof.
/// - [`Refusal::Invalid`] when the grant is another person's, or a
///   machine's.
/// - [`Refusal::WrongIssuer`] while the route holds tokens to no issuer.
/// - [`Refusal::Unavailable`] when a lookup fails.
async fn ensure_grant_stands(
    ports: &PersonPorts,
    checking: &Checking<'_>,
    bearer: Bearer,
    user_id: &UserId,
) -> Result<DpopBinding, Refusal> {
    let presented = PresentedAccessToken {
        token: bearer.token,
        sender: SenderEvidence {
            dpop: bearer.dpop,
            method: checking.target.method.as_str().to_owned(),
            url: checking.target.url.as_str().to_owned(),
        },
        issuer: checking.issuer()?.clone(),
    };
    let grant = ports
        .grants
        .execute(checking.tenant, presented)
        .await
        .map_err(grant_refusal)?;
    if grant.subject != TokenSubject::Person(*user_id) {
        return Err(Refusal::Invalid);
    }
    Ok(key_binding(&grant.binding))
}

/// Whether a grant the resolver let through was bound to a `DPoP` key: it
/// admits a bound token only beside a verified proof of that key.
fn key_binding(binding: &SenderBinding) -> DpopBinding {
    match binding {
        SenderBinding::DpopKey(_) => DpopBinding::Bound,
        SenderBinding::Bearer | SenderBinding::Certificate(_) => DpopBinding::Unbound,
    }
}

/// The refusal of a grant the resolver turned away.
fn grant_refusal(error: AppError) -> Refusal {
    match error {
        AppError::Unauthenticated => Refusal::Revoked,
        other => Refusal::unavailable(other),
    }
}
