//! The member behind a sign-in request: one signed in, or one whose sign-in
//! still waits for a second factor to be proved or set up.
//!
//! Both come with the session's refresh token as their bearer, and the auth
//! middleware resolves either to the member. Which of the two the request
//! speaks for is what the request itself says: a member signed in proves
//! who they are again, a waiting sign-in shows only itself. Whether the
//! session really finished signing in, or really waits, is the app's
//! question.
//!
//! So the holder is not an [`OrgMember`](crate::extractors::callers::OrgMember):
//! that one refuses a session still waiting for its factor before any use
//! case runs, which is right for everything else a member does and would
//! leave a waiting sign-in no way to finish. The holder checks only that
//! the credential is a member's of this organization, and marks nothing
//! used. The use case it runs refuses a waiting sign-in that owes nothing
//! it can answer, and a member signed in whose session no longer counts.
//! Only the steps a waiting sign-in must reach take it: answering its
//! factor with a code or a recovery code, and setting up its first factor
//! or passkey.
//!
//! A sign-in through the organization's identity provider has nobody to
//! name yet: only where it came from and where the provider answers to.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::{OrgCaller, OrgCredential};
use ianua_app::error::AppError;
use ianua_app::ports::federation::ServiceProvider;
use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::use_cases::authentication::federation::SsoReturn;
use ianua_app::use_cases::authentication::mfa::SetupProof;
use ianua_app::use_cases::organization::mfa::setter::{MemberFactorSetter, PendingMemberSession};
use ianua_app::use_cases::organization::passkeys::MemberSetupProof;
use ianua_app::use_cases::organization::passkeys::registrant::{
    MemberRegistrant, PendingMemberToken,
};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, SamlEntityId, SessionId};

use crate::dto::organization::sign_in::origin_of;
use crate::error::ApiError;
use crate::extractors::callers::{Visitor, member_of_path_organization};
use crate::state::ApiState;

/// A member of the organization the path names, with the session they came
/// with, whether finished or still signing in.
pub(crate) struct SignInHolder {
    /// The member and the sign-in they hold.
    pub held: HeldSignIn,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

/// The member and the refresh token of the sign-in they hold. The token is
/// a credential, so this has no `Debug`.
pub(crate) struct HeldSignIn {
    caller: OrgCaller,
    bearer: Secret,
}

/// Which sign-in a member adds a passkey from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holding {
    /// Enrolls a passkey from an authenticated member who proves their identity again.
    FinishedSignIn,
    /// A sign-in that waits for a second factor to be set up.
    WaitingSignIn,
}

impl FromRequestParts<ApiState> for SignInHolder {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let caller = member_of_path_organization(parts, state).await?;
        let bearer = bearer_of(parts)?;
        Ok(Self {
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context()),
            held: HeldSignIn { caller, bearer },
        })
    }
}

impl HeldSignIn {
    /// Who sets up a second factor on `proof`: the member signed in when
    /// they proved who they are again, their waiting sign-in when it is
    /// the sign-in that owes the factor.
    ///
    /// # Errors
    ///
    /// `401` when a waiting sign-in is claimed through a key, which is no
    /// sign-in at all.
    pub(crate) fn factor_setter(self, proof: &SetupProof) -> Result<MemberFactorSetter, ApiError> {
        match proof {
            SetupProof::Reentered(_) => Ok(MemberFactorSetter::SignedIn(self.caller)),
            SetupProof::OwedBySignIn => self.pending_session().map(MemberFactorSetter::SigningIn),
        }
    }

    /// Who confirms a second factor: the waiting sign-in `waiting` names,
    /// or the member signed in when it names none.
    ///
    /// A waiting sign-in is shown by its own refresh token, so the one
    /// named must be the session the bearer is. Otherwise whoever holds one
    /// of the member's keys or other sessions, and learnt the id of a
    /// sign-in they never finished, could set up their own authenticator
    /// on it.
    ///
    /// # Errors
    ///
    /// - `401` when a waiting sign-in is named through a key.
    /// - `403` when the sign-in named is not the bearer's own session.
    pub(crate) fn confirming_setter(
        self,
        waiting: Option<SessionId>,
    ) -> Result<MemberFactorSetter, ApiError> {
        let Some(named) = waiting else {
            return Ok(MemberFactorSetter::SignedIn(self.caller));
        };
        let pending = self.pending_session()?;
        if pending.session_id != named {
            return Err(ApiError(AppError::Forbidden(message!(
                "api-the-sign-in-named-is-not",
                "the sign-in named is not the one this request comes from"
            ))));
        }
        Ok(MemberFactorSetter::SigningIn(pending))
    }

    /// The sign-in this request is made from, as one waiting for a factor.
    ///
    /// # Errors
    ///
    /// `401` when the member came with a key rather than a session.
    pub(crate) fn pending_session(&self) -> Result<PendingMemberSession, ApiError> {
        let OrgCredential::Session(session_id) = self.caller.credential() else {
            return Err(ApiError(AppError::Unauthenticated));
        };
        Ok(PendingMemberSession {
            session_id: *session_id,
            member: *self.caller.member(),
        })
    }

    /// Who adds a passkey from `holding`: the member signed in, or the
    /// waiting sign-in their refresh token shows.
    #[must_use]
    pub(crate) fn registrant(self, holding: Holding) -> MemberRegistrant {
        match holding {
            Holding::FinishedSignIn => MemberRegistrant::SignedIn(self.caller),
            Holding::WaitingSignIn => MemberRegistrant::SettingUpFactor(PendingMemberToken {
                refresh_token: self.bearer,
            }),
        }
    }
}

impl From<&MemberSetupProof> for Holding {
    fn from(proof: &MemberSetupProof) -> Self {
        match proof {
            MemberSetupProof::Reentered(_) => Self::FinishedSignIn,
            MemberSetupProof::WaitingSignIn => Self::WaitingSignIn,
        }
    }
}

/// Someone signing in to the dashboard through their organization's
/// identity provider: where the request came from, and where the provider
/// sends the browser back to.
pub(crate) struct SsoVisitor {
    /// The client's address and user agent.
    pub origin: ClientOrigin,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
    /// The dashboard pages the provider answers to, built from the
    /// deployment's own address, never from the request.
    pub returns_to: SsoReturn,
}

impl FromRequestParts<ApiState> for SsoVisitor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Ok(visitor) = Visitor::from_request_parts(parts, state).await;
        Ok(Self {
            origin: origin_of(visitor.meta),
            auditor: visitor.auditor,
            returns_to: dashboard_return(&state.organization.sign_in.app_base_url)?,
        })
    }
}

/// The dashboard's single sign-on pages under `base`: the page an OIDC
/// provider redirects to, and this deployment as the SAML service provider
/// whose page a SAML provider posts to. The dashboard hands each answer on
/// to `/api/v1/login/sso/callback`.
fn dashboard_return(base: &HttpsUrl) -> Result<SsoReturn, ApiError> {
    let base = base.as_str().trim_end_matches('/');
    let page = |path: &str| HttpsUrl::new(format!("{base}{path}")).map_err(AppError::internal);
    Ok(SsoReturn {
        oidc_callback: page("/login/sso/oidc")?,
        service_provider: ServiceProvider {
            entity_id: SamlEntityId::new(base).map_err(AppError::internal)?,
            acs_url: page("/login/sso/saml")?,
        },
    })
}

/// The bearer token the request came with, which the auth middleware
/// already resolved to the member.
fn bearer_of(parts: &Parts) -> Result<Secret, ApiError> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .filter(|token| !token.is_empty())
        .map(Secret::new)
        .ok_or(ApiError(AppError::Unauthenticated))
}
