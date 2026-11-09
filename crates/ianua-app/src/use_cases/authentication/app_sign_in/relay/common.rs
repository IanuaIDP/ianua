//! What the app sign-in use cases share: the app a request is for, the
//! challenge cookie a sign-in still under way is held by, and opening the
//! person's session on its host once they have proved who they are.

use ianua_domain::domains::authentication::device_trust::DeviceSecret;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallenge;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::routing::sign_in::app::SignInAction;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, SamlEntityId, SessionId, TokenHash};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{AppSessionGrant, IssuedAppSession};
use crate::ports::federation::ServiceProvider;
use crate::services::issuers::issuer_of;
use crate::use_cases::authentication::app_sign_in::relay::target::{Target, resolve};
use crate::use_cases::authentication::app_sign_in::sessions::across::{
    AcrossHosts, AcrossHostsPorts, idle_timeout,
};
use crate::use_cases::authentication::app_sign_in::{
    AppSignInContext, AppSignInLifetimes, AppSignInOutcome, SignInPorts,
};
use crate::use_cases::authentication::federation::SsoReturn;

/// The app a request is carried out for, resolved and checked.
pub(in crate::use_cases::authentication::app_sign_in) struct OnTarget<'a> {
    /// The request's context.
    pub(in crate::use_cases::authentication::app_sign_in) ctx: &'a AppSignInContext,
    /// The tenant, service and host the request names.
    pub(in crate::use_cases::authentication::app_sign_in) target: &'a Target,
}

/// A person who proved who they are, with what their sign-in still owes.
pub(in crate::use_cases::authentication::app_sign_in) struct Proved {
    /// The session the proof opened.
    pub(in crate::use_cases::authentication::app_sign_in) session_id: SessionId,
    /// What it still owes in the way of a second factor.
    pub(in crate::use_cases::authentication::app_sign_in) owed: SecondFactor,
    /// Where to send them once they are in.
    pub(in crate::use_cases::authentication::app_sign_in) return_to: Option<ReturnPath>,
}

/// The ports, the cross-host hand-over and the platform address every app
/// sign-in use case works with.
pub(in crate::use_cases::authentication::app_sign_in) struct AppSignInCommon {
    /// The ports every action reads and writes through.
    pub(in crate::use_cases::authentication::app_sign_in) ports: SignInPorts,
    /// Carries a sign-in to the hosts of services accepting it.
    pub(in crate::use_cases::authentication::app_sign_in) across: AcrossHosts,
    /// How long the short steps last.
    pub(in crate::use_cases::authentication::app_sign_in) lifetimes: AppSignInLifetimes,
    app_base_url: HttpsUrl,
}

impl AppSignInCommon {
    /// Builds the shared part over `ports`. `app_base_url` is the platform's
    /// own address, which a tenant's token issuer is built from when it sets
    /// none.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        ports: SignInPorts,
        app_base_url: HttpsUrl,
        lifetimes: AppSignInLifetimes,
    ) -> Self {
        let across = AcrossHosts::new(
            AcrossHostsPorts {
                target: ports.target.clone(),
                session_store: ports.session_store.clone(),
                code_hasher: ports.code_hasher.clone(),
                tokens: ports.tokens.clone(),
                handoff_store: ports.handoff_store.clone(),
                session_check: ports.session_check.clone(),
            },
            app_base_url.clone(),
            lifetimes,
        );
        Self {
            ports,
            across,
            lifetimes,
            app_base_url,
        }
    }

    /// The app `ctx` names, provided it has app sign-in on that host, with
    /// `auditor` scoped to its organization and tenant.
    ///
    /// # Errors
    ///
    /// `AppError::NotFound` if the tenant, service or host do not have app
    /// sign-in; `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::app_sign_in) async fn resolved(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
    ) -> Result<(Target, RequestAuditor), AppError> {
        let target = resolve(&self.ports.target, &ctx.tenant, &ctx.service_id, &ctx.host).await?;
        let scoped = auditor
            .with_organization(*target.org.id())
            .with_tenant(*target.tenant.id());
        Ok((target, scoped))
    }

    /// Binds the finished session to the app, mints the token for its host,
    /// and names each host of a service accepting the sign-in with a cookie
    /// of its own, for the browser to pass through.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` if the session is gone or cannot be bound, the
    /// token cannot be made, or the services cannot be read.
    pub(in crate::use_cases::authentication::app_sign_in) async fn open_on_host(
        &self,
        on: &OnTarget<'_>,
        session_id: &SessionId,
        return_to: Option<ReturnPath>,
    ) -> Result<AppSignInOutcome, AppError> {
        self.open_remembering(on, session_id, return_to, None).await
    }

    /// As [`open_on_host`](Self::open_on_host), handing back the secret of
    /// the device the sign-in just remembered, for the host's device
    /// cookie.
    ///
    /// # Errors
    ///
    /// As [`open_on_host`](Self::open_on_host).
    pub(in crate::use_cases::authentication::app_sign_in) async fn open_remembering(
        &self,
        on: &OnTarget<'_>,
        session_id: &SessionId,
        return_to: Option<ReturnPath>,
        remembered: Option<DeviceSecret>,
    ) -> Result<AppSignInOutcome, AppError> {
        let session = self.bound_session(on, session_id).await?;
        let issued = self.issue_session_token(on, &session).await?;
        let owner = on.target.service.id();
        Ok(AppSignInOutcome::SignedIn {
            session: issued,
            return_to: landing(on.target, return_to)?,
            hops: self.across.hop_hosts(on.ctx, owner).await?,
            remembered,
        })
    }

    /// Where a sign-in goes once the person proved who they are: opened on
    /// the host, or held by a challenge cookie until the code or the mailed
    /// link answers what it still owes.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if the person must first set up a second
    ///   factor, which an app's host does not offer.
    /// - `AppError::NotFound` if the session is gone.
    /// - `AppError::Internal` on storage or signing failure.
    pub(in crate::use_cases::authentication::app_sign_in) async fn onward(
        &self,
        on: &OnTarget<'_>,
        proved: Proved,
    ) -> Result<AppSignInOutcome, AppError> {
        let Proved {
            session_id,
            owed,
            return_to,
        } = proved;
        match owed {
            SecondFactor::NotOwed => self.open_on_host(on, &session_id, return_to).await,
            SecondFactor::Verify => {
                let (challenge, expires_at) = self.challenge(on.ctx, &session_id).await?;
                Ok(AppSignInOutcome::MfaRequired {
                    challenge,
                    expires_at,
                })
            }
            SecondFactor::ConfirmByEmail => {
                let (challenge, expires_at) = self.challenge(on.ctx, &session_id).await?;
                Ok(AppSignInOutcome::ConfirmByEmail {
                    challenge,
                    expires_at,
                })
            }
            SecondFactor::Enrol | SecondFactor::ConfirmThenEnrol => Err(not_finished_here()),
        }
    }

    /// Hands out a challenge token for a session that still owes a step,
    /// with when it lapses. The host keeps it in its challenge cookie.
    async fn challenge(
        &self,
        ctx: &AppSignInContext,
        session_id: &SessionId,
    ) -> Result<(Secret, OffsetDateTime), AppError> {
        let ports = &self.ports;
        let session = ports
            .session_store
            .find_by_id(&ctx.tenant, session_id)
            .await
            .or_internal()?
            .ok_or_else(sign_in_expired)?;
        let (token, token_hash) = ports.code_hasher.generate_code().await.or_internal()?;
        let lifetime = self.lifetimes.mfa_challenge;
        let challenge =
            MfaChallenge::issue(&session, token_hash, lifetime).map_err(AppError::from_domain)?;
        ports
            .challenge_store
            .save(&ctx.tenant, &challenge)
            .await
            .or_internal()?;
        Ok((token, challenge.expires_at()))
    }

    /// Where an outside identity provider sends the browser back to the
    /// target's host: its single sign-on return address, for OIDC and SAML
    /// alike, with this platform as the SAML service provider.
    ///
    /// Built from the service's stored settings and the host they name,
    /// never from anything the request carried.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the address cannot be built.
    pub(in crate::use_cases::authentication::app_sign_in) fn sso_return(
        &self,
        target: &Target,
    ) -> Result<SsoReturn, AppError> {
        let path = target.sign_in.path(SignInAction::SsoCallback);
        let callback = HttpsUrl::new(format!("https://{}{path}", target.host)).or_internal()?;
        let platform = self.app_base_url.as_str().trim_end_matches('/');
        let entity_id = SamlEntityId::new(platform).or_internal()?;
        Ok(SsoReturn {
            oidc_callback: callback.clone(),
            service_provider: ServiceProvider {
                entity_id,
                acs_url: callback,
            },
        })
    }

    /// The session just opened, bound to the target's service and saved.
    async fn bound_session(
        &self,
        on: &OnTarget<'_>,
        session_id: &SessionId,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let store = self.ports.session_store.as_ref();
        let mut session = store
            .find_by_id(&on.ctx.tenant, session_id)
            .await
            .or_internal()?
            .ok_or_else(|| AppError::internal_msg("a session just opened is gone"))?;
        session
            .bind_to_app(*on.target.service.id())
            .map_err(AppError::from_domain)?;
        store.save(&on.ctx.tenant, &session).await.or_internal()?;
        Ok(session)
    }

    /// The challenge the host's challenge cookie holds the token of, while
    /// it is still open. One that has closed is forgotten on the way out.
    ///
    /// # Errors
    ///
    /// `AppError::NotFound` if it is unknown or closed;
    /// `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::app_sign_in) async fn open_challenge(
        &self,
        ctx: &AppSignInContext,
        token: &Secret,
    ) -> Result<MfaChallenge<ResolvedTenant>, AppError> {
        let token_hash = self
            .ports
            .code_hasher
            .hash_code(token)
            .await
            .or_internal()?;
        let challenge = self
            .ports
            .challenge_store
            .find_by_token_hash(&ctx.tenant, &token_hash)
            .await
            .or_internal()?
            .ok_or_else(sign_in_expired)?;
        let attempts = self.lifetimes.mfa_challenge_attempts;
        if !challenge.is_open(clock::now(), attempts) {
            self.forget_challenge(ctx, &token_hash).await?;
            return Err(sign_in_expired());
        }
        Ok(challenge)
    }

    /// Spends the answered challenge and forgets it.
    ///
    /// # Errors
    ///
    /// `AppError::NotFound` if it closed meanwhile; `AppError::Internal` on
    /// storage failure.
    pub(in crate::use_cases::authentication::app_sign_in) async fn spend_challenge(
        &self,
        ctx: &AppSignInContext,
        mut challenge: MfaChallenge<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let attempts = self.lifetimes.mfa_challenge_attempts;
        challenge
            .consume(clock::now(), attempts)
            .map_err(|_| sign_in_expired())?;
        self.forget_challenge(ctx, challenge.token_hash()).await
    }

    async fn forget_challenge(
        &self,
        ctx: &AppSignInContext,
        token_hash: &TokenHash,
    ) -> Result<(), AppError> {
        self.ports
            .challenge_store
            .delete(&ctx.tenant, token_hash)
            .await
            .or_internal()
    }

    /// The challenged session, which must still exist.
    ///
    /// # Errors
    ///
    /// `AppError::NotFound` if it is gone; `AppError::Internal` on storage
    /// failure.
    pub(in crate::use_cases::authentication::app_sign_in) async fn challenged_session(
        &self,
        ctx: &AppSignInContext,
        challenge: &MfaChallenge<ResolvedTenant>,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        self.ports
            .session_store
            .find_by_id(&ctx.tenant, challenge.session_id())
            .await
            .or_internal()?
            .ok_or_else(sign_in_expired)
    }

    /// Mints the session token for the target's host.
    async fn issue_session_token(
        &self,
        on: &OnTarget<'_>,
        session: &Session<ResolvedTenant>,
    ) -> Result<IssuedAppSession, AppError> {
        let target = on.target;
        let grant = AppSessionGrant {
            issuer: issuer_of(&self.app_base_url, &target.tenant, &target.org),
            audience: target.audience()?,
            host: target.host.clone(),
            user_id: *session.user_id(),
            session_id: *session.id(),
            service_id: *target.service.id(),
            assurance: session.assurance_level(),
            expires_at: session.expires_at(),
            idle_timeout: idle_timeout(&target.tenant),
            signed_in_from: session.signed_in_from(),
        };
        self.ports
            .tokens
            .issue(&on.ctx.tenant, &grant)
            .await
            .or_internal()
    }
}

/// The refusal for a challenge that is unknown, closed, or whose session is
/// gone.
pub(in crate::use_cases::authentication::app_sign_in) fn sign_in_expired() -> AppError {
    AppError::NotFound(message!(
        "authentication-the-sign-in-has-expired-start",
        "the sign-in has expired; start again"
    ))
}

/// The refusal for a sign-in that owes a step an app's host does not take:
/// setting up a factor.
pub(in crate::use_cases::authentication::app_sign_in) fn not_finished_here() -> AppError {
    AppError::Forbidden(message!(
        "authentication-this-sign-in-must-have-a",
        "this sign-in must have a second factor set up before it goes on here"
    ))
}

/// What a sign-in that mailed no confirmation link still owes. Only a
/// password sign-in mails one, so a way in that owes a mailbox confirmation
/// cannot be finished on the app's host.
///
/// # Errors
///
/// `AppError::Forbidden` when the sign-in owes a mailbox confirmation.
pub(in crate::use_cases::authentication::app_sign_in) fn without_mailed_link(
    owed: SecondFactor,
) -> Result<SecondFactor, AppError> {
    match owed {
        SecondFactor::ConfirmByEmail | SecondFactor::ConfirmThenEnrol => Err(mailbox_only()),
        SecondFactor::NotOwed | SecondFactor::Verify | SecondFactor::Enrol => Ok(owed),
    }
}

/// The refusal for a sign-in that only a mailbox confirmation can finish,
/// reached by a way in that mails none.
fn mailbox_only() -> AppError {
    AppError::Forbidden(message!(
        "authentication-this-sign-in-must-be-confirmed",
        "this sign-in must be confirmed from the mailbox; sign in with the password instead"
    ))
}

/// Where the person lands once signed in: where they asked to go, or where
/// the app sends people by default.
fn landing(target: &Target, return_to: Option<ReturnPath>) -> Result<ReturnPath, AppError> {
    let Some(path) = return_to else {
        return ReturnPath::new(target.sign_in.after_sign_in().as_str()).or_internal();
    };
    Ok(path)
}
