//! Short-lived bearer tokens for services accepting an app's sign-in by
//! token, fetched from the owner's host while the person is signed in.

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::sign_in::accepted::SignInDelivery;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Audience};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{AppAccessGrant, AppSessionClaim, IssuedAppSession};
use crate::services::issuers::issuer_of;
use crate::use_cases::authentication::app_sign_in::relay::target::Target;
use crate::use_cases::authentication::app_sign_in::sessions::across::{
    AcrossHosts, idle_timeout, signed_out,
};
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};

/// The session cookie a token is asked for with, and the audience it is for.
pub(in crate::use_cases::authentication::app_sign_in) struct TokenGrant<'a> {
    /// The session cookie's token, as presented, if one was.
    pub(in crate::use_cases::authentication::app_sign_in) session: Option<&'a Secret>,
    /// The audience the token is minted for.
    pub(in crate::use_cases::authentication::app_sign_in) audience: &'a Audience,
}

/// The services a token is minted with: the one it is for, and the owner's
/// sign-in it carries on from.
struct Reach<'a> {
    target: &'a Target,
    reached: &'a Service<ResolvedTenant>,
    audience: &'a Audience,
}

impl AcrossHosts {
    /// A short-lived bearer token for the service accepting `target`'s
    /// sign-in by token whose audience is `grant.audience`, for the person
    /// whose session cookie `grant.session` is.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` without a live session of `target`'s
    /// sign-in, and `AppError::NotFound` when no service takes tokens for
    /// the audience from it.
    pub(in crate::use_cases::authentication::app_sign_in) async fn issue_token(
        &self,
        ctx: &AppSignInContext,
        target: &Target,
        grant: TokenGrant<'_>,
        auditor: &RequestAuditor,
    ) -> Result<AppSignInOutcome, AppError> {
        let claim = self.live_claim(ctx, target, grant.session).await?;
        let reached = self.token_service(ctx, target, grant.audience).await?;
        let reach = Reach {
            target,
            reached: &reached,
            audience: grant.audience,
        };
        let (issued, mut session) = self.handed_out_access(ctx, &reach, &claim).await?;
        auditor
            .dispatch_by(
                &ActorRef::User(claim.user_id),
                session.take_events(&ctx.tenant),
            )
            .await
            .or_internal()?;
        Ok(AppSignInOutcome::Token(issued))
    }

    /// Mints the access token for the reached service, ending no later
    /// than the session it carries on from, and the session, which records
    /// the token issued.
    async fn handed_out_access(
        &self,
        ctx: &AppSignInContext,
        reach: &Reach<'_>,
        claim: &AppSessionClaim,
    ) -> Result<(IssuedAppSession, Session<ResolvedTenant>), AppError> {
        let mut session = self.held_session(ctx, &claim.session_id).await?;
        let target = reach.target;
        let grant = AppAccessGrant {
            issuer: issuer_of(&self.app_base_url, &target.tenant, &target.org),
            audience: reach.audience.clone(),
            user_id: claim.user_id,
            session_id: claim.session_id,
            owner: *target.service.id(),
            assurance: session.assurance_level(),
            expires_at: session
                .expires_at()
                .min(self.lifetimes.access.ends_after(clock::now())),
            idle_timeout: idle_timeout(&target.tenant),
            signed_in_from: session.signed_in_from(),
        };
        let issued = self
            .ports
            .tokens
            .issue_access(&ctx.tenant, &grant)
            .await
            .or_internal()?;
        session.record_app_token(reach.reached.id(), reach.reached.name(), issued.expires_at);
        Ok((issued, session))
    }

    /// What the session cookie says, provided it is a live session of
    /// `target`'s own sign-in.
    pub(in crate::use_cases::authentication::app_sign_in) async fn live_claim(
        &self,
        ctx: &AppSignInContext,
        target: &Target,
        session: Option<&Secret>,
    ) -> Result<AppSessionClaim, AppError> {
        let token = session.ok_or_else(signed_out)?;
        let claim = self
            .ports
            .tokens
            .read(&ctx.tenant, token, &target.host)
            .await
            .map_err(|_| signed_out())?;
        if claim.service_id != *target.service.id() {
            return Err(signed_out());
        }
        self.ensure_live(ctx, &claim).await?;
        Ok(claim)
    }

    /// The service accepting `target`'s sign-in by token whose audience is
    /// `audience`.
    async fn token_service(
        &self,
        ctx: &AppSignInContext,
        target: &Target,
        audience: &Audience,
    ) -> Result<Service<ResolvedTenant>, AppError> {
        self.accepting(ctx, target.service.id())
            .await?
            .into_iter()
            .find(|service| takes_tokens_for(service, audience))
            .ok_or_else(|| {
                AppError::NotFound(message!(
                    "authentication-no-service-takes-tokens-for-that",
                    "no service takes tokens for that audience from this sign-in"
                ))
            })
    }
}

/// Whether `service` takes tokens, and for `audience`.
fn takes_tokens_for(service: &Service<ResolvedTenant>, audience: &Audience) -> bool {
    service.upstream().expected_audience() == Some(audience)
        && service
            .accepted_sign_in()
            .is_some_and(|accepted| *accepted.delivery() == SignInDelivery::Tokens)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::authentication::{
        CrossHostFixture, SHOP_HOST, cross_host_ctx, cross_host_fixture,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::app_sign_in::relay::target::resolve;

    fn token_for(
        f: &CrossHostFixture,
        session: Option<&str>,
        audience: &str,
    ) -> Result<AppSignInOutcome, AppError> {
        let host = DomainName::new(SHOP_HOST).unwrap();
        let target = block_on(resolve(&f.ports, &test_ctx().tenant(), &f.owner, &host)).unwrap();
        let cookie = session.map(Secret::new);
        block_on(f.across.issue_token(
            &cross_host_ctx(f.owner, SHOP_HOST),
            &target,
            TokenGrant {
                session: cookie.as_ref(),
                audience: &Audience::new(audience).unwrap(),
            },
            &test_auditor(f.audit.clone()),
        ))
    }

    /// Ann, signed in on the shop, asks for a token for the reports service,
    /// which takes tokens from the shop's sign-in. She gets one naming the
    /// shop, and it is recorded.
    #[test]
    fn a_token_is_issued_for_a_service_taking_tokens_and_names_the_sign_in() {
        let f = cross_host_fixture();

        let issued = token_for(&f, Some("cookie"), "reports");

        assert!(matches!(issued, Ok(AppSignInOutcome::Token(_))));
        assert_eq!(
            f.tokens.minted.lock().unwrap().as_slice(),
            [format!("access:reports:{}", f.owner)]
        );
        assert_eq!(
            f.audit.records.lock().unwrap().as_slice(),
            ["authentication.app_token_issued"]
        );
    }

    /// Ann asks for a token for the API, which keeps a cookie of its own and
    /// takes no tokens. She gets nothing.
    #[test]
    fn no_token_for_a_service_that_does_not_take_tokens() {
        let f = cross_host_fixture();

        assert!(matches!(
            token_for(&f, Some("cookie"), "api"),
            Err(AppError::NotFound(_))
        ));
    }

    /// Missing and ended sessions are both refused when requesting a
    /// reports token, and neither attempt mints a token.
    #[test]
    fn no_token_without_a_live_session() {
        let f = cross_host_fixture();

        let no_cookie = token_for(&f, None, "reports");
        f.live.0.store(false, Ordering::SeqCst);
        let ended = token_for(&f, Some("cookie"), "reports");

        assert!(matches!(no_cookie, Err(AppError::Forbidden(_))));
        assert!(matches!(ended, Err(AppError::Forbidden(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }
}
