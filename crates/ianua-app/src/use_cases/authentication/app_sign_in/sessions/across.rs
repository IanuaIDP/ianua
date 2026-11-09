//! A sign-in reaching services on hosts other than the owner's: a cookie of
//! their own, set by a hop through each of their hosts. Tokens fetched from
//! the owner's host are in `across_tokens`.
//!
//! A hop takes three steps, so the code it carries works only in the browser
//! that signed in. The browser lands on the other host, which keeps a random
//! value in a cookie of its own there; it goes back to the owner's host,
//! where its session is, and is handed a code bound to the digest of that
//! value; it lands on the other host again with the code, and the value
//! there must match. A code sent to anyone else, in a link, sets nothing in
//! their browser.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::handoff::{
    HandoffKeys, HandoffLanding, HandoffTarget, SessionHandoff,
};
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, DomainName, HttpsUrl, ServiceId, SessionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::authentication::{
    AppSessionCheck, AppSessionClaim, AppSessionGrant, AppSessionTokens, HandoffStore,
    IssuedAppSession,
};
use crate::ports::oauth::CodeHasher;
use crate::ports::shared::SessionStore;
use crate::services::issuers::issuer_of;
use crate::use_cases::authentication::app_sign_in::relay::target::{
    CookieTarget, Target, TargetPorts, pinned_audience, resolve_cookie_host,
};
use crate::use_cases::authentication::app_sign_in::{
    AppHandOverRequest, AppSignInContext, AppSignInLifetimes, AppSignInOutcome, Hop,
};

/// What a hop's code is asked for with, on the owner's host. Holds the
/// session cookie's token, so it has no `Debug`.
pub(in crate::use_cases::authentication::app_sign_in) struct HopAsk<'a> {
    /// The session cookie's token, as presented, if one was.
    pub(in crate::use_cases::authentication::app_sign_in) session: Option<&'a Secret>,
    /// The host the code is for.
    pub(in crate::use_cases::authentication::app_sign_in) host: DomainName,
    /// The digest of the value the asking browser keeps on that host.
    pub(in crate::use_cases::authentication::app_sign_in) browser: &'a Secret,
}

/// How many of a tenant's services are looked through; far above what any
/// tenant defines.
const MAX_TENANT_SERVICES: u32 = 10_000;

/// The ports a sign-in reaching other hosts needs.
#[derive(ianua_macros::Fakes)]
pub struct AcrossHostsPorts {
    /// The stores a request is resolved against.
    pub target: TargetPorts,
    /// Port for the session being handed on.
    pub session_store: Arc<dyn SessionStore>,
    /// Port for generating and hashing the one-time codes.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// Port for minting sessions and tokens for the other hosts.
    pub tokens: Arc<dyn AppSessionTokens>,
    /// Port for the one-time codes.
    pub handoff_store: Arc<dyn HandoffStore>,
    /// Port for checking a session is still live before handing it on.
    pub session_check: Arc<dyn AppSessionCheck>,
}

/// Carries an app sign-in to services that accept it on hosts of their own.
pub struct AcrossHosts {
    pub(in crate::use_cases::authentication::app_sign_in) ports: AcrossHostsPorts,
    pub(in crate::use_cases::authentication::app_sign_in) app_base_url: HttpsUrl,
    pub(in crate::use_cases::authentication::app_sign_in) lifetimes: AppSignInLifetimes,
}

impl AcrossHosts {
    /// Creates the flows. `app_base_url` is the platform's own address, which
    /// a tenant's token issuer is built from when it sets none; `lifetimes`
    /// bounds the codes and tokens handed out.
    #[must_use]
    pub fn new(
        ports: AcrossHostsPorts,
        app_base_url: HttpsUrl,
        lifetimes: AppSignInLifetimes,
    ) -> Self {
        Self {
            ports,
            app_base_url,
            lifetimes,
        }
    }

    /// Every host of every service accepting `owner`'s sign-in with a cookie
    /// of its own, for a browser signing in to pass through. Each hands out
    /// its code only once the browser is there.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` if the services cannot be read.
    pub(in crate::use_cases::authentication::app_sign_in) async fn hop_hosts(
        &self,
        ctx: &AppSignInContext,
        owner: &ServiceId,
    ) -> Result<Vec<DomainName>, AppError> {
        Ok(self
            .accepting(ctx, owner)
            .await?
            .iter()
            .flat_map(cookie_hosts_of)
            .collect())
    }

    /// A one-time code carrying the session `ask.session` holds to
    /// `ask.host`, bound to the browser whose hop cookie there digests to
    /// `ask.browser`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` without a live session of `target`'s sign-in.
    /// - `AppError::NotFound` when no service accepting it keeps a cookie on
    ///   `ask.host`.
    /// - `AppError::Internal` if a code cannot be made or saved.
    pub(in crate::use_cases::authentication::app_sign_in) async fn issue_hop(
        &self,
        ctx: &AppSignInContext,
        target: &Target,
        ask: HopAsk<'_>,
    ) -> Result<AppSignInOutcome, AppError> {
        let claim = self.live_claim(ctx, target, ask.session).await?;
        let to = self.cookie_target(ctx, target, ask.host).await?;
        let session = self.held_session(ctx, &claim.session_id).await?;
        let hop = self.bound_hop(ctx, &session, to, ask.browser).await?;
        Ok(AppSignInOutcome::HopIssued(hop))
    }

    /// The service accepting `target`'s sign-in with a cookie of its own on
    /// `host`, as a handoff names it.
    async fn cookie_target(
        &self,
        ctx: &AppSignInContext,
        target: &Target,
        host: DomainName,
    ) -> Result<HandoffTarget, AppError> {
        let service = self
            .accepting(ctx, target.service.id())
            .await?
            .into_iter()
            .find(|service| cookie_hosts_of(service).contains(&host))
            .ok_or_else(link_expired)?;
        Ok(HandoffTarget {
            service_id: *service.id(),
            host,
        })
    }

    /// Mints a code carrying `session` to `to`, bound to the browser whose
    /// hop cookie digests to `browser`, and saves its hashes.
    async fn bound_hop(
        &self,
        ctx: &AppSignInContext,
        session: &Session<ResolvedTenant>,
        to: HandoffTarget,
        browser: &Secret,
    ) -> Result<Hop, AppError> {
        let hasher = &self.ports.code_hasher;
        let (code, code_hash) = hasher.generate_code().await.or_internal()?;
        let keys = HandoffKeys {
            code: code_hash,
            browser: hasher.hash_code(browser).await.or_internal()?,
        };
        let host = to.host.clone();
        let handoff = SessionHandoff::issue(session, to, keys, self.lifetimes.handoff)
            .map_err(AppError::from_domain)?;
        self.ports
            .handoff_store
            .save(&ctx.tenant, &handoff)
            .await
            .or_internal()?;
        Ok(Hop { host, code })
    }

    /// Sets the session a hop carries as a cookie on the host `ctx` names,
    /// for the service accepting the owner's sign-in there, provided the
    /// code arrived in the browser it was bound to.
    ///
    /// # Errors
    ///
    /// Returns `AppError::NotFound` when the host is not one of a service's
    /// own cookie, or the code is unknown, used, lapsed, for another host or
    /// for another browser; `AppError::Forbidden` when the session it
    /// carries has ended; `AppError::Internal` on storage failure.
    pub async fn hand_over(
        &self,
        ctx: &AppSignInContext,
        landing: &AppHandOverRequest,
        auditor: &RequestAuditor,
    ) -> Result<AppSignInOutcome, AppError> {
        let target =
            resolve_cookie_host(&self.ports.target, &ctx.tenant, &ctx.service_id, &ctx.host)
                .await?;
        let auditor = auditor
            .with_organization(*target.org.id())
            .with_tenant(*target.tenant.id());
        let (mut handoff, session_id) = self.redeemed_handoff(ctx, &target, landing).await?;
        let session = self.held_session(ctx, &session_id).await?;
        let claim = AppSessionClaim {
            session_id,
            user_id: *session.user_id(),
            service_id: *target.owner.id(),
            idle_timeout: idle_timeout(&target.tenant),
            signed_in_from: session.signed_in_from(),
        };
        self.ensure_live(ctx, &claim).await?;
        let issued = self
            .issue_cookie_session(ctx, &target, &session, &claim)
            .await?;
        auditor
            .dispatch_by(
                &ActorRef::User(claim.user_id),
                handoff.take_events(&ctx.tenant),
            )
            .await
            .or_internal()?;
        Ok(AppSignInOutcome::HandedOver(issued))
    }

    /// The handoff the landing's code names, taken and spent so it cannot be
    /// used twice, and the session it hands on, provided it was made for
    /// this service and host and this browser, and has not lapsed. A code
    /// refused here is gone all the same: it was taken.
    async fn redeemed_handoff(
        &self,
        ctx: &AppSignInContext,
        target: &CookieTarget,
        landing: &AppHandOverRequest,
    ) -> Result<(SessionHandoff<ResolvedTenant>, SessionId), AppError> {
        let hasher = &self.ports.code_hasher;
        let code_hash = hasher.hash_code(&landing.code).await.or_internal()?;
        let browser = hasher.hash_code(&landing.browser).await.or_internal()?;
        let mut handoff = self
            .ports
            .handoff_store
            .take(&ctx.tenant, &code_hash)
            .await
            .or_internal()?
            .ok_or_else(link_expired)?;
        let service = &target.service;
        let arrived = HandoffLanding {
            service: service.id(),
            service_name: service.name(),
            host: &ctx.host,
            browser: &browser,
        };
        let session_id = handoff
            .redeem(&arrived, clock::now())
            .map_err(|_| link_expired())?;
        Ok((handoff, session_id))
    }

    /// Mints the cookie session for the accepting service on the host `ctx`
    /// names, carrying on from the owner's session.
    async fn issue_cookie_session(
        &self,
        ctx: &AppSignInContext,
        target: &CookieTarget,
        session: &Session<ResolvedTenant>,
        claim: &AppSessionClaim,
    ) -> Result<IssuedAppSession, AppError> {
        let grant = AppSessionGrant {
            issuer: issuer_of(&self.app_base_url, &target.tenant, &target.org),
            audience: pinned_audience(&target.service)?,
            host: ctx.host.clone(),
            user_id: claim.user_id,
            session_id: claim.session_id,
            service_id: claim.service_id,
            assurance: session.assurance_level(),
            expires_at: session.expires_at(),
            idle_timeout: claim.idle_timeout,
            signed_in_from: session.signed_in_from(),
        };
        self.ports
            .tokens
            .issue(&ctx.tenant, &grant)
            .await
            .or_internal()
    }

    /// The session `session_id` names, which must still exist.
    pub(in crate::use_cases::authentication::app_sign_in) async fn held_session(
        &self,
        ctx: &AppSignInContext,
        session_id: &SessionId,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        self.ports
            .session_store
            .find_by_id(&ctx.tenant, session_id)
            .await
            .or_internal()?
            .ok_or_else(signed_out)
    }

    /// Refuses a claim whose session has ended.
    pub(in crate::use_cases::authentication::app_sign_in) async fn ensure_live(
        &self,
        ctx: &AppSignInContext,
        claim: &AppSessionClaim,
    ) -> Result<(), AppError> {
        let live = self
            .ports
            .session_check
            .is_live(&ctx.tenant, claim)
            .await
            .or_internal()?;
        if !live {
            return Err(signed_out());
        }
        Ok(())
    }

    /// The tenant's active services accepting `owner`'s sign-in.
    pub(in crate::use_cases::authentication::app_sign_in) async fn accepting(
        &self,
        ctx: &AppSignInContext,
        owner: &ServiceId,
    ) -> Result<Vec<Service<ResolvedTenant>>, AppError> {
        let services = self
            .ports
            .target
            .service_store
            .list_all(
                &ctx.tenant,
                &SortOrder::default(),
                &PageRequest::first(Limit::internal(MAX_TENANT_SERVICES)),
            )
            .await
            .or_internal()?
            .items;
        Ok(services
            .into_iter()
            .filter(|service| {
                service.is_active() && service.accepts_app_sign_in_of() == Some(owner)
            })
            .collect())
    }
}

/// The hosts `service` keeps a cookie of its own on, if it accepts another's
/// sign-in that way.
fn cookie_hosts_of(service: &Service<ResolvedTenant>) -> Vec<DomainName> {
    service
        .accepted_sign_in()
        .map(|accepted| accepted.cookie_hosts().to_vec())
        .unwrap_or_default()
}

/// How long the tenant lets a session go unused; `None` when it set no limit.
pub(in crate::use_cases::authentication::app_sign_in) fn idle_timeout(
    tenant: &Tenant,
) -> Option<std::time::Duration> {
    let seconds = tenant.auth_config().idle_timeout_secs();
    (seconds.get() > 0).then(|| seconds.std_duration())
}

/// The refusal for a request with no live session of the sign-in.
pub(in crate::use_cases::authentication::app_sign_in) fn signed_out() -> AppError {
    AppError::Forbidden(message!("authentication-sign-in-first", "sign in first"))
}

fn link_expired() -> AppError {
    AppError::NotFound(message!(
        "authentication-the-sign-in-link-has-expired",
        "the sign-in link has expired"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::test_support::authentication::{
        CrossHostFixture, SHOP_HOST, cross_host_ctx, cross_host_fixture,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::app_sign_in::relay::target::resolve;

    const API: &str = "api.example.com";
    const FILES: &str = "files.example.com";

    /// The digest of the hop cookie Ann's browser keeps on the API's host.
    const ANNS_BROWSER: &str = "ann-browser-digest";

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    /// The code the shop hands out for `on`, to the browser whose hop cookie
    /// digests to `browser`, under the session cookie `session`.
    fn issued(
        f: &CrossHostFixture,
        session: Option<&str>,
        on: &str,
        browser: &str,
    ) -> Result<AppSignInOutcome, AppError> {
        let tenant = test_ctx().tenant();
        let target = block_on(resolve(&f.ports, &tenant, &f.owner, &host(SHOP_HOST))).unwrap();
        let cookie = session.map(Secret::new);
        let browser = Secret::new(browser);
        let ask = HopAsk {
            session: cookie.as_ref(),
            host: host(on),
            browser: &browser,
        };
        block_on(
            f.across
                .issue_hop(&cross_host_ctx(f.owner, SHOP_HOST), &target, ask),
        )
    }

    /// The code Ann's browser is handed for `on`.
    fn hop_code(f: &CrossHostFixture, on: &str) -> Secret {
        let Ok(AppSignInOutcome::HopIssued(hop)) = issued(f, Some("cookie"), on, ANNS_BROWSER)
        else {
            panic!("a hop's code is handed out");
        };
        assert_eq!(hop.host.as_str(), on);
        hop.code
    }

    fn hand_over_in(
        f: &CrossHostFixture,
        on: &str,
        code: &Secret,
        browser: &str,
    ) -> Result<AppSignInOutcome, AppError> {
        let landing = AppHandOverRequest {
            code: Secret::new(code.expose()),
            browser: Secret::new(browser),
        };
        block_on(f.across.hand_over(
            &cross_host_ctx(f.api, on),
            &landing,
            &test_auditor(f.audit.clone()),
        ))
    }

    fn hand_over(
        f: &CrossHostFixture,
        on: &str,
        code: &Secret,
    ) -> Result<AppSignInOutcome, AppError> {
        hand_over_in(f, on, code, ANNS_BROWSER)
    }

    /// Ann signs in on the shop. Her browser is to pass through each host
    /// of the API, which keeps a cookie of its own on two hosts; no code is
    /// handed out before her browser is there to ask.
    #[test]
    fn signing_in_lists_each_host_of_each_own_cookie_and_hands_out_no_code() {
        let f = cross_host_fixture();

        let hosts = block_on(
            f.across
                .hop_hosts(&cross_host_ctx(f.owner, SHOP_HOST), &f.owner),
        )
        .unwrap();

        let hosts: Vec<&str> = hosts.iter().map(DomainName::as_str).collect();
        assert_eq!(hosts, [API, FILES]);
        assert_eq!(f.handoffs.count(), 0);
    }

    /// Ann's browser asks the shop for the API's code, then carries it to
    /// the API's host. Her session is set there once, and the hand-over is
    /// recorded.
    #[test]
    fn a_hop_sets_the_session_for_its_service_once_and_is_recorded() {
        let f = cross_host_fixture();
        let code = hop_code(&f, API);

        let first = hand_over(&f, API, &code);

        assert!(matches!(first, Ok(AppSignInOutcome::HandedOver(_))));
        assert_eq!(
            f.tokens.minted.lock().unwrap().as_slice(),
            [format!("session:{API}:api")]
        );
        assert_eq!(
            f.audit.records.lock().unwrap().as_slice(),
            ["authentication.app_session_handed_over"]
        );
    }

    /// Replaying a hop code after a successful handover returns not found.
    #[test]
    fn a_replayed_code_sets_nothing() {
        let f = cross_host_fixture();
        let code = hop_code(&f, API);
        hand_over(&f, API, &code).unwrap();

        let again = hand_over(&f, API, &code);

        assert!(matches!(again, Err(AppError::NotFound(_))));
    }

    /// A hop code issued for the API host returns not found on the files host.
    #[test]
    fn a_code_is_good_on_its_own_host_only() {
        let f = cross_host_fixture();
        let code = hop_code(&f, API);

        let elsewhere = hand_over(&f, FILES, &code);

        assert!(matches!(elsewhere, Err(AppError::NotFound(_))));
    }

    /// A session ending before its hop reaches the API causes the handover
    /// to be refused without minting a cookie.
    #[test]
    fn a_hop_carrying_an_ended_session_sets_nothing() {
        let f = cross_host_fixture();
        let code = hop_code(&f, API);
        f.live.0.store(false, Ordering::SeqCst);

        let refused = hand_over(&f, API, &code);

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Presenting a hop code from a different browser refuses and spends
    /// it. Retrying in its original browser is also refused, and neither
    /// attempt mints a cookie.
    #[test]
    fn a_code_opened_in_another_browser_sets_nothing() {
        let f = cross_host_fixture();
        let eves_code = hop_code(&f, API);

        let in_anns_browser = hand_over_in(&f, API, &eves_code, "another-browser-digest");
        let in_eves_browser = hand_over(&f, API, &eves_code);

        assert!(matches!(in_anns_browser, Err(AppError::NotFound(_))));
        assert!(matches!(in_eves_browser, Err(AppError::NotFound(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Requests without a shop cookie or with an ended session are both
    /// refused and leave no stored hop codes.
    #[test]
    fn no_code_without_a_live_session_of_the_sign_in() {
        let f = cross_host_fixture();

        let no_cookie = issued(&f, None, API, ANNS_BROWSER);
        f.live.0.store(false, Ordering::SeqCst);
        let ended = issued(&f, Some("cookie"), API, ANNS_BROWSER);

        assert!(matches!(no_cookie, Err(AppError::Forbidden(_))));
        assert!(matches!(ended, Err(AppError::Forbidden(_))));
        assert_eq!(f.handoffs.count(), 0);
    }

    /// A host outside the accepting services' cookie hosts returns not found
    /// when requesting a hop and leaves no stored code.
    #[test]
    fn no_code_for_a_host_without_a_cookie_of_the_sign_in() {
        let f = cross_host_fixture();

        let elsewhere = issued(&f, Some("cookie"), "evil.example.com", ANNS_BROWSER);

        assert!(matches!(elsewhere, Err(AppError::NotFound(_))));
        assert_eq!(f.handoffs.count(), 0);
    }
}
