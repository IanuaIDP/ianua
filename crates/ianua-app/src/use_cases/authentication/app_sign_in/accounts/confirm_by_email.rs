//! Finishing an app sign-in from the link mailed to its person.
//!
//! The password was right, but the sign-in waits for its person to confirm
//! it from their mailbox. The host's challenge cookie shows which sign-in
//! it is; the link proves the mailbox. Together they finish it, through the
//! dashboard's own confirmation, and the session opens on the host.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::{
    AppSignInCommon, OnTarget, not_finished_here,
};
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::password::sign_in::email_confirmation::{
    ConfirmSignInByEmailUseCase, PendingConfirmation,
};

/// A followed confirmation link, on the host whose challenge cookie holds
/// the sign-in. Holds both tokens, so it has no `Debug`.
pub struct AppConfirmByEmailRequest {
    /// The challenge token handed out when the password was accepted.
    pub challenge: Secret,
    /// The link's token, as followed.
    pub link: Secret,
    /// Where to send them afterwards, if they came from somewhere.
    pub return_to: Option<ReturnPath>,
}

/// Finishes the sign-in a challenge holds with the link mailed for it.
pub struct AppConfirmByEmailUseCase {
    common: Arc<AppSignInCommon>,
    confirm: Arc<ConfirmSignInByEmailUseCase>,
}

impl AppConfirmByEmailUseCase {
    /// A use case confirming through the dashboard's own `confirm`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        confirm: Arc<ConfirmSignInByEmailUseCase>,
    ) -> Self {
        Self { common, confirm }
    }
}

impl Command for AppConfirmByEmailUseCase {
    type Caller = AppSignInContext;
    type Input = AppConfirmByEmailRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Answers what the challenged sign-in owes with the link, records
    /// `authentication.mfa_verified`, spends the challenge, and signs the
    /// person in on the host. A link that is refused leaves the challenge
    /// open: it is not a guess at anything the person chose.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the
    ///   challenge is unknown, closed, or its sign-in gone or ended.
    /// - `AppError::Conflict` when the sign-in owes nothing.
    /// - `AppError::Forbidden` when the sign-in owes another factor, the
    ///   link is unknown, used, or another account's, the tenant does not
    ///   take the sign-in from here, or a factor must still be set up,
    ///   which the host does not take.
    /// - `AppError::LinkExpired` when the link ran out or went to an address
    ///   the account has since left.
    /// - `AppError::Internal` on persistence, audit or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppConfirmByEmailRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let challenge = self.common.open_challenge(ctx, &request.challenge).await?;
        let session = self.common.challenged_session(ctx, &challenge).await?;
        let origin = ctx.origin();
        let pending = PendingConfirmation {
            session,
            link: &request.link,
            origin: &origin,
        };
        let confirmed = self.confirm.confirm(&ctx.tenant, &auditor, pending).await?;
        self.common.spend_challenge(ctx, challenge).await?;
        ensure_finished(confirmed.second_factor)?;
        let on = OnTarget {
            ctx,
            target: &target,
        };
        self.common
            .open_on_host(&on, &confirmed.session_id, request.return_to)
            .await
    }
}

/// Refuses a sign-in that still owes a factor to set up, which the host
/// does not take.
///
/// # Errors
///
/// - `AppError::Forbidden` unless the sign-in owes nothing more.
fn ensure_finished(owed: SecondFactor) -> Result<(), AppError> {
    match owed {
        SecondFactor::NotOwed => Ok(()),
        SecondFactor::Verify
        | SecondFactor::Enrol
        | SecondFactor::ConfirmByEmail
        | SecondFactor::ConfirmThenEnrol => Err(not_finished_here()),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallenge;
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::domains::identity::tokens::secure::{NewSecureToken, SecureToken};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{Email, HttpsUrl, Lifetime, ServiceId, UserId};

    use super::*;
    use crate::ports::authentication::MfaChallengeStore;
    use crate::ports::identity::SignInConfirmationToken;
    use crate::test_support::authentication::{
        FakeAppSessionTokens, FakeMfaChallengeStore, FakeSessionStore, SHOP_HOST,
        app_sign_in_lifetimes, app_sign_in_services, app_sign_in_target_ports, clone_session,
        cross_host_ctx, password_session, shop_with_app_sign_in,
    };
    use crate::test_support::identity::{FakeSignInLinks, FakeUserStore, hash_of_link};
    use crate::test_support::oauth::hash_of;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::password::ConfirmSignInByEmailPorts;

    const BOB: &str = "bob@acme.test";
    const CHALLENGE: &str = "challenge-token";
    const LINK: &str = "fake_refresh_link";

    struct Fixture {
        use_case: AppConfirmByEmailUseCase,
        shop: ServiceId,
        tokens: Arc<FakeAppSessionTokens>,
        challenges: Arc<FakeMfaChallengeStore>,
        links: Arc<FakeSignInLinks>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// A confirmation link mailed to Bob's address for `user_id`.
    fn link_for(user_id: UserId) -> SignInConfirmationToken {
        SecureToken::create(NewSecureToken {
            token_hash: hash_of_link(LINK),
            user_id,
            sent_to: Email::new(BOB).unwrap(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    /// Bob's sign-in on the shop, owing `owed`, held by a challenge, with
    /// the link `link_owner` was mailed.
    fn fixture(owed: SecondFactor, link_owner: Option<UserId>) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let bob = UserId::new();
        let waiting = password_session(bob, "hash", owed);
        let sessions = Arc::new(FakeSessionStore::with_session(clone_session(&waiting)));
        let challenges = Arc::new(FakeMfaChallengeStore::default());
        save_challenge(&challenges, &waiting);
        let links = Arc::new(FakeSignInLinks::holding(&link_for(
            link_owner.unwrap_or(bob),
        )));
        let tokens = Arc::new(FakeAppSessionTokens::default());
        let confirm = confirmation(bob, &sessions, &links);
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            session_store: sessions,
            challenge_store: challenges.clone(),
            tokens: tokens.clone(),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppConfirmByEmailUseCase::new(Arc::new(common), Arc::new(confirm)),
            shop: shop_id,
            tokens,
            challenges,
            links,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Bob confirms his sign-in through the fixture's stored sessions and mailed links.
    fn confirmation(
        bob: UserId,
        sessions: &Arc<FakeSessionStore>,
        links: &Arc<FakeSignInLinks>,
    ) -> ConfirmSignInByEmailUseCase {
        ConfirmSignInByEmailUseCase::new(ConfirmSignInByEmailPorts {
            tenants: tenant_store_signing_in_with(Default::default()),
            sessions: sessions.clone(),
            users: Arc::new(FakeUserStore::with_user(bob, BOB)),
            links: links.clone(),
            ..ConfirmSignInByEmailPorts::fakes()
        })
    }

    /// The browser challenge remains bound to Bob's session awaiting the mailed link.
    fn save_challenge(store: &FakeMfaChallengeStore, waiting: &Session<ResolvedTenant>) {
        let lifetime = app_sign_in_lifetimes().mfa_challenge;
        let challenge = MfaChallenge::issue(waiting, hash_of(CHALLENGE), lifetime).unwrap();
        block_on(store.save(&test_ctx().tenant(), &challenge)).unwrap();
    }

    fn follow(f: &Fixture, challenge: &str) -> Result<AppSignInOutcome, AppError> {
        let request = AppConfirmByEmailRequest {
            challenge: Secret::new(challenge),
            link: Secret::new(LINK),
            return_to: None,
        };
        let ctx = cross_host_ctx(f.shop, SHOP_HOST);
        let auditor = test_auditor(f.audit.clone());
        block_on(f.use_case.execute(&ctx, &auditor, request))
    }

    fn minted(f: &Fixture) -> usize {
        f.tokens.minted.lock().unwrap().len()
    }

    /// Bob's sign-in on the shop waits for him to confirm it. He follows
    /// the link in the browser holding the challenge. He is signed in on
    /// the shop's host, the link and the challenge are spent, and the
    /// confirmation is recorded.
    #[test]
    fn following_the_link_signs_in_on_the_host() {
        let f = fixture(SecondFactor::ConfirmByEmail, None);

        let outcome = follow(&f, CHALLENGE);

        assert!(matches!(outcome, Ok(AppSignInOutcome::SignedIn { .. })));
        assert_eq!(f.challenges.count(), 0);
        assert_eq!(f.links.count(), 0);
        assert_eq!(minted(&f), 1);
        assert_eq!(
            f.audit.records.lock().unwrap().as_slice(),
            ["authentication.mfa_verified"]
        );
    }

    /// Another account's confirmation link cannot finish Bob's sign-in.
    /// No cookie is minted, and his challenge remains available.
    #[test]
    fn a_link_for_another_account_is_refused() {
        let f = fixture(SecondFactor::ConfirmByEmail, Some(UserId::new()));

        let outcome = follow(&f, CHALLENGE);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.challenges.count(), 1);
        assert_eq!(minted(&f), 0);
    }

    /// A mailbox link is refused when Bob's sign-in owes an authenticator
    /// code. The link remains unspent, and no cookie is minted.
    #[test]
    fn a_sign_in_owing_a_code_is_refused() {
        let f = fixture(SecondFactor::Verify, None);

        let outcome = follow(&f, CHALLENGE);

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(f.links.count(), 1);
        assert_eq!(minted(&f), 0);
    }

    /// An unknown browser challenge returns not found and leaves Bob's
    /// confirmation link unspent.
    #[test]
    fn an_unknown_challenge_is_refused() {
        let f = fixture(SecondFactor::ConfirmByEmail, None);

        let outcome = follow(&f, "made-up");

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.links.count(), 1);
    }

    /// A confirmation that still leaves Bob owing factor enrollment is
    /// refused on the shop's host and mints no cookie there.
    #[test]
    fn a_confirmation_that_leaves_a_factor_to_set_up_does_not_sign_in_here() {
        let f = fixture(SecondFactor::ConfirmThenEnrol, None);

        let outcome = follow(&f, CHALLENGE);

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(minted(&f), 0);
    }
}
