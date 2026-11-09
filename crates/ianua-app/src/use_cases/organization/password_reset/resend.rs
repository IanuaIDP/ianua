//! A member asking for another reset link from one that no longer works.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
use ianua_domain::types::OrgUserId;

use crate::auditor::RequestAuditor;
use crate::email::{ResendCooldown, TokenResent};
use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::organization::OrgTokenStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_token;
use crate::use_cases::organization::password_reset::RequestOrgResetUseCase;

/// The ports [`ResendOrgResetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendOrgResetPorts {
    /// Members' reset links: the one held and the member's newest.
    pub token_store: Arc<dyn OrgTokenStore<PasswordReset>>,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Mails a fresh reset link to the holder of a dead one.
pub struct ResendOrgResetUseCase {
    reset: Arc<RequestOrgResetUseCase>,
    cooldown: ResendCooldown,
    ports: ResendOrgResetPorts,
}

impl ResendOrgResetUseCase {
    /// A use case issuing links through `reset`, no more often than
    /// `cooldown` allows, working through `ports`.
    #[must_use]
    pub fn new(
        reset: Arc<RequestOrgResetUseCase>,
        cooldown: ResendCooldown,
        ports: ResendOrgResetPorts,
    ) -> Self {
        Self {
            reset,
            cooldown,
            ports,
        }
    }

    /// Refuses a replacement while the member's newest link is younger
    /// than the cooldown.
    async fn ensure_cooled_down(&self, member: &OrgUserId) -> Result<(), AppError> {
        let newest = self
            .ports
            .token_store
            .find_latest_by_user(member)
            .await
            .or_internal()?;
        self.cooldown
            .enforce(newest.map(|link| link.created_at()), "reset link")
    }
}

impl Command for ResendOrgResetUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<TokenResent, AppError>;

    /// Mails another reset link to where the held one went.
    ///
    /// Keyed on the token rather than an address, so it tells nobody who
    /// has an account: only someone already sent a link can ask for its
    /// replacement. An expired or spent token is what this expects; it only
    /// names its member. The cooldown is measured against the member's
    /// newest link, not the superseded one in hand, so the button cannot be
    /// pressed as often as one likes.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is malformed.
    /// - `AppError::NotFound` when the token is unknown.
    /// - `AppError::TooManyRequests` when the newest link is younger than
    ///   the cooldown, with the seconds still to wait.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<TokenResent, AppError> {
        validate_token("token", &raw_token)?;
        let hash = self.ports.token_generator.hash_raw(&raw_token);
        let held = existing_token(self.ports.token_store.as_ref(), &hash).await?;
        self.ensure_cooled_down(held.org_user_id()).await?;
        self.reset
            .execute(&(), auditor, held.sent_to().clone())
            .await?;
        Ok(self.cooldown.sent())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::token::{OrgToken, OrgTokenRow};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Email, HttpsUrl, Lifetime, OrganizationId, Usage};

    use super::*;
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, RESEND_COOLDOWN_SECONDS, block_on, resend_cooldown,
        test_auditor,
    };
    use crate::use_cases::organization::password_reset::{OrgResetPolicy, RequestOrgResetPorts};

    const ADDRESS: &str = "alice@acme.test";
    const HELD: &str = "fake_refresh_held";

    struct Fixture {
        use_case: ResendOrgResetUseCase,
        tokens: Arc<FakeOrgTokenStore<PasswordReset>>,
        mailer: Arc<FakeMailer>,
    }

    /// Alice, holding a spent reset link issued `age` ago.
    fn alice_holding_a_link_issued(age: time::Duration) -> Fixture {
        let organization = OrganizationId::new();
        let alice = test_org_user(organization, ADDRESS, OrgRole::Member);
        let held = spent_link(*alice.id(), age);
        let tokens = Arc::new(FakeOrgTokenStore::holding([held]));
        let mailer = Arc::new(FakeMailer::new());
        let reset = RequestOrgResetUseCase::new(
            OrgResetPolicy {
                lifetime: Lifetime::seconds(3600).unwrap(),
                base_url: HttpsUrl::new("https://test.example.com").unwrap(),
            },
            RequestOrgResetPorts {
                org_user_store: Arc::new(org_user_store_with([alice])),
                org_store: org_store_with([test_org(organization, "acme")]),
                token_store: tokens.clone(),
                mailer: mailer.clone(),
                ..RequestOrgResetPorts::fakes()
            },
        );
        Fixture {
            use_case: ResendOrgResetUseCase::new(
                Arc::new(reset),
                resend_cooldown(),
                ResendOrgResetPorts {
                    token_store: tokens.clone(),
                    ..ResendOrgResetPorts::fakes()
                },
            ),
            tokens,
            mailer,
        }
    }

    /// Alice's one-hour reset link, issued at the requested age and spent a minute later.
    fn spent_link(member: OrgUserId, age: time::Duration) -> OrgToken<PasswordReset> {
        let issued = clock::now() - age;
        OrgToken::reconstitute(OrgTokenRow {
            token_hash: hash_of_link(HELD),
            org_user_id: member,
            sent_to: Email::new(ADDRESS).unwrap(),
            created_at: issued,
            expires_at: issued + time::Duration::hours(1),
            usage: Usage::Used {
                at: issued + time::Duration::minutes(1),
            },
        })
        .unwrap()
    }

    fn resend(fixture: &Fixture, raw_token: &str) -> Result<TokenResent, AppError> {
        block_on(fixture.use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            raw_token.to_owned(),
        ))
    }

    /// Alice's link was spent ten minutes ago and she comes back to the
    /// stale tab. A fresh link goes to where the first one went.
    #[test]
    fn a_dead_link_is_replaced_by_a_new_one() {
        let fixture = alice_holding_a_link_issued(time::Duration::minutes(10));

        let resent = resend(&fixture, HELD).unwrap();

        assert_eq!(resent.retry_after_seconds, RESEND_COOLDOWN_SECONDS);
        assert_eq!(fixture.mailer.recipients(), vec![ADDRESS.to_owned()]);
        assert_eq!(fixture.tokens.count(), 2);
    }

    /// Reusing a superseded link within the newest link's cooldown is rate
    /// limited, so only the first replacement is mailed.
    #[test]
    fn asking_again_inside_the_cooldown_is_refused() {
        let fixture = alice_holding_a_link_issued(time::Duration::minutes(10));
        resend(&fixture, HELD).unwrap();

        let again = resend(&fixture, HELD);

        assert!(matches!(again, Err(AppError::TooManyRequests(_))));
        assert_eq!(fixture.mailer.recipients().len(), 1);
    }

    /// An unknown reset token is not found, and no replacement is mailed.
    #[test]
    fn an_unknown_token_has_nothing_to_replace() {
        let fixture = alice_holding_a_link_issued(time::Duration::minutes(10));

        let resent = resend(&fixture, "fake_refresh_never_issued");

        assert!(matches!(resent, Err(AppError::NotFound(_))));
        assert!(fixture.mailer.recipients().is_empty());
    }

    /// An empty reset token fails validation, and no replacement is mailed.
    #[test]
    fn a_malformed_token_is_rejected_before_any_lookup() {
        let fixture = alice_holding_a_link_issued(time::Duration::minutes(10));

        let resent = resend(&fixture, "");

        assert!(matches!(resent, Err(AppError::Domain(_))));
        assert!(fixture.mailer.recipients().is_empty());
    }
}
