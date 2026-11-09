//! Resend org verification from a link: the holder of an expired link asks
//! for another one.

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;

use crate::auditor::RequestAuditor;
use crate::email::VerificationResent;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::services::authentication::channels::NO_CONFIRMATION_LINKS;
use crate::use_case::Command;
use crate::use_cases::organization::invitations::verification::mail::{
    OrgVerificationMail, VerificationLink,
};
use crate::use_cases::organization::lookup::existing_token;

/// Mails another verification link to the holder of an old one.
pub struct ResendOrgVerificationFromLinkUseCase {
    ports: OrgVerificationMail,
}

impl ResendOrgVerificationFromLinkUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgVerificationMail) -> Self {
        Self { ports }
    }

    /// The member the link `raw_token` was mailed to, while their address
    /// still needs confirming.
    async fn unconfirmed_holder(&self, raw_token: &str) -> Result<OrgUser, AppError> {
        crate::input::validate_token("token", raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(raw_token);
        let token = existing_token(self.ports.token_store.as_ref(), &token_hash).await?;
        self.ports
            .org_user_store
            .find_by_id(token.org_user_id())
            .await
            .or_internal()?
            .filter(|member| !member.email_verified())
            .or_not_found(message!(
                "organization-this-address-needs-no-confirming",
                "this address needs no confirming"
            ))
    }

    /// Refuses a resend that comes too soon after the last link.
    async fn ensure_cooled_down(&self, member: &OrgUser) -> Result<(), AppError> {
        let last_sent_at = self.ports.last_sent_at(member).await?;
        self.ports
            .policy
            .resend_cooldown
            .enforce(last_sent_at, "verification email")
    }
}

impl Command for ResendOrgVerificationFromLinkUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<VerificationResent, AppError>;

    /// Mails another link to the member an old link `raw_token` was mailed
    /// to, landing on their own organization's pages, and answers how long
    /// before another may be asked for.
    ///
    /// Keyed on the link rather than an address, so it tells nothing about
    /// who is registered: only someone sent a link can ask for its
    /// replacement. An expired link is as good as a live one here; what
    /// decides is whether the address still needs confirming. A link that
    /// goes out records `organization.org_verification_email_sent`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown, the address is already
    ///   confirmed, or the member or their organization is gone.
    /// - `AppError::TooManyRequests` if the last link is newer than the
    ///   wait between links.
    /// - `AppError::Forbidden` on a deployment with no mail server, before
    ///   the link is looked up.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<VerificationResent, AppError> {
        self.ports.ensure_mailable(NO_CONFIRMATION_LINKS)?;
        let member = self.unconfirmed_holder(&raw_token).await?;
        self.ensure_cooled_down(&member).await?;
        let scope = self.ports.pages_of(&member).await?.or_not_found(message!(
            "authentication-organization-not-found",
            "organization not found"
        ))?;
        let link = VerificationLink {
            member: &member,
            scope: &scope,
        };
        let events = self.ports.send_unless_confirmed(link).await?;
        auditor.dispatch(&events).await.or_internal()?;
        Ok(VerificationResent {
            retry_after_seconds: self.ports.policy.resend_cooldown.sent().retry_after_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::OrganizationId;
    use time::Duration;

    use super::*;
    use crate::test_support::organization::{
        FakeOrgTokenStore, org_store_with, org_user_store_with, stored_org_token, test_org,
        test_org_user, unconfirmed_org_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, RESEND_COOLDOWN_SECONDS, block_on, test_auditor,
    };

    const OLD_LINK: &str = "fake_refresh_old";

    struct Setup {
        uc: ResendOrgVerificationFromLinkUseCase,
        mailer: Arc<FakeMailer>,
    }

    /// `member` of Acme, holding a link of theirs that runs out
    /// `expires_in` from now.
    fn setup(member: OrgUser, expires_in: Duration) -> Setup {
        let organization_id = *member.organization_id();
        let link =
            stored_org_token::<EmailVerification>(&member, OLD_LINK, clock::now() + expires_in);
        let mailer = Arc::new(FakeMailer::new());
        Setup {
            uc: ResendOrgVerificationFromLinkUseCase::new(OrgVerificationMail {
                org_user_store: Arc::new(org_user_store_with([member])),
                organization_store: org_store_with([test_org(organization_id, "acme")]),
                token_store: Arc::new(FakeOrgTokenStore::holding([link])),
                mailer: mailer.clone(),
                ..OrgVerificationMail::fakes()
            }),
            mailer,
        }
    }

    fn resend(setup: &Setup) -> Result<VerificationResent, AppError> {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            OLD_LINK.to_owned(),
        ))
    }

    /// Fiona's link ran out a while ago, and she asks for another from it.
    /// It goes out, and she is told how long until she may ask again.
    #[test]
    fn an_expired_link_is_replaced() {
        let fiona = unconfirmed_org_user(OrganizationId::new(), "fiona@acme.test");
        let setup = setup(fiona, Duration::hours(-2));

        let resent = resend(&setup).unwrap();

        assert_eq!(setup.mailer.count(), 1);
        assert_eq!(resent.retry_after_seconds, RESEND_COOLDOWN_SECONDS);
    }

    /// Fiona asks again a moment after the last link. She must wait.
    #[test]
    fn asking_again_too_soon_is_refused() {
        let fiona = unconfirmed_org_user(OrganizationId::new(), "fiona@acme.test");
        let setup = setup(fiona, Duration::hours(-2));
        resend(&setup).unwrap();

        let again = resend(&setup);

        assert!(matches!(again, Err(AppError::TooManyRequests(_))));
    }

    /// Dana's address is already confirmed. Her old link has nothing left
    /// to do, so there is nothing to send.
    #[test]
    fn a_confirmed_address_is_not_found() {
        let dana = test_org_user(OrganizationId::new(), "dana@acme.test", OrgRole::Member);
        let setup = setup(dana, Duration::hours(1));

        let result = resend(&setup);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.mailer.count(), 0);
    }

    /// An unknown verification link cannot identify a recipient for a replacement.
    #[test]
    fn an_unknown_link_is_not_found() {
        let fiona = unconfirmed_org_user(OrganizationId::new(), "fiona@acme.test");
        let setup = setup(fiona, Duration::hours(1));

        let result = block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            "fake_refresh_madeup".to_owned(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
