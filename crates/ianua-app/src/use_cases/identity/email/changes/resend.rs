//! Resend email change: the holder of a confirmation link that ran out asks
//! for another, sent to the same new address.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::ChangingAccount;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::email::{LinkScope, TokenResent};
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::{MailSetup, Mailer, TenantEmailChangeStore};
use crate::services::authentication::channels::{NO_EMAIL_CHANGES, ensure_mail_reaches};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::email::changes::links::{
    ConfirmationMail, EmailChangePolicy, MailedIn, mail_confirmation,
};
use crate::use_cases::identity::email::changes::tenant::{change_by_link, changing_user};
use crate::use_cases::identity::renewal::renewed_link;

/// The ports [`ResendChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendChangePorts {
    /// Loads and saves pending email changes.
    pub change_store: Arc<dyn TenantEmailChangeStore>,
    /// Loads the account a change was asked for.
    pub user_store: Arc<dyn UserStore>,
    /// Mails the new link.
    pub mailer: Arc<dyn Mailer>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
    /// Makes and hashes confirmation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// How long the new link lasts, the address it is built on and how soon
    /// another may be asked for.
    pub policy: EmailChangePolicy,
}

/// The confirmation link to renew, by its token, and the pages the new one
/// opens.
pub struct ResendChangeRequest {
    /// The token from the link the person still holds.
    pub raw_token: String,
    /// Where the new link lands.
    pub scope: LinkScope,
}

/// Renews the confirmation link of a tenant user's email change from the
/// link that ran out.
pub struct ResendChangeUseCase {
    ports: ResendChangePorts,
}

impl ResendChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResendChangePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResendChangeUseCase {
    type Caller = ScopedTenant;
    type Input = ResendChangeRequest;
    type Output = Result<TokenResent, AppError>;

    /// Mails a new confirmation link to the address the change waits on,
    /// never one the caller names.
    ///
    /// Only a link that ran out is renewed, and only while the change stands
    /// as it was asked: not cancelled, and the account kept its address and
    /// how it signs in. Ann resets her password after her session was
    /// stolen, and the change the thief asked for stays dead.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown or its account is gone.
    /// - `AppError::Conflict` when the link still works, or the change landed,
    ///   was cancelled, or the account changed since.
    /// - `AppError::Forbidden` on a deployment with no mail server, before
    ///   the link is looked up: the new address could never be confirmed.
    /// - `AppError::Internal` on persistence or mail failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ResendChangeRequest,
    ) -> Result<TokenResent, AppError> {
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_EMAIL_CHANGES)?;
        let ResendChangeRequest { raw_token, scope } = request;
        crate::input::validate_token("token", &raw_token)?;
        let (changes, policy) = (self.ports.change_store.as_ref(), &self.ports.policy);
        let generator = self.ports.token_generator.as_ref();
        let presented = generator.hash_raw(&raw_token);
        let mut change = change_by_link(changes, tenant, &presented).await?;
        let user = changing_user(self.ports.user_store.as_ref(), tenant, &change).await?;
        let (raw_link, renewed) = renewed_link(generator, policy.lifetime)?;
        let account = ChangingAccount::from(&user);
        let reissued = change.reissue(account, &presented, renewed, clock::now());
        reissued.map_err(AppError::from_domain)?;

        changes.save(tenant, &change).await.or_internal()?;
        let mail = ConfirmationMail {
            to: change.new_email(),
            mailed_in: mailed_in(tenant, &user),
            raw_token: &raw_link,
            scope: &scope,
        };
        mail_confirmation(self.ports.mailer.as_ref(), policy, mail).await?;
        let actor = ActorRef::User(*user.id());
        auditor
            .dispatch_by(&actor, change.take_events(tenant))
            .await
            .or_internal()?;
        Ok(policy.resend_cooldown.sent())
    }
}

/// The plane the renewed link is mailed in: `tenant`'s, in the language
/// `user` reads.
fn mailed_in<'a>(tenant: &ScopedTenant, user: &'a User<ResolvedTenant>) -> MailedIn<'a> {
    MailedIn::Tenant {
        tenant: *tenant,
        locale: user.locale(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{Locale, Preference, UserId};
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::identity::{
        FakeEmailChangeStore, FakeUserStore, stored_change, stored_user, user_reading,
    };
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, RESEND_COOLDOWN_SECONDS, block_on,
        test_auditor, test_ctx, test_link_scope,
    };

    const LINK: &str = "ann-change";

    /// Ann, at ann@acme.com, who asked to move to new@acme.com, and the link
    /// mailed there.
    struct Change {
        ann: UserId,
        users: Arc<FakeUserStore>,
        changes: Arc<FakeEmailChangeStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Change {
        fn with_link_until(expires_at: OffsetDateTime) -> Self {
            let ann = UserId::new();
            let changes = FakeEmailChangeStore::empty();
            let pending = stored_change(
                ann.into(),
                ("ann@acme.com", "new@acme.com"),
                LINK,
                expires_at,
            );
            block_on(TenantEmailChangeStore::save(
                &changes,
                &test_ctx().tenant(),
                &pending,
            ))
            .unwrap();
            Self {
                ann,
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.com")),
                changes: Arc::new(changes),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ran_out() -> Self {
            Self::with_link_until(clock::now() - time::Duration::minutes(1))
        }

        fn resend(&self, raw_token: &str) -> Result<TokenResent, AppError> {
            self.resend_reaching(raw_token, Fake::fake())
        }

        fn resend_reaching(
            &self,
            raw_token: &str,
            mail: Arc<dyn MailSetup>,
        ) -> Result<TokenResent, AppError> {
            let use_case = ResendChangeUseCase::new(ResendChangePorts {
                change_store: self.changes.clone(),
                user_store: self.users.clone(),
                mailer: self.mailer.clone(),
                mail,
                ..ResendChangePorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                ResendChangeRequest {
                    raw_token: raw_token.to_owned(),
                    scope: test_link_scope(),
                },
            ))
        }
    }

    /// Ann opens her confirmation link a day late. A new one goes to
    /// new@acme.com, she is told how long to wait, and the resend is
    /// recorded.
    #[test]
    fn a_link_that_ran_out_is_renewed() {
        let change = Change::ran_out();

        let resent = change.resend(LINK).unwrap();

        assert_eq!(resent.retry_after_seconds, RESEND_COOLDOWN_SECONDS);
        assert_eq!(change.mailer.recipients(), ["new@acme.com"]);
        assert_eq!(
            change.sink.records.lock().unwrap().as_slice(),
            ["identity.email_change_link_resent"]
        );
    }

    /// Without a mail server, Ann cannot renew her expired email-change
    /// link. No mail or audit event is produced.
    #[test]
    fn no_link_is_renewed_where_nothing_is_mailed() {
        let change = Change::ran_out();

        let result = change.resend_reaching(LINK, FakeMailSetup::not_set_up());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(change.mailer.count(), 0);
        assert!(change.sink.records.lock().unwrap().is_empty());
    }

    /// Ann reads mail in German. Her renewed confirmation link is written
    /// in German.
    #[test]
    fn the_renewed_link_goes_out_in_the_persons_language() {
        let mut change = Change::ran_out();
        let users = FakeUserStore::empty();
        users.add(user_reading(change.ann, "ann@acme.com", "de-DE"));
        change.users = Arc::new(users);

        change.resend(LINK).unwrap();

        let sent = change.mailer.sent.lock().unwrap();
        assert_eq!(
            sent[0].locale,
            Preference::Own(Locale::new("de-DE").unwrap())
        );
    }

    /// Ann's link still works. There is nothing to renew.
    #[test]
    fn a_link_that_still_works_is_not_renewed() {
        let change = Change::with_link_until(clock::now() + time::Duration::hours(1));

        let result = change.resend(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(change.mailer.count(), 0);
    }

    /// A credential change prevents renewal of Ann's earlier email-change
    /// link. The request conflicts, and no mail is sent.
    #[test]
    fn a_change_the_account_outlived_stays_dead() {
        let change = Change::ran_out();
        let mut ann = stored_user(change.ann, "ann@acme.com", UserStatus::Active);
        ann.record_credential_change();
        block_on(change.users.save(&test_ctx().tenant(), &ann)).unwrap();

        let result = change.resend(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(change.mailer.count(), 0);
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let change = Change::ran_out();

        let result = change.resend("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
