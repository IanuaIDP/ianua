//! Resend org email change: an organization member or an operator holding
//! a confirmation link that ran out asks for another, sent to the same new
//! address.

use std::sync::Arc;

use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::auditor::RequestAuditor;
use crate::email::TokenResent;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::{MailSetup, Mailer};
use crate::services::authentication::channels::{NO_EMAIL_CHANGES, ensure_mail_reaches};
use crate::use_case::Command;
use crate::use_cases::identity::email::ResendChangeRequest;
use crate::use_cases::identity::email::changes::links::{
    ConfirmationMail, EmailChangePolicy, MailedIn, mail_confirmation,
};
use crate::use_cases::identity::email::org_changes::org_change::{
    OrgChangePorts, changing_account, org_change_by_link,
};
use crate::use_cases::identity::renewal::renewed_link;

/// The ports [`ResendOrgChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendOrgChangePorts {
    /// The pending changes and the accounts they move.
    pub stores: OrgChangePorts,
    /// Mails the new link.
    pub mailer: Arc<dyn Mailer>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
    /// How long the new link lasts, the address it is built on and how soon
    /// another may be asked for.
    pub policy: EmailChangePolicy,
}

/// Renews the confirmation link of an organization-plane email change from
/// the link that ran out.
pub struct ResendOrgChangeUseCase {
    ports: ResendOrgChangePorts,
}

impl ResendOrgChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResendOrgChangePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResendOrgChangeUseCase {
    type Caller = ();
    type Input = ResendChangeRequest;
    type Output = Result<TokenResent, AppError>;

    /// Mails a new confirmation link to the address the change waits on,
    /// never one the caller names. Only a link that ran out is renewed, and
    /// only while the change stands as it was asked.
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
        (): &(),
        auditor: &RequestAuditor,
        request: ResendChangeRequest,
    ) -> Result<TokenResent, AppError> {
        ensure_mail_reaches(self.ports.mail.as_ref(), NO_EMAIL_CHANGES)?;
        let ResendChangeRequest { raw_token, scope } = request;
        crate::input::validate_token("token", &raw_token)?;
        let stores = &self.ports.stores;
        let policy = &self.ports.policy;
        let presented = stores.token_generator.hash_raw(&raw_token);
        let mut change = org_change_by_link(stores, &presented).await?;
        let account = changing_account(stores, &change).await?;
        let (raw_link, renewed) = renewed_link(stores.token_generator.as_ref(), policy.lifetime)?;
        change
            .reissue(account.changing(), &presented, renewed, clock::now())
            .map_err(AppError::from_domain)?;

        stores.change_store.save(&change).await.or_internal()?;
        let mail = ConfirmationMail {
            to: change.new_email(),
            mailed_in: MailedIn::Organization,
            raw_token: &raw_link,
            scope: &scope,
        };
        mail_confirmation(self.ports.mailer.as_ref(), policy, mail).await?;
        auditor
            .dispatch(&change.take_events())
            .await
            .or_internal()?;
        Ok(policy.resend_cooldown.sent())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::organization::OrgUserStore;
    use crate::ports::shared::OrgEmailChangeStore;
    use crate::test_support::identity::{FakeEmailChangeStore, email_change_policy, stored_change};
    use crate::test_support::organization::{FakeOrgUserStore, test_org_user};
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
        test_org_link_scope,
    };

    const LINK: &str = "owen-change";

    /// The stores holding Owen, who asked to move to new@acme.com, with the
    /// link mailed there running out at `expires_at`.
    fn with_link_until(expires_at: OffsetDateTime) -> (OrgChangePorts, Arc<FakeMailer>) {
        let owen = test_org_user(OrganizationId::new(), "owen@acme.com", OrgRole::Member);
        let members = FakeOrgUserStore::empty();
        block_on(members.save(&owen)).unwrap();
        let changes = FakeEmailChangeStore::empty();
        let change = stored_change(
            (*owen.id()).into(),
            ("owen@acme.com", "new@acme.com"),
            LINK,
            expires_at,
        );
        block_on(OrgEmailChangeStore::save(&changes, &change)).unwrap();
        let stores = OrgChangePorts {
            change_store: Arc::new(changes),
            org_user_store: Arc::new(members),
            ..OrgChangePorts::fakes()
        };
        (stores, Arc::new(FakeMailer::new()))
    }

    fn resend(
        stores: OrgChangePorts,
        mailer: &Arc<FakeMailer>,
        sink: &Arc<FakeEventDispatcher>,
        raw_token: &str,
    ) -> Result<TokenResent, AppError> {
        resend_through(
            ResendOrgChangePorts {
                stores,
                mailer: mailer.clone(),
                mail: Fake::fake(),
                policy: email_change_policy(),
            },
            sink,
            raw_token,
        )
    }

    fn resend_through(
        ports: ResendOrgChangePorts,
        sink: &Arc<FakeEventDispatcher>,
        raw_token: &str,
    ) -> Result<TokenResent, AppError> {
        let use_case = ResendOrgChangeUseCase::new(ports);
        block_on(use_case.execute(
            &(),
            &test_auditor(sink.clone()),
            ResendChangeRequest {
                raw_token: raw_token.to_owned(),
                scope: test_org_link_scope(),
            },
        ))
    }

    /// Owen opens his confirmation link a day late. A new one goes to
    /// new@acme.com and the resend is recorded.
    #[test]
    fn a_link_that_ran_out_is_renewed() {
        let (stores, mailer) = with_link_until(clock::now() - time::Duration::minutes(1));
        let sink = Arc::new(FakeEventDispatcher::new());

        resend(stores, &mailer, &sink, LINK).unwrap();

        assert_eq!(mailer.recipients(), ["new@acme.com"]);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.management_email_change_link_resent"]
        );
    }

    /// Without a mail server, Owen cannot renew his expired email-change
    /// link. No mail or audit event is produced.
    #[test]
    fn no_link_is_renewed_where_nothing_is_mailed() {
        let (stores, mailer) = with_link_until(clock::now() - time::Duration::minutes(1));
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ResendOrgChangePorts {
            stores,
            mailer: mailer.clone(),
            mail: FakeMailSetup::not_set_up(),
            policy: email_change_policy(),
        };

        let result = resend_through(ports, &sink, LINK);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(mailer.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Owen's link still works. There is nothing to renew.
    #[test]
    fn a_link_that_still_works_is_not_renewed() {
        let (stores, mailer) = with_link_until(clock::now() + time::Duration::hours(1));

        let result = resend(stores, &mailer, &Arc::new(FakeEventDispatcher::new()), LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(mailer.count(), 0);
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let (stores, mailer) = with_link_until(clock::now() - time::Duration::minutes(1));

        let result = resend(
            stores,
            &mailer,
            &Arc::new(FakeEventDispatcher::new()),
            "nobody",
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
