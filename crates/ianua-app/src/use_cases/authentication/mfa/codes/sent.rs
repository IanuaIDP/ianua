//! Sending a code for a factor whose codes are mailed or texted: one made
//! fresh, kept only as its hash, replacing the one sent before, and handed
//! to the mail or SMS provider.
//!
//! A person asks again only after a short wait. Without it, Mallory holding
//! Ann's password asks for a code a hundred times a minute: Ann's phone
//! fills with texts, and each costs the tenant a message.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{EnrolledFactor, MfaEnrollment};
use ianua_domain::domains::authentication::mfa::one_time_code::OneTimeCode;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{Lifetime, UserId};
use time::{Duration, OffsetDateTime};

use crate::auditor::raised_by_holder;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    CodeDestination, FactorCodeSender, OutgoingCode, SentCodeGenerator, SentCodeStore,
    TextMessaging,
};
use crate::ports::shared::MailSetup;
use crate::services::authentication::channels::Channels;
use crate::tenancy::ScopedTenant;

/// How long a sent code lives and how soon another may be asked for.
#[derive(Debug, Clone, Copy)]
pub struct SentCodePolicy {
    /// How long a code works, at most ten minutes.
    pub lifetime: Lifetime,
    /// How long after one code another may be sent.
    pub resend_after: Duration,
}

/// Where sent codes are kept, made and handed over.
#[derive(Clone, ianua_macros::Fakes)]
pub struct SentCodePorts {
    /// Keeps the latest code sent for each person.
    pub sent_codes: Arc<dyn SentCodeStore>,
    /// Makes codes and hashes them.
    pub generator: Arc<dyn SentCodeGenerator>,
    /// Hands codes to the mail or SMS provider.
    pub sender: Arc<dyn FactorCodeSender>,
    /// Whether codes can be texted here at all.
    pub text_messaging: Arc<dyn TextMessaging>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

/// A code just sent, and when it stops working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeSent {
    /// When the code lapses.
    pub expires_at: OffsetDateTime,
}

/// A factor to send a code for, and the account it belongs to: one a
/// signed-in person or a waiting sign-in names, or one a followed reset
/// link names.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication) struct CodeFor<'a> {
    /// The tenant the account is in.
    pub(in crate::use_cases::authentication) tenant: &'a ScopedTenant,
    /// The account, whose address a mailed code goes to.
    pub(in crate::use_cases::authentication) account: &'a User<ResolvedTenant>,
    /// The factor, pending or in force.
    pub(in crate::use_cases::authentication) factor: &'a MfaEnrollment<ResolvedTenant>,
}

impl SentCodePorts {
    /// The ways this deployment delivers codes.
    pub(in crate::use_cases::authentication) fn channels(&self) -> Channels<'_> {
        Channels {
            texts: self.text_messaging.as_ref(),
            mail: self.mail.as_ref(),
        }
    }

    /// Sends a fresh code for `to.factor` under `policy`, keeping its hash in
    /// place of the one before, and answers with what it raised.
    ///
    /// # Errors
    ///
    /// - `AppError::TooManyRequests` when a code was sent less than
    ///   `policy.resend_after` ago and still works.
    /// - `AppError::Conflict` when the factor's codes come from an app.
    /// - `AppError::Domain` when the policy's lifetime is longer than a sent
    ///   code may live.
    /// - `AppError::Forbidden` when the factor was given up or turned off,
    ///   or its codes cannot be delivered on this deployment: texted with no
    ///   text message provider, or mailed with no mail server. Nothing is
    ///   made or kept then.
    /// - `AppError::Internal` when the code cannot be made, kept or handed
    ///   to the provider.
    pub(in crate::use_cases::authentication) async fn send(
        &self,
        to: CodeFor<'_>,
        policy: SentCodePolicy,
    ) -> Result<(CodeSent, Vec<DomainEvent>), AppError> {
        let destination = destination(to.account, to.factor.factor())?;
        self.channels().ensure_deliverable(to.factor.method())?;
        self.ensure_may_resend(to.tenant, to.account.id(), policy)
            .await?;
        let code = self.generator.generate().or_internal()?;
        let hash = self.generator.hash(&code);
        let mut sent =
            OneTimeCode::issue(to.factor, hash, policy.lifetime).map_err(AppError::from_domain)?;
        self.sent_codes.save(to.tenant, &sent).await.or_internal()?;
        let outgoing = OutgoingCode {
            tenant_id: to.tenant,
            code: &code,
            expires_at: sent.expires_at(),
            locale: to.account.locale(),
        };
        self.sender
            .send(destination, outgoing)
            .await
            .or_internal()?;
        let answer = CodeSent {
            expires_at: sent.expires_at(),
        };
        let events = raised_by_holder(&mut sent, to.tenant, *to.account.id());
        Ok((answer, events))
    }

    /// Refuses a new code while the one sent before is recent and still
    /// works.
    async fn ensure_may_resend(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
        policy: SentCodePolicy,
    ) -> Result<(), AppError> {
        let Some(latest) = self
            .sent_codes
            .latest(tenant, user_id)
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        let now = clock::now();
        let recent = now < latest.issued_at().saturating_add(policy.resend_after);
        if recent && latest.takes_tries_at(now) {
            return Err(AppError::TooManyRequests(message!(
                "authentication-a-code-was-sent-moments-ago",
                "a code was sent moments ago; wait before asking for another"
            )));
        }
        Ok(())
    }
}

/// Where a code for `factor` goes: the account's address as it is now, or
/// the number the factor was set up with.
///
/// # Errors
///
/// Returns `AppError::Conflict` when the factor is an authenticator app,
/// which makes its own codes.
fn destination<'a>(
    account: &'a User<ResolvedTenant>,
    factor: &'a EnrolledFactor,
) -> Result<CodeDestination<'a>, AppError> {
    match factor {
        EnrolledFactor::EmailCode => Ok(CodeDestination::Mail(account.email())),
        EnrolledFactor::SmsCode(number) => Ok(CodeDestination::Text(number)),
        EnrolledFactor::Totp(_) => Err(AppError::Conflict(message!(
            "authentication-an-authenticator-app-makes-its-own",
            "an authenticator app makes its own codes; nothing is sent"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{Locale, Preference};

    use super::*;
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, RecordingCodeSender};
    use crate::test_support::identity::user_reading;
    use crate::test_support::{FakeMailSetup, block_on, test_ctx};

    /// Ann reads mail in German and her factor mails her codes. The code
    /// handed to the mail provider carries her language, so it reaches her
    /// in German.
    #[test]
    fn a_mailed_code_goes_out_in_the_persons_language() {
        let ann = user_reading(UserId::new(), "ann@acme.test", "de-DE");
        let enrollments =
            FakeMfaEnrollmentStore::active_with_factor(*ann.id(), EnrolledFactor::EmailCode);
        let factor = enrollments.enrollment_of(*ann.id()).unwrap();
        let sender = Arc::new(RecordingCodeSender::default());
        let ports = SentCodePorts {
            sender: sender.clone(),
            ..SentCodePorts::fakes()
        };
        let policy = SentCodePolicy {
            lifetime: Lifetime::seconds(300).unwrap(),
            resend_after: Duration::seconds(30),
        };
        let tenant = test_ctx().tenant();
        let to = CodeFor {
            tenant: &tenant,
            account: &ann,
            factor: &factor,
        };

        block_on(ports.send(to, policy)).unwrap();

        assert_eq!(
            sender.messages()[0].locale,
            Preference::Own(Locale::new("de-DE").unwrap())
        );
    }

    /// Missing mail setup forbids sending a mailed factor code and leaves
    /// the sender's message list empty.
    #[test]
    fn a_mailed_code_is_not_sent_where_nothing_is_mailed() {
        let ann = user_reading(UserId::new(), "ann@acme.test", "de-DE");
        let enrollments =
            FakeMfaEnrollmentStore::active_with_factor(*ann.id(), EnrolledFactor::EmailCode);
        let factor = enrollments.enrollment_of(*ann.id()).unwrap();
        let sender = Arc::new(RecordingCodeSender::default());
        let ports = SentCodePorts {
            sender: sender.clone(),
            mail: FakeMailSetup::not_set_up(),
            ..SentCodePorts::fakes()
        };
        let policy = SentCodePolicy {
            lifetime: Lifetime::seconds(300).unwrap(),
            resend_after: Duration::seconds(30),
        };
        let tenant = test_ctx().tenant();
        let to = CodeFor {
            tenant: &tenant,
            account: &ann,
            factor: &factor,
        };

        let sent = block_on(ports.send(to, policy));

        assert!(matches!(sent, Err(AppError::Forbidden(_))));
        assert!(sender.messages().is_empty());
    }
}
