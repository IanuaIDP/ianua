//! What this deployment can deliver, and so what it may offer.
//!
//! A tenant or organization lists the kinds of second factor and the ways
//! in it offers, and the domain checks each can reach its baseline.
//! Whether a code can be texted or anything mailed at all is a fact of the
//! deployment, not of the tenant. With no text message provider, a texted
//! factor could never deliver a code; with no mail server, neither could a
//! mailed one, nor would a magic link, a reset link or an address
//! confirmation ever arrive. Its holder would be locked out at the first
//! sign-in that asks for it. So such a factor or way in is neither set up,
//! newly offered, nor sent there.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::enrollment::MfaMethod;
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::error::AppError;
use crate::ports::authentication::{TextAvailability, TextMessaging};
use crate::ports::shared::MailSetup;

/// Why a texted code is refused here.
const NO_TEXTS: &str = "text messages are not set up on this deployment, so codes cannot be texted";

/// Why a mailed code is refused here.
const NO_MAILED_CODES: &str =
    "no mail server is set up on this deployment, so codes cannot be mailed";

/// Why a magic link is refused here.
pub(crate) const NO_MAGIC_LINKS: &str =
    "no mail server is set up on this deployment, so sign-in links cannot be mailed";

/// Why a password reset link is refused here.
pub(crate) const NO_RESET_LINKS: &str = "no mail server is set up on this deployment, so no reset \
     link can be mailed; an administrator must reset the password";

/// Why an address confirmation link is refused here.
pub(crate) const NO_CONFIRMATION_LINKS: &str = "no mail server is set up on this deployment, so no \
     link confirming an address can be mailed";

/// Why an account that could join only through a mailed link is refused
/// here.
pub(crate) const NO_PENDING_ACCOUNTS: &str = "no mail server is set up on this deployment, so an \
     account waiting to confirm its address by mail could never join; let it in at once instead";

/// Why signing up is refused here.
pub(crate) const NO_SIGN_UPS: &str = "no mail server is set up on this deployment, so a new \
     account could never confirm its address; ask an administrator for an account";

/// Why renewing an invitation from a dead link is refused here.
pub(crate) const NO_INVITATION_RENEWALS: &str = "no mail server is set up on this deployment, so \
     no new invitation link can be mailed; ask whoever invited you to send it again";

/// Why changing an address is refused here.
pub(crate) const NO_EMAIL_CHANGES: &str = "no mail server is set up on this deployment, so a new \
     address cannot be confirmed";

/// The ways this deployment delivers codes: text messages and mail.
#[derive(Clone, Copy)]
pub(crate) struct Channels<'a> {
    /// Whether codes can be texted.
    pub(crate) texts: &'a dyn TextMessaging,
    /// Whether anything can be mailed.
    pub(crate) mail: &'a dyn MailSetup,
}

/// What a tenant's or an organization's sign-in settings offer: the kinds
/// of second factor and the ways in.
#[derive(Clone, Copy)]
pub(crate) struct Offered<'a> {
    /// The kinds of second factor offered.
    pub(crate) second_factors: &'a [MfaMethod],
    /// The ways in enabled.
    pub(crate) methods: &'a [AuthMethod],
}

impl<'a> From<&'a TenantAuthConfig> for Offered<'a> {
    fn from(config: &'a TenantAuthConfig) -> Self {
        Self {
            second_factors: &config.settings().second_factors,
            methods: config.enabled_methods(),
        }
    }
}

impl<'a> From<&'a OrganizationAuthConfig> for Offered<'a> {
    fn from(config: &'a OrganizationAuthConfig) -> Self {
        Self {
            second_factors: &config.settings().second_factors,
            methods: config.enabled_methods(),
        }
    }
}

impl<'a> Channels<'a> {
    /// The channels `texts` and `mail` deliver through.
    pub(crate) fn of(texts: &'a Arc<dyn TextMessaging>, mail: &'a Arc<dyn MailSetup>) -> Self {
        Self {
            texts: texts.as_ref(),
            mail: mail.as_ref(),
        }
    }

    /// Refuses `after` when it newly offers what `before` did not and this
    /// deployment cannot deliver: texted codes with nothing to text them,
    /// mailed codes or magic links with no mail server. What was already
    /// offered may stay, so the other settings can still change.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Domain` with a validation error naming
    /// `second_factors` or `enabled_methods`.
    pub(crate) fn ensure_newly_deliverable(
        &self,
        before: Offered<'_>,
        after: Offered<'_>,
    ) -> Result<(), AppError> {
        self.ensure_newly_offered_deliverable(before.second_factors, after.second_factors)?;
        ensure_newly_enabled_reachable(self.mail, before.methods, after.methods)
    }

    /// Whether a factor of kind `method` can have its codes delivered here.
    pub(crate) fn deliverable(&self, method: MfaMethod) -> bool {
        self.undeliverable(method).is_none()
    }

    /// Refuses setting up, or sending a code for, a factor of kind `method`
    /// that could never deliver a code here.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` for a texted factor on a deployment
    /// with no text message provider, or a mailed one with no mail server.
    pub(crate) fn ensure_deliverable(&self, method: MfaMethod) -> Result<(), AppError> {
        let Some(why) = self.undeliverable(method) else {
            return Ok(());
        };
        Err(AppError::Forbidden(why.to_owned().into()))
    }

    /// Refuses `after`, a list of offered factor kinds, when it newly
    /// offers one that `before` did not and whose codes cannot be delivered
    /// here. One already offered may stay, so the other settings can still
    /// change.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Domain` with a validation error naming
    /// `second_factors`.
    fn ensure_newly_offered_deliverable(
        &self,
        before: &[MfaMethod],
        after: &[MfaMethod],
    ) -> Result<(), AppError> {
        let newly_undeliverable = after
            .iter()
            .filter(|method| !before.contains(*method))
            .find_map(|method| self.undeliverable(*method));
        let Some(why) = newly_undeliverable else {
            return Ok(());
        };
        Err(AppError::Domain(DomainError::invalid(message!(
            "authentication-second-factors",
            format!("second_factors: {why}")
        ))))
    }

    /// Why a code of kind `method` cannot be delivered here, or none when
    /// it can.
    fn undeliverable(&self, method: MfaMethod) -> Option<&'static str> {
        match method {
            MfaMethod::Totp => None,
            MfaMethod::EmailCode => {
                (self.mail.reach() == MailReach::NotSetUp).then_some(NO_MAILED_CODES)
            }
            MfaMethod::SmsCode => {
                (self.texts.availability() == TextAvailability::NotSetUp).then_some(NO_TEXTS)
            }
        }
    }
}

/// Whether a mailed link reaches anyone here.
pub(crate) fn mail_reaches(mail: &dyn MailSetup) -> bool {
    mail.reach() == MailReach::Available
}

/// Refuses mailing a link where no mail server is set up, with `why`: the
/// person would wait for a mail that never arrives.
///
/// # Errors
///
/// Returns `AppError::Forbidden` with `why` when no mail server is set up.
pub(crate) fn ensure_mail_reaches(mail: &dyn MailSetup, why: &str) -> Result<(), AppError> {
    if mail_reaches(mail) {
        return Ok(());
    }
    Err(AppError::Forbidden(why.to_owned().into()))
}

/// Refuses `after`, a list of enabled ways in, when it newly enables
/// magic links, which `before` did not, on a deployment with no mail
/// server. Ones already enabled may stay, so the other settings can still
/// change.
///
/// # Errors
///
/// Returns `AppError::Domain` with a validation error naming
/// `enabled_methods`.
fn ensure_newly_enabled_reachable(
    mail: &dyn MailSetup,
    before: &[AuthMethod],
    after: &[AuthMethod],
) -> Result<(), AppError> {
    let newly_mailed =
        after.contains(&AuthMethod::MagicLink) && !before.contains(&AuthMethod::MagicLink);
    if !newly_mailed || mail_reaches(mail) {
        return Ok(());
    }
    Err(AppError::Domain(DomainError::invalid(message!(
        "authentication-enabled-methods",
        format!("enabled_methods: {NO_MAGIC_LINKS}")
    ))))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::authentication::FakeTextMessaging;
    use crate::test_support::{Fake, FakeMailSetup};

    fn without_mail() -> (Arc<dyn TextMessaging>, Arc<dyn MailSetup>) {
        (Fake::fake(), FakeMailSetup::not_set_up())
    }

    fn without_texts() -> (Arc<dyn TextMessaging>, Arc<dyn MailSetup>) {
        (FakeTextMessaging::not_set_up(), Fake::fake())
    }

    fn with_both() -> (Arc<dyn TextMessaging>, Arc<dyn MailSetup>) {
        (Fake::fake(), Fake::fake())
    }

    fn channels<'a>(both: &'a (Arc<dyn TextMessaging>, Arc<dyn MailSetup>)) -> Channels<'a> {
        Channels {
            texts: both.0.as_ref(),
            mail: both.1.as_ref(),
        }
    }

    /// Without a text provider, SMS factors fail the delivery check while
    /// authenticator and email factors remain allowed.
    #[test]
    fn a_texted_factor_is_refused_where_nothing_texts() {
        let both = without_texts();
        let here = channels(&both);

        let texted = here.ensure_deliverable(MfaMethod::SmsCode);

        assert!(matches!(texted, Err(AppError::Forbidden(_))));
        assert!(here.ensure_deliverable(MfaMethod::Totp).is_ok());
        assert!(here.ensure_deliverable(MfaMethod::EmailCode).is_ok());
    }

    /// Email factors are forbidden without a mail server. Authenticator
    /// and SMS factors still pass the delivery check.
    #[test]
    fn a_mailed_factor_is_refused_where_nothing_is_mailed() {
        let both = without_mail();
        let here = channels(&both);

        let mailed = here.ensure_deliverable(MfaMethod::EmailCode);

        assert!(matches!(mailed, Err(AppError::Forbidden(_))));
        assert!(here.ensure_deliverable(MfaMethod::Totp).is_ok());
        assert!(here.ensure_deliverable(MfaMethod::SmsCode).is_ok());
    }

    /// With a text provider and a mail server set up, every kind can be set
    /// up.
    #[test]
    fn every_factor_is_allowed_where_texts_and_mail_go_out() {
        let both = with_both();
        let here = channels(&both);

        for method in MfaMethod::ALL {
            assert!(here.ensure_deliverable(method).is_ok(), "{method:?}");
        }
    }

    /// Adding SMS to the offered factors fails validation when the
    /// deployment has no text provider.
    #[test]
    fn newly_offering_texted_codes_is_refused_where_nothing_texts() {
        let both = without_texts();

        let changed = channels(&both).ensure_newly_offered_deliverable(
            &[MfaMethod::Totp],
            &[MfaMethod::Totp, MfaMethod::SmsCode],
        );

        assert!(matches!(
            changed,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// Offering email codes for the first time fails validation without
    /// a configured mail server.
    #[test]
    fn newly_offering_mailed_codes_is_refused_where_nothing_is_mailed() {
        let both = without_mail();

        let changed = channels(&both).ensure_newly_offered_deliverable(
            &[MfaMethod::Totp],
            &[MfaMethod::Totp, MfaMethod::EmailCode],
        );

        assert!(matches!(
            changed,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// A tenant that already offered texted or mailed codes can still
    /// change its other settings, and one that does not offer them is
    /// untouched.
    #[test]
    fn an_offer_already_made_or_never_made_is_left_alone() {
        let both = (FakeTextMessaging::not_set_up(), FakeMailSetup::not_set_up());
        let here = channels(&both);
        let every = MfaMethod::ALL;
        let app_only = [MfaMethod::Totp];

        assert!(
            here.ensure_newly_offered_deliverable(&every, &every)
                .is_ok()
        );
        assert!(
            here.ensure_newly_offered_deliverable(&app_only, &app_only)
                .is_ok()
        );
    }

    /// Newly enabling magic links requires mail delivery. Existing magic
    /// links may stay enabled without mail, and newly enabling them passes
    /// when a mail server is configured.
    #[test]
    fn newly_enabling_magic_links_is_refused_where_nothing_is_mailed() {
        let password = [AuthMethod::Password];
        let linked = [AuthMethod::Password, AuthMethod::MagicLink];
        let mail: Arc<dyn MailSetup> = Fake::fake();

        let refused = ensure_newly_enabled_reachable(
            FakeMailSetup::not_set_up().as_ref(),
            &password,
            &linked,
        );

        assert!(matches!(
            refused,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert!(ensure_newly_enabled_reachable(mail.as_ref(), &password, &linked).is_ok());
        assert!(
            ensure_newly_enabled_reachable(FakeMailSetup::not_set_up().as_ref(), &linked, &linked)
                .is_ok()
        );
    }

    /// A link is refused where no mail server is set up, with the reason
    /// given, and allowed where one is.
    #[test]
    fn a_mailed_link_is_refused_only_where_nothing_is_mailed() {
        let mail: Arc<dyn MailSetup> = Fake::fake();

        let refused = ensure_mail_reaches(FakeMailSetup::not_set_up().as_ref(), NO_RESET_LINKS);

        assert!(
            matches!(refused, Err(AppError::Forbidden(why)) if why.as_str().contains("administrator"))
        );
        assert!(ensure_mail_reaches(mail.as_ref(), NO_RESET_LINKS).is_ok());
    }
}
