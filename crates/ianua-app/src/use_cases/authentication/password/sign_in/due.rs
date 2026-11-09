//! What a password sign-in does about the password itself once it is
//! proved: whether it must be changed before the person goes on, and
//! replacing a hash another system made with one of the platform's own.
//!
//! A password an admin set, or one past the tenant's age, opens no session.
//! The sign-in instead begins a password change, bound to it alone: a
//! single-use token, good for a few minutes. A password past its age was
//! the person's own, so the token goes back to the browser that proved it.
//! A password an admin set is known to that admin too, so the change also
//! asks for something only the person holds, as [`ChangeProof`] decides:
//! a code from their own second factor, given with the new password, or
//! their mailbox, where the token is mailed instead of handed back. With
//! neither, the sign-in is refused, and an administrator must send an
//! invitation instead.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::credentials::password_rules::{
    ChangeReason, PasswordDue,
};
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::owed::Enrolment;
use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
use ianua_domain::domains::authentication::recovery::reset::{
    IN_SIGN_IN_LONGEST, PasswordResetRequest,
};
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, Lifetime, PasswordHash, TokenHash, UserId};
use time::OffsetDateTime;

use crate::auditor::raised_by_holder;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    CredentialStore, MfaEnrollmentStore, PasswordHashFormat, ResetRequestStore, TextMessaging,
};
use crate::ports::shared::{MailRecipient, MailSetup, Mailer};
use crate::services::authentication::channels::Channels;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::tenancy::ScopedTenant;

/// The page a mailed password change opens.
const CHANGE_PAGE: &str = "change-password";

/// Why a sign-in refuses a password an admin set when nothing only the
/// person holds can be asked for.
const NO_PROOF_OF_THE_PERSON: &str = "this password was set by an administrator, and \
     nothing only you hold can confirm the change on this deployment; ask an administrator \
     to send you an invitation instead of setting a password";

/// The ports a password sign-in reads and writes the password through.
#[derive(ianua_macros::Fakes)]
pub struct DuePorts {
    /// Who set the current password and when, and where a rehash goes.
    pub credentials: Arc<dyn CredentialStore>,
    /// Whether a stored hash is in the platform's own format.
    pub hash_format: Arc<dyn PasswordHashFormat>,
    /// Keeps the password change a sign-in begins.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// The person's second factor, which a change of a password an admin
    /// set may ask for.
    pub enrollments: Arc<dyn MfaEnrollmentStore>,
    /// Whether codes can be texted here, for a texted factor.
    pub text_messaging: Arc<dyn TextMessaging>,
    /// Whether anything can be mailed here.
    pub mail: Arc<dyn MailSetup>,
    /// Mails the change's token when the mailbox is the proof.
    pub mailer: Arc<dyn Mailer>,
}

/// Where the change's token goes.
pub enum ChangeToken {
    /// Back to the browser that proved the password. It is never stored.
    HandedBack(Secret),
    /// To the account's address, as a link to set the new password: only
    /// the mailbox's holder answers it.
    Mailed,
}

/// A password change a sign-in owes before it finishes. It may hold the
/// token that answers it, so it has no `Debug`.
pub struct PasswordChangeOwed {
    /// Where the single-use token went.
    pub token: ChangeToken,
    /// What the change asks besides the new password.
    pub proof: ChangeProof,
    /// Why the password must change.
    pub reason: ChangeReason,
    /// When the token stops working.
    pub expires_at: OffsetDateTime,
}

/// A proved password whose holder must change it, and where a mailed
/// change's link lands.
pub(in crate::use_cases::authentication::password) struct DueChange<'a> {
    /// The tenant the account is in.
    pub(in crate::use_cases::authentication::password) tenant: &'a ScopedTenant,
    /// The account.
    pub(in crate::use_cases::authentication::password) holder: &'a User<ResolvedTenant>,
    /// Why it must change.
    pub(in crate::use_cases::authentication::password) reason: ChangeReason,
    /// What the change asks besides the new password.
    pub(in crate::use_cases::authentication::password) proof: ChangeProof,
    /// The pages a mailed link opens.
    pub(in crate::use_cases::authentication::password) scope: &'a LinkScope,
    /// The address the dashboard's pages hang off.
    pub(in crate::use_cases::authentication::password) base_url: &'a HttpsUrl,
}

/// A password just proved, to keep in the platform's own format.
pub(in crate::use_cases::authentication::password) struct ProvedPassword<'a> {
    /// The tenant the account is in.
    pub(in crate::use_cases::authentication::password) tenant: &'a ScopedTenant,
    /// The account.
    pub(in crate::use_cases::authentication::password) user_id: &'a UserId,
    /// The hash it was proved against.
    pub(in crate::use_cases::authentication::password) stored: &'a PasswordHash,
    /// The password as typed.
    pub(in crate::use_cases::authentication::password) typed: &'a Secret,
}

impl DuePorts {
    /// Whether `user_id`'s password must change before a sign-in goes on,
    /// under `record`'s password expiry. An account without a password on
    /// record owes nothing here.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the record cannot be read.
    pub(in crate::use_cases::authentication::password) async fn due(
        &self,
        tenant: &ScopedTenant,
        record: &Tenant,
        user_id: &UserId,
    ) -> Result<PasswordDue, AppError> {
        let Some(current) = self
            .credentials
            .current_password(tenant, user_id)
            .await
            .or_internal()?
        else {
            return Ok(PasswordDue::Current);
        };
        let expiry = record.auth_config().password_policy().hygiene().expiry;
        Ok(current.due(expiry, clock::now()))
    }

    /// What a change owed for `reason` asks of `holder` besides the new
    /// password: from the factor they hold, if its codes can be answered
    /// here, and whether a mail reaches them.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the factor cannot be read.
    pub(in crate::use_cases::authentication::password) async fn proof_for(
        &self,
        tenant: &ScopedTenant,
        holder: &User<ResolvedTenant>,
        reason: ChangeReason,
    ) -> Result<ChangeProof, AppError> {
        let held = self
            .enrollments
            .find_by_user(tenant, holder.id())
            .await
            .or_internal()?;
        let factor = self.answerable(held.as_ref());
        Ok(ChangeProof::for_change(reason, self.mail.reach(), factor))
    }

    /// Whether `held` is a factor in force whose codes can be answered on
    /// this deployment.
    fn answerable(&self, held: Option<&MfaEnrollment<ResolvedTenant>>) -> Enrolment {
        let channels = Channels {
            texts: self.text_messaging.as_ref(),
            mail: self.mail.as_ref(),
        };
        match held {
            Some(factor) if factor.is_active() && channels.deliverable(factor.method()) => {
                Enrolment::Enrolled
            }
            Some(_) | None => Enrolment::NotEnrolled,
        }
    }

    /// Replaces `proved.stored` with a fresh hash of the typed password when
    /// it is not in the platform's own format, such as a hash an import
    /// brought over. Who set the password, and when, stay as they were.
    ///
    /// # Errors
    ///
    /// - `AppError::Busy` when no hash could start on this node in time.
    /// - `AppError::Internal` when the password cannot be hashed or the
    ///   hash cannot be written.
    pub(in crate::use_cases::authentication::password) async fn rehash_if_foreign(
        &self,
        proved: ProvedPassword<'_>,
        hashing: &PasswordHashing,
    ) -> Result<(), AppError> {
        if !self.hash_format.needs_rehash(proved.stored) {
            return Ok(());
        }
        let fresh = hashing
            .permitted()
            .await?
            .hash(proved.typed.expose())
            .or_internal()?;
        self.credentials
            .rehash_password(proved.tenant, proved.user_id, proved.stored, &fresh)
            .await
            .or_internal()
    }

    /// Begins the password change `due` owes, superseding any change or
    /// reset link the account had open, and answers where its token went
    /// with what it raised. The token is good for [`IN_SIGN_IN_LONGEST`].
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when nothing only the person holds can be
    ///   asked for, saying an administrator must send an invitation, and
    ///   when the account may not sign in.
    /// - `AppError::Internal` on storage or token failure.
    pub(in crate::use_cases::authentication::password) async fn begin_change(
        &self,
        due: DueChange<'_>,
        tokens: &dyn RefreshTokenGenerator,
    ) -> Result<(PasswordChangeOwed, Vec<DomainEvent>), AppError> {
        ensure_possible(due.proof)?;
        let (raw, token_hash) = tokens
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let lifetime = Lifetime::new(IN_SIGN_IN_LONGEST).or_internal()?;
        let mut change = self.kept_change(&due, token_hash, lifetime).await?;
        let token = self.delivered(&due, raw, lifetime).await?;
        let events = raised_by_holder(&mut change, due.tenant, *due.holder.id());
        let owed = PasswordChangeOwed {
            token,
            proof: due.proof,
            reason: due.reason,
            expires_at: change.expires_at(),
        };
        Ok((owed, events))
    }

    /// A new change for `due.holder`, kept in place of any change or reset
    /// link they had open.
    async fn kept_change(
        &self,
        due: &DueChange<'_>,
        token_hash: TokenHash,
        lifetime: Lifetime,
    ) -> Result<PasswordResetRequest, AppError> {
        let change = PasswordResetRequest::in_sign_in(due.holder, token_hash, lifetime)
            .map_err(AppError::from_domain)?;
        self.reset_store
            .expire_pending_for_user(due.tenant, change.user_id())
            .await
            .or_internal()?;
        self.reset_store
            .save(due.tenant, &change)
            .await
            .or_internal()?;
        Ok(change)
    }

    /// Where `raw`, the change's token, goes: back to the browser, or by
    /// mail to the account's address when the mailbox is the proof.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the mail cannot be queued: a
    /// change whose only proof never left would wait for good.
    async fn delivered(
        &self,
        due: &DueChange<'_>,
        raw: Secret,
        lifetime: Lifetime,
    ) -> Result<ChangeToken, AppError> {
        if due.proof.hands_token_back() {
            return Ok(ChangeToken::HandedBack(raw));
        }
        let to = MailRecipient {
            email: due.holder.email(),
            locale: due.holder.locale(),
        };
        let variables = change_mail_variables(due, &raw, lifetime);
        self.mailer
            .send_to_person(
                to,
                *due.tenant,
                EmailTemplateType::PasswordReset,
                &variables,
            )
            .await
            .or_internal()?;
        Ok(ChangeToken::Mailed)
    }
}

/// What the mail carrying the change's token `raw` is filled with: the
/// person's name, the link that sets the new password, and how long it
/// works.
fn change_mail_variables(
    due: &DueChange<'_>,
    raw: &Secret,
    lifetime: Lifetime,
) -> HashMap<TemplateVariable, String> {
    HashMap::from([
        (
            TemplateVariable::UserName,
            due.holder.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::ActionUrl,
            due.scope
                .action_url(due.base_url, CHANGE_PAGE, raw.expose()),
        ),
        (
            TemplateVariable::ExpiresAt,
            format!("{} minutes", lifetime.whole_seconds() / 60),
        ),
    ])
}

/// Refuses a change nothing only the person holds can answer.
///
/// # Errors
///
/// Returns `AppError::Forbidden`, saying an administrator must send an
/// invitation instead of setting a password.
pub(in crate::use_cases::authentication::password) fn ensure_possible(
    proof: ChangeProof,
) -> Result<(), AppError> {
    match proof {
        ChangeProof::NotPossible => Err(AppError::Forbidden(
            NO_PROOF_OF_THE_PERSON.to_owned().into(),
        )),
        ChangeProof::PasswordAlone | ChangeProof::OwnFactor | ChangeProof::MailedLink => Ok(()),
    }
}
