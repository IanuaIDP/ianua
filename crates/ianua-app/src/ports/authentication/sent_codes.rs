//! Codes sent for a second factor: mailed to the account's address or
//! texted to the number the factor was set up with. Where they are kept,
//! how they are made and hashed, and how they reach the person.

use async_trait::async_trait;
use ianua_domain::domains::authentication::mfa::one_time_code::OneTimeCode;
use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, Locale, Preference, TokenHash, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for the codes sent for tenant users' second factors.
///
/// A user has at most one code that counts: the latest sent. Sending a new
/// one replaces the old, so a code read late from a mailbox or a lock
/// screen stops working once another was asked for.
#[async_trait]
pub trait SentCodeStore: Send + Sync + TenantScoped {
    /// The latest code sent for `user_id`'s factor, whatever it stands at.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the code cannot be read.
    async fn latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OneTimeCode<ResolvedTenant>>, DomainError>;

    /// The latest code sent for `user_id`'s factor, held until the unit of
    /// work the caller runs in ends, for a caller that will check a typed
    /// code against it and save it.
    ///
    /// Two answers to one code sent at once both count their wrong tries,
    /// and only one spends a right one: storage locks the row, such as
    /// `SELECT .. FROM mfa_sent_codes WHERE tenant_id = $1 AND user_id = $2
    /// FOR UPDATE`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the code cannot be read.
    async fn hold_latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OneTimeCode<ResolvedTenant>>, DomainError>;

    /// Keeps `code` as the user's latest, replacing the one before, or saves
    /// a change to it: a wrong try counted or its spending.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the code cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &OneTimeCode<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for making sent codes and hashing typed ones.
///
/// The adapter draws each code with the domain's
/// [`new_code`](ianua_domain::domains::authentication::mfa::one_time_code::new_code)
/// over the operating system's randomness. The hash is keyed, an HMAC under
/// a key the server holds and the database does not, as for recovery codes:
/// a six-digit code hashed bare is reversed by trying every one.
pub trait SentCodeGenerator: Send + Sync {
    /// A fresh code, to be sent once and kept only as its hash.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if no code can be drawn.
    fn generate(&self) -> Result<Secret, DomainError>;

    /// The hash of `code`, made or typed, under the same key every time.
    fn hash(&self, code: &Secret) -> TokenHash;
}

/// Where a sent code goes.
#[derive(Debug, Clone, Copy)]
pub enum CodeDestination<'a> {
    /// Mailed to the account's address as it is now.
    Mail(&'a Email),
    /// Texted to the number the factor was set up with.
    Text(&'a PhoneNumber),
}

/// A code on its way to the person, with when it lapses. Holds the code,
/// so it has no `Debug`.
pub struct OutgoingCode<'a> {
    /// The tenant whose user it is, for the mail's names and its sender.
    pub tenant_id: &'a ScopedTenant,
    /// The code itself.
    pub code: &'a Secret,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
    /// The language the person reads, for the mail or the text: their own,
    /// or that they follow the tenant's. A mail is the tenant's
    /// [`SignInCode`](ianua_domain::domains::branding::email_template::EmailTemplateType::SignInCode)
    /// template in it.
    pub locale: &'a Preference<Locale>,
}

/// Whether this deployment can text a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAvailability {
    /// A text message provider is set up, so texted codes are sent.
    Available,
    /// None is: a code to be texted would never arrive.
    NotSetUp,
}

/// Dyn-safe port saying whether this deployment can text a code.
///
/// A deployment with no text message provider must not let a person set
/// up a texted factor, nor a tenant offer one: the factor could never
/// deliver a code, and the person would be locked out by the first sign-in
/// that asks for it. A factor set up before the provider went away is not
/// moved to mail; its codes fail to send, as the
/// [`FactorCodeSender`] answers.
pub trait TextMessaging: Send + Sync {
    /// Whether texted codes can be sent here now.
    fn availability(&self) -> TextAvailability;
}

/// Dyn-safe port delivering a second-factor code by mail or text message.
///
/// The adapter composes the message and hands it to the mail transport or
/// the SMS provider. It must give up after a few seconds: a provider that
/// hangs must not hold the sign-in open. It never logs the code, and never
/// writes it into an error.
#[async_trait]
pub trait FactorCodeSender: Send + Sync {
    /// Sends `outgoing` to `to`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] if the message could not be
    /// handed over, or the provider did not answer in time.
    async fn send(
        &self,
        to: CodeDestination<'_>,
        outgoing: OutgoingCode<'_>,
    ) -> Result<(), DomainError>;
}
