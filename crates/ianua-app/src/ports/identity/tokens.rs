//! The single-use links mailed to a user: email verification, magic-link
//! sign-in and sign-in confirmation.

use async_trait::async_trait;
use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::identity::tokens::purpose::TenantLinkPurpose;
use ianua_domain::domains::identity::tokens::secure::SecureToken;
use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TokenHash, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Type alias for email verification tokens.
pub type EmailVerificationToken = SecureToken<ResolvedTenant, EmailVerification>;

/// Dyn-safe port for persisting and retrieving email verification tokens.
///
/// Every call names the tenant even where a hash would find the row on its
/// own: a token pairs a user id with an email address, and for a tenant that
/// keeps its directory in its own database that pair belongs there too.
#[async_trait]
pub trait VerificationTokenStore: Send + Sync + TenantScoped {
    /// Finds a token by its hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<EmailVerificationToken>, DomainError>;

    /// Saves a new or updated token.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &EmailVerificationToken,
    ) -> Result<(), DomainError>;

    /// Consumes every unused token this user holds.
    ///
    /// Issuing a replacement supersedes the previous link rather than leaving
    /// both live, so resending an email invalidates whatever was sent before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume_outstanding(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError>;

    /// The most recently issued token for this user, spent or not.
    ///
    /// When the last email went out, which is what a resend cooldown is
    /// measured from. The token the caller presents cannot answer it: issuing
    /// a replacement supersedes it, so its age stops moving and every later
    /// request would look old enough to send again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<EmailVerificationToken>, DomainError>;
}

/// Type alias for magic-link (passwordless login) tokens.
pub(crate) type MagicLinkToken = SecureToken<ResolvedTenant, MagicLink>;

/// Type alias for the links that confirm a sign-in from the mailbox.
pub(crate) type SignInConfirmationToken = SecureToken<ResolvedTenant, SignInConfirmation>;

/// Dyn-safe port for persisting and retrieving the single-use links that
/// sign a person in, or finish their sign-in: magic links and sign-in
/// confirmations.
///
/// Each `Purpose` is a store of its own. A lookup finds only links of its
/// purpose, so a confirmation link presented where a magic link is expected
/// is unknown there, and opens no session. Storage keeps the purpose with
/// every link and filters by it.
///
/// Tokens are single-use: [`consume`](Self::consume) removes the token so a
/// link can never authenticate twice.
///
/// The tenant is a parameter rather than something read out of the token,
/// because it decides which database to open, a question that has to be
/// answered before there is a token to read. Every endpoint that reaches
/// this port is already addressed by tenant, so the caller always has it.
#[async_trait]
pub trait SignInLinkStore<Purpose: TenantLinkPurpose + Send + Sync + 'static>:
    Send + Sync + TenantScoped
{
    /// Finds a link of this purpose by its hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SecureToken<ResolvedTenant, Purpose>>, DomainError>;

    /// Saves a new link of this purpose.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &SecureToken<ResolvedTenant, Purpose>,
    ) -> Result<(), DomainError>;

    /// Permanently removes the link of this purpose with this hash, which
    /// is how it is used up, and answers whether this call removed it.
    ///
    /// `false` means the link was already gone: of two follows of one link
    /// arriving together, only one gets `true`, so only one signs in.
    /// Storage does it in one statement, such as a `DELETE .. WHERE
    /// tenant_id = $1 AND purpose = $2 AND token_hash = $3` counting the
    /// rows it removed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<bool, DomainError>;
}
