//! The credentials an account holds: passwords and their resets, MFA
//! factors and recovery codes, and the encryption of the secrets among
//! them. The LDAP client certificates a directory bind needs are in
//! [`crate::ports::directory`].

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password_rules::CurrentPassword;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::time_step::TimeStep;
use ianua_domain::domains::authentication::recovery::codes::RecoveryCodeSet;
use ianua_domain::domains::authentication::recovery::reset::PasswordResetRequest;
use ianua_domain::domains::identity::account::admin_password_reset::AdminPasswordReset;
use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::password_policy::CommonPassword;
use ianua_domain::types::{PasswordHash, SealedSecret, TokenHash, UserId};

use crate::ports::TenantScoped;
use crate::ports::authentication::SealedFor;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for reading and updating a user's password hash.
///
/// A user id alone would be enough to find the row, but not enough to find
/// the *database*: a tenant may keep its users in its own Postgres, and a
/// password written to the wrong one silently stops matching the password
/// read at login. The tenant is therefore part of every call.
#[async_trait]
pub trait CredentialStore: Send + Sync + TenantScoped {
    /// Loads the current password hash for a user.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the hash cannot be read.
    async fn find_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordHash>, DomainError>;

    /// Returns when the user's password was last changed.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the time cannot be read.
    async fn password_changed_at(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<time::OffsetDateTime>, DomainError>;

    /// Who set the user's current password and when, or none when the
    /// account has no password.
    ///
    /// A hash written by [`update_password_hash`](Self::update_password_hash)
    /// or [`import_password_hash`](Self::import_password_hash) was chosen by
    /// its holder; one written by
    /// [`reset_password_hash`](Self::reset_password_hash) was set by an
    /// admin. Storage keeps the origin and the time beside the hash.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the record cannot be read, or holds an
    /// origin it does not know.
    async fn current_password(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<CurrentPassword>, DomainError>;

    /// Replaces the user's password hash with one they chose themselves, or
    /// that their own sign-up, invitation or reset link set. The password
    /// is recorded as chosen by its holder, changed now.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the hash cannot be written.
    async fn update_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &PasswordHash,
    ) -> Result<(), DomainError>;

    /// Keeps the hash another system made of the password the person
    /// already uses, brought over by an import, as chosen by its holder and
    /// changed now.
    ///
    /// The hash is kept exactly as it came. The adapter's
    /// [`PasswordHasher::verify`](ianua_domain::domains::authentication::credentials::password::PasswordHasher::verify)
    /// must check a password against each format
    /// [`HashScheme`](ianua_domain::domains::identity::account::import::password_hash::HashScheme)
    /// lists, and the first sign-in that proves it replaces it through
    /// [`rehash_password`](Self::rehash_password).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the hash cannot be written.
    async fn import_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &ImportedPasswordHash,
    ) -> Result<(), DomainError>;

    /// Replaces the user's hash `replaced` with `hash`, a new hash of the
    /// same password in the platform's own format, keeping who set the
    /// password and when. A sign-in that just proved the password against
    /// `replaced` calls it for a hash [`PasswordHashFormat::needs_rehash`]
    /// names. Storage replaces it only while the stored hash is still
    /// `replaced`, in one statement, so a password changed since the
    /// sign-in read it is never put back.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the hash cannot be written.
    async fn rehash_password(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        replaced: &PasswordHash,
        hash: &PasswordHash,
    ) -> Result<(), DomainError>;

    /// Replaces the password hash of the account `leave` was given for with
    /// one its owner did not choose, set by someone acting on the account.
    /// The password is recorded as set by an admin, so the
    /// holder must change it at their next sign-in.
    ///
    /// The leave is what the account's own checks gave the person acting:
    /// they hold all the account holds, and it is not switched off. Without
    /// it, anyone who may edit users would set an admin's password and sign
    /// in as them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the hash cannot be written.
    async fn reset_password_hash(
        &self,
        tenant_id: &ScopedTenant,
        leave: &AdminPasswordReset<ResolvedTenant>,
        hash: &PasswordHash,
    ) -> Result<(), DomainError>;
}

/// Port telling whether a stored hash is in the platform's own format.
///
/// A hash an import brought over, or one made with weaker settings than
/// the platform uses now, still checks the person's password, but is
/// replaced the first time a sign-in proves it.
pub trait PasswordHashFormat: Send + Sync {
    /// Whether `hash` should be replaced by a fresh hash of the same
    /// password.
    fn needs_rehash(&self, hash: &PasswordHash) -> bool;
}

/// Port for a list of common passwords, such as the most used ones from
/// public breach corpora, which a new password may not be.
///
/// The adapter keeps the list in memory, bundled with the build, so a
/// check makes no call out and cannot hang. It compares ignoring case, as
/// [`CommonPassword::among`] does.
pub trait CommonPasswordList: Send + Sync {
    /// Whether `password` is on the list.
    fn verdict(&self, password: &Secret) -> CommonPassword;
}

/// Dyn-safe port for checking and recording password history.
///
/// Tenant-keyed for the same reason as [`CredentialStore`]: history that
/// lives in a different database from the credentials it guards would let a
/// user cycle straight back to a password it is supposed to refuse.
#[async_trait]
pub trait PasswordHistory: Send + Sync + TenantScoped {
    /// The hashes of the user's last `count` retired passwords, newest first.
    ///
    /// Hashes, not a yes-or-no answer: every hash is salted, so a new
    /// password never hashes to an old one. Reuse is found by verifying the
    /// new password against each of these.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the history cannot be read.
    async fn recent(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        count: u32,
    ) -> Result<Vec<PasswordHash>, DomainError>;

    /// Records a password hash in the user's history.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the hash cannot be written.
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &PasswordHash,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for persisting password reset requests.
#[async_trait]
pub trait ResetRequestStore: Send + Sync + TenantScoped {
    /// Finds a reset request by the hash of its token.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the request cannot be read.
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<PasswordResetRequest>, DomainError>;

    /// Saves a new or updated reset request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the request cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<(), DomainError>;

    /// Stores `request`, just completed, only while the stored request is
    /// still pending, and answers whether this call did.
    ///
    /// `false` means the link was used, superseded or expired meanwhile: of
    /// two confirms of one reset arriving together, only one sets a
    /// password. Storage does it in one statement, such as an `UPDATE ..
    /// SET status = 'completed', completed_at = $3 WHERE tenant_id = $1 AND
    /// id = $2 AND status = 'pending'`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the request cannot be written.
    async fn complete(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<bool, DomainError>;

    /// Expires every pending reset request this user holds.
    ///
    /// Issuing a replacement supersedes the old link rather than leaving both
    /// live. Asking again, which is what "resend" is, invalidates whatever
    /// was mailed before.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the requests cannot be written.
    async fn expire_pending_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError>;

    /// The most recently created reset request for this user, whatever its
    /// status.
    ///
    /// A resend cooldown has to be measured against the last mail that went
    /// out, not against the link the caller happens to be holding. That one
    /// is superseded and stops moving, so timing off it would let a caller
    /// press the button as often as they liked.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the request cannot be read.
    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordResetRequest>, DomainError>;

    /// Every reset request kept for this user, whatever its status, newest
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the requests cannot be read.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasswordResetRequest>, DomainError>;
}

/// Whether a person holds a second factor, without opening the secrets
/// behind it, so the gateway, which may not read those secrets, can still
/// tell.
///
/// The gateway freezes a stolen session only when someone can lift it; a
/// person with no factor gets their session ended instead.
#[async_trait]
pub trait FactorStanding: Send + Sync + TenantScoped {
    /// Whether `user_id` has a confirmed second factor.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if it cannot be read.
    async fn holds_active_factor(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for persisting and retrieving MFA enrollments.
#[async_trait]
pub trait MfaEnrollmentStore: Send + Sync + TenantScoped {
    /// Finds the MFA enrollment for a user.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the enrollment cannot be read.
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError>;

    /// Finds the MFA enrollment for a user and holds it until the unit of
    /// work the caller runs in ends, for a caller that will count an answer
    /// on it and save it.
    ///
    /// The lock rules are the domain's (how many wrong answers within which
    /// window), so storage does not count in SQL: it locks the row, and a
    /// second answer to the same factor waits until this one is saved, then
    /// reads its count. Two wrong codes sent at once both count. Storage
    /// does it in one statement, such as `SELECT .. FROM mfa_enrollments
    /// WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the enrollment cannot be read.
    async fn hold_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated MFA enrollment.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the enrollment cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        enrollment: &MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Records `step` as the user's latest accepted code, in one atomic
    /// update, and answers whether it was later than every step accepted
    /// before. `false` means the code was already used, or one after it was:
    /// two requests racing with one code get one `true` between them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the step cannot be recorded.
    async fn claim_step(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        step: TimeStep,
    ) -> Result<bool, DomainError>;
}

/// A single recovery code: the code itself and its one-way hash. Holds a
/// secret, so it has no `Debug`.
pub struct RecoveryCodePair {
    /// The code, shown to the user once.
    pub raw: Secret,
    /// The one-way hash stored in the database.
    pub hash: TokenHash,
}

/// Dyn-safe port for generating recovery codes.
///
/// A recovery code stands in for a second factor, so its stored hash must
/// not give the code away to whoever reads the database. The hash is keyed:
/// an HMAC under a key the server holds and the database does not, so a
/// copied table cannot be searched for codes offline. It is also the same
/// for the same code every time, since a typed code is found by its hash.
/// A salted password hash would never match again, and a bare digest of a
/// short code is quick to reverse.
#[async_trait]
pub trait RecoveryCodeGenerator: Send + Sync {
    /// Generates a batch of `count` recovery codes, typically 10.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the codes cannot be generated.
    async fn generate_batch(&self, count: u8) -> Result<Vec<RecoveryCodePair>, DomainError>;

    /// Hashes a recovery code someone typed, for lookup, under the same key
    /// [`generate_batch`](Self::generate_batch) hashed it with.
    fn hash_raw(&self, raw: &Secret) -> TokenHash;
}

/// Dyn-safe port for persisting and retrieving recovery code sets.
#[async_trait]
pub trait RecoveryCodeStore: Send + Sync + TenantScoped {
    /// Finds the recovery code set for a user.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the set cannot be read.
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated recovery code set.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the set cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Stores the code with `hash` in `codes`, just spent, as used, only if
    /// the stored code is still unused. Returns whether this call spent it:
    /// of two sign-ins offering one code at once, only one gets through.
    /// Storage does it in one statement, such as `UPDATE recovery_codes SET
    /// used_at = $4 WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3
    /// AND used_at IS NULL`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the code cannot be written.
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for encrypting and decrypting secrets.
///
/// Every value is sealed for one place, which the adapter binds into it
/// (as AES-GCM's associated data, say), so it opens only when asked for
/// that same place. A value copied into another row, field or tenant does
/// not open there.
#[async_trait]
pub trait SecretEncryptor: Send + Sync {
    /// Encrypts raw bytes for storage at `place`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the bytes cannot be encrypted.
    async fn encrypt(
        &self,
        plaintext: &[u8],
        place: &SealedFor,
    ) -> Result<SealedSecret, DomainError>;

    /// Decrypts a sealed secret kept at `place` back to raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure`, a corrupt row, if the secret
    /// was sealed for another place or was changed, and [`DomainError`] if
    /// it cannot be decrypted otherwise.
    async fn decrypt(
        &self,
        ciphertext: &SealedSecret,
        place: &SealedFor,
    ) -> Result<Vec<u8>, DomainError>;
}
