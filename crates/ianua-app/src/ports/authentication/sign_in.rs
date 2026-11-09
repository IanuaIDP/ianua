//! Signing in: finding the account, throttling attempts, the risk of the
//! place it comes from, sign-in codes, trusted devices, history and break
//! glass.

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::risk_engine::attack::AttackSigns;
use ianua_domain::domains::authentication::risk_engine::history::SignInHistory;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureCount;
use ianua_domain::domains::authentication::risk_engine::rate_limit::Lockout;
use ianua_domain::domains::authentication::sessions::sign_in_code::SignInCode;
use ianua_domain::domains::authorization::break_glass::{BreakGlassGrant, BreakGlassPolicy};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    BreakGlassGrantId, Email, IpAddress, Lifetime, OrganizationId, TokenHash, TrustedDeviceId,
    UserId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Port for checking passwords against known breach databases.
///
/// The adapter uses the `HaveIBeenPwned` range API with k-anonymity: it
/// hashes the password with SHA-1, sends only the first five hex
/// characters, and checks the returned suffixes locally. Neither the
/// password nor its full hash leaves the server.
///
/// It is asked at sign-in and whenever a password is set, so the adapter
/// gives up after a couple of seconds and answers with an error: a range
/// service that hangs must not hold a sign-in or a password change open.
/// A caller treats that error as the lookup being unavailable.
#[async_trait]
pub trait CredentialBreachChecker: Send + Sync {
    /// Checks whether a password appears in known breach databases.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the breach check service is unreachable
    /// or did not answer in time.
    async fn check(&self, raw_password: &Secret) -> Result<BreachStatus, DomainError>;
}

/// Port for resolving IP addresses to geographic locations, backed by a
/// geolocation database such as `MaxMind` `GeoIP2`.
#[async_trait]
pub trait Geolocator: Send + Sync {
    /// Resolves an IP address to a geographic location.
    ///
    /// Returns `None` if the IP cannot be geolocated.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the geolocation service fails.
    async fn locate(&self, ip: &IpAddress) -> Result<Option<IpGeolocation>, DomainError>;
}

/// Dyn-safe port for looking up a user by email during login.
#[async_trait]
pub trait UserLookup: Send + Sync + TenantScoped {
    /// Finds a user by email within the resolved tenant.
    ///
    /// The adapter fills the candidate's `password_due` as
    /// [`PasswordDue::Current`](ianua_domain::domains::authentication::credentials::password_rules::PasswordDue::Current):
    /// the sign-in works out whether the password must change from
    /// [`CredentialStore::current_password`](crate::ports::authentication::CredentialStore::current_password)
    /// and the tenant's expiry.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the user cannot be read.
    async fn find_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<LoginCandidate>, DomainError>;
}

/// The account a password's failures are counted against: the address it
/// signs in with, in one tenant or in one organization.
///
/// Keyed by the address rather than the account's id, so an address with no
/// account counts and locks out alike, and the lockout cannot be used to
/// tell which addresses have one.
#[derive(Debug, Clone, Copy)]
pub enum CountedAccount<'a> {
    /// An address signing in to a tenant.
    Tenant {
        /// The scope in which this address's failures are counted.
        tenant: &'a ScopedTenant,
        /// The address.
        email: &'a Email,
    },
    /// An address signing in to an organization. An organization member
    /// belongs to no single tenant, so their failures are counted by
    /// organization.
    Organization {
        /// The scope shared by this member's sign-in attempts.
        organization: &'a OrganizationId,
        /// The address.
        email: &'a Email,
    },
    /// An address signing in as a platform operator, counted across the
    /// platform, since operators belong to no organization or tenant.
    Operator {
        /// The address.
        email: &'a Email,
    },
}

/// Dyn-safe port counting failed passwords per account and origin, and per
/// account across every origin, and keeping each origin's lockout.
///
/// The rules are the domain's: how many failures from one origin lock it
/// out, for how long, how long a sign-in to an account waits, and when it
/// is under attack. The port only counts, in one step on state every node
/// shares, so two guesses at once both count. Every count, lockout and
/// attack mark lapses on its own: nothing kept here is a record. The adapter answers within a few hundred milliseconds,
/// or fails; a caller treats a failure as an internal error and lets no
/// sign-in through on it.
#[async_trait]
pub trait SignInAttemptCounts: Send + Sync {
    /// Whether `origin` is locked out of `account`, and until when.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the lockout cannot be read.
    async fn lockout(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<Lockout, DomainError>;

    /// The failures counted against `account` from every origin in the
    /// current window.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the count cannot be read.
    async fn account_failures(
        &self,
        account: CountedAccount<'_>,
    ) -> Result<FailureCount, DomainError>;

    /// The failures counted from `origin` against `account` in the current
    /// window: none once a right password or a lockout started its count
    /// again.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the count cannot be read.
    async fn origin_failures(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<u32, DomainError>;

    /// How many distinct origins failed on `account` in the current window,
    /// and whether the account is marked under attack.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when either cannot be read.
    async fn attack_signs(&self, account: CountedAccount<'_>) -> Result<AttackSigns, DomainError>;

    /// Claims the recording of the attack on `account` for `claim`, and
    /// answers whether this call made the claim or found one already there,
    /// in one step, so of two sign-ins finding the attack at once one
    /// records it. The claim marks nothing: [`mark_attack`](Self::mark_attack)
    /// does once the attack is recorded, and a claim whose record was never
    /// written lapses, so a later sign-in records the attack.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the claim cannot be made.
    async fn claim_attack(
        &self,
        account: CountedAccount<'_>,
        claim: Lifetime,
    ) -> Result<AttackClaim, DomainError>;

    /// Marks `account` under attack until `lasting` has passed, once the
    /// attack is recorded.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the mark cannot be kept.
    async fn mark_attack(
        &self,
        account: CountedAccount<'_>,
        lasting: Lifetime,
    ) -> Result<(), DomainError>;

    /// Counts one failure from `origin` against `account`, and against the
    /// account from every origin, notes `origin` among the origins that
    /// failed on the account, and answers the origin's count with it, this
    /// failure included. A count, and the note of failing origins, starts
    /// at its first failure and lapses `window` later.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the failure cannot be counted.
    async fn count_failure(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
        window: Lifetime,
    ) -> Result<u32, DomainError>;

    /// Locks `origin` out of `account` until `until`, and starts its count
    /// of failures again, so the next failure after the lockout is the
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the lockout cannot be kept.
    async fn lock(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
        until: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Starts `origin`'s count of failures against `account` again, after a
    /// right password. The account's count across every origin is left to
    /// lapse.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the count cannot be cleared.
    async fn clear(
        &self,
        account: CountedAccount<'_>,
        origin: &AttemptOrigin,
    ) -> Result<(), DomainError>;
}

/// Whether claiming the recording of an account's attack made the claim,
/// or found one already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackClaim {
    /// This call made it: whoever asked records the attack, then marks the
    /// account.
    ClaimedNow,
    /// Another sign-in made it first and records it.
    ClaimedBefore,
}

/// Dyn-safe port for persisting and retrieving break-glass grants.
#[async_trait]
pub trait BreakGlassStore: Send + Sync + TenantScoped {
    /// Finds a grant by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the grant cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &BreakGlassGrantId,
    ) -> Result<Option<BreakGlassGrant>, DomainError>;

    /// Every grant of the tenant, active or not. What someone holds through
    /// one is worked out from all of them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the grants cannot be read.
    async fn list(&self, tenant_id: &ScopedTenant) -> Result<Vec<BreakGlassGrant>, DomainError>;

    /// Saves a new or updated grant. A revoked grant is final: a save over
    /// it changes nothing and is refused, so a copy read before the
    /// revocation never makes it live again.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Conflict`] when the stored grant was revoked
    /// already or is another user's, or another [`DomainError`] if the
    /// grant cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        grant: &BreakGlassGrant,
    ) -> Result<(), DomainError>;

    /// The tenant's break-glass policy, or `None` when it never set one,
    /// which reads as self-service switched off.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the policy cannot be read.
    async fn find_policy(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<BreakGlassPolicy>, DomainError>;

    /// Saves the tenant's break-glass policy.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the policy cannot be written.
    async fn save_policy(
        &self,
        tenant_id: &ScopedTenant,
        policy: &BreakGlassPolicy,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for where each person has signed in from before.
///
/// Kept per country: the place and time of the latest sign-in from each.
#[async_trait]
pub trait SignInHistoryStore: Send + Sync + TenantScoped {
    /// The countries `user_id` has signed in from, and their latest sign-in.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the history cannot be read.
    async fn history(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<SignInHistory, DomainError>;

    /// Records a sign-in by `user_id` from `place` at `at`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the sign-in cannot be written.
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        place: &IpGeolocation,
        at: time::OffsetDateTime,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for the one-time codes that carry a single sign-on back to
/// the dashboard.
#[async_trait]
pub trait SignInCodeStore: Send + Sync + TenantScoped {
    /// Saves a new code.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the code cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &SignInCode<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes and returns the code hashing to `token_hash`, so a code is
    /// used once however many times it is sent.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the code cannot be taken.
    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SignInCode<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for persisting and retrieving trusted devices.
#[async_trait]
pub trait TrustedDeviceStore: Send + Sync + TenantScoped {
    /// Lists all trusted devices for a user.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the devices cannot be read.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<TrustedDevice<ResolvedTenant>>, DomainError>;

    /// Finds a device by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the device cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TrustedDeviceId,
    ) -> Result<Option<TrustedDevice<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated trusted device.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the device cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        device: &TrustedDevice<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a trusted device by its id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the device cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &TrustedDeviceId,
    ) -> Result<(), DomainError>;
}
