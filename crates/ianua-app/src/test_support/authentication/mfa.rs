//! Fakes for second factors: enrollments, recovery codes, the codes'
//! generator and the encryptor that seals factor secrets.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, EnrollmentState, LockoutPolicy, MfaEnrollment, MfaEnrollmentRow, RecentFailures,
};
use ianua_domain::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
use ianua_domain::domains::authentication::mfa::time_step::TimeStep;
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::domains::authentication::recovery::codes::{
    RecoveryCode, RecoveryCodeRow, RecoveryCodeSet, RecoveryCodeSetRow,
};
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::isolation::SecurityScope;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::fakes::FakeMfaVerifier;
use ianua_domain::types::{
    CredentialChange, Fact, OrgUserId, PrincipalId, SealedSecret, SessionId, TokenHash, Usage,
    UserId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::authentication::{
    FactorStanding, MfaEnrollmentStore, RecoveryCodeGenerator, RecoveryCodePair, RecoveryCodeStore,
    SealOwner, SealedFor, SecretEncryptor,
};
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::{Holder, Plane};
use crate::test_support::{Fake, ReadBeforeWrite};

/// The second-factor lockout tests run under: five wrong codes within
/// fifteen minutes.
///
/// # Panics
///
/// Never in practice: the policy's values are fixed and valid.
#[must_use]
pub fn lockout() -> LockoutPolicy {
    LockoutPolicy::new(5, time::Duration::minutes(15)).expect("a fixed lockout policy is valid")
}

/// The authenticator seed a fake verifier generates.
pub const ENROLLED_SEED: [u8; 3] = [1, 2, 3];

/// Reversible encryptor for tests: seals as `enc_1,2,3@<place>`, the
/// comma-separated byte values and then the place it was sealed for, so the
/// plaintext never appears in what it stores.
///
/// Like the real sealer it opens a value only for the place it was sealed
/// for, and refuses any other as a corrupt row, so a use case that seals
/// for one place and opens for another fails its tests.
pub struct FakeEncryptor;

impl FakeEncryptor {
    /// What this encryptor stores for `plaintext` sealed for `place`.
    ///
    /// # Panics
    ///
    /// Never in practice: the sealed form is always a valid token, as no
    /// place holds whitespace.
    #[must_use]
    pub fn sealed_for(plaintext: impl AsRef<[u8]>, place: &SealedFor) -> SealedSecret {
        let encoded: Vec<String> = plaintext.as_ref().iter().map(ToString::to_string).collect();
        SealedSecret::new(format!("enc_{}@{}", encoded.join(","), tag_of(place)))
            .expect("a sealed form is a token")
    }
}

/// How `place` is written after a sealed value.
fn tag_of(place: &SealedFor) -> String {
    let owner = match place.owner() {
        SealOwner::Platform => "platform".to_owned(),
        SealOwner::Organization(organization) => format!("organization:{organization}"),
        SealOwner::Tenant(tenant) => format!("tenant:{tenant}"),
    };
    format!("{owner}/{}/{}", place.field().label(), place.record())
}

/// The refusal of a value the fake did not seal: a stored value that does
/// not open is a damaged row, as the AES sealer answers it.
fn not_sealed_here() -> DomainError {
    DomainError::corrupt_row("sealed value", "not sealed by this encryptor")
}

#[async_trait]
impl SecretEncryptor for FakeEncryptor {
    async fn encrypt(
        &self,
        plaintext: &[u8],
        place: &SealedFor,
    ) -> Result<SealedSecret, DomainError> {
        Ok(Self::sealed_for(plaintext, place))
    }

    async fn decrypt(
        &self,
        ciphertext: &SealedSecret,
        place: &SealedFor,
    ) -> Result<Vec<u8>, DomainError> {
        let Some(sealed) = ciphertext.as_str().strip_prefix("enc_") else {
            return Err(not_sealed_here());
        };
        let Some((csv, tag)) = sealed.split_once('@') else {
            return Err(not_sealed_here());
        };
        if tag != tag_of(place) {
            return Err(DomainError::corrupt_row(
                "sealed value",
                "a value changed, or sealed for another place",
            ));
        }
        csv.split(',')
            .filter(|byte| !byte.is_empty())
            .map(|byte| byte.parse::<u8>().map_err(|_| not_sealed_here()))
            .collect()
    }
}

/// Where the seed of `holder`'s authenticator is sealed: in the tenant the
/// holder is kept in, or in the organization a member belongs to.
#[must_use]
pub fn seed_place(holder: impl Into<Holder>) -> SealedFor {
    let holder = holder.into();
    holder.seeds().place(holder.subject())
}

/// What [`FakeEncryptor`] stores for [`ENROLLED_SEED`], sealed for
/// `holder`'s authenticator.
#[must_use]
pub fn enrolled_secret(holder: impl Into<Holder>) -> SealedSecret {
    FakeEncryptor::sealed_for(ENROLLED_SEED, &seed_place(holder))
}

/// Recovery code generator handing out `code_0`, `code_1` and so on, hashed
/// as `hash_0`, `hash_1`; any other code hashes to `hash_` followed by it.
pub struct FakeRecoveryGenerator;

#[async_trait]
impl RecoveryCodeGenerator for FakeRecoveryGenerator {
    async fn generate_batch(&self, count: u8) -> Result<Vec<RecoveryCodePair>, DomainError> {
        Ok((0..count)
            .map(|i| RecoveryCodePair {
                raw: Secret::new(format!("code_{i}")),
                hash: TokenHash::from_stored(format!("hash_{i}")),
            })
            .collect())
    }

    fn hash_raw(&self, raw: &Secret) -> TokenHash {
        let code = raw.expose();
        TokenHash::from_stored(format!(
            "hash_{}",
            code.strip_prefix("code_").unwrap_or(code)
        ))
    }
}

/// In-memory recovery code store, keeping each user's set in their tenant
/// as it was last saved, so used codes stay used.
#[derive(Default)]
pub struct FakeRecoveryCodeStore {
    sets: Mutex<Vec<(Plane, RecoveryCodeSet<ResolvedTenant>)>>,
}

impl FakeRecoveryCodeStore {
    /// Nobody has recovery codes.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// `user_id` holds, in the test tenant, a fresh set of unused codes with
    /// these hashes.
    ///
    /// # Panics
    ///
    /// Panics if `hashes` is empty or names a hash twice, which no set may.
    #[must_use]
    pub fn with_codes(user_id: UserId, hashes: &[&str]) -> Self {
        let codes = hashes
            .iter()
            .map(|hash| {
                RecoveryCode::reconstitute(RecoveryCodeRow {
                    hash: TokenHash::from_stored((*hash).to_owned()),
                    usage: Usage::Unused,
                })
                .expect("an unused code rebuilds")
            })
            .collect();
        let set = RecoveryCodeSet::reconstitute(RecoveryCodeSetRow {
            subject_id: user_id.into(),
            codes,
            generated_at: clock::now(),
        })
        .expect("a test passes distinct hashes");
        Self {
            sets: Mutex::new(vec![(Plane::test_tenant(), set)]),
        }
    }

    /// How many unused codes the first set held has left, if there is one.
    #[must_use]
    pub fn remaining(&self) -> Option<usize> {
        self.sets
            .lock()
            .unwrap()
            .first()
            .map(|(_, set)| set.remaining())
    }
}

/// A copy of `set`, which does not implement `Clone`.
fn copy_recovery_codes(set: &RecoveryCodeSet<ResolvedTenant>) -> RecoveryCodeSet<ResolvedTenant> {
    RecoveryCodeSet::reconstitute(RecoveryCodeSetRow {
        subject_id: set.subject_id(),
        codes: set.codes().to_vec(),
        generated_at: set.generated_at(),
    })
    .expect("a live set's own row rebuilds")
}

impl TenantScoped for FakeRecoveryCodeStore {}

#[async_trait]
impl RecoveryCodeStore for FakeRecoveryCodeStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedTenant>>, DomainError> {
        let plane = Plane::of(tenant_id);
        let owner = PrincipalId::from(*user_id);
        Ok(self
            .sets
            .lock()
            .unwrap()
            .iter()
            .find(|(held_on, set)| *held_on == plane && set.subject_id() == owner)
            .map(|(_, set)| copy_recovery_codes(set)))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let plane = Plane::of(tenant_id);
        let mut sets = self.sets.lock().unwrap();
        sets.retain(|(held_on, set)| {
            !(*held_on == plane && set.subject_id() == codes.subject_id())
        });
        sets.push((plane, copy_recovery_codes(codes)));
        Ok(())
    }

    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        let plane = Plane::of(tenant_id);
        let Some(spent) = codes.codes().iter().find(|code| code.hash() == hash) else {
            return Ok(false);
        };
        let mut sets = self.sets.lock().unwrap();
        let Some((_, stored)) = sets
            .iter_mut()
            .find(|(held_on, set)| *held_on == plane && set.subject_id() == codes.subject_id())
        else {
            return Ok(false);
        };
        if !stored
            .codes()
            .iter()
            .any(|code| code.hash() == hash && !code.is_used())
        {
            return Ok(false);
        }
        *stored = with_code(stored, spent)?;
        Ok(true)
    }
}

/// `set` with its code of the same hash as `spent` replaced by `spent`.
fn with_code(
    set: &RecoveryCodeSet<ResolvedTenant>,
    spent: &RecoveryCode,
) -> Result<RecoveryCodeSet<ResolvedTenant>, DomainError> {
    let codes = set
        .codes()
        .iter()
        .map(|code| {
            let kept = if code.hash() == spent.hash() {
                spent
            } else {
                code
            };
            kept.clone()
        })
        .collect();
    RecoveryCodeSet::reconstitute(RecoveryCodeSetRow {
        subject_id: set.subject_id(),
        codes,
        generated_at: set.generated_at(),
    })
}

/// Reading the codes is a plain read, from the copy both sign-ins started
/// from. Spending and saving reach the store as it is now.
#[async_trait]
impl RecoveryCodeStore for ReadBeforeWrite<FakeRecoveryCodeStore> {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedTenant>>, DomainError> {
        self.seen.find_by_user(tenant_id, user_id).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.live.save(tenant_id, codes).await
    }

    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        codes: &RecoveryCodeSet<ResolvedTenant>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        self.live.spend(tenant_id, codes, hash).await
    }
}

/// In-memory MFA enrollment store for tenant users and organization members
/// alike: at most one enrollment per person on each plane, kept as it was
/// last saved, so failed attempts and confirmations persist between calls
/// the way the real store's do.
///
/// It keeps each enrollment as its row and reads it back into its plane's
/// own type, a tenant user's as `MfaEnrollment<ResolvedTenant>` and a
/// member's as `MfaEnrollment<ResolvedOrganization>`, the way the real
/// stores reconstitute on every read.
#[derive(Default)]
pub struct FakeMfaEnrollmentStore {
    enrollments: Mutex<Vec<(Plane, KeptEnrollment)>>,
    claimed_steps: Mutex<HashMap<(Plane, PrincipalId), TimeStep>>,
}

/// Whose enrollment a test reads back, and the plane's type it comes back
/// in.
pub trait EnrollmentHolder: Into<Holder> {
    /// The scope of the plane the enrollment is kept on.
    type Scope: SecurityScope;
}

impl EnrollmentHolder for UserId {
    type Scope = ResolvedTenant;
}

impl EnrollmentHolder for OrgUserId {
    type Scope = ResolvedOrganization;
}

/// An enrollment as the fake keeps it: the row storage would hold.
#[derive(Clone)]
struct KeptEnrollment {
    subject_id: PrincipalId,
    factor: EnrolledFactor,
    state: EnrollmentState,
    failures: RecentFailures,
    enrolled_at: OffsetDateTime,
}

impl KeptEnrollment {
    fn of<S: SecurityScope>(enrollment: &MfaEnrollment<S>) -> Self {
        Self {
            subject_id: enrollment.subject_id(),
            factor: enrollment.factor().clone(),
            state: enrollment.state().clone(),
            failures: enrollment.failures(),
            enrolled_at: enrollment.enrolled_at(),
        }
    }

    fn rebuilt<S: SecurityScope>(&self) -> MfaEnrollment<S> {
        MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: self.subject_id,
            factor: self.factor.clone(),
            state: self.state.clone(),
            failures: self.failures,
            enrolled_at: self.enrolled_at,
        })
        .expect("a kept enrollment row rebuilds")
    }
}

impl FakeMfaEnrollmentStore {
    /// Nobody has a second factor.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// `holder` has an active authenticator over [`ENROLLED_SEED`], sealed
    /// for their authenticator.
    #[must_use]
    pub fn active_for(holder: impl Into<Holder>) -> Self {
        let store = Self::default();
        store.enroll(holder);
        store
    }

    /// Each of `holders` has an active authenticator over
    /// [`ENROLLED_SEED`].
    #[must_use]
    pub fn active_for_all<H: Into<Holder>>(holders: impl IntoIterator<Item = H>) -> Self {
        let store = Self::default();
        for holder in holders {
            store.enroll(holder);
        }
        store
    }

    /// `holder` has begun enrolling over [`ENROLLED_SEED`] and not yet
    /// confirmed.
    #[must_use]
    pub fn pending_for(holder: impl Into<Holder>) -> Self {
        let holder = holder.into();
        Self::pending_with_factor(holder, app_over(enrolled_secret(holder)))
    }

    /// `holder` has begun setting up `factor` and not yet confirmed it.
    #[must_use]
    pub fn pending_with_factor(holder: impl Into<Holder>, factor: EnrolledFactor) -> Self {
        let holder = holder.into();
        let store = Self::default();
        store.put_on(
            holder.plane(),
            stored_enrollment(
                holder.subject(),
                factor,
                EnrollmentState::Pending,
                clock::now(),
            ),
        );
        store
    }

    /// `holder` has `factor` confirmed and in force.
    #[must_use]
    pub fn active_with_factor(holder: impl Into<Holder>, factor: EnrolledFactor) -> Self {
        let store = Self::default();
        store.enroll_factor(holder, factor);
        store
    }

    /// Gives `holder` an active authenticator over [`ENROLLED_SEED`],
    /// sealed for their authenticator.
    pub fn enroll(&self, holder: impl Into<Holder>) {
        let holder = holder.into();
        self.enroll_factor(holder, app_over(enrolled_secret(holder)));
    }

    /// Gives `holder` `factor`, confirmed and in force.
    ///
    /// # Panics
    ///
    /// Never in practice: the confirmation's values are fixed and valid.
    pub fn enroll_factor(&self, holder: impl Into<Holder>, factor: EnrolledFactor) {
        let holder = holder.into();
        let now = clock::now();
        let confirmed = EnrollmentState::from_stored(
            MfaEnrollmentStatus::Verified,
            Some(now),
            Some(TokenHash::from_stored("recovery_hash".to_owned())),
            None,
        )
        .expect("a confirmation with its codes is a verified state");
        self.put_on(
            holder.plane(),
            stored_enrollment(holder.subject(), factor, confirmed, now),
        );
    }

    /// The enrollment held for `holder`, as last saved, in their plane's
    /// type.
    #[must_use]
    pub fn enrollment_of<H: EnrollmentHolder>(&self, holder: H) -> Option<MfaEnrollment<H::Scope>> {
        let holder = holder.into();
        self.find(holder.plane(), holder.subject())
    }

    fn put_on(&self, plane: Plane, enrollment: KeptEnrollment) {
        let mut enrollments = self.enrollments.lock().unwrap();
        enrollments.retain(|(held_on, held)| {
            !(*held_on == plane && held.subject_id == enrollment.subject_id)
        });
        enrollments.push((plane, enrollment));
    }

    /// How many failed attempts are on record for the first enrollment held.
    #[must_use]
    pub fn failed_attempts(&self) -> u32 {
        self.enrollments
            .lock()
            .unwrap()
            .first()
            .map_or(0, |(_, enrollment)| enrollment.failures.count())
    }

    fn find<S: SecurityScope>(
        &self,
        plane: Plane,
        subject: PrincipalId,
    ) -> Option<MfaEnrollment<S>> {
        self.enrollments
            .lock()
            .unwrap()
            .iter()
            .find(|(held_on, held)| *held_on == plane && held.subject_id == subject)
            .map(|(_, held)| held.rebuilt())
    }

    fn claim(&self, plane: Plane, subject: PrincipalId, step: TimeStep) -> bool {
        let mut claimed = self.claimed_steps.lock().unwrap();
        let key = (plane, subject);
        if claimed.get(&key).is_some_and(|last| *last >= step) {
            return false;
        }
        claimed.insert(key, step);
        true
    }
}

/// An authenticator app over the sealed seed `encrypted_secret`.
#[must_use]
pub fn app_over(encrypted_secret: SealedSecret) -> EnrolledFactor {
    EnrolledFactor::Totp(encrypted_secret)
}

/// An enrollment of `factor` begun at `enrolled_at`, in `state`, as storage
/// would hold it.
fn stored_enrollment(
    subject: PrincipalId,
    factor: EnrolledFactor,
    state: EnrollmentState,
    enrolled_at: OffsetDateTime,
) -> KeptEnrollment {
    KeptEnrollment {
        subject_id: subject,
        factor,
        state,
        failures: RecentFailures::Clear,
        enrolled_at,
    }
}

/// A fresh dashboard session of `user_id` in the test tenant, signed in as
/// `progress` says: how, with which factor, and what it still owes.
///
/// # Panics
///
/// Panics if `progress` is one no sign-in reaches, such as a step still
/// owed after the factor that settles it.
#[must_use]
pub fn session_signed_in(user_id: UserId, progress: SignInProgressRow) -> Session<ResolvedTenant> {
    let now = clock::now();
    Session::reconstitute(SessionRow {
        id: SessionId::new(),
        user_id,
        refresh_token_hash: TokenHash::from_stored(format!("refresh_{user_id}")),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress,
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: now,
        created_at: now,
        last_active_at: now,
        expires_at: now + time::Duration::hours(8),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    })
    .expect("a test passes a progress some sign-in reaches")
}

impl TenantScoped for FakeMfaEnrollmentStore {}

#[async_trait]
impl MfaEnrollmentStore for FakeMfaEnrollmentStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError> {
        Ok(self.find(Plane::of(tenant_id), (*user_id).into()))
    }

    async fn hold_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError> {
        Ok(self.find(Plane::of(tenant_id), (*user_id).into()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        enrollment: &MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.put_on(Plane::of(tenant_id), KeptEnrollment::of(enrollment));
        Ok(())
    }

    async fn claim_step(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        step: TimeStep,
    ) -> Result<bool, DomainError> {
        Ok(self.claim(Plane::of(tenant_id), (*user_id).into(), step))
    }
}

/// Finding the enrollment is a plain read, from the copy both answers
/// started from. Holding it is a locking read, which waits for the answer
/// in flight to be saved and so reads the store as it is now, as saving and
/// claiming a step do.
#[async_trait]
impl MfaEnrollmentStore for ReadBeforeWrite<FakeMfaEnrollmentStore> {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError> {
        MfaEnrollmentStore::find_by_user(&self.seen, tenant_id, user_id).await
    }

    async fn hold_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, DomainError> {
        MfaEnrollmentStore::hold_by_user(self.live.as_ref(), tenant_id, user_id).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        enrollment: &MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        MfaEnrollmentStore::save(self.live.as_ref(), tenant_id, enrollment).await
    }

    async fn claim_step(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        step: TimeStep,
    ) -> Result<bool, DomainError> {
        MfaEnrollmentStore::claim_step(self.live.as_ref(), tenant_id, user_id, step).await
    }
}

#[async_trait]
impl OrgMfaEnrollmentStore for FakeMfaEnrollmentStore {
    async fn find_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, DomainError> {
        Ok(self.find(Plane::Organization, (*org_user_id).into()))
    }

    async fn hold_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MfaEnrollment<ResolvedOrganization>>, DomainError> {
        Ok(self.find(Plane::Organization, (*org_user_id).into()))
    }

    async fn save(
        &self,
        org_user_id: &OrgUserId,
        enrollment: &MfaEnrollment<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        if enrollment.subject_id() != PrincipalId::from(*org_user_id) {
            return Err(DomainError::invalid(
                "a second factor is saved for the member it belongs to",
            ));
        }
        self.put_on(Plane::Organization, KeptEnrollment::of(enrollment));
        Ok(())
    }

    async fn claim_step(
        &self,
        org_user_id: &OrgUserId,
        step: TimeStep,
    ) -> Result<bool, DomainError> {
        let subject = PrincipalId::from(*org_user_id);
        let enrolled = self
            .find::<ResolvedOrganization>(Plane::Organization, subject)
            .is_some();
        Ok(enrolled && self.claim(Plane::Organization, subject, step))
    }
}

impl Fake for Arc<dyn SecretEncryptor> {
    fn fake() -> Self {
        Arc::new(FakeEncryptor)
    }
}

impl Fake for Arc<dyn RecoveryCodeGenerator> {
    fn fake() -> Self {
        Arc::new(FakeRecoveryGenerator)
    }
}

impl Fake for Arc<dyn RecoveryCodeStore> {
    fn fake() -> Self {
        Arc::new(FakeRecoveryCodeStore::empty())
    }
}

impl Fake for Arc<dyn MfaEnrollmentStore> {
    fn fake() -> Self {
        Arc::new(FakeMfaEnrollmentStore::empty())
    }
}

/// Answers for one fixed account whether it holds a factor, or says it
/// cannot tell.
#[derive(Default)]
pub struct FakeFactorStanding {
    holders: Mutex<Vec<UserId>>,
    /// Whether the answer fails.
    pub fails: Mutex<bool>,
}

impl FakeFactorStanding {
    /// Answers `true` for `holder` and `false` for everyone else.
    #[must_use]
    pub fn holding(holder: UserId) -> Self {
        Self {
            holders: Mutex::new(vec![holder]),
            ..Self::default()
        }
    }
}

impl TenantScoped for FakeFactorStanding {}

#[async_trait]
impl FactorStanding for FakeFactorStanding {
    async fn holds_active_factor(
        &self,
        _: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<bool, DomainError> {
        if *self.fails.lock().unwrap() {
            return Err(DomainError::infra_msg("factor standing unreadable"));
        }
        Ok(self.holders.lock().unwrap().contains(user_id))
    }
}

impl Fake for Arc<dyn FactorStanding> {
    fn fake() -> Self {
        Arc::new(FakeFactorStanding::default())
    }
}

impl Fake for Arc<dyn OrgMfaEnrollmentStore> {
    fn fake() -> Self {
        Arc::new(FakeMfaEnrollmentStore::empty())
    }
}

impl Fake for Arc<dyn MfaVerifier> {
    fn fake() -> Self {
        Arc::new(FakeMfaVerifier {
            valid_code: "123456".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;
    use crate::ports::authentication::SealedField;
    use crate::services::authentication::sign_in_steps::SeedHolder;
    use crate::test_support::block_on;

    fn anns_seed(tenant: TenantId) -> SealedFor {
        SeedHolder::TenantUser(tenant)
            .place(PrincipalId::from(UserId::from_uuid(uuid::Uuid::nil())))
    }

    /// A secret the fake sealed opens again, for the place it was sealed
    /// for, to what was sealed.
    #[test]
    fn a_sealed_value_opens_for_its_own_place() {
        let place = anns_seed(TenantId::new());

        let sealed = block_on(FakeEncryptor.encrypt(b"seed", &place)).unwrap();
        let opened = block_on(FakeEncryptor.decrypt(&sealed, &place)).unwrap();

        assert_eq!(opened, b"seed");
        assert_eq!(sealed, FakeEncryptor::sealed_for(b"seed", &place));
    }

    /// The fake encryptor rejects a secret opened under a different tenant,
    /// field, record or owner as an infrastructure error.
    #[test]
    fn a_value_opened_for_another_place_is_refused() {
        let acme = TenantId::new();
        let sealed = FakeEncryptor::sealed_for(b"seed", &anns_seed(acme));
        let elsewhere = [
            anns_seed(TenantId::new()),
            SealedFor::new(
                SealOwner::Tenant(acme),
                SealedField::WebhookSigningSecret,
                uuid::Uuid::nil(),
            ),
            SealedFor::new(
                SealOwner::Tenant(acme),
                SealedField::TotpSeed,
                UserId::new(),
            ),
            SealedFor::new(
                SealOwner::Organization(OrganizationId::from_uuid(*acme.as_uuid())),
                SealedField::TotpSeed,
                uuid::Uuid::nil(),
            ),
        ];

        for place in elsewhere {
            let opened = block_on(FakeEncryptor.decrypt(&sealed, &place));
            assert!(
                matches!(opened, Err(DomainError::Infrastructure(_))),
                "{place:?} opened"
            );
        }
    }
}
