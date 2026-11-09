//! Proving who you are again before a change an open session must not make
//! alone: a new address, a new way to sign in, the tenant's sign-in
//! settings.
//!
//! Whoever steals a session holds it until it ends. Such a change would let
//! them keep the account after that, so the person proves who they are
//! again, the way they sign in, and the domain's [`FreshSignIn`] comes only
//! from that. A request never carries a ready proof. Wrong passwords count
//! towards the account's lockout and wrong codes towards its factor's, as
//! at sign-in, so the step cannot be used to guess either.
//!
//! A tenant user proves themselves in their tenant, a member of an
//! organization on the organization plane.

pub(crate) mod admin;
mod mailbox;
mod member;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{
    FreshSignIn, PasswordCheck, WithFactor,
};
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PasswordHash, PrincipalId};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::context::{CallerContext, DirectoryBound};
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    CountedAccount, CredentialStore, MfaEnrollmentStore, PasskeyCeremonyStore, PasskeyStore,
    PasskeyVerifier, SecretEncryptor, SentCodeGenerator, SentCodeStore,
};
use crate::ports::directory::LdapCertificateStore;
use crate::ports::identity::SignInLinkStore;
use crate::ports::organization::{
    OrgMfaEnrollmentStore, OrgPasskeyCeremonyStore, OrgPasskeyStore, OrgUserStore,
};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::account_factor::{
    AccountFactor, FactorAnswer, FactorChecks, FactorCode, SentCodes,
};
use crate::services::authentication::fresh_proof::member::{
    MemberPassword, member_bind_refused, member_mailbox_refused,
};
use crate::services::authentication::passkey_answer::{PasskeyAnswering, PresentedAssertion};
use crate::services::authentication::password_hashing::{PasswordHashing, PermittedHasher};
use crate::services::authentication::sign_in_counts::{CountedAt, SignInCounts};
use crate::services::authentication::sign_in_steps::{CodeCheck, SentCodeCheck};
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// What a person gives to prove who they are again, the way they sign in.
/// It holds secrets, so it has no `Debug`.
pub enum ReenteredProof {
    /// Their password typed again, with a code from their second factor
    /// when they have one.
    Password {
        /// The password as typed.
        password: Secret,
        /// The code their authenticator shows, if they gave one.
        code: Option<String>,
    },
    /// A sign-in link mailed to them and followed just now, for an account
    /// whose mailbox is how it signs in, with a code from their second
    /// factor when they have one.
    Mailbox {
        /// The link's token, as followed.
        link: Secret,
        /// The code their authenticator shows, if they gave one.
        code: Option<String>,
    },
    /// Their passkey's answer to a sign-in challenge opened for them.
    Passkey(PresentedAssertion),
    /// Their password typed again over the directory connection they bound,
    /// whose client certificate stands in for their second factor while
    /// the bind is fresh. Only a directory bind makes `bound`.
    OverDirectoryBind {
        /// The password as typed.
        password: Secret,
        /// The bind the connection came with.
        bound: DirectoryBound,
    },
}

/// Turns what a person gave again into the domain's fresh proof of them.
#[async_trait]
pub trait FreshProofs: Send + Sync {
    /// The fresh proof that `proof`, sent from `from`, gives of `account`'s
    /// holder, in `tenant`. A password typed again counts against the
    /// lockout of `from` on the account, as at sign-in.
    ///
    /// # Errors
    ///
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Forbidden` for wrong, spent or foreign proof, password lockout, or an unsupported sign-in method.
    /// - `AppError::NotFound` for an unknown passkey or challenge; `Domain` for an expired or spent challenge.
    /// - `AppError::Busy` when a password check cannot start in time; `Internal` on storage failure.
    async fn prove(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        proof: ReenteredProof,
        from: AttemptOrigin,
    ) -> Result<FreshSignIn, AppError>;

    /// The fresh proof that `proof`, sent from `from`, gives of `member`, a
    /// member of `organization`.
    ///
    /// A member proves who they are with their password and a code from
    /// their second factor when they have one, or with their passkey. They
    /// sign in to the organization with no mailed link, so a link proves
    /// nothing of them.
    ///
    /// # Errors
    ///
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Forbidden` for wrong, spent or foreign proof, password lockout, no password, or mailed proof.
    /// - `AppError::NotFound` for an unknown passkey or challenge; `Domain` for an expired/spent challenge or corrupt lockout settings.
    /// - `AppError::Busy` when a password check cannot start in time; `Internal` on storage failure.
    async fn prove_member(
        &self,
        member: &OrgUser,
        organization: &Organization,
        proof: ReenteredProof,
        from: AttemptOrigin,
    ) -> Result<FreshSignIn, AppError>;
}

/// The ports [`FreshProofStep`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FreshProofPorts {
    /// What a password typed again is checked against.
    pub password: PasswordProof,
    /// What a second-factor code is checked against.
    pub factors: FactorProof,
    /// What a followed sign-in link is checked against.
    pub links: LinkProof,
    /// What a passkey's answer is checked against.
    pub passkeys: PasskeyProof,
    /// What an organization member's proof is checked against.
    pub members: MemberProof,
}

/// What a password typed again is checked against.
#[derive(ianua_macros::Fakes)]
pub struct PasswordProof {
    /// The tenant, for when wrong passwords lock an account.
    pub tenants: Arc<dyn TenantStore>,
    /// The account's stored password hash.
    pub credentials: Arc<dyn CredentialStore>,
    /// The wrong passwords counted per account and network, of tenant
    /// users and members alike, as sign-in keeps them.
    pub attempts: SignInCounts,
    /// Checks a typed password against the stored hash, under the node's
    /// cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// The tenant's LDAP client certificates, for a password typed again
    /// over a directory bind.
    pub certificates: Arc<dyn LdapCertificateStore>,
}

/// What a second-factor code is checked against.
#[derive(ianua_macros::Fakes)]
pub struct FactorProof {
    /// The account's second factor.
    pub enrollments: Arc<dyn MfaEnrollmentStore>,
    /// Opens the factor's stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against the factor's secret.
    pub verifier: Arc<dyn MfaVerifier>,
    /// The codes sent for mailed and texted factors.
    pub sent_codes: Arc<dyn SentCodeStore>,
    /// Hashes a typed code the way a sent one was hashed.
    pub sent_code_generator: Arc<dyn SentCodeGenerator>,
}

/// What a followed sign-in link is checked against.
#[derive(ianua_macros::Fakes)]
pub struct LinkProof {
    /// Sign-in links mailed out.
    pub magic_links: Arc<dyn SignInLinkStore<MagicLink>>,
    /// Hashes a followed link's token the way it was stored.
    pub link_hasher: Arc<dyn RefreshTokenGenerator>,
}

/// What a passkey's answer is checked against.
#[derive(ianua_macros::Fakes)]
pub struct PasskeyProof {
    /// The tenant's passkeys.
    pub passkeys: Arc<dyn PasskeyStore>,
    /// Passkey challenges in flight.
    pub ceremonies: Arc<dyn PasskeyCeremonyStore>,
    /// Checks a passkey's answer.
    pub passkey_verifier: Arc<dyn PasskeyVerifier>,
}

/// What an organization member's proof is checked against.
#[derive(ianua_macros::Fakes)]
pub struct MemberProof {
    /// Organization members, to find who owns a passkey.
    pub members: Arc<dyn OrgUserStore>,
    /// Members' second factors.
    pub member_enrollments: Arc<dyn OrgMfaEnrollmentStore>,
    /// Loads registered credentials used to prove a member's presence.
    pub member_passkeys: Arc<dyn OrgPasskeyStore>,
    /// Passkey challenges in flight on the organization plane.
    pub member_ceremonies: Arc<dyn OrgPasskeyCeremonyStore>,
}

/// The account a proof is given for, in its tenant, and where the proof
/// came from.
#[derive(Clone, Copy)]
struct Proving<'a> {
    tenant: &'a ScopedTenant,
    account: &'a User<ResolvedTenant>,
    from: AttemptOrigin,
}

/// A password typed again for an account, with its stored hash to check it
/// against.
struct TypedAgain<'a> {
    proving: Proving<'a>,
    stored: &'a PasswordHash,
    password: &'a Secret,
}

/// Checks a re-entered proof against the account's own records.
pub struct FreshProofStep {
    lockout: LockoutPolicy,
    ports: FreshProofPorts,
}

impl FreshProofStep {
    /// A step reading through `ports`, locking a second factor under
    /// `lockout` as sign-in does.
    #[must_use]
    pub fn new(lockout: LockoutPolicy, ports: FreshProofPorts) -> Self {
        Self { lockout, ports }
    }

    /// The password typed again, after the account's factor answered.
    async fn by_password(
        &self,
        proving: Proving<'_>,
        password: &Secret,
        code: Option<&str>,
    ) -> Result<FreshSignIn, AppError> {
        let (tenant, account) = (proving.tenant, proving.account);
        let stored = self.password_hash(tenant, account).await?;
        let factor = self.factor_answer(tenant, account, code).await?;
        let typed = TypedAgain {
            proving,
            stored: &stored,
            password,
        };
        self.password_proof(typed, |check| {
            FreshSignIn::by_password(holder(account), check, with_factor(&factor))
        })
        .await
    }

    /// The password typed again over the directory connection `bound`,
    /// beside the certificate the bind was made over, loaded fresh.
    async fn over_directory_bind(
        &self,
        proving: Proving<'_>,
        password: &Secret,
        bound: &DirectoryBound,
    ) -> Result<FreshSignIn, AppError> {
        let (tenant, account) = (proving.tenant, proving.account);
        let stored = self.password_hash(tenant, account).await?;
        let certificate = self
            .ports
            .password
            .certificates
            .find_by_id(tenant, bound.certificate())
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)?;
        let typed = TypedAgain {
            proving,
            stored: &stored,
            password,
        };
        self.password_proof(typed, |check| {
            bound.bind().fresh_sign_in(account, &certificate, check)
        })
        .await
    }

    /// The fresh proof `prove` makes of the password `typed` gives, counted
    /// against where it came from under the tenant's lockout, whatever the
    /// answer, once the account's pace has been waited out. The password
    /// is checked under a permit; with none free, nothing is checked or
    /// counted.
    async fn password_proof(
        &self,
        typed: TypedAgain<'_>,
        prove: impl FnOnce(PasswordCheck<'_, PermittedHasher<'_>>) -> Result<FreshSignIn, DomainError>
        + Send,
    ) -> Result<FreshSignIn, AppError> {
        let TypedAgain {
            proving,
            stored,
            password,
        } = typed;
        let rate_policy = existing_tenant(self.ports.password.tenants.as_ref(), proving.tenant)
            .await?
            .auth_config()
            .limits()
            .lockout()
            .map_err(AppError::from_domain)?;
        let at = CountedAt {
            account: CountedAccount::Tenant {
                tenant: proving.tenant,
                email: proving.account.email(),
            },
            origin: proving.from,
            policy: &rate_policy,
        };
        self.counted_check(at, password, stored, prove).await
    }

    /// What `prove` makes of `password` against `stored`, checked under a
    /// hashing permit, the attempt counted at `at` once the account's pace
    /// has been waited out, whatever the answer. With no permit free,
    /// nothing is checked or counted.
    pub(super) async fn counted_check(
        &self,
        at: CountedAt<'_>,
        password: &Secret,
        stored: &PasswordHash,
        prove: impl FnOnce(PasswordCheck<'_, PermittedHasher<'_>>) -> Result<FreshSignIn, DomainError>
        + Send,
    ) -> Result<FreshSignIn, AppError> {
        let attempts = &self.ports.password.attempts;
        let mut tracker = attempts.held(at, async { Familiarity::New }).await?;
        let proved = {
            let hasher = self.ports.password.hashing.permitted().await?;
            prove(PasswordCheck {
                raw: password.expose(),
                stored,
                hasher: &hasher,
                tracker: &mut tracker,
            })
        };
        attempts.settled(at, &tracker).await?;
        proved.map_err(AppError::from_domain)
    }

    /// A passkey's answer to a sign-in challenge.
    async fn by_passkey(
        &self,
        tenant: &ScopedTenant,
        presented: &PresentedAssertion,
    ) -> Result<FreshSignIn, AppError> {
        let answering = PasskeyAnswering {
            passkeys: self.ports.passkeys.passkeys.as_ref(),
            ceremonies: self.ports.passkeys.ceremonies.as_ref(),
            verifier: self.ports.passkeys.passkey_verifier.as_ref(),
        };
        let answered = answering.answered(tenant, presented).await?;
        FreshSignIn::by_passkey(answered.spent).map_err(AppError::from_domain)
    }

    async fn password_hash(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
    ) -> Result<PasswordHash, AppError> {
        self.ports
            .password
            .credentials
            .find_password_hash(tenant, account.id())
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "authentication-this-account-has-no-password-prove",
                    "this account has no password; prove it is you the way you sign in"
                ))
            })
    }

    async fn factor_answer(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        code: Option<&str>,
    ) -> Result<FactorAnswer, AppError> {
        let factor = AccountFactor {
            enrollments: self.ports.factors.enrollments.as_ref(),
            checks: FactorChecks {
                app: CodeCheck {
                    encryptor: self.ports.factors.encryptor.as_ref(),
                    verifier: self.ports.factors.verifier.as_ref(),
                    lockout: self.lockout,
                },
                sent: SentCodes {
                    store: self.ports.factors.sent_codes.as_ref(),
                    check: SentCodeCheck {
                        generator: self.ports.factors.sent_code_generator.as_ref(),
                        lockout: self.lockout,
                    },
                },
            },
        };
        factor
            .answer(FactorCode {
                tenant,
                user_id: account.id(),
                code,
            })
            .await
    }
}

#[async_trait]
impl FreshProofs for FreshProofStep {
    async fn prove(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        proof: ReenteredProof,
        from: AttemptOrigin,
    ) -> Result<FreshSignIn, AppError> {
        let proving = Proving {
            tenant,
            account,
            from,
        };
        let fresh = match proof {
            ReenteredProof::Password { password, code } => {
                self.by_password(proving, &password, code.as_deref())
                    .await?
            }
            ReenteredProof::Mailbox { link, code } => {
                self.by_mailbox(tenant, account, &link, code.as_deref())
                    .await?
            }
            ReenteredProof::Passkey(presented) => self.by_passkey(tenant, &presented).await?,
            ReenteredProof::OverDirectoryBind { password, bound } => {
                self.over_directory_bind(proving, &password, &bound).await?
            }
        };
        ensure_proves(&fresh, holder(account))?;
        Ok(fresh)
    }

    async fn prove_member(
        &self,
        member: &OrgUser,
        organization: &Organization,
        proof: ReenteredProof,
        from: AttemptOrigin,
    ) -> Result<FreshSignIn, AppError> {
        let fresh = match proof {
            ReenteredProof::Password { password, code } => {
                let given = MemberPassword {
                    member,
                    organization,
                    password: &password,
                    code: code.as_deref(),
                    from,
                };
                self.member_by_password(given).await?
            }
            ReenteredProof::Passkey(presented) => self.member_by_passkey(&presented).await?,
            ReenteredProof::Mailbox { .. } => return Err(member_mailbox_refused()),
            ReenteredProof::OverDirectoryBind { .. } => return Err(member_bind_refused()),
        };
        ensure_proves(&fresh, PrincipalId::from(*member.id()))?;
        Ok(fresh)
    }
}

/// The person signed in to `caller`'s session, with the fresh proof of
/// them that `proof` gives, sent from where the caller's request came.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the caller came with no tenant
///   session, or it no longer counts.
/// - The errors of [`FreshProofs::prove`].
pub(crate) async fn proved_person(
    authorities: &dyn TenantAuthorities,
    proofs: &dyn FreshProofs,
    caller: &CallerContext,
    proof: ReenteredProof,
) -> Result<(SignedInAccount, FreshSignIn), AppError> {
    let person = authorities.signed_in(caller).await?;
    let fresh = proofs
        .prove(&caller.tenant(), &person.account, proof, caller.origin())
        .await?;
    Ok((person, fresh))
}

/// Refuses a proof of another account than `account`, the one changing.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `fresh` proves someone else.
fn ensure_proves(fresh: &FreshSignIn, account: PrincipalId) -> Result<(), AppError> {
    if fresh.account() == account {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "authentication-the-proof-is-another-account-s",
        "the proof is another account's"
    )))
}

fn holder(account: &User<ResolvedTenant>) -> PrincipalId {
    PrincipalId::from(*account.id())
}

fn with_factor(answer: &FactorAnswer) -> WithFactor<'_> {
    match answer {
        FactorAnswer::NoneOnFile => WithFactor::NoneOnFile,
        FactorAnswer::Answered(code) => WithFactor::Code(code),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
        OpenCeremonyParams, PasskeyCeremony, TargetedPurpose,
    };
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
    use ianua_domain::domains::authentication::ldap_certificate::{
        DirectoryBind, LdapClientCertificate,
    };
    use ianua_domain::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::tokens::secure::{SecureToken, SecureTokenRow};
    use ianua_domain::shared::clock;
    use ianua_domain::test_support::fakes::{FakeHasher, FakeMfaVerifier};
    use ianua_domain::types::{
        CeremonyId, CertificateFingerprint, Email, Fact, IpAddress, Lifetime, Usage, UserId,
    };
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::identity::MagicLinkToken;
    use crate::test_support::authentication::{
        CertificateStanding, FakeEncryptor, FakeLdapCertificateStore, FakeMfaEnrollmentStore,
        FakePasskeyCeremonyStore, FakePasskeyStore, FakePasskeyVerifier, FakeSignInAttemptCounts,
        PASSKEY_CEREMONY_STATE, ldap_certificate, lockout, passkey_credential_id, revoked_now,
    };
    use crate::test_support::identity::{
        FakeSignInLinks, RecordingCredentialStore, hash_of_link, stored_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{Fake, block_on, test_ctx};

    const PASSWORD: &str = "correct horse battery staple";
    const RIGHT_CODE: &str = "123456";
    const LINK: &str = "fake_refresh_link";

    struct Fixture {
        ann: User<ResolvedTenant>,
        attempts: Arc<FakeSignInAttemptCounts>,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
        step: FreshProofStep,
        from: AttemptOrigin,
    }

    struct Holds {
        password: Option<&'static str>,
        enrollments: FakeMfaEnrollmentStore,
        passkeys: FakePasskeyStore,
        links: FakeSignInLinks,
        certificates: FakeLdapCertificateStore,
    }

    impl Holds {
        fn password() -> Self {
            Self {
                password: Some(PASSWORD),
                enrollments: FakeMfaEnrollmentStore::empty(),
                passkeys: FakePasskeyStore::empty(),
                links: FakeSignInLinks::new(),
                certificates: FakeLdapCertificateStore::empty(),
            }
        }

        /// Ann's password, an authenticator app, and her laptop's LDAP
        /// client certificate.
        fn password_factor_and(certificate: LdapClientCertificate<ResolvedTenant>) -> Self {
            Self {
                enrollments: FakeMfaEnrollmentStore::active_for(*certificate.user_id()),
                certificates: FakeLdapCertificateStore::holding(
                    test_ctx().tenant_id(),
                    [certificate],
                ),
                ..Self::password()
            }
        }

        /// Supplies the mailed link for an account with no password.
        fn mailbox(link: &MagicLinkToken) -> Self {
            Self {
                password: None,
                links: FakeSignInLinks::holding(link),
                ..Self::password()
            }
        }
    }

    impl Fixture {
        /// Builds the proof ports from the credentials Ann currently holds.
        fn for_ann(ann: UserId, holds: Holds) -> Self {
            let credentials = credentials_for(ann, holds.password);
            let attempts = Arc::new(FakeSignInAttemptCounts::default());
            let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
            let ports = FreshProofPorts {
                password: PasswordProof {
                    tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    credentials: Arc::new(credentials),
                    attempts: SignInCounts::new(attempts.clone(), Fake::fake()),
                    hashing: PasswordHashing::fakes(),
                    certificates: Arc::new(holds.certificates),
                },
                factors: factor_proof(holds.enrollments),
                links: LinkProof {
                    magic_links: Arc::new(holds.links),
                    ..LinkProof::fakes()
                },
                passkeys: PasskeyProof {
                    passkeys: Arc::new(holds.passkeys),
                    ceremonies: ceremonies.clone(),
                    passkey_verifier: Arc::new(FakePasskeyVerifier::succeeding()),
                },
                ..FreshProofPorts::fakes()
            };
            Self {
                ann: stored_user(ann, "ann@acme.test", UserStatus::Active),
                attempts,
                ceremonies,
                step: FreshProofStep::new(lockout(), ports),
                from: from_ip("198.51.100.66"),
            }
        }

        fn with(holds: Holds) -> Self {
            Self::for_ann(UserId::new(), holds)
        }

        /// The same fixture, its proofs sent from `ip`.
        fn sent_from(self, ip: &str) -> Self {
            Self {
                from: from_ip(ip),
                ..self
            }
        }

        fn prove(&self, proof: ReenteredProof) -> Result<FreshSignIn, AppError> {
            block_on(
                self.step
                    .prove(&test_ctx().tenant(), &self.ann, proof, self.from),
            )
        }

        fn wrong_passwords(&self) -> u64 {
            let tenant = test_ctx().tenant();
            self.attempts.on_account(CountedAccount::Tenant {
                tenant: &tenant,
                email: self.ann.email(),
            })
        }

        fn open_ceremony(&self, ceremony: &PasskeyCeremony) -> CeremonyId {
            block_on(self.ceremonies.save(ceremony)).unwrap();
            *ceremony.id()
        }
    }

    /// Stores the supplied password hash, or no password for a mailbox account.
    fn credentials_for(ann: UserId, password: Option<&str>) -> RecordingCredentialStore {
        password.map_or_else(RecordingCredentialStore::default, |raw| {
            RecordingCredentialStore::holding(ann, &FakeHasher.hash(raw).unwrap())
        })
    }

    /// Checks the fixture's factor code against its chosen enrollments.
    fn factor_proof(enrollments: FakeMfaEnrollmentStore) -> FactorProof {
        FactorProof {
            enrollments: Arc::new(enrollments),
            encryptor: Arc::new(FakeEncryptor),
            verifier: Arc::new(FakeMfaVerifier {
                valid_code: RIGHT_CODE.to_owned(),
            }),
            ..FactorProof::fakes()
        }
    }

    fn from_ip(ip: &str) -> AttemptOrigin {
        AttemptOrigin::of(Fact::Known(&IpAddress::new(ip).unwrap()))
    }

    fn typed(password: &str, code: Option<&str>) -> ReenteredProof {
        ReenteredProof::Password {
            password: Secret::new(password),
            code: code.map(str::to_owned),
        }
    }

    /// What became of Ann's laptop's certificate after she bound with it.
    #[derive(Clone, Copy)]
    enum Since {
        Nothing,
        Revoked,
    }

    /// Ann, who holds her password, an authenticator app and her laptop's
    /// certificate, bound to the directory from that laptop.
    fn ann_bound_from_her_laptop() -> (Fixture, DirectoryBound) {
        ann_bound_from_her_laptop_and(Since::Nothing)
    }

    /// Ann bound from her laptop, its certificate as `since` says now.
    fn ann_bound_from_her_laptop_and(since: Since) -> (Fixture, DirectoryBound) {
        let ann = UserId::new();
        let laptop = CertificateFingerprint::from_digest([7; 32]);
        let certificate = ldap_certificate(ann, laptop, CertificateStanding::InForce);
        let stored = FakeHasher.hash(PASSWORD).unwrap();
        let check = PasswordCheck {
            raw: PASSWORD,
            stored: &stored,
            hasher: &FakeHasher,
            tracker: &mut LoginAttemptTracker::new(),
        };
        let account = stored_user(ann, "ann@acme.test", UserStatus::Active);
        let bind = DirectoryBind::with_certificate(&account, check, &certificate, &laptop).unwrap();
        let kept = match since {
            Since::Nothing => certificate,
            Since::Revoked => revoked_now(&certificate),
        };
        let fixture = Fixture::for_ann(ann, Holds::password_factor_and(kept));
        (fixture, DirectoryBound::new(bind))
    }

    fn over_bind(password: &str, bound: DirectoryBound) -> ReenteredProof {
        ReenteredProof::OverDirectoryBind {
            password: Secret::new(password),
            bound,
        }
    }

    fn followed(code: Option<&str>) -> ReenteredProof {
        ReenteredProof::Mailbox {
            link: Secret::new(LINK),
            code: code.map(str::to_owned),
        }
    }

    fn link_for(ann: UserId, expires_at: OffsetDateTime) -> MagicLinkToken {
        SecureToken::reconstitute(SecureTokenRow {
            token_hash: hash_of_link(LINK),
            user_id: ann,
            sent_to: Email::new("ann@acme.test").unwrap(),
            created_at: expires_at.min(clock::now()) - time::Duration::minutes(5),
            expires_at,
            usage: Usage::from_stored(None),
        })
        .unwrap()
    }

    fn answered(ceremony_id: CeremonyId) -> ReenteredProof {
        ReenteredProof::Passkey(PresentedAssertion {
            ceremony_id,
            credential_id: passkey_credential_id(),
            response: b"signed".to_vec(),
        })
    }

    fn sign_in_challenge(owner: UserId) -> PasskeyCeremony {
        PasskeyCeremony::open(OpenCeremonyParams {
            tenant_id: test_ctx().tenant_id(),
            user_id: owner,
            purpose: TargetedPurpose::Authentication,
            state: PASSKEY_CEREMONY_STATE.to_vec(),
            ttl: Lifetime::seconds(300).unwrap(),
        })
    }

    /// Ann types her password again. It proves her, and her count of wrong
    /// passwords stays at nothing.
    #[test]
    fn the_right_password_proves_the_person() {
        let fixture = Fixture::with(Holds::password());

        let fresh = fixture.prove(typed(PASSWORD, None)).unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(*fixture.ann.id()));
        assert_eq!(fixture.wrong_passwords(), 0);
    }

    /// Ann has an authenticator app, and changes her password over the
    /// directory, where no code can be sent. She types her password again
    /// over the connection her laptop bound, and the laptop's certificate
    /// stands in for her app. The same password with no code and no bind
    /// still asks for the code.
    #[test]
    fn a_directory_bind_stands_in_for_the_second_factor() {
        let (fixture, bound) = ann_bound_from_her_laptop();

        let fresh = fixture.prove(over_bind(PASSWORD, bound)).unwrap();
        let without = fixture.prove(typed(PASSWORD, None));

        assert_eq!(fresh.account(), PrincipalId::from(*fixture.ann.id()));
        assert!(matches!(without, Err(AppError::StepUpRequired)));
    }

    /// A wrong password over Ann's certificate-bound directory connection
    /// is forbidden and adds one failed password attempt to her account.
    #[test]
    fn a_wrong_password_over_a_bind_is_refused_and_counted() {
        let (fixture, bound) = ann_bound_from_her_laptop();

        let result = fixture.prove(over_bind("guess", bound));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.wrong_passwords(), 1);
    }

    /// Revoking the certificate after a directory bind invalidates that
    /// bind as fresh proof. The right password is refused without counting
    /// a wrong-password attempt.
    #[test]
    fn a_bind_whose_certificate_was_revoked_proves_nobody() {
        let (fixture, bound) = ann_bound_from_her_laptop_and(Since::Revoked);

        let result = fixture.prove(over_bind(PASSWORD, bound));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.wrong_passwords(), 0);
    }

    /// Re-entering the wrong password is forbidden and increments Ann's
    /// failed-password count, just as a sign-in attempt would.
    #[test]
    fn a_wrong_password_is_refused_and_counted() {
        let fixture = Fixture::with(Holds::password());

        let result = fixture.prove(typed("guess", None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.wrong_passwords(), 1);
    }

    /// Ten wrong passwords lock the originating network out of Ann's
    /// account. The right password is refused there but succeeds from a
    /// different network.
    #[test]
    fn a_locked_out_network_refuses_even_the_right_password() {
        let fixture = Fixture::with(Holds::password());
        for _ in 0..10 {
            let _ = fixture.prove(typed("guess", None));
        }

        let mallory = fixture.prove(typed(PASSWORD, None));
        let ann = fixture
            .sent_from("203.0.113.7")
            .prove(typed(PASSWORD, None));

        assert!(matches!(mallory, Err(AppError::Forbidden(_))));
        assert!(ann.is_ok());
    }

    /// Ann has an active second factor. Her correct password without its
    /// code returns step-up required rather than fresh proof.
    #[test]
    fn an_account_with_a_factor_must_give_its_code() {
        let ann = UserId::new();
        let fixture = Fixture::for_ann(
            ann,
            Holds {
                enrollments: FakeMfaEnrollmentStore::active_for(ann),
                ..Holds::password()
            },
        );

        let result = fixture.prove(typed(PASSWORD, None));

        assert!(matches!(result, Err(AppError::StepUpRequired)));
    }

    /// Ann types her password and the code her authenticator shows. Together
    /// they prove her.
    #[test]
    fn the_password_and_the_code_prove_the_person() {
        let ann = UserId::new();
        let fixture = Fixture::for_ann(
            ann,
            Holds {
                enrollments: FakeMfaEnrollmentStore::active_for(ann),
                ..Holds::password()
            },
        );

        let fresh = fixture.prove(typed(PASSWORD, Some(RIGHT_CODE)));

        assert!(fresh.is_ok());
    }

    /// A password and authenticator code prove Ann once. Repeating both
    /// is forbidden because the code's step has already been claimed.
    #[test]
    fn a_replayed_code_is_refused() {
        let ann = UserId::new();
        let fixture = Fixture::for_ann(
            ann,
            Holds {
                enrollments: FakeMfaEnrollmentStore::active_for(ann),
                ..Holds::password()
            },
        );
        fixture.prove(typed(PASSWORD, Some(RIGHT_CODE))).unwrap();

        let replayed = fixture.prove(typed(PASSWORD, Some(RIGHT_CODE)));

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }

    /// The correct password cannot compensate for a wrong factor code;
    /// fresh proof is refused as forbidden.
    #[test]
    fn a_wrong_code_is_refused() {
        let ann = UserId::new();
        let fixture = Fixture::for_ann(
            ann,
            Holds {
                enrollments: FakeMfaEnrollmentStore::active_for(ann),
                ..Holds::password()
            },
        );

        let result = fixture.prove(typed(PASSWORD, Some("000000")));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann signs in only through links mailed to her. Following one just
    /// now proves her.
    #[test]
    fn a_followed_link_proves_a_person_who_signs_in_by_mail() {
        let ann = UserId::new();
        let link = link_for(ann, clock::now() + time::Duration::minutes(10));
        let fixture = Fixture::for_ann(ann, Holds::mailbox(&link));

        let fresh = fixture.prove(followed(None)).unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(ann));
    }

    /// Ann's mailbox-only account cannot be proved with a sign-in link
    /// that expired a minute ago.
    #[test]
    fn an_expired_link_is_refused() {
        let ann = UserId::new();
        let link = link_for(ann, clock::now() - time::Duration::minutes(1));
        let fixture = Fixture::for_ann(ann, Holds::mailbox(&link));

        let result = fixture.prove(followed(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A valid mailed link is insufficient fresh proof for Ann while her
    /// account has a password; the link attempt is forbidden.
    #[test]
    fn a_link_does_not_prove_a_person_with_a_password() {
        let ann = UserId::new();
        let link = link_for(ann, clock::now() + time::Duration::minutes(10));
        let fixture = Fixture::for_ann(
            ann,
            Holds {
                password: Some(PASSWORD),
                ..Holds::mailbox(&link)
            },
        );

        let result = fixture.prove(followed(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann answers a sign-in challenge with her passkey. It proves her.
    #[test]
    fn a_passkey_answer_proves_the_person() {
        let ann = UserId::new();
        let fixture = Fixture::for_ann(
            ann,
            Holds {
                passkeys: FakePasskeyStore::with_passkey(ann),
                ..Holds::password()
            },
        );
        let ceremony = fixture.open_ceremony(&sign_in_challenge(ann));

        let fresh = fixture.prove(answered(ceremony)).unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(ann));
    }

    /// A valid passkey answer for Mallory cannot provide fresh proof of
    /// Ann. The account mismatch returns forbidden.
    #[test]
    fn a_passkey_of_another_account_is_refused() {
        let mallory = UserId::new();
        let fixture = Fixture::with(Holds {
            passkeys: FakePasskeyStore::with_passkey(mallory),
            ..Holds::password()
        });
        let ceremony = fixture.open_ceremony(&sign_in_challenge(mallory));

        let result = fixture.prove(answered(ceremony));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
