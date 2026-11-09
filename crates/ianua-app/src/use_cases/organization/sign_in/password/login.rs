//! A member signing in to the organization with their address and
//! password.
//!
//! While a flood of failures puts the sign-in under high pressure, a device
//! no member remembered must first show a passed challenge, before any
//! password is hashed. Then the password is checked first, whatever else is
//! true, so every refusal costs the same hash and a guesser learns nothing
//! from how fast the answer comes. Only once the account is proven does the
//! member learn that their address is unconfirmed, or that the organization
//! refuses passwords or their network: ahead of the password those answers
//! would tell anybody which addresses have an account. Then the domain
//! begins the sign-in, owing what the organization's policies ask, and
//! opens the session in the tenant chosen.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::{DeviceSecret, TrustWindow};
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::risk_engine::attack::AccountAttack;
use ianua_domain::domains::authentication::risk_engine::challenge::ChallengeProof;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureThreshold;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::sessions::way_in::WayIn;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::access::landing::SignInLanding;
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::events::access::{OrgAccountUnderAttack, OrgSignInMethod};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DisplayName, Email, Label, OrgUserId, OrganizationId, SessionId, TenantSlug,
};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::RoleStore;
use crate::ports::oauth::CodeHasher;
use crate::ports::organization::{
    OrgMfaEnrollmentStore, OrgPasskeyStore, OrgSessionStore, OrgTenantGrantStore,
    OrgTrustedDeviceStore, OrgUserStore, OrganizationStore,
};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::flood_gate::FloodGatePorts;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::sign_in_counts::SignInCounts;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_case::Command;
use crate::use_cases::authentication::password::sign_in::confirmation::ConfirmationLinkPolicy;
use crate::use_cases::organization::lookup::existing_organization;
use crate::use_cases::organization::members::rights::access::OrgUserAccess;
use crate::use_cases::organization::sign_in::mailed::confirmation_mail::OrgConfirmationMailPorts;
use crate::use_cases::organization::sign_in::password::flood::MemberFlood;
use crate::use_cases::organization::sign_in::password::held_factors::MemberFactorSources;
use crate::use_cases::organization::sign_in::password::kept::{KeptSignIn, Landed};
use crate::use_cases::organization::sign_in::password::second_factor::{
    OwedFactor, SignInCircumstances,
};
use crate::use_cases::organization::sign_in::steps::choice::{
    AddressAccounts, Holder, OrgLoginOutcome, OrganizationChoice, ensure_address_proven, offered,
};
use crate::use_cases::organization::sign_in::steps::landing::{LandedTenant, Landing};
use crate::use_cases::organization::sign_in_record::org_sign_in_record;

/// One password sign-in attempt. It holds the password, so it has no
/// `Debug`.
pub struct OrgPasswordLoginRequest {
    /// The address the member signs in with.
    pub email: Email,
    /// The password as typed.
    pub password: Secret,
    /// The organization to sign in to: none named at first, or one an
    /// earlier sign-in offered.
    pub organization: OrganizationChoice,
    /// The tenant to sign in to. Without it the session lands in the first
    /// active tenant the member reaches.
    pub tenant_slug: Option<TenantSlug>,
    /// The secret of a device the member remembered, if it sent one.
    pub device_secret: Option<DeviceSecret>,
    /// The proof of a passed challenge, if the browser solved one.
    pub challenge: Option<ChallengeProof>,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// A password sign-in that opened a session. It holds the refresh token,
/// so it has no `Debug`.
pub struct OrgLoginSuccess {
    /// The new session.
    pub session_id: SessionId,
    /// The member signed in.
    pub org_user_id: OrgUserId,
    /// The raw refresh token, sent to the client and never stored.
    pub refresh_token: Secret,
    /// What the sign-in still owes in the way of a second factor.
    pub second_factor: SecondFactor,
    /// The tenant the session works in, or that the member's role reaches
    /// none.
    pub tenant: LandedTenant,
    /// The member's organization.
    pub organization_id: OrganizationId,
    /// The organization's slug.
    pub org_slug: TenantSlug,
    /// The organization's name.
    pub organization_name: Label,
    /// The member's display name.
    pub display_name: DisplayName,
    /// What the member reaches, once the sign-in owes nothing more. A
    /// session that proved only a password is not told the organization's
    /// tenant layout.
    pub access: Option<OrgUserAccess>,
}

/// The ports [`OrgPasswordLoginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgPasswordLoginPorts {
    /// Finds the member an address signs in to.
    pub members: Arc<dyn OrgUserStore>,
    /// The member's organization, which sets the sign-in's rules.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The organization's tenants, to land in one.
    pub tenants: Arc<dyn TenantStore>,
    /// What a typed password is checked through: hashing, the flood gate and the wrong guesses counted.
    pub password: OrgPasswordCheckPorts,
    /// The member's own factors and remembered devices, which decide the second step.
    pub factors: OrgLoginFactorPorts,
    /// What opens the member's session: the sessions, their tenant grants, the tokens and the roles a grant names.
    pub session: OrgSessionOpeningPorts,
    /// Mails the link a sign-in owing an email confirmation waits for.
    pub confirmation: OrgConfirmationMailPorts,
}

/// What a typed password is checked through: hashing, the flood gate and the wrong guesses counted.
#[derive(ianua_macros::Fakes)]
pub struct OrgPasswordCheckPorts {
    /// Checks the typed password against the stored hash, under the node's
    /// cap on hashes running at once.
    pub hashing: PasswordHashing,
    /// The counts of failures across organizations, and the challenge a
    /// device no member remembered passes while one is high.
    pub flood: FloodGatePorts,
    /// The failed passwords counted per account and network, and the wait
    /// an account being guessed at asks.
    pub attempts: SignInCounts,
}

/// The member's own factors and remembered devices, which decide the second step.
#[derive(ianua_macros::Fakes)]
pub struct OrgLoginFactorPorts {
    /// Members' authenticator apps.
    pub enrollments: Arc<dyn OrgMfaEnrollmentStore>,
    /// Members' passkeys.
    pub passkeys: Arc<dyn OrgPasskeyStore>,
    /// The devices members remembered.
    pub devices: Arc<dyn OrgTrustedDeviceStore>,
    /// Hashes a device's secret the way remembering it stored it.
    pub device_secret_hasher: Arc<dyn CodeHasher>,
}

/// What opens the member's session: the sessions, their tenant grants, the tokens and the roles a grant names.
#[derive(ianua_macros::Fakes)]
pub struct OrgSessionOpeningPorts {
    /// Where the new session is kept.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The tenants and roles members were granted.
    pub grants: Arc<dyn OrgTenantGrantStore>,
    /// Makes the session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The roles of each tenant, to describe what the member reaches.
    pub roles: Arc<dyn RoleStore>,
}

/// What a deployment sets for members' password sign-ins.
#[derive(Debug, Clone)]
pub struct OrgLoginSettings {
    /// How long a remembered device counts.
    pub device_trust: TrustWindow,
    /// How long a sign-in confirmation link lasts, and the address it is
    /// built on.
    pub confirmation: ConfirmationLinkPolicy,
    /// The failures across the platform, among sign-ins that name no
    /// organization, that put those sign-ins under high pressure.
    pub unnamed_threshold: FailureThreshold,
}

/// Signs members in to the organization with their password.
pub struct OrgPasswordLoginUseCase {
    ports: OrgPasswordLoginPorts,
    settings: OrgLoginSettings,
}

impl OrgPasswordLoginUseCase {
    /// A use case signing in through `ports` under `settings`.
    #[must_use]
    pub fn new(ports: OrgPasswordLoginPorts, settings: OrgLoginSettings) -> Self {
        Self { ports, settings }
    }

    /// Where the accounts on an address are read from.
    fn accounts(&self) -> AddressAccounts<'_> {
        AddressAccounts {
            members: self.ports.members.as_ref(),
            organizations: self.ports.organizations.as_ref(),
            hashing: &self.ports.password.hashing,
            attempts: &self.ports.password.attempts,
            owed: self.owed_factor(),
        }
    }

    /// What a sign-in is held to before its password is hashed.
    fn flood(&self) -> MemberFlood<'_> {
        MemberFlood {
            organizations: self.ports.organizations.as_ref(),
            gate: &self.ports.password.flood,
            owed: self.owed_factor(),
            unnamed: self.settings.unnamed_threshold,
        }
    }

    /// The sign-in `request` asks for on the accounts `holders`: the one
    /// account there is, the one the password opens among several, or a
    /// refusal answering as an unknown address does when there is none.
    async fn settled(
        &self,
        auditor: &RequestAuditor,
        holders: &[Holder],
        request: &OrgPasswordLoginRequest,
    ) -> Result<OrgLoginOutcome, AppError> {
        match holders {
            [] => Err(self
                .accounts()
                .refused_after_a_hash(&request.password)
                .await),
            [only] => self
                .recorded(auditor, only, request)
                .await
                .map(OrgLoginOutcome::signed_in),
            every => self.settled_among(auditor, every, request).await,
        }
    }

    /// Signs `holder`'s member in and records
    /// `organization.org_login_succeeded`, or `organization.org_login_failed`
    /// for a refused attempt, and `organization.org_account_under_attack`
    /// when this attempt found the account's attack begun.
    async fn recorded(
        &self,
        auditor: &RequestAuditor,
        holder: &Holder,
        request: &OrgPasswordLoginRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let member = &holder.member;
        let attack = self.accounts().attack_on(holder, request).await?;
        let outcome = self.sign_in_outcome(member, attack, request).await;
        let found = attack
            .begun()
            .map(|begun| OrgAccountUnderAttack::observed(member, begun).system());
        let signed_in = org_sign_in_record(member, OrgSignInMethod::Password, &outcome);
        let events: Vec<_> = found.into_iter().chain(signed_in).collect();
        if !events.is_empty() {
            auditor.dispatch(&events).await.or_internal()?;
        }
        self.accounts()
            .attack_recorded(holder, request, attack)
            .await?;
        outcome
    }

    /// The sign-in to one of `holders`, the accounts on an address in
    /// several organizations: the one the password opens, or the
    /// organizations to choose from when it opens several.
    async fn settled_among(
        &self,
        auditor: &RequestAuditor,
        holders: &[Holder],
        request: &OrgPasswordLoginRequest,
    ) -> Result<OrgLoginOutcome, AppError> {
        let opened = self.accounts().opened_by(holders, request).await?;
        match opened.as_slice() {
            [] => self.refused_everywhere(auditor, holders, request).await,
            [only] => self
                .recorded(auditor, only, request)
                .await
                .map(OrgLoginOutcome::signed_in),
            several => Ok(OrgLoginOutcome::ChooseOrganization(offered(several))),
        }
    }

    /// The refusal of a password no account on the address takes, counted
    /// and recorded against each of `holders` as a single one would be.
    async fn refused_everywhere(
        &self,
        auditor: &RequestAuditor,
        holders: &[Holder],
        request: &OrgPasswordLoginRequest,
    ) -> Result<OrgLoginOutcome, AppError> {
        for holder in holders {
            match self.recorded(auditor, holder, request).await {
                Ok(success) => return Ok(OrgLoginOutcome::signed_in(success)),
                Err(error @ (AppError::Internal(_) | AppError::Busy)) => return Err(error),
                Err(_) => {}
            }
        }
        Err(invalid_credentials())
    }

    /// Signs `member` in once their password, account and organization
    /// allow it, owing more from a device they did not trust while their
    /// account is under `attack`.
    async fn sign_in_outcome(
        &self,
        member: &OrgUser,
        attack: AccountAttack,
        request: &OrgPasswordLoginRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let organization =
            existing_organization(self.ports.organizations.as_ref(), member.organization_id())
                .await?;
        self.ensure_admitted(&organization, request).await?;
        let way_in = self
            .accounts()
            .counted_way_in(member, &organization, request)
            .await?;
        ensure_address_proven(member, self.ports.confirmation.mail.reach())?;
        let place = self
            .landing_place(member, &organization, request.tenant_slug.as_ref())
            .await?;
        let came = SignInCircumstances {
            secret: request.device_secret.as_ref(),
            attack,
        };
        let start = self.begun(member, &organization, way_in, came).await?;
        let landed = Landed {
            member,
            organization: &organization,
            place: &place,
        };
        self.kept().opened(landed, start, request).await
    }

    /// Refuses a password sign-in the organization's settings rule out,
    /// before the password is compared or counted.
    ///
    /// It answers as a wrong password does, after hashing the password all
    /// the same, under a permit like a real check. Acme lets Alice sign in
    /// from its office network only. Without this, Mallory guesses from
    /// anywhere: a right guess answers differently from a wrong one, and her
    /// wrong guesses lock Alice out.
    async fn ensure_admitted(
        &self,
        organization: &Organization,
        request: &OrgPasswordLoginRequest,
    ) -> Result<(), AppError> {
        let admitted = organization
            .auth_config()
            .admits(AuthMethod::Password, request.origin.ip_address.as_ref());
        match admitted {
            Ok(_) => Ok(()),
            Err(DomainError::Forbidden(_)) => Err(self
                .accounts()
                .refused_after_a_hash(&request.password)
                .await),
            Err(other) => Err(AppError::from_domain(other)),
        }
    }

    /// Where the sign-in lands.
    async fn landing_place(
        &self,
        member: &OrgUser,
        organization: &Organization,
        named: Option<&TenantSlug>,
    ) -> Result<SignInLanding, AppError> {
        let landing = Landing {
            tenants: self.ports.tenants.as_ref(),
            grants: self.ports.session.grants.as_ref(),
        };
        landing.place_for(member, organization, named).await
    }

    /// The sign-in the domain begins for `member`, owing what the
    /// organization's policies ask in the circumstances it `came` in.
    async fn begun(
        &self,
        member: &OrgUser,
        organization: &Organization,
        way_in: WayIn,
        came: SignInCircumstances<'_>,
    ) -> Result<OrgSignInStart, AppError> {
        let owed = self
            .owed_factor()
            .owed_by_member(member, organization, came)
            .await?;
        OrgSignInStart::new(member, way_in, owed, organization.auth_config()).map_err(start_refused)
    }

    /// What a sign-in's second factor is worked out from, and the devices
    /// members remembered.
    fn owed_factor(&self) -> OwedFactor<'_> {
        OwedFactor {
            factors: MemberFactorSources {
                enrollments: self.ports.factors.enrollments.as_ref(),
                passkeys: self.ports.factors.passkeys.as_ref(),
            },
            devices: self.ports.factors.devices.as_ref(),
            secret_hasher: self.ports.factors.device_secret_hasher.as_ref(),
            window: self.settings.device_trust,
            mail: self.ports.confirmation.mail.reach(),
        }
    }

    /// Where a begun sign-in is kept.
    fn kept(&self) -> KeptSignIn<'_> {
        KeptSignIn {
            ports: &self.ports,
            settings: &self.settings,
            owed: self.owed_factor(),
        }
    }
}

impl Command for OrgPasswordLoginUseCase {
    type Caller = ();
    type Input = OrgPasswordLoginRequest;
    type Output = Result<OrgLoginOutcome, AppError>;

    /// Signs `request.email` in with `request.password` and records
    /// `organization.org_login_succeeded`, or `organization.org_login_failed`
    /// for a refused attempt on a known account. An unknown address records
    /// nothing, and answers no sooner than a known one. A sign-in that owes
    /// a confirmation by email has its link mailed to the member.
    ///
    /// While failures from many networks put the member's account under
    /// attack, a right password from a device they did not remember owes
    /// their second factor or a mailed confirmation, and the attempt that
    /// finds the attack records `organization.org_account_under_attack`
    /// once.
    ///
    /// An address may hold an account in several organizations. With none
    /// named, the password settles which: the one organization whose
    /// account it opens is signed in to, and when it opens several, those
    /// organizations are offered and nothing is recorded, for the person to
    /// sign in again naming one. A password no account takes is counted
    /// against each. A named organization is the only one tried.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` hides unknown addresses, wrong passwords, locked/deactivated/invited accounts and refused password methods/origins/assurance; also reports an unknown tenant slug.
    /// - `AppError::EmailNotVerified` for a right password with an unconfirmed address; `Forbidden` for excluded members/tenants or risky sign-in without a factor or mail proof.
    /// - `AppError::Domain` for invalid session settings or excessive confirmation lifetime; `ChallengeRequired` under high pressure without trusted-device/challenge proof, before hashing and without counting or identifying accounts.
    /// - `AppError::Busy` when hashing cannot start, without counting or recording; `Internal` on storage, token, mail or audit failure, or invalid lockout settings.
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: OrgPasswordLoginRequest,
    ) -> Result<OrgLoginOutcome, AppError> {
        let holders = self
            .accounts()
            .holding(&request.email, &request.organization)
            .await?;
        let flood = self.flood();
        let budget = flood.budget(&request.organization).await?;
        let eased = flood.admit(budget, &holders, &request).await?;
        let outcome = self.settled(auditor, &holders, &request).await;
        let rose = flood.counted(budget, &holders, &outcome).await;
        let recorded: Vec<_> = [eased, rose].into_iter().flatten().collect();
        if !recorded.is_empty() {
            auditor.dispatch(&recorded).await.or_internal()?;
        }
        outcome
    }
}

/// The error a sign-in the domain would not begin answers with: never an
/// internal error, since the member's own proof fell short.
fn start_refused(refused: SignInRefused) -> AppError {
    AppError::Forbidden(refused.to_string().into())
}

pub(in crate::use_cases::organization::sign_in) use crate::services::authentication::refused::invalid_credentials;

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::{TrustedDevice, TrustedDeviceRow};
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::authentication::risk_engine::challenge::{
        ChallengeKind, RequiredChallenge,
    };
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
    use ianua_domain::domains::organization::access::auth_config::{
        OrganizationAuthSettings, SsoEnforcement,
    };
    use ianua_domain::domains::organization::access::session::{OrgSession, SessionPlace};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUserRow};
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::domains::organization::status::{OrgSuspensionReason, Suspension};
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::isolation::organization::scope::ResolvedOrganization;
    use ianua_domain::shared::clock;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{
        ActedBy, CidrRange, CredentialChange, Fact, HttpsUrl, IpAddress, Joining, Lifetime,
        Preference, PrincipalId, RoleId, Seconds, TrustedDeviceId, UserAgent,
    };

    use super::*;
    use crate::ports::authentication::{
        ChallengeVerifier, CountedAccount, FailureScope, PasswordHashPermits,
    };
    use crate::ports::shared::MailSetup;
    use crate::test_support::authentication::{
        BusyHashPermits, CountingHasher, FakeChallengeVerifier, FakeHashPermits,
        FakeMfaEnrollmentStore, FakeSignInAttemptCounts, FakeSignInFailureBudget,
        FakeTrustedDeviceStore, RecordingPause, RevocationSwitch,
    };
    use crate::test_support::oauth::hash_of;
    use crate::test_support::organization::{
        FakeOrgTenantGrantStore, FakeOrgTokenStore, FakeOrgUserStore, FakeOrganizationStore,
        OrgShape, RecordingOrgSessionStore, cfg, org_shaped, org_store_with, org_user_store_with,
        test_org,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, FakeMailer, block_on, test_auditor,
    };

    const PASSWORD: &str = "correct";
    const SOLVED: &str = "solved-puzzle-0042";
    const ALICE: &str = "alice@acme.com";
    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Alice in `role`, standing at `status`, her address as `standing`
    /// says, signing in with [`PASSWORD`].
    fn alice(
        organization_id: OrganizationId,
        role: OrgRole,
        status: OrgUserStatus,
        standing: AddressStanding,
    ) -> OrgUser {
        let now = clock::now();
        OrgUser::reconstitute(OrgUserRow {
            id: OrgUserId::new(),
            organization_id,
            email: Email::new(ALICE).unwrap(),
            display_name: DisplayName::new("Alice", &cfg().display_name).unwrap(),
            password_hash: OrgPassword::Set(FakeHasher.hash(PASSWORD).unwrap()),
            status,
            role,
            email_standing: standing,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining: joining_at(status, now),
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        })
        .unwrap()
    }

    /// How far an account standing at `status` got by `now`: one still
    /// waiting on its address has not joined, any other joined then.
    fn joining_at(status: OrgUserStatus, now: time::OffsetDateTime) -> Joining {
        match status {
            OrgUserStatus::PendingVerification => Joining::NotYet,
            OrgUserStatus::Invited
            | OrgUserStatus::Active
            | OrgUserStatus::Locked
            | OrgUserStatus::Deactivated
            | OrgUserStatus::Closing => Joining::Joined { at: now },
        }
    }

    fn owner(organization_id: OrganizationId) -> OrgUser {
        alice(
            organization_id,
            OrgRole::Owner,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        )
    }

    /// Alice, an owner of `organization_id` on the same address, keeping
    /// `password` there.
    fn owner_keeping(organization_id: OrganizationId, password: &str) -> OrgUser {
        OrgUser::reconstitute(owner_row(organization_id, password)).unwrap()
    }

    /// Olive, the owner the install made, right after its setup token
    /// confirmed her: the token vouches for her first sign-in.
    fn owner_just_confirmed(organization_id: OrganizationId) -> OrgUser {
        OrgUser::reconstitute(OrgUserRow {
            vouching: Vouching::Fresh,
            ..owner_row(organization_id, PASSWORD)
        })
        .unwrap()
    }

    /// The stored row of an active owner of `organization_id` at [`ALICE`],
    /// keeping `password`, whom nothing vouches for.
    fn owner_row(organization_id: OrganizationId, password: &str) -> OrgUserRow {
        let now = clock::now();
        OrgUserRow {
            id: OrgUserId::new(),
            organization_id,
            email: Email::new(ALICE).unwrap(),
            display_name: DisplayName::new("Alice", &cfg().display_name).unwrap(),
            password_hash: OrgPassword::Set(FakeHasher.hash(password).unwrap()),
            status: OrgUserStatus::Active,
            role: OrgRole::Owner,
            email_standing: AddressStanding::Verified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining: Joining::Joined { at: now },
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        }
    }

    /// A device of `member` whose secret is [`SECRET`], in `status`.
    fn remembered(member: &OrgUser, status: DeviceStatus) -> TrustedDevice<ResolvedOrganization> {
        let now = clock::now();
        TrustedDevice::reconstitute(TrustedDeviceRow {
            id: TrustedDeviceId::new(),
            subject_id: PrincipalId::from(*member.id()),
            secret_hash: hash_of(SECRET),
            device_name: Label::new("device_name", "Alice's laptop").unwrap(),
            last_user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            last_ip: IpAddress::new("10.0.0.1").unwrap(),
            status,
            last_seen_at: now,
            created_at: now,
        })
        .unwrap()
    }

    fn grant(member: &OrgUser, tenant: &Tenant) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *member.id(),
            tenant_id: *tenant.id(),
            role_id: RoleId::new(),
            granted_by: ActedBy::Platform,
            granted_at: clock::now(),
        })
        .unwrap()
    }

    fn relaxed(settings: OrganizationAuthSettings) -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            step_up_policy: StepUpPolicy::relaxed(),
            ..settings
        }
    }

    /// Acme, its member Alice and its tenants, as a test arranges them.
    struct Scene {
        organization_id: OrganizationId,
        settings: OrganizationAuthSettings,
        suspension: Suspension,
        member: OrgUser,
        tenants: Vec<Tenant>,
        enrollments: FakeMfaEnrollmentStore,
        devices: FakeTrustedDeviceStore,
        grants: FakeOrgTenantGrantStore,
        sessions: RecordingOrgSessionStore,
        elsewhere: Vec<(OrgUser, Organization)>,
        failures: Arc<FakeSignInFailureBudget>,
        challenges: Option<Arc<dyn ChallengeVerifier>>,
        permits: Arc<dyn PasswordHashPermits>,
        mail: Arc<dyn MailSetup>,
        counts: Arc<FakeSignInAttemptCounts>,
    }

    impl Scene {
        /// Alice, an owner of Acme, which owns the `production` tenant and
        /// signs members in as a new organization does.
        fn acme() -> Self {
            let organization_id = OrganizationId::new();
            Self::with_member(owner(organization_id))
        }

        fn with_member(member: OrgUser) -> Self {
            let organization_id = *member.organization_id();
            Self {
                organization_id,
                settings: OrganizationAuthSettings::default(),
                suspension: Suspension::NotSuspended,
                member,
                tenants: vec![test_tenant_in(
                    organization_id,
                    "production",
                    "production.com",
                )],
                enrollments: FakeMfaEnrollmentStore::empty(),
                devices: FakeTrustedDeviceStore::empty(),
                grants: FakeOrgTenantGrantStore::empty(),
                sessions: RecordingOrgSessionStore::new(),
                elsewhere: Vec::new(),
                failures: Arc::new(FakeSignInFailureBudget::default()),
                challenges: Some(Arc::new(FakeChallengeVerifier::accepting(SOLVED))),
                permits: Arc::new(FakeHashPermits::default()),
                mail: Fake::fake(),
                counts: Arc::new(FakeSignInAttemptCounts::default()),
            }
        }

        /// Failures against Alice's account from twenty networks, twice
        /// Acme's limit of ten a network, as a botnet leaves them: her
        /// account is under attack.
        fn under_attack(self) -> Self {
            let account = CountedAccount::Organization {
                organization: &self.organization_id,
                email: self.member.email(),
            };
            let counts = Arc::new(FakeSignInAttemptCounts::guessed_from_networks(account, 20));
            Self { counts, ..self }
        }

        fn settings(self, settings: OrganizationAuthSettings) -> Self {
            Self { settings, ..self }
        }

        /// A deployment with no mail server.
        fn without_mail(self) -> Self {
            Self {
                mail: FakeMailSetup::not_set_up(),
                ..self
            }
        }

        /// Sign-ins naming no organization under high pressure: ten
        /// failures counted against the deployment's threshold of ten.
        fn flooded(self) -> Self {
            self.failing(FailureScope::UnnamedOrganizations)
        }

        /// Ten failures counted against `scope`.
        fn failing(self, scope: FailureScope) -> Self {
            Self {
                failures: Arc::new(FakeSignInFailureBudget::over(scope, 10)),
                ..self
            }
        }

        /// Alice holds an account on her address in Globex too, keeping
        /// `password` there.
        fn also_at_globex(mut self, password: &str) -> Self {
            let globex = test_org(OrganizationId::new(), "globex");
            let alice = owner_keeping(*globex.id(), password);
            self.elsewhere.push((alice, globex));
            self
        }

        fn enrolled(self) -> Self {
            let enrollments = FakeMfaEnrollmentStore::active_for(*self.member.id());
            Self {
                enrollments,
                ..self
            }
        }

        fn remembering(self, status: DeviceStatus) -> Self {
            let devices =
                FakeTrustedDeviceStore::holding_members([remembered(&self.member, status)]);
            Self { devices, ..self }
        }

        /// Wires the arranged accounts into a sign-in with observable stores.
        fn build(self) -> Setup {
            let hasher = Arc::new(CountingHasher::default());
            let password = self.password_checks(&hasher);
            let accounts = account_stores(self.organization(), self.member, self.elsewhere);
            let sessions = Arc::new(self.sessions);
            let grants = Arc::new(self.grants);
            let devices = Arc::new(self.devices);
            let mailer = Arc::new(FakeMailer::new());
            let links = Arc::new(FakeOrgTokenStore::<SignInConfirmation>::empty());
            let ports = OrgPasswordLoginPorts {
                members: accounts.members.clone(),
                organizations: accounts.organizations,
                tenants: Arc::new(FakeTenantStore::holding_all(self.tenants)),
                confirmation: confirmation_mail(&links, &mailer, self.mail),
                password,
                factors: login_factors(self.enrollments, &devices),
                session: session_opening(&sessions, &grants),
                ..OrgPasswordLoginPorts::fakes()
            };
            Setup {
                uc: OrgPasswordLoginUseCase::new(ports, login_settings()),
                members: accounts.members,
                sessions,
                grants,
                devices,
                mailer,
                links,
                audit: Arc::new(FakeEventDispatcher::new()),
                failures: self.failures,
                hasher,
            }
        }

        /// Takes a snapshot of Acme's settings and tenant layout for sign-in.
        fn organization(&self) -> Organization {
            org_shaped(
                self.organization_id,
                OrgShape {
                    tenants: self.tenants.iter().map(|tenant| *tenant.id()).collect(),
                    settings: self.settings.clone(),
                    suspension: self.suspension,
                },
            )
        }

        /// Shares the arranged hash permits, challenge provider and failure counts.
        fn password_checks(&self, hasher: &Arc<CountingHasher>) -> OrgPasswordCheckPorts {
            OrgPasswordCheckPorts {
                hashing: PasswordHashing::new(hasher.clone(), self.permits.clone()),
                flood: FloodGatePorts {
                    failures: self.failures.clone(),
                    challenges: self.challenges.clone(),
                },
                attempts: SignInCounts::new(
                    self.counts.clone(),
                    Arc::new(RecordingPause::default()),
                ),
            }
        }
    }

    /// Accounts and organizations sharing the sign-in address.
    struct AccountStores {
        members: Arc<FakeOrgUserStore>,
        organizations: Arc<FakeOrganizationStore>,
    }

    /// Stores Acme's account together with the arranged accounts elsewhere.
    fn account_stores(
        organization: Organization,
        member: OrgUser,
        elsewhere: Vec<(OrgUser, Organization)>,
    ) -> AccountStores {
        let (others, other_orgs): (Vec<_>, Vec<_>) = elsewhere.into_iter().unzip();
        AccountStores {
            members: Arc::new(org_user_store_with(std::iter::once(member).chain(others))),
            organizations: org_store_with(std::iter::once(organization).chain(other_orgs)),
        }
    }

    /// Keeps confirmation links and outgoing mail visible to the test.
    fn confirmation_mail(
        links: &Arc<FakeOrgTokenStore<SignInConfirmation>>,
        mailer: &Arc<FakeMailer>,
        mail: Arc<dyn MailSetup>,
    ) -> OrgConfirmationMailPorts {
        OrgConfirmationMailPorts {
            links: links.clone(),
            mailer: mailer.clone(),
            mail,
            ..OrgConfirmationMailPorts::fakes()
        }
    }

    /// Checks the arranged authenticator and remembered devices at sign-in.
    fn login_factors(
        enrollments: FakeMfaEnrollmentStore,
        devices: &Arc<FakeTrustedDeviceStore>,
    ) -> OrgLoginFactorPorts {
        OrgLoginFactorPorts {
            enrollments: Arc::new(enrollments),
            devices: devices.clone(),
            ..OrgLoginFactorPorts::fakes()
        }
    }

    /// Opens sessions using the test's grants and recording session store.
    fn session_opening(
        sessions: &Arc<RecordingOrgSessionStore>,
        grants: &Arc<FakeOrgTenantGrantStore>,
    ) -> OrgSessionOpeningPorts {
        OrgSessionOpeningPorts {
            sessions: sessions.clone(),
            grants: grants.clone(),
            ..OrgSessionOpeningPorts::fakes()
        }
    }

    fn login_settings() -> OrgLoginSettings {
        OrgLoginSettings {
            device_trust: TrustWindow::standard(),
            confirmation: ConfirmationLinkPolicy {
                lifetime: Lifetime::seconds(900).unwrap(),
                base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
            },
            unnamed_threshold: FailureThreshold::new(10).unwrap(),
        }
    }

    struct Setup {
        uc: OrgPasswordLoginUseCase,
        members: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        grants: Arc<FakeOrgTenantGrantStore>,
        devices: Arc<FakeTrustedDeviceStore>,
        mailer: Arc<FakeMailer>,
        links: Arc<FakeOrgTokenStore<SignInConfirmation>>,
        audit: Arc<FakeEventDispatcher>,
        failures: Arc<FakeSignInFailureBudget>,
        hasher: Arc<CountingHasher>,
    }

    impl Setup {
        fn outcome(&self, request: OrgPasswordLoginRequest) -> Result<OrgLoginOutcome, AppError> {
            block_on(
                self.uc
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn sign_in(&self, request: OrgPasswordLoginRequest) -> Result<OrgLoginSuccess, AppError> {
            self.outcome(request).map(|outcome| match outcome {
                OrgLoginOutcome::SignedIn(success) => *success,
                OrgLoginOutcome::ChooseOrganization(_) => panic!("Alice is asked to choose"),
            })
        }

        fn sign_in_with(&self, password: &str) -> Result<OrgLoginSuccess, AppError> {
            self.sign_in(typed(password))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        /// Whether a route still vouches for the member `id` as stored now.
        fn vouching_of(&self, id: &OrgUserId) -> Vouching {
            block_on(self.members.find_by_id(id))
                .unwrap()
                .unwrap()
                .vouching()
        }

        fn unnamed_failures(&self) -> u64 {
            self.failures.counted(&FailureScope::UnnamedOrganizations)
        }

        fn first_session(&self) -> OrgSession {
            self.sessions.saved().into_iter().next().unwrap()
        }
    }

    fn typed(password: &str) -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            email: Email::new(ALICE).unwrap(),
            password: Secret::new(password),
            organization: OrganizationChoice::Unnamed,
            tenant_slug: None,
            device_secret: None,
            challenge: None,
            origin: ClientOrigin::default(),
        }
    }

    fn proving(proof: &str, request: OrgPasswordLoginRequest) -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            challenge: Some(ChallengeProof::new(proof).unwrap()),
            ..request
        }
    }

    fn nobody() -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            email: Email::new("nobody@acme.com").unwrap(),
            ..typed("guess")
        }
    }

    /// Alice's sign-in with [`PASSWORD`], naming the organization `slug`.
    fn choosing(slug: &str) -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            organization: OrganizationChoice::Named(TenantSlug::new(slug, &cfg().slug).unwrap()),
            ..typed(PASSWORD)
        }
    }

    fn from_ip(ip: &str) -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            origin: ClientOrigin {
                ip_address: Fact::Known(IpAddress::new(ip).unwrap()),
                user_agent: None,
            },
            ..typed(PASSWORD)
        }
    }

    fn from_device(secret: &str) -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            device_secret: Some(DeviceSecret::new(secret).unwrap()),
            ..typed(PASSWORD)
        }
    }

    fn naming(slug: &str) -> OrgPasswordLoginRequest {
        OrgPasswordLoginRequest {
            tenant_slug: Some(TenantSlug::new(slug, &cfg().slug).unwrap()),
            ..typed(PASSWORD)
        }
    }

    fn allowing_only_ten() -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            ip_allowlist: vec![CidrRange::new("10.0.0.0/8").unwrap()],
            ..OrganizationAuthSettings::default()
        }
    }

    fn three_attempts() -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            max_login_attempts: 3,
            ..OrganizationAuthSettings::default()
        }
    }

    fn mfa(policy: MfaPolicy) -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            mfa_policy: policy,
            ..OrganizationAuthSettings::default()
        }
    }

    /// Alice, an owner of Acme, signs in with her password. A session opens
    /// in Acme's only tenant and the sign-in is recorded.
    #[test]
    fn the_right_password_opens_a_session() {
        let setup = Scene::acme().build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(setup.sessions.count(), 1);
        assert_eq!(*setup.first_session().id(), success.session_id);
        assert_eq!(setup.recorded(), ["organization.org_login_succeeded"]);
    }

    /// Settings where Acme signs its members in through single sign-on.
    fn sso_enforced() -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Saml],
            sso: SsoEnforcement::Enforced,
            ..OrganizationAuthSettings::default()
        }
    }

    /// When Acme enforces single sign-on, a plain member's correct
    /// password is forbidden and opens no session.
    #[test]
    fn enforced_single_sign_on_refuses_a_members_password() {
        let bob = alice(
            OrganizationId::new(),
            OrgRole::Member,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let setup = Scene::with_member(bob)
            .settings(relaxed(sso_enforced()))
            .build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Alice, an owner, keeps her password under enforced single sign-on,
    /// so a broken identity provider never locks the organization out.
    #[test]
    fn enforced_single_sign_on_lets_an_owner_use_the_password() {
        let setup = Scene::acme().settings(relaxed(sso_enforced())).build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(result.is_ok());
        assert_eq!(setup.sessions.count(), 1);
    }

    /// Alice's session names Acme by slug and name, so the dashboard opens
    /// on the right organization.
    #[test]
    fn the_success_names_the_organization() {
        let setup = Scene::acme().build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.org_slug.as_str(), "acme-corp");
        assert_eq!(success.organization_name.as_str(), "Acme");
        assert_eq!(success.tenant.slug().unwrap().as_str(), "production");
    }

    /// A wrong password returns not found, records a failed sign-in
    /// against Alice and opens no session.
    #[test]
    fn a_wrong_password_is_refused_and_recorded() {
        let setup = Scene::acme().build();

        let result = setup.sign_in_with("wrong");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.recorded(), ["organization.org_login_failed"]);
        assert_eq!(setup.sessions.count(), 0);
    }

    /// An unknown address returns the same not-found message as a wrong
    /// password and adds no audit event.
    #[test]
    fn an_unknown_address_answers_like_a_wrong_password() {
        let setup = Scene::acme().build();
        let wrong = setup.sign_in_with("wrong");

        let unknown = setup.sign_in(OrgPasswordLoginRequest {
            email: Email::new("nobody@acme.com").unwrap(),
            ..typed("any")
        });

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b))) = (&wrong, &unknown) else {
            panic!("both are refused as invalid credentials");
        };
        assert_eq!(a, b);
        assert_eq!(setup.recorded(), ["organization.org_login_failed"]);
    }

    /// After three wrong guesses reach Acme's configured limit, even
    /// Alice's correct password returns not found.
    #[test]
    fn the_lockout_the_organization_set_is_enforced() {
        let setup = Scene::acme().settings(three_attempts()).build();
        for _ in 0..3 {
            let _ = setup.sign_in_with("wrong");
        }

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// After three guesses lock Alice's account, her correct password and
    /// an unknown address return the same not-found message.
    #[test]
    fn a_locked_out_address_answers_like_an_unknown_one() {
        let setup = Scene::acme().settings(three_attempts()).build();
        for _ in 0..3 {
            let _ = setup.sign_in_with("wrong");
        }

        let locked = setup.sign_in_with(PASSWORD);
        let unknown = setup.sign_in(OrgPasswordLoginRequest {
            email: Email::new("nobody@acme.com").unwrap(),
            ..typed("any")
        });

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b))) = (&locked, &unknown) else {
            panic!("both are refused as invalid credentials");
        };
        assert_eq!(a, b);
    }

    /// Alice mistypes twice where Acme allows three. Her account stays
    /// usable.
    #[test]
    fn failures_below_the_threshold_do_not_lock_the_account() {
        let setup = Scene::acme().settings(three_attempts()).build();
        for _ in 0..2 {
            let _ = setup.sign_in_with("wrong");
        }

        assert!(setup.sign_in_with(PASSWORD).is_ok());
    }

    /// Alice mistypes twice, signs in, then mistypes twice again. Her right
    /// password cleared the count, so she is not locked out.
    #[test]
    fn a_correct_password_clears_the_counter() {
        let setup = Scene::acme().settings(three_attempts()).build();
        let _ = setup.sign_in_with("wrong");
        let _ = setup.sign_in_with("wrong");
        setup.sign_in_with(PASSWORD).unwrap();
        let _ = setup.sign_in_with("wrong");
        let _ = setup.sign_in_with("wrong");

        assert!(setup.sign_in_with(PASSWORD).is_ok());
    }

    /// Mallory guesses Alice's password five times from her own network,
    /// which is then locked out even with the right password. Alice, from
    /// another network, still signs in with hers.
    #[test]
    fn a_guessers_lockout_never_locks_the_owner_out() {
        let setup = Scene::acme().settings(three_attempts()).build();
        let mallory = |password: &str| OrgPasswordLoginRequest {
            password: Secret::new(password),
            ..from_ip("198.51.100.66")
        };
        for _ in 0..5 {
            let _ = setup.sign_in(mallory("wrong"));
        }

        let mallory_right = setup.sign_in(mallory(PASSWORD));
        let alice = setup.sign_in(from_ip("203.0.113.7"));

        assert!(
            matches!(mallory_right, Err(AppError::NotFound(_))),
            "{:?}",
            mallory_right.as_ref().err()
        );
        assert!(alice.is_ok(), "{:?}", alice.as_ref().err());
    }

    /// With passkeys as the organization's only sign-in method, Alice's
    /// correct password returns not found and opens no session.
    #[test]
    fn an_organization_that_refuses_passwords_refuses_the_right_one() {
        let settings = OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Passkey],
            ..OrganizationAuthSettings::default()
        };
        let setup = Scene::acme().settings(settings).build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Outside Acme's allowed networks, correct and wrong passwords
    /// return the same not-found message and open no session.
    #[test]
    fn an_address_outside_the_allowlist_is_refused() {
        let setup = Scene::acme().settings(allowing_only_ten()).build();

        let right = setup.sign_in(from_ip("203.0.113.5"));
        let wrong = setup.sign_in(OrgPasswordLoginRequest {
            password: Secret::new("wrong"),
            ..from_ip("203.0.113.5")
        });

        let (Err(AppError::NotFound(a)), Err(AppError::NotFound(b))) = (&right, &wrong) else {
            panic!("both are refused as invalid credentials");
        };
        assert_eq!(a, b);
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Three wrong guesses outside Acme's allowed networks do not prevent
    /// Alice from signing in with her correct password from the office.
    #[test]
    fn guesses_from_outside_the_allowlist_never_lock_the_account() {
        let settings = OrganizationAuthSettings {
            max_login_attempts: 3,
            ..allowing_only_ten()
        };
        let setup = Scene::acme().settings(settings).build();
        for _ in 0..3 {
            let _ = setup.sign_in(OrgPasswordLoginRequest {
                password: Secret::new("wrong"),
                ..from_ip("203.0.113.5")
            });
        }

        assert!(setup.sign_in(from_ip("10.1.2.3")).is_ok());
    }

    /// Alice signs in from inside the network Acme allows. She is let in.
    #[test]
    fn an_address_inside_the_allowlist_is_admitted() {
        let setup = Scene::acme().settings(allowing_only_ten()).build();

        assert!(setup.sign_in(from_ip("10.1.2.3")).is_ok());
    }

    /// When Acme restricts sign-in to listed networks, a request with no
    /// known IP address returns not found even with the correct password.
    #[test]
    fn an_unknown_address_is_refused_when_an_allowlist_exists() {
        let setup = Scene::acme().settings(allowing_only_ten()).build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Acme never listed networks. Alice signs in from anywhere.
    #[test]
    fn an_empty_allowlist_admits_every_address() {
        let setup = Scene::acme().build();

        assert!(setup.sign_in(from_ip("203.0.113.5")).is_ok());
    }

    /// Acme keeps sessions for fifteen minutes. Alice's session ends when
    /// Acme said, not on a server-wide default.
    #[test]
    fn the_session_lifetime_the_organization_set_is_the_one_issued() {
        let settings = OrganizationAuthSettings {
            session_lifetime_secs: Seconds::new(900),
            idle_timeout_secs: Seconds::new(300),
            ..OrganizationAuthSettings::default()
        };
        let setup = Scene::acme().settings(settings).build();

        setup.sign_in_with(PASSWORD).unwrap();

        let session = setup.first_session();
        let drift =
            (session.expires_at() - session.created_at() - time::Duration::seconds(900)).abs();
        assert!(drift < time::Duration::seconds(1));
    }

    /// Alice's correct password cannot open a session while her address
    /// is unconfirmed; the refusal asks her to verify her email.
    #[test]
    fn an_unconfirmed_address_is_refused_after_the_password() {
        let organization_id = OrganizationId::new();
        let unconfirmed = alice(
            organization_id,
            OrgRole::Owner,
            OrgUserStatus::Active,
            AddressStanding::Unverified,
        );
        let setup = Scene::with_member(unconfirmed).build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::EmailNotVerified)));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Alice still waits to confirm her address, on a deployment that can
    /// mail her the link. Her right password is refused until she follows
    /// it.
    #[test]
    fn a_waiting_member_is_refused_where_mail_goes_out() {
        let organization_id = OrganizationId::new();
        let waiting = alice(
            organization_id,
            OrgRole::Owner,
            OrgUserStatus::PendingVerification,
            AddressStanding::Unverified,
        );
        let setup = Scene::with_member(waiting).build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::EmailNotVerified)));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// A member still awaiting verification is forbidden from signing in
    /// even without a mail server, and no session opens.
    #[test]
    fn a_waiting_member_is_refused_where_nothing_is_mailed() {
        let organization_id = OrganizationId::new();
        let waiting = alice(
            organization_id,
            OrgRole::Owner,
            OrgUserStatus::PendingVerification,
            AddressStanding::Unverified,
        );
        let setup = Scene::with_member(waiting)
            .settings(relaxed(OrganizationAuthSettings::default()))
            .without_mail()
            .build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Alice's address was never confirmed, on a deployment with no mail
    /// server where no link could confirm it. Her right password signs her
    /// in, and the address stays unverified.
    #[test]
    fn an_unconfirmed_address_signs_in_where_nothing_is_mailed() {
        let organization_id = OrganizationId::new();
        let unconfirmed = alice(
            organization_id,
            OrgRole::Owner,
            OrgUserStatus::Active,
            AddressStanding::Unverified,
        );
        let setup = Scene::with_member(unconfirmed)
            .settings(relaxed(OrganizationAuthSettings::default()))
            .without_mail()
            .build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert_eq!(setup.sessions.count(), 1);
    }

    /// A locked member's correct password returns not found.
    #[test]
    fn a_locked_member_is_refused_as_for_a_wrong_password() {
        let organization_id = OrganizationId::new();
        let locked = alice(
            organization_id,
            OrgRole::Owner,
            OrgUserStatus::Locked,
            AddressStanding::Verified,
        );
        let setup = Scene::with_member(locked).build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Acme has a second factor as optional and asks for more on nothing
    /// in particular. Alice, who set none up, goes straight in and is told
    /// what she reaches.
    #[test]
    fn an_optional_factor_is_never_asked_of_someone_without_one() {
        let setup = Scene::acme()
            .settings(relaxed(OrganizationAuthSettings::default()))
            .build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert!(success.access.is_some());
        assert!(setup.first_session().mfa_satisfied());
    }

    /// Acme requires a second factor and Alice has none. Her session can
    /// only set one up: she is told nothing about Acme's tenants yet.
    #[test]
    fn a_required_factor_is_set_up_by_someone_without_one() {
        let setup = Scene::acme()
            .settings(relaxed(mfa(MfaPolicy::Required)))
            .build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Enrol);
        assert!(success.access.is_none());
        assert!(!setup.first_session().mfa_satisfied());
    }

    /// Acme requires a second factor and Alice has one. Her password alone
    /// does not count as past it, whatever device she uses.
    #[test]
    fn requiring_mfa_asks_every_enrolled_member() {
        let setup = Scene::acme()
            .settings(mfa(MfaPolicy::Required))
            .enrolled()
            .remembering(DeviceStatus::Trusted)
            .build();

        let success = setup.sign_in(from_device(SECRET)).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
        assert!(!setup.first_session().mfa_satisfied());
    }

    /// Acme switched second factors off and asks for more on nothing in
    /// particular. Alice, who has one, is not asked for it.
    #[test]
    fn switching_mfa_off_stops_the_challenge() {
        let setup = Scene::acme()
            .settings(relaxed(mfa(MfaPolicy::Disabled)))
            .enrolled()
            .build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
    }

    /// Alice set a factor up and signs in from a device she never
    /// remembered. Acme asks new devices for more, so she is asked for her
    /// factor.
    #[test]
    fn an_enrolled_member_on_an_unknown_device_is_asked_for_her_factor() {
        let setup = Scene::acme().enrolled().build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Alice set a factor up and signs in from the laptop she remembered.
    /// It spares her the factor.
    #[test]
    fn a_remembered_device_spares_an_enrolled_member_the_challenge() {
        let setup = Scene::acme()
            .enrolled()
            .remembering(DeviceStatus::Trusted)
            .build();

        let success = setup.sign_in(from_device(SECRET)).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert!(success.access.is_some());
    }

    /// Alice signs in on her remembered laptop from the office, with a newer
    /// browser. The laptop is stamped as just used, with that browser and
    /// address, so it keeps counting while she uses it.
    #[test]
    fn a_sign_in_on_a_remembered_device_stamps_the_device() {
        let scene = Scene::acme().remembering(DeviceStatus::Trusted);
        let alice = *scene.member.id();
        let setup = scene.build();
        let request = OrgPasswordLoginRequest {
            origin: ClientOrigin {
                ip_address: Fact::Known(IpAddress::new("198.51.100.4").unwrap()),
                user_agent: Some(UserAgent::new("Mozilla/6.0").unwrap()),
            },
            ..from_device(SECRET)
        };

        setup.sign_in(request).unwrap();

        let laptop = block_on(setup.devices.list_by_user(&alice))
            .unwrap()
            .remove(0);
        assert_eq!(laptop.last_ip().as_str(), "198.51.100.4");
        assert_eq!(laptop.last_user_agent().as_str(), "Mozilla/6.0");
    }

    /// A revoked device secret does not spare an enrolled member the
    /// second-factor challenge after a correct password.
    #[test]
    fn a_forgotten_device_is_not_a_remembered_one() {
        let setup = Scene::acme()
            .enrolled()
            .remembering(DeviceStatus::Revoked)
            .build();

        let success = setup.sign_in(from_device(SECRET)).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// A secret that differs from Alice's trusted device secret still
    /// requires her second factor after the correct password.
    #[test]
    fn a_secret_matching_nothing_is_not_remembered() {
        let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let setup = Scene::acme()
            .enrolled()
            .remembering(DeviceStatus::Trusted)
            .build();

        let success = setup.sign_in(from_device(other)).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Omitting the device secret requires Alice's second factor even
    /// though she has a trusted device.
    #[test]
    fn sending_no_secret_is_not_remembered() {
        let setup = Scene::acme()
            .enrolled()
            .remembering(DeviceStatus::Trusted)
            .build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Verify);
    }

    /// Alice has no second factor and signs in from a new device to an
    /// organization that asks new devices for more. Setting a factor up
    /// there and then would prove nothing, so she owes a confirmation by
    /// email.
    #[test]
    fn a_new_device_without_a_factor_owes_a_confirmation_by_email() {
        let setup = Scene::acme().build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::ConfirmByEmail);
        assert!(success.access.is_none());
    }

    /// With guesses reported from twenty networks, a correct password on
    /// a new device requires Alice's factor even under relaxed settings.
    /// The account attack is recorded.
    #[test]
    fn under_attack_a_right_guess_from_a_new_device_owes_the_factor() {
        let setup = Scene::acme()
            .settings(relaxed(OrganizationAuthSettings::default()))
            .enrolled()
            .under_attack()
            .build();

        let botnet = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(botnet.second_factor, SecondFactor::Verify);
        assert!(
            setup
                .recorded()
                .contains(&"organization.org_account_under_attack".to_owned())
        );
    }

    /// Alice signs in on the laptop she remembered while her account is
    /// under attack. She is asked for nothing more.
    #[test]
    fn under_attack_a_remembered_device_goes_straight_in() {
        let setup = Scene::acme()
            .settings(relaxed(OrganizationAuthSettings::default()))
            .enrolled()
            .remembering(DeviceStatus::Trusted)
            .under_attack()
            .build();

        let alice = setup.sign_in(from_device(SECRET)).unwrap();

        assert_eq!(alice.second_factor, SecondFactor::NotOwed);
    }

    /// Alice, with no factor, signs in from her new phone while her account
    /// is under attack. The sign-in waits for the link mailed to her.
    #[test]
    fn under_attack_a_new_device_without_a_factor_confirms_by_mail() {
        let setup = Scene::acme()
            .settings(relaxed(OrganizationAuthSettings::default()))
            .under_attack()
            .build();

        let alice = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(alice.second_factor, SecondFactor::ConfirmByEmail);
        assert_eq!(setup.mailer.count(), 1);
    }

    /// Under attack, a member without a factor cannot sign in with a
    /// correct password when no mail server is available. The refusal asks
    /// for a new invitation and opens no session.
    #[test]
    fn under_attack_without_a_factor_or_mail_is_refused() {
        let setup = Scene::acme()
            .settings(relaxed(OrganizationAuthSettings::default()))
            .without_mail()
            .under_attack()
            .build();

        let refused = setup.sign_in_with(PASSWORD);

        assert!(matches!(
            refused,
            Err(AppError::Forbidden(message)) if message.as_str().contains("new invitation")
        ));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// The botnet keeps guessing at Alice's account. Its attack is recorded
    /// by the first attempt that finds it, and by none after.
    #[test]
    fn under_attack_the_attack_is_recorded_once() {
        let setup = Scene::acme().under_attack().build();

        for _ in 0..3 {
            let _ = setup.sign_in_with("guess");
        }

        let found = setup
            .recorded()
            .iter()
            .filter(|name| *name == "organization.org_account_under_attack")
            .count();
        assert_eq!(found, 1);
    }

    /// A new device cannot sign in with Alice's correct password when she
    /// has no factor and no mail server is available. The refusal asks for
    /// a new invitation and opens no session. No link is stored or mailed,
    /// and a failed sign-in is recorded.
    #[test]
    fn a_new_device_without_a_factor_or_mail_is_refused() {
        let setup = Scene::acme().without_mail().build();

        let refused = setup.sign_in_with(PASSWORD);

        assert!(matches!(
            refused,
            Err(AppError::Forbidden(message)) if message.as_str().contains("new invitation")
        ));
        assert_eq!(setup.sessions.count(), 0);
        assert_eq!(setup.links.count(), 0);
        assert_eq!(setup.mailer.count(), 0);
        assert_eq!(setup.recorded(), ["organization.org_login_failed"]);
    }

    /// Olive installed the platform with no mail server and confirmed
    /// herself with the setup token. Her first sign-in, from a new device,
    /// gets in owing a factor she sets up there and then, and spends what
    /// the token vouched for: her next risky sign-in must use that factor.
    #[test]
    fn the_owner_fresh_from_the_install_gets_in_and_sets_up_a_factor() {
        let olive = owner_just_confirmed(OrganizationId::new());
        let olive_id = *olive.id();
        let setup = Scene::with_member(olive).without_mail().build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.second_factor, SecondFactor::Enrol);
        assert!(success.access.is_none());
        assert_eq!(setup.sessions.count(), 1);
        assert_eq!(setup.mailer.count(), 0);
        assert_eq!(setup.vouching_of(&olive_id), Vouching::Absent);
    }

    /// Olive's setup token vouches for one sign-in only. After it, a second
    /// risky sign-in with no factor and no mail is refused.
    #[test]
    fn the_install_vouches_for_the_first_sign_in_only() {
        let olive = owner_just_confirmed(OrganizationId::new());
        let setup = Scene::with_member(olive).without_mail().build();
        setup.sign_in_with(PASSWORD).unwrap();

        let again = setup.sign_in_with(PASSWORD);

        assert!(matches!(again, Err(AppError::Forbidden(_))));
    }

    /// Alice's sign-in from a new device waits for her to confirm it. One
    /// link is kept for her and mailed to her own address, opening the
    /// organization's confirmation page.
    #[test]
    fn a_sign_in_owing_a_confirmation_mails_one_link() {
        let setup = Scene::acme().build();

        setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(setup.links.count(), 1);
        assert_eq!(setup.mailer.recipients(), [ALICE]);
        assert!(setup.mailer.action_url().contains("confirm-sign-in"));
    }

    /// Alice has a second factor. Her sign-in asks for it, and no
    /// confirmation link is mailed.
    #[test]
    fn a_sign_in_owing_a_code_mails_no_link() {
        let setup = Scene::acme().enrolled().build();

        setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(setup.links.count(), 0);
        assert_eq!(setup.mailer.count(), 0);
    }

    /// Acme owns a tenant still being set up, listed first, and an active
    /// one. Alice lands in the active one.
    #[test]
    fn an_active_tenant_is_chosen_over_one_listed_ahead_of_it() {
        let mut scene = Scene::acme();
        let mut production = test_tenant_in(scene.organization_id, "production", "prod.com");
        production.activate(ActedBy::Platform).unwrap();
        scene.tenants = vec![
            test_tenant_in(scene.organization_id, "staging", "staging.com"),
            production,
        ];
        let setup = scene.build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.tenant.slug().unwrap().as_str(), "production");
    }

    /// Alice names the staging tenant. Her session opens there.
    #[test]
    fn a_named_tenant_is_the_one_signed_in_to() {
        let mut scene = Scene::acme();
        scene.tenants.push(test_tenant_in(
            scene.organization_id,
            "staging",
            "staging.com",
        ));
        let setup = scene.build();

        let success = setup.sign_in(naming("staging")).unwrap();

        assert_eq!(success.tenant.slug().unwrap().as_str(), "staging");
    }

    /// Naming a tenant Acme does not have returns not found and opens no session.
    #[test]
    fn a_tenant_the_organization_lacks_is_not_found() {
        let setup = Scene::acme().build();

        let result = setup.sign_in(naming("nonexistent"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// A wrong password returns not found even when Acme has two tenants.
    #[test]
    fn a_wrong_password_reveals_no_tenants() {
        let mut scene = Scene::acme();
        scene.tenants.push(test_tenant_in(
            scene.organization_id,
            "staging",
            "staging.com",
        ));
        let setup = scene.build();

        let result = setup.sign_in_with("wrong");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A plain member granted only staging is forbidden from signing in
    /// to production, and no session opens.
    #[test]
    fn a_plain_member_is_refused_a_tenant_without_a_grant() {
        let organization_id = OrganizationId::new();
        let sam = alice(
            organization_id,
            OrgRole::Member,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let mut scene = Scene::with_member(sam);
        let staging = test_tenant_in(organization_id, "staging", "staging.com");
        scene.grants = FakeOrgTenantGrantStore::holding([grant(&scene.member, &staging)]);
        scene.tenants.push(staging);
        let setup = scene.build();

        let result = setup.sign_in(naming("production"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Sam, a plain member granted only staging, names no tenant. He lands
    /// in staging, though production is listed first.
    #[test]
    fn a_plain_member_lands_in_a_tenant_they_were_granted() {
        let organization_id = OrganizationId::new();
        let sam = alice(
            organization_id,
            OrgRole::Member,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let mut scene = Scene::with_member(sam);
        let staging = test_tenant_in(organization_id, "staging", "staging.com");
        scene.grants = FakeOrgTenantGrantStore::holding([grant(&scene.member, &staging)]);
        scene.tenants.push(staging);
        let setup = scene.build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.tenant.slug().unwrap().as_str(), "staging");
    }

    /// Sam accepted his invitation to Acme a minute ago, and nobody granted
    /// him a tenant yet. He signs in, and his session works on the
    /// organization alone: he is told he has no tenant access.
    #[test]
    fn a_member_without_a_grant_signs_in_to_the_organization_only() {
        let sam = alice(
            OrganizationId::new(),
            OrgRole::Member,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let setup = Scene::with_member(sam).build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.tenant, LandedTenant::NoTenantAccess);
        assert_eq!(setup.first_session().place(), SessionPlace::Organization);
        assert_eq!(setup.recorded(), ["organization.org_login_succeeded"]);
    }

    /// Ann grants Sam staging after his first sign-in to the organization
    /// alone. He signs in again and lands in staging.
    #[test]
    fn a_member_granted_a_tenant_later_lands_there_on_the_next_sign_in() {
        let organization_id = OrganizationId::new();
        let sam = alice(
            organization_id,
            OrgRole::Member,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let staging = test_tenant_in(organization_id, "staging", "staging.com");
        let (sam_id, staging_id) = (*sam.id(), *staging.id());
        let granted = [grant(&sam, &staging)];
        let mut scene = Scene::with_member(sam);
        scene.tenants.push(staging);
        let setup = scene.build();
        let first = setup.sign_in_with(PASSWORD).unwrap();
        block_on(
            setup
                .grants
                .replace_in_tenant(&sam_id, &staging_id, &granted),
        )
        .unwrap();

        let second = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(first.tenant, LandedTenant::NoTenantAccess);
        assert_eq!(second.tenant.slug().unwrap().as_str(), "staging");
    }

    /// Bob, Acme's billing contact, signs in. His role reaches no tenant,
    /// so his session works on the organization alone and he is told he
    /// has no tenant access.
    #[test]
    fn a_billing_contact_signs_in_to_the_organization_only() {
        let bob = alice(
            OrganizationId::new(),
            OrgRole::Billing,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let setup = Scene::with_member(bob).build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.tenant, LandedTenant::NoTenantAccess);
        assert_eq!(setup.first_session().place(), SessionPlace::Organization);
    }

    /// A viewer naming production receives no tenant access; her session
    /// opens at the organization instead.
    #[test]
    fn a_viewer_naming_a_tenant_opens_no_session_there() {
        let vera = alice(
            OrganizationId::new(),
            OrgRole::Viewer,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let setup = Scene::with_member(vera).build();

        let success = setup.sign_in(naming("production")).unwrap();

        assert_eq!(success.tenant, LandedTenant::NoTenantAccess);
        assert_eq!(setup.first_session().place(), SessionPlace::Organization);
    }

    /// A plain member with a tenant grant is forbidden from signing in
    /// while the platform has suspended the organization.
    #[test]
    fn a_suspended_organization_refuses_a_plain_member() {
        let organization_id = OrganizationId::new();
        let sam = alice(
            organization_id,
            OrgRole::Member,
            OrgUserStatus::Active,
            AddressStanding::Verified,
        );
        let mut scene = Scene::with_member(sam);
        scene.grants = FakeOrgTenantGrantStore::holding([grant(&scene.member, &scene.tenants[0])]);
        scene.suspension = Suspension::ByPlatform(OrgSuspensionReason::Operator);
        let setup = scene.build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The platform suspended Acme. Alice, an owner, still signs in, so she
    /// can settle what caused it.
    #[test]
    fn a_suspended_organization_still_admits_an_owner() {
        let mut scene = Scene::acme();
        scene.suspension = Suspension::ByPlatform(OrgSuspensionReason::NonPayment);
        let setup = scene.build();

        assert!(setup.sign_in_with(PASSWORD).is_ok());
    }

    /// The store cannot end Alice's earlier sessions. No new session is
    /// handed out while an earlier one might still be live.
    #[test]
    fn a_session_is_not_issued_when_the_earlier_ones_cannot_be_revoked() {
        let mut scene = Scene::acme();
        scene.sessions = RecordingOrgSessionStore::new().failing_revocation();
        let setup = scene.build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Alice keeps the same password at Acme and at Globex. Her password
    /// opens both, so she is offered the two organizations, no session
    /// opens and nothing is recorded until she names one.
    #[test]
    fn a_password_opening_two_organizations_offers_both() {
        let setup = Scene::acme().also_at_globex(PASSWORD).build();

        let outcome = setup.outcome(typed(PASSWORD)).unwrap();

        let OrgLoginOutcome::ChooseOrganization(offered) = outcome else {
            panic!("Alice is offered her organizations");
        };
        let slugs: Vec<&str> = offered.iter().map(|offer| offer.slug.as_str()).collect();
        assert_eq!(slugs, ["acme-corp", "globex"]);
        assert_eq!(setup.sessions.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// Alice names Acme among the organizations she was offered, with her
    /// password again. She signs in to Acme.
    #[test]
    fn naming_an_offered_organization_signs_in_there() {
        let setup = Scene::acme().also_at_globex(PASSWORD).build();

        let success = setup.sign_in(choosing("acme-corp")).unwrap();

        assert_eq!(success.org_slug.as_str(), "acme-corp");
        assert_eq!(setup.recorded(), ["organization.org_login_succeeded"]);
    }

    /// Alice keeps another password at Globex. The one she types opens
    /// only Acme, so she signs in there, and nothing counts against
    /// Globex's lockout.
    #[test]
    fn a_password_opening_one_organization_signs_in_there() {
        let setup = Scene::acme().also_at_globex("another").build();

        let success = setup.sign_in_with(PASSWORD).unwrap();

        assert_eq!(success.org_slug.as_str(), "acme-corp");
        assert_eq!(setup.recorded(), ["organization.org_login_succeeded"]);
    }

    /// A password matching neither of Alice's organization accounts
    /// returns not found and records two failed sign-ins.
    #[test]
    fn a_password_opening_no_organization_is_refused_everywhere() {
        let setup = Scene::acme().also_at_globex("another").build();

        let result = setup.sign_in_with("wrong");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            setup.recorded(),
            [
                "organization.org_login_failed",
                "organization.org_login_failed"
            ]
        );
    }

    /// Naming an organization where Alice has no account returns not
    /// found even with her correct password, and records no audit event.
    #[test]
    fn naming_an_organization_without_the_address_is_refused() {
        let setup = Scene::acme().also_at_globex(PASSWORD).build();

        let result = setup.sign_in(choosing("initech"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Exhausted hash permits return busy for both known and unknown
    /// addresses. No hash runs, the unnamed failure count stays at zero,
    /// and no audit event is recorded.
    #[test]
    fn a_busy_node_refuses_before_any_hash_runs() {
        let setup = Scene {
            permits: Arc::new(BusyHashPermits),
            ..Scene::acme()
        }
        .build();

        let known = setup.sign_in_with(PASSWORD);
        let unknown = setup.outcome(nobody());

        assert!(matches!(known, Err(AppError::Busy)));
        assert!(matches!(unknown, Err(AppError::Busy)));
        assert_eq!(setup.hasher.hashed(), 0);
        assert_eq!(setup.unnamed_failures(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// Mallory guesses Alice's password with no organization named. The
    /// guess counts against every unnamed sign-in, and against Acme, where
    /// Alice's account is.
    #[test]
    fn a_wrong_password_counts_against_the_platform_and_the_organization() {
        let scene = Scene::acme();
        let acme = FailureScope::Organization(scene.organization_id);
        let setup = scene.build();

        let _ = setup.sign_in_with("wrong");

        assert_eq!(setup.unnamed_failures(), 1);
        assert_eq!(setup.failures.counted(&acme), 1);
    }

    /// At the unnamed sign-in failure limit, a correct password from an
    /// untrusted device requires proof of work before hashing. The failure
    /// count stays at ten and no audit event is recorded.
    #[test]
    fn an_untrusted_device_is_challenged_before_any_hash() {
        let setup = Scene::acme().flooded().build();

        let result = setup.sign_in_with(PASSWORD);

        assert!(matches!(
            result,
            Err(AppError::ChallengeRequired(RequiredChallenge::Solve(
                ChallengeKind::ProofOfWork
            )))
        ));
        assert_eq!(setup.hasher.hashed(), 0);
        assert_eq!(setup.unnamed_failures(), 10);
        assert!(setup.recorded().is_empty());
    }

    /// At the unnamed sign-in failure limit, known and unknown addresses
    /// receive the same challenge.
    #[test]
    fn the_challenge_reads_the_same_for_known_and_unknown_addresses() {
        let setup = Scene::acme().flooded().build();

        let known = setup.outcome(typed("guess"));
        let unknown = setup.outcome(nobody());

        let (Err(AppError::ChallengeRequired(a)), Err(AppError::ChallengeRequired(b))) =
            (known, unknown)
        else {
            panic!("both are challenged");
        };
        assert_eq!(a, b);
    }

    /// Alice signs in on the laptop she remembered while sign-in is under
    /// pressure. She goes through without a challenge.
    #[test]
    fn a_remembered_device_goes_through_under_pressure() {
        let setup = Scene::acme()
            .flooded()
            .remembering(DeviceStatus::Trusted)
            .build();

        let result = setup.sign_in(from_device(SECRET));

        assert!(result.is_ok());
    }

    /// Alice, on a new phone while sign-in is under pressure, solves the
    /// challenge and goes through. Mallory replaying her proof, or sending
    /// one she made up, is refused.
    #[test]
    fn a_passed_challenge_goes_through_once() {
        let setup = Scene::acme().flooded().build();

        let first = setup.sign_in(proving(SOLVED, typed(PASSWORD)));
        let replayed = setup.outcome(proving(SOLVED, typed(PASSWORD)));
        let forged = setup.outcome(proving("made-up", typed(PASSWORD)));

        assert!(first.is_ok());
        for refused in [replayed, forged] {
            assert!(matches!(refused, Err(AppError::ChallengeRequired(_))));
        }
    }

    /// Without a challenge provider at the failure limit, an untrusted
    /// device receives a challenge-unavailable refusal even with a proof.
    /// Alice's trusted device can still sign in.
    #[test]
    fn with_no_provider_an_untrusted_device_is_refused() {
        let setup = Scene {
            challenges: None,
            ..Scene::acme().flooded().remembering(DeviceStatus::Trusted)
        }
        .build();

        let bare = setup.outcome(proving(SOLVED, typed(PASSWORD)));
        let trusted = setup.sign_in(from_device(SECRET));

        assert!(matches!(
            bare,
            Err(AppError::ChallengeRequired(RequiredChallenge::Unavailable))
        ));
        assert!(trusted.is_ok());
    }

    /// Acme's own sign-in is under pressure at its threshold of ten. A
    /// sign-in naming Acme is challenged; one naming no organization is
    /// held to the platform's count instead and goes through.
    #[test]
    fn naming_an_organization_holds_the_sign_in_to_its_count() {
        let scene = Scene::acme().settings(OrganizationAuthSettings {
            challenge_threshold: FailureThreshold::new(10).unwrap(),
            ..OrganizationAuthSettings::default()
        });
        let acme = FailureScope::Organization(scene.organization_id);
        let setup = scene.failing(acme).build();

        let named = setup.outcome(choosing("acme-corp"));
        let unnamed = setup.sign_in_with(PASSWORD);

        assert!(matches!(named, Err(AppError::ChallengeRequired(_))));
        assert!(unnamed.is_ok());
    }
}
