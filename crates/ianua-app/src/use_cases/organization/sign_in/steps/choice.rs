//! Which organization a sign-in by address goes to.
//!
//! An address is unique within an organization, not across the platform,
//! so one address may hold an account in several. The sign-in page carries
//! no organization. Which account is meant is settled only by the password
//! itself: the organizations whose account it opens. When it opens one,
//! that one signs in. When it opens several, the person is offered those
//! organizations and signs in again naming one, with the password again, so
//! the choice is bound to the proof. Someone without the password learns
//! nothing: every refusal answers as an unknown address does.

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::risk_engine::attack::AccountAttack;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::rate_limit::{
    LoginAttemptTracker, RateLimitPolicy,
};
use ianua_domain::domains::authentication::sessions::way_in::WayIn;
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, Label, OrganizationId, TenantSlug};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CountedAccount;
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::services::authentication::organization_accounts::organizations_of;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::sign_in_counts::{CountedAt, SignInCounts, lockout_of};
use crate::use_cases::organization::sign_in::password::login::{
    OrgLoginSuccess, OrgPasswordLoginRequest, invalid_credentials,
};
use crate::use_cases::organization::sign_in::password::second_factor::OwedFactor;

/// Which organization a password sign-in goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrganizationChoice {
    /// None named: every organization holding the address is tried.
    Unnamed,
    /// The organization with this slug, picked from those an earlier
    /// sign-in offered.
    Named(TenantSlug),
}

impl OrganizationChoice {
    /// Whether a sign-in under this choice may go to `organization`.
    fn admits(&self, organization: &Organization) -> bool {
        match self {
            Self::Unnamed => true,
            Self::Named(slug) => organization.slug() == slug,
        }
    }
}

/// An organization a sign-in is offered, once the password opened the
/// account on the address there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedOrganization {
    /// The owning account the accepted password allows the person to choose.
    pub organization_id: OrganizationId,
    /// Its slug, to name it in the sign-in that follows.
    pub slug: TenantSlug,
    /// Its name, as the person is shown it.
    pub name: Label,
}

/// How a password sign-in ends when it is not refused.
pub enum OrgLoginOutcome {
    /// A session opened in the organization the password opened.
    SignedIn(Box<OrgLoginSuccess>),
    /// The password opened the account on the address in each of these
    /// organizations: the person signs in again naming one.
    ChooseOrganization(Vec<OfferedOrganization>),
}

impl OrgLoginOutcome {
    /// The outcome of a sign-in that opened `success`.
    #[must_use]
    pub fn signed_in(success: OrgLoginSuccess) -> Self {
        Self::SignedIn(Box::new(success))
    }
}

/// One organization's account on an address, with the organization.
pub(in crate::use_cases::organization::sign_in) struct Holder {
    /// The account.
    pub(in crate::use_cases::organization::sign_in) member: OrgUser,
    /// Its organization, as it stands now.
    pub(in crate::use_cases::organization::sign_in) organization: Organization,
}

/// Where the accounts on an address, and their counts of failed attempts,
/// are read from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::sign_in) struct AddressAccounts<'a> {
    /// Every organization's members.
    pub(in crate::use_cases::organization::sign_in) members: &'a dyn OrgUserStore,
    /// The organizations they belong to.
    pub(in crate::use_cases::organization::sign_in) organizations: &'a dyn OrganizationStore,
    /// Checks a password against an account's hash, under the node's cap
    /// on hashes running at once.
    pub(in crate::use_cases::organization::sign_in) hashing: &'a PasswordHashing,
    /// Each account's failed passwords per network, and the wait an
    /// account being guessed at asks.
    pub(in crate::use_cases::organization::sign_in) attempts: &'a SignInCounts,
    /// The devices members remembered, which do not wait.
    pub(in crate::use_cases::organization::sign_in) owed: OwedFactor<'a>,
}

impl AddressAccounts<'_> {
    /// Every account on `email` in an organization `choice` admits. An
    /// account whose organization is gone is left out.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization::sign_in) async fn holding(
        &self,
        email: &Email,
        choice: &OrganizationChoice,
    ) -> Result<Vec<Holder>, AppError> {
        let members = self.members.find_all_by_email(email).await.or_internal()?;
        let mut organizations = organizations_of(self.organizations, &members).await?;
        let mut holders = Vec::with_capacity(members.len());
        for member in members {
            let found = organizations.remove(member.organization_id());
            let Some(organization) = found.filter(|held| choice.admits(held)) else {
                continue;
            };
            holders.push(Holder {
                member,
                organization,
            });
        }
        Ok(holders)
    }

    /// The holders whose account the password `request` brings opens from
    /// where it came, counting nothing either way.
    ///
    /// Every password is hashed, whatever else is true, each under its own
    /// permit. An account whose organization refuses a password from there,
    /// that cannot answer a sign-in, or that the request's network is locked
    /// out of, is not opened. Alice keeps one password at Acme and another
    /// at Globex: her Acme sign-ins never count against Globex's lockout.
    ///
    /// # Errors
    ///
    /// - `AppError::Busy` when no hash could start on this node in time.
    /// - `AppError::Internal` when a lockout cannot be read, or an
    ///   organization's lockout settings make no lockout.
    pub(in crate::use_cases::organization::sign_in) async fn opened_by<'h>(
        &self,
        holders: &'h [Holder],
        request: &OrgPasswordLoginRequest,
    ) -> Result<Vec<&'h Holder>, AppError> {
        let mut opened = Vec::new();
        for holder in holders {
            if self.opens(holder, request).await? {
                opened.push(holder);
            }
        }
        Ok(opened)
    }

    /// The way in the password `request` brings gives into `member`'s
    /// account in `organization`, counted against the network it came from,
    /// whatever the answer, once the account's pace has been waited out.
    ///
    /// The hash is always computed. A network locked out of the account,
    /// or an account that cannot sign in, answers exactly as a wrong
    /// password does. A wrong password counts towards the network's
    /// lockout, a right one clears its count.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` ("invalid credentials") for a wrong password,
    ///   a network locked out of the account, or an account unable to
    ///   answer a sign-in.
    /// - `AppError::Busy` when no hash could start on this node in time.
    ///   Nothing is counted.
    /// - `AppError::Internal` when the count cannot be read or kept, or the
    ///   organization's lockout settings make no lockout.
    pub(in crate::use_cases::organization::sign_in) async fn counted_way_in(
        &self,
        member: &OrgUser,
        organization: &Organization,
        request: &OrgPasswordLoginRequest,
    ) -> Result<WayIn, AppError> {
        let lockout = lockout_of(organization.auth_config().limits())?;
        let at = counted_at(member, organization, request, &lockout);
        let device = self
            .owed
            .member_device(member, request.device_secret.as_ref());
        let mut tracker = self.attempts.held(at, device).await?;
        let proven = {
            let hasher = self.hashing.permitted().await?;
            member.sign_in_with_password(request.password.expose(), &hasher)
        };
        let counted = counted(proven, member, &mut tracker);
        self.attempts.settled(at, &tracker).await?;
        counted
    }

    /// Whether the account of `holder` is under attack, as a sign-in from
    /// where `request` came finds it. The record of an attack the counts
    /// just showed is claimed, and the attack answered as begun to this
    /// sign-in alone, which records it and then calls
    /// [`attack_recorded`](Self::attack_recorded).
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the counts cannot be read or the claim
    ///   made, or the organization's lockout settings make no lockout.
    pub(in crate::use_cases::organization::sign_in) async fn attack_on(
        &self,
        holder: &Holder,
        request: &OrgPasswordLoginRequest,
    ) -> Result<AccountAttack, AppError> {
        let lockout = lockout_of(holder.organization.auth_config().limits())?;
        let at = counted_at(&holder.member, &holder.organization, request, &lockout);
        self.attempts.attack(at).await
    }

    /// Marks the account of `holder` under `attack`, found begun by the
    /// sign-in from where `request` came, now that its record is written.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the mark cannot be kept, or the
    ///   organization's lockout settings make no lockout.
    pub(in crate::use_cases::organization::sign_in) async fn attack_recorded(
        &self,
        holder: &Holder,
        request: &OrgPasswordLoginRequest,
        attack: AccountAttack,
    ) -> Result<(), AppError> {
        let lockout = lockout_of(holder.organization.auth_config().limits())?;
        let at = counted_at(&holder.member, &holder.organization, request, &lockout);
        self.attempts.mark_recorded(at, attack).await
    }

    /// The refusal of a sign-in turned away before its password is
    /// compared, given only after hashing the password all the same, under
    /// a permit like a real check, so it comes back no sooner than a wrong
    /// password's. With no permit free, the node is busy instead.
    pub(in crate::use_cases::organization::sign_in) async fn refused_after_a_hash(
        &self,
        password: &Secret,
    ) -> AppError {
        let hasher = match self.hashing.permitted().await {
            Ok(hasher) => hasher,
            Err(busy) => return busy,
        };
        let _ = hasher.hash(password.expose());
        invalid_credentials()
    }

    /// Whether the password `request` brings opens `holder`'s account from
    /// where it came, now.
    async fn opens(
        &self,
        holder: &Holder,
        request: &OrgPasswordLoginRequest,
    ) -> Result<bool, AppError> {
        let (member, organization) = (&holder.member, &holder.organization);
        let proven = member
            .sign_in_with_password(request.password.expose(), &self.hashing.permitted().await?)
            .is_ok();
        let admitted = organization
            .auth_config()
            .admits(AuthMethod::Password, request.origin.ip_address.as_ref())
            .is_ok();
        let lockout = lockout_of(organization.auth_config().limits())?;
        let at = counted_at(member, organization, request, &lockout);
        let locked = self.attempts.standing(at).await?.is_locked(clock::now());
        Ok(proven && admitted && answers_a_sign_in(member) && !locked)
    }
}

/// Where the password `request` brings is counted for `member`: their
/// address in `organization`, from the network the request came from,
/// under `lockout`.
fn counted_at<'a>(
    member: &'a OrgUser,
    organization: &'a Organization,
    request: &OrgPasswordLoginRequest,
    lockout: &'a RateLimitPolicy,
) -> CountedAt<'a> {
    CountedAt {
        account: CountedAccount::Organization {
            organization: organization.id(),
            email: member.email(),
        },
        origin: AttemptOrigin::of(request.origin.ip_address.as_ref()),
        policy: lockout,
    }
}

/// Refuses a member whose address was never confirmed, where `mail` says a
/// link could confirm it. Without a mail server the sign-in goes on and the
/// address stays unverified.
pub(in crate::use_cases::organization::sign_in) fn ensure_address_proven(
    member: &OrgUser,
    mail: MailReach,
) -> Result<(), AppError> {
    if member.address_admits_sign_in(mail) {
        return Ok(());
    }
    Err(AppError::EmailNotVerified)
}

/// Whether `member`'s account answers a sign-in at all. An unconfirmed
/// member does, to be told so once their password proves the account is
/// theirs.
pub(in crate::use_cases::organization::sign_in) fn answers_a_sign_in(member: &OrgUser) -> bool {
    match member.status() {
        OrgUserStatus::Active | OrgUserStatus::PendingVerification => true,
        OrgUserStatus::Invited
        | OrgUserStatus::Locked
        | OrgUserStatus::Deactivated
        | OrgUserStatus::Closing => false,
    }
}

/// The way in `proven` gave `member`, marked on `tracker`: refused as a
/// wrong password while the network is locked out of the account or the
/// account cannot answer, a failure for a wrong password, the count cleared
/// for a right one.
fn counted(
    proven: Result<WayIn, DomainError>,
    member: &OrgUser,
    tracker: &mut LoginAttemptTracker,
) -> Result<WayIn, AppError> {
    if !answers_a_sign_in(member) || tracker.is_locked(clock::now()) {
        return Err(invalid_credentials());
    }
    match proven {
        Ok(way_in) => {
            tracker.reset();
            Ok(way_in)
        }
        Err(DomainError::Forbidden(_)) => {
            tracker.record_failure();
            Err(invalid_credentials())
        }
        Err(other) => Err(AppError::from_domain(other)),
    }
}

/// The organizations `opened` offers the person to choose from.
pub(in crate::use_cases::organization::sign_in) fn offered(
    opened: &[&Holder],
) -> Vec<OfferedOrganization> {
    opened
        .iter()
        .map(|holder| OfferedOrganization {
            organization_id: *holder.organization.id(),
            slug: holder.organization.slug().clone(),
            name: holder.organization.name().clone(),
        })
        .collect()
}
