//! The tenant user an external identity provider signs in.
//!
//! OIDC and SAML differ in how the identity provider proves who the person
//! is. Once it has, the rules are the same, and they live here so the two
//! flows cannot drift apart.
//!
//! The person is found by the link from who they are at the provider to
//! their account, never by the address alone. The domain's [`admission`]
//! decides, from the tenant's own records, whether a first sign-in may link
//! an account or make one. Only an account that may sign in gets a session,
//! and an account made on first sign-in counts against the plan and starts
//! with the roles every new account starts with.

use ianua_domain::domains::federation::account_privilege::AccountPrivilege;
use ianua_domain::domains::federation::admission::{
    AdmissionOutcome, FederatedAdmission, KnownRecords, Standing, admission,
};
use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::federation::link::{FederatedLink, LinkGrounds};
use ianua_domain::domains::federation::vouched_identity::VouchedIdentity;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::verified_email::VerifiedEmail;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DisplayName, PrincipalRef, UserId};
use time::OffsetDateTime;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{
    AccessRecordStore, HeldRecords, Holders, RoleAssignmentStore, RoleStore, SeparationRuleStore,
};
use crate::ports::federation::FederatedLinkStore;
use crate::ports::identity::UserStore;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::services::authorization::duties::DutySources;
use crate::services::authorization::provider_grants::{self, ProviderRoleStores};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;

/// The stores a federated sign-in reads and writes users and links through.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::federation) struct FederatedUserPorts<'a> {
    pub(in crate::use_cases::authentication::federation) users: &'a dyn UserStore,
    pub(in crate::use_cases::authentication::federation) roles: &'a dyn RoleStore,
    pub(in crate::use_cases::authentication::federation) assignments: &'a dyn RoleAssignmentStore,
    pub(in crate::use_cases::authentication::federation) links: &'a dyn FederatedLinkStore,
    pub(in crate::use_cases::authentication::federation) access: &'a dyn AccessRecordStore,
    pub(in crate::use_cases::authentication::federation) separation_rules:
        &'a dyn SeparationRuleStore,
    pub(in crate::use_cases::authentication::federation) limit_enforcer: &'a dyn LimitEnforcer,
    pub(in crate::use_cases::authentication::federation) plan_limits: &'a dyn PlanLimitsSource,
}

/// Who a provider vouched for, through which connection, into which tenant.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::federation) struct Arriving<'a> {
    pub(in crate::use_cases::authentication::federation) tenant: &'a ScopedTenant,
    pub(in crate::use_cases::authentication::federation) connection:
        &'a FederatedIdpConnection<ResolvedTenant>,
    pub(in crate::use_cases::authentication::federation) identity: &'a VouchedIdentity,
    /// How long the name of an account made here may be.
    pub(in crate::use_cases::authentication::federation) display_names: &'a DisplayNameLimits,
}

/// How the person came to be signed in to their account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::authentication::federation) enum Arrival {
    /// They were linked to it already.
    Returning,
    /// Their existing account was linked to them by this sign-in.
    Linked,
    /// Their account was made, and linked, by this sign-in.
    Provisioned,
}

/// Who signed in, the link they signed in by, and how they came to.
pub(in crate::use_cases::authentication::federation) struct FederatedUser {
    pub(in crate::use_cases::authentication::federation) account: User<ResolvedTenant>,
    pub(in crate::use_cases::authentication::federation) link: FederatedLink<ResolvedTenant>,
    /// Whether the account holds built-in permissions, which decides how
    /// much the provider's word on a second factor counts.
    pub(in crate::use_cases::authentication::federation) privilege: AccountPrivilege,
    pub(in crate::use_cases::authentication::federation) arrival: Arrival,
}

/// What the tenant already knows about the identity: the link from its
/// subject, the account with its address, and that account's link here.
struct Known {
    subject_link: Option<FederatedLink<ResolvedTenant>>,
    holder: Option<User<ResolvedTenant>>,
    holder_link: Option<FederatedLink<ResolvedTenant>>,
}

/// The account admission let in, the link it signs in by, and how.
struct Entered {
    account: User<ResolvedTenant>,
    link: FederatedLink<ResolvedTenant>,
    arrival: Arrival,
}

impl Entered {
    fn by(
        account: User<ResolvedTenant>,
        link: FederatedLink<ResolvedTenant>,
        arrival: Arrival,
    ) -> Self {
        Self {
            account,
            link,
            arrival,
        }
    }
}

/// The account `arriving` signs in to: the one its subject is linked to,
/// the one with its address on a first sign-in, or one made on the spot
/// when the connection makes accounts. A first sign-in leaves the link
/// behind.
///
/// # Errors
///
/// - `AppError::Forbidden` when admission refuses: the connection is off,
///   may not vouch for the address, the provider calls it unverified or
///   nothing proves it, the account is linked to someone else, holds admin
///   rights, never proved its address, or there is no account and the
///   connection makes none. Also when the account may not sign in, or the
///   plan has no room for another user.
/// - `AppError::NotFound` if the linked account or the connection's role
///   for new accounts no longer exists.
/// - `AppError::Conflict` if another sign-in linked the account first.
/// - `AppError::Internal` on persistence failure, or records that do not
///   fit together.
pub(in crate::use_cases::authentication::federation) async fn signing_in(
    ports: FederatedUserPorts<'_>,
    arriving: Arriving<'_>,
) -> Result<FederatedUser, AppError> {
    let known = known(ports, arriving).await?;
    let records = records_of(ports.access, arriving.tenant, &known).await?;
    let now = clock::now();
    let standing = standing_of(&known, &records, arriving, now)?;
    let admitted = admission(arriving.connection, arriving.identity, standing)
        .map_err(|refusal| AppError::Forbidden(refusal.to_string().into()))?;
    let entered = admitted_account(ports, arriving, &admitted, known).await?;
    let privilege = records
        .access(**arriving.tenant)
        .privilege_of(entered.account.id(), now)
        .map_err(AppError::from_domain)?;
    Ok(FederatedUser {
        account: entered.account,
        link: entered.link,
        privilege,
        arrival: entered.arrival,
    })
}

/// The link from the identity's subject, the account with its address and
/// that account's link at this connection.
async fn known(ports: FederatedUserPorts<'_>, arriving: Arriving<'_>) -> Result<Known, AppError> {
    let connection_id = arriving.connection.id();
    let subject_link = ports
        .links
        .find_by_subject(arriving.tenant, connection_id, arriving.identity.subject())
        .await
        .or_internal()?;
    let holder = ports
        .users
        .find_by_email(arriving.tenant, arriving.identity.email())
        .await
        .or_internal()?;
    let holder_link = match &holder {
        Some(user) => ports
            .links
            .find_by_user(arriving.tenant, connection_id, user.id())
            .await
            .or_internal()?,
        None => None,
    };
    Ok(Known {
        subject_link,
        holder,
        holder_link,
    })
}

/// The share of the tenant's access records that decides what the accounts
/// `known` names hold: the one the subject is linked to and the one with
/// the address. Nobody else's records are read, so a sign-in costs the
/// same in a tenant of ten people as in one of a hundred thousand.
async fn records_of(
    access: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    known: &Known,
) -> Result<HeldRecords, AppError> {
    let principals: Vec<PrincipalRef> = known
        .subject_link
        .iter()
        .map(|link| *link.user_id())
        .chain(known.holder.iter().map(|user| *user.id()))
        .map(PrincipalRef::User)
        .collect();
    let holders = Holders {
        principals: &principals,
        groups: &[],
        roles: &[],
    };
    access.load_held_by_all(tenant, holders).await.or_internal()
}

/// What the tenant's records say about the identity, as the domain reads
/// them.
fn standing_of(
    known: &Known,
    records: &HeldRecords,
    arriving: Arriving<'_>,
    now: OffsetDateTime,
) -> Result<Standing, AppError> {
    let access = records.access(**arriving.tenant);
    let read = KnownRecords {
        subject_link: known.subject_link.as_ref(),
        address_holder: known.holder.as_ref(),
        holder_link: known.holder_link.as_ref(),
        access: &access,
    };
    Standing::of(arriving.identity, &read, now).map_err(AppError::from_domain)
}

/// The account `admitted` lets in, with the link it signs in by.
async fn admitted_account(
    ports: FederatedUserPorts<'_>,
    arriving: Arriving<'_>,
    admitted: &FederatedAdmission,
    known: Known,
) -> Result<Entered, AppError> {
    match admitted.outcome() {
        AdmissionOutcome::Returning(user_id) => {
            let account = active_user(ports, arriving.tenant, user_id).await?;
            let link = known
                .subject_link
                .ok_or_else(|| AppError::internal_msg("a returning subject has no link"))?;
            Ok(Entered::by(account, link, Arrival::Returning))
        }
        AdmissionOutcome::Link(user_id) => {
            let account = active_user(ports, arriving.tenant, user_id).await?;
            let link = new_link(ports, arriving, &account, admitted).await?;
            Ok(Entered::by(account, link, Arrival::Linked))
        }
        AdmissionOutcome::Provision(address) => {
            let account = provision(ports, arriving, address.clone()).await?;
            let link = new_link(ports, arriving, &account, admitted).await?;
            Ok(Entered::by(account, link, Arrival::Provisioned))
        }
    }
}

/// The account `user_id`, if it may sign in.
async fn active_user(
    ports: FederatedUserPorts<'_>,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<User<ResolvedTenant>, AppError> {
    let user = ports
        .users
        .find_by_id(tenant, user_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-user-not-found", "user not found"))?;
    if !user.can_authenticate() {
        return Err(AppError::Forbidden(message!(
            "authentication-this-account-is-not-active-and",
            "this account is not active and cannot sign in"
        )));
    }
    Ok(user)
}

/// Links the identity's subject to `account`, on what `admitted` allowed.
/// The link raises how the person arrived, taken once the sign-in is
/// recorded.
async fn new_link(
    ports: FederatedUserPorts<'_>,
    arriving: Arriving<'_>,
    account: &User<ResolvedTenant>,
    admitted: &FederatedAdmission,
) -> Result<FederatedLink<ResolvedTenant>, AppError> {
    let grounds = LinkGrounds::Admitted(admitted);
    let link = FederatedLink::link(arriving.identity, account, grounds, arriving.connection)
        .map_err(AppError::from_domain)?;
    ports
        .links
        .save(arriving.tenant, &link)
        .await
        .map_err(AppError::from_domain)?;
    Ok(link)
}

/// Makes the account for the proven `address`, once the plan has room for
/// it.
///
/// Active at once: the provider proved the address, which is all a
/// verification link would have proved. It starts with the tenant's
/// default roles and the role the connection gives new accounts.
async fn provision(
    ports: FederatedUserPorts<'_>,
    arriving: Arriving<'_>,
    address: VerifiedEmail,
) -> Result<User<ResolvedTenant>, AppError> {
    ensure_room(ports, arriving.tenant).await?;
    let display_name = DisplayName::new(address.as_email().as_str(), arriving.display_names)
        .map_err(|invalid| AppError::from_domain(DomainError::from(invalid)))?;
    let account = User::provision(UserId::new(), address, display_name);
    ports
        .users
        .save(arriving.tenant, &account)
        .await
        .or_internal()?;
    grant_starting_roles(ports, arriving, &account).await?;
    Ok(account)
}

/// Refuses another user once the tenant's plan holds as many as it allows.
async fn ensure_room(ports: FederatedUserPorts<'_>, tenant: &ScopedTenant) -> Result<(), AppError> {
    let plan = ports
        .plan_limits
        .for_tenant(tenant)
        .await
        .map_err(AppError::from_domain)?;
    ports
        .limit_enforcer
        .check_tenant_limit(&plan, tenant, ResourceKind::Users)
        .await
        .map_err(AppError::from_domain)
}

/// Gives `account` the tenant's default roles and the connection's role for
/// new accounts, when it names one and the tenant's separation of duties
/// allows it alongside the defaults.
async fn grant_starting_roles(
    ports: FederatedUserPorts<'_>,
    arriving: Arriving<'_>,
    account: &User<ResolvedTenant>,
) -> Result<(), AppError> {
    let given = match arriving.connection.jit_default_role_id() {
        Some(role_id) => {
            let role = existing_role(ports.roles, arriving.tenant, role_id).await?;
            let given = arriving
                .connection
                .default_assignment(*account.id(), &role)
                .map_err(AppError::from_domain)?;
            vec![given]
        }
        None => Vec::new(),
    };
    let stores = ProviderRoleStores {
        role_store: ports.roles,
        assignment_store: ports.assignments,
        duties: DutySources::of(ports.access, ports.separation_rules),
    };
    provider_grants::grant_starting_roles(stores, arriving.tenant, *account.id(), given).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{Fake, RejectingLimitEnforcer, block_on, test_ctx};

    struct Stores {
        users: Arc<dyn UserStore>,
        roles: Arc<dyn RoleStore>,
        assignments: Arc<dyn RoleAssignmentStore>,
        links: Arc<dyn FederatedLinkStore>,
        access: Arc<dyn AccessRecordStore>,
        separation_rules: Arc<dyn SeparationRuleStore>,
        limit_enforcer: Arc<dyn LimitEnforcer>,
        plan_limits: Arc<dyn PlanLimitsSource>,
    }

    impl Stores {
        fn enforcing(limit_enforcer: Arc<dyn LimitEnforcer>) -> Self {
            Self {
                users: Fake::fake(),
                roles: Fake::fake(),
                assignments: Fake::fake(),
                links: Fake::fake(),
                access: Fake::fake(),
                separation_rules: Fake::fake(),
                limit_enforcer,
                plan_limits: Fake::fake(),
            }
        }

        fn room(&self) -> Result<(), AppError> {
            let ports = FederatedUserPorts {
                users: self.users.as_ref(),
                roles: self.roles.as_ref(),
                assignments: self.assignments.as_ref(),
                links: self.links.as_ref(),
                access: self.access.as_ref(),
                separation_rules: self.separation_rules.as_ref(),
                limit_enforcer: self.limit_enforcer.as_ref(),
                plan_limits: self.plan_limits.as_ref(),
            };
            block_on(ensure_room(ports, &test_ctx().tenant()))
        }
    }

    /// Acme's plan has room for another user, so a first sign-in may make
    /// one.
    #[test]
    fn a_plan_with_room_lets_an_account_be_made() {
        let stores = Stores::enforcing(Fake::fake());

        assert!(stores.room().is_ok());
    }

    /// A full tenant plan refuses the capacity check for provisioning a federated account.
    #[test]
    fn a_full_plan_refuses_another_account() {
        let stores = Stores::enforcing(Arc::new(RejectingLimitEnforcer));

        assert!(matches!(stores.room(), Err(AppError::Forbidden(_))));
    }
}
