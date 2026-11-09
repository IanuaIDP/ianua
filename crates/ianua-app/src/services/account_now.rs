//! What a person holds now, worked out from the tenant's records while
//! nobody is signed in.
//!
//! A schedule fires for whoever published a workflow version, an approval
//! resumes an execution days later, an account is lent while its owner is
//! away, and a worker drives an agent run under a person's delegation. Each
//! time, the person's account is loaded as it stands, so someone who left,
//! was suspended or lost a grant holds nothing, and the work done for them
//! stops at the next step.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::authorization::authority::TenantAccess;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::account_now::{AccountNow, MemberNow};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Human, HumanAccount, OrgUserId, PrincipalRef, RoleId};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::RelationshipResolver;
use crate::ports::authorization::{AccessRecordStore, HeldRecords, Holder};
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
use crate::tenancy::ScopedTenant;

/// The ports [`AccountsNow`] reads through.
#[derive(ianua_macros::Fakes)]
pub struct AccountsNowPorts {
    /// Who holds what in the tenant.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's users.
    pub users: Arc<dyn UserStore>,
    /// Organization members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for whether a member's still lets them in.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Organization members' tenant grants.
    pub org_grants: Arc<dyn OrgTenantGrantStore>,
    /// Which resources people were given use of.
    pub relationships: Arc<dyn RelationshipResolver>,
}

/// Loads a person's account, their share of the tenant's access records and
/// the resources they were given use of, as they stand now.
pub struct AccountsNow {
    ports: AccountsNowPorts,
}

/// One person's records, loaded fresh: their account, what the tenant's
/// records say they hold, and the resources they were given use of.
pub(crate) struct PersonNow {
    tenant: ScopedTenant,
    account: StoredAccount,
    records: HeldRecords,
    resources: HeldResources,
}

/// A person's account as stored now.
enum StoredAccount {
    /// A tenant user.
    User(Box<User<ResolvedTenant>>),
    /// An organization member, with their organization and tenant grants.
    Member(Box<StoredMember>),
}

/// An organization member's account as stored now, with their organization
/// and their tenant grants.
struct StoredMember {
    member: OrgUser,
    organization: Organization,
    grants: Vec<OrgTenantGrant>,
}

impl AccountsNow {
    /// A loader reading through `ports`.
    #[must_use]
    pub fn new(ports: AccountsNowPorts) -> Self {
        Self { ports }
    }

    /// `person`'s records now, with what the graph says they hold of
    /// `wanted`. `None` when their account, or their organization, is gone.
    pub(crate) async fn person(
        &self,
        tenant: &ScopedTenant,
        person: &Human,
        wanted: &[ResourceCapability],
    ) -> Result<Option<PersonNow>, AppError> {
        self.holder_of(tenant, person.account(), wanted).await
    }

    /// The records now of whoever holds `account`, with what the graph says
    /// they hold of `wanted`. `None` when the account, or its organization,
    /// is gone.
    pub(crate) async fn holder_of(
        &self,
        tenant: &ScopedTenant,
        account: HumanAccount,
        wanted: &[ResourceCapability],
    ) -> Result<Option<PersonNow>, AppError> {
        let principal = PrincipalRef::from(account);
        let Some(account) = self.account(tenant, account).await? else {
            return Ok(None);
        };
        let roles = account.granted_roles();
        let holder = Holder {
            principal,
            granted_roles: &roles,
        };
        let records = self
            .ports
            .access_records
            .load_held_by(tenant, holder)
            .await
            .or_internal()?;
        let held = self
            .ports
            .relationships
            .held_subset(tenant, &principal, wanted)
            .await
            .or_internal()?;
        Ok(Some(PersonNow {
            tenant: *tenant,
            account,
            records,
            resources: HeldResources::answered(principal, held),
        }))
    }

    async fn account(
        &self,
        tenant: &ScopedTenant,
        account: HumanAccount,
    ) -> Result<Option<StoredAccount>, AppError> {
        match account {
            HumanAccount::User(id) => {
                let user = self
                    .ports
                    .users
                    .find_by_id(tenant, &id)
                    .await
                    .or_internal()?;
                Ok(user.map(|user| StoredAccount::User(Box::new(user))))
            }
            HumanAccount::OrgUser(id) => self.member(tenant, &id).await,
        }
    }

    async fn member(
        &self,
        tenant: &ScopedTenant,
        id: &OrgUserId,
    ) -> Result<Option<StoredAccount>, AppError> {
        let Some(member) = self.ports.org_users.find_by_id(id).await.or_internal()? else {
            return Ok(None);
        };
        let Some(organization) = self
            .ports
            .organizations
            .find_by_id(member.organization_id())
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        let grants = self
            .ports
            .org_grants
            .list_by_user_in_tenant(id, tenant)
            .await
            .or_internal()?;
        Ok(Some(StoredAccount::Member(Box::new(StoredMember {
            member,
            organization,
            grants,
        }))))
    }
}

impl PersonNow {
    /// What the person holds now, as `worked_out` makes it from their
    /// account, the tenant's records and their resources. `None` when the
    /// domain says they may not act now.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the records name a role or group that is
    ///   not there.
    pub(crate) fn authority<A>(
        &self,
        worked_out: impl FnOnce(
            &AccountNow<'_, ResolvedTenant>,
            &TenantAccess<'_, ResolvedTenant>,
            &HeldResources,
        ) -> Result<A, DomainError>,
    ) -> Result<Option<A>, AppError> {
        let access = self.records.access(*self.tenant);
        match worked_out(&self.account.now(), &access, &self.resources) {
            Ok(authority) => Ok(Some(authority)),
            Err(DomainError::Forbidden(_)) => Ok(None),
            Err(other) => Err(AppError::from_domain(other)),
        }
    }
}

impl StoredAccount {
    /// The roles the account's tenant grants give it: none for a tenant
    /// user, whose roles are all in the tenant's records.
    fn granted_roles(&self) -> Vec<RoleId> {
        match self {
            Self::User(_) => Vec::new(),
            Self::Member(stored) => stored.grants.iter().map(|grant| *grant.role_id()).collect(),
        }
    }

    /// The account as the domain reads it.
    fn now(&self) -> AccountNow<'_, ResolvedTenant> {
        match self {
            Self::User(user) => AccountNow::User(user),
            Self::Member(stored) => AccountNow::Member(MemberNow {
                member: &stored.member,
                organization: &stored.organization,
                grants: &stored.grants,
            }),
        }
    }
}
