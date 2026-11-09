//! The account that made a webhook, loaded as the records hold it at
//! delivery.
//!
//! A webhook keeps sending long after its creator made it. So each delivery
//! loads their account again: a tenant user's, or an organization member's
//! with their organization and tenant grants. The domain then works out what
//! they may see now.

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::domains::webhooks::creator::CreatorNow;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{EventType, OrgUserId, PrincipalRef, RoleId, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
use crate::tenancy::ScopedTenant;

/// What a webhook's creator may see now is read from: their account and
/// the share of the tenant's access records that decides what they hold.
pub(super) struct Audience<'a> {
    /// Where the creator's account is read from.
    pub(super) creators: CreatorStores<'a>,
    /// Who holds what in the tenant, read for the creator alone.
    pub(super) access: &'a dyn AccessRecordStore,
}

impl Audience<'_> {
    /// Whether the domain says `subscription` lists `event_type` and its
    /// creator may still see it, with their account and rights as stored
    /// now. A creator who is gone sees nothing.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store cannot be read, or a record names a
    /// role or group that is not there.
    pub(super) async fn receives_now(
        &self,
        tenant: &ScopedTenant,
        subscription: &WebhookSubscription<ResolvedTenant>,
        event_type: &EventType,
    ) -> Result<bool, AppError> {
        let Some(creator) =
            creator_records(&self.creators, tenant, subscription.created_by()).await?
        else {
            return Ok(false);
        };
        let roles = creator.granted_roles();
        let records = self
            .access
            .load_held_by(tenant, creator.holder(&roles))
            .await
            .or_internal()?;
        subscription
            .receives(event_type, &creator.now(), &records.access(**tenant))
            .map_err(AppError::from_domain)
    }
}

/// The stores a creator's account is read from.
pub(super) struct CreatorStores<'a> {
    /// The tenant's users.
    pub(super) users: &'a dyn UserStore,
    /// Organization members.
    pub(super) org_users: &'a dyn OrgUserStore,
    /// Organizations, for their standing.
    pub(super) organizations: &'a dyn OrganizationStore,
    /// Organization members' tenant grants.
    pub(super) org_grants: &'a dyn OrgTenantGrantStore,
}

/// A creator's account and what it rests on, as loaded now.
pub(super) enum CreatorRecords {
    /// A tenant user's account.
    User(Box<User<ResolvedTenant>>),
    /// An organization member's account, with their organization and their
    /// grants in the tenant.
    Member {
        /// The member's account, boxed so a user's records stay small.
        member: Box<OrgUser>,
        /// Their organization, boxed for the same reason.
        organization: Box<Organization>,
        /// Their grants in the tenant.
        grants: Vec<OrgTenantGrant>,
    },
}

impl CreatorRecords {
    /// The records as the domain reads a webhook's creator.
    pub(super) fn now(&self) -> CreatorNow<'_, ResolvedTenant> {
        match self {
            Self::User(user) => CreatorNow::User(user),
            Self::Member {
                member,
                organization,
                grants,
            } => CreatorNow::Member {
                member,
                organization,
                grants,
            },
        }
    }

    /// The roles the creator's tenant grants give them: none for a tenant
    /// user.
    fn granted_roles(&self) -> Vec<RoleId> {
        match self {
            Self::User(_) => Vec::new(),
            Self::Member { grants, .. } => grants.iter().map(|grant| *grant.role_id()).collect(),
        }
    }

    /// Whose records decide what the creator holds, with `granted_roles`
    /// their tenant grants name.
    fn holder<'a>(&self, granted_roles: &'a [RoleId]) -> Holder<'a> {
        match self {
            Self::User(user) => Holder::user(*user.id()),
            Self::Member { member, .. } => Holder::member(*member.id(), granted_roles),
        }
    }
}

/// The account `created_by` names, or `None` when it is gone or is no
/// person's.
///
/// A webhook whose creator is gone sends nothing, the same as one whose
/// creator holds nothing now.
///
/// # Errors
///
/// `AppError::Internal` when a store cannot be read.
pub(super) async fn creator_records(
    stores: &CreatorStores<'_>,
    tenant: &ScopedTenant,
    created_by: &PrincipalRef,
) -> Result<Option<CreatorRecords>, AppError> {
    match created_by {
        PrincipalRef::User(user_id) => user_creator(stores.users, tenant, user_id).await,
        PrincipalRef::OrgUser(member_id) => member_creator(stores, tenant, member_id).await,
        PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => Ok(None),
    }
}

async fn user_creator(
    users: &dyn UserStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<Option<CreatorRecords>, AppError> {
    let user = users.find_by_id(tenant, user_id).await.or_internal()?;
    Ok(user.map(|user| CreatorRecords::User(Box::new(user))))
}

async fn member_creator(
    stores: &CreatorStores<'_>,
    tenant: &ScopedTenant,
    member_id: &OrgUserId,
) -> Result<Option<CreatorRecords>, AppError> {
    let Some(member) = stores.org_users.find_by_id(member_id).await.or_internal()? else {
        return Ok(None);
    };
    let Some(organization) = stores
        .organizations
        .find_by_id(member.organization_id())
        .await
        .or_internal()?
    else {
        return Ok(None);
    };
    let grants = stores
        .org_grants
        .list_by_user_in_tenant(member_id, tenant)
        .await
        .or_internal()?;
    Ok(Some(CreatorRecords::Member {
        member: Box::new(member),
        organization: Box::new(organization),
        grants,
    }))
}
