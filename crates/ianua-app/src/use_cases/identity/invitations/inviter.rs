//! What the person who sent an invitation holds in its tenant now, worked
//! out from the stored records when the invitation is accepted.

use std::sync::Arc;

use ianua_domain::domains::authorization::inviter::InviterNow;
use ianua_domain::domains::organization::members::tenant_authority::member_as_inviter;
use ianua_domain::message;
use ianua_domain::types::{ActorRef, OrgUserId, RoleId, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::{existing_organization, existing_tenant};
use crate::tenancy::ScopedTenant;

/// Where an inviter's standing in the tenant is read from: the tenant's own
/// records, and for an organization member their organization and grants.
#[derive(ianua_macros::Fakes)]
pub struct InviterPorts {
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's users.
    pub user_store: Arc<dyn UserStore>,
    /// Tenants, for the organization they belong to.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Loads the owning organization when resolving invitation authority.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Organization members.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Organization members' grants in the tenant.
    pub org_grant_store: Arc<dyn OrgTenantGrantStore>,
}

/// What `invited_by`, who sent an invitation in `tenant`, holds there now.
///
/// # Errors
///
/// - `AppError::Forbidden` when the sender is gone, or is no user or
///   member who can have sent it.
/// - `AppError::NotFound` when the tenant or its organization is gone.
/// - `AppError::Internal` when a store fails or a record is broken.
pub(in crate::use_cases::identity) async fn inviter_now(
    ports: &InviterPorts,
    tenant: &ScopedTenant,
    invited_by: &ActorRef,
) -> Result<InviterNow, AppError> {
    match invited_by {
        ActorRef::User(id) => tenant_user(ports, tenant, id).await,
        ActorRef::OrgUser(id) => member(ports, tenant, id).await,
        _ => Err(gone()),
    }
}

/// A user of the tenant who sent the invitation, as they hold now.
async fn tenant_user(
    ports: &InviterPorts,
    tenant: &ScopedTenant,
    id: &UserId,
) -> Result<InviterNow, AppError> {
    let inviter = ports
        .user_store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .ok_or_else(gone)?;
    let records = ports
        .access_records
        .load_held_by(tenant, Holder::user(*id))
        .await
        .or_internal()?;
    InviterNow::tenant_user(&records.access(**tenant), &inviter).map_err(AppError::from_domain)
}

/// A member of the tenant's organization who sent the invitation, as they
/// hold in the tenant now.
async fn member(
    ports: &InviterPorts,
    tenant: &ScopedTenant,
    id: &OrgUserId,
) -> Result<InviterNow, AppError> {
    let sender = ports
        .org_user_store
        .find_by_id(id)
        .await
        .or_internal()?
        .ok_or_else(gone)?;
    let found = existing_tenant(ports.tenant_store.as_ref(), tenant).await?;
    let organization =
        existing_organization(ports.organization_store.as_ref(), found.organization_id()).await?;
    let grants = ports
        .org_grant_store
        .list_by_user_in_tenant(id, tenant)
        .await
        .or_internal()?;
    let roles: Vec<RoleId> = grants.iter().map(|grant| *grant.role_id()).collect();
    let records = ports
        .access_records
        .load_held_by(tenant, Holder::member(*id, &roles))
        .await
        .or_internal()?;
    member_as_inviter(&records.access(**tenant), &organization, &sender, &grants)
        .map_err(AppError::from_domain)
}

/// The refusal for an invitation whose sender can no longer stand behind it.
fn gone() -> AppError {
    AppError::Forbidden(message!(
        "identity-the-person-who-sent-this-invitation",
        "the person who sent this invitation can no longer give it"
    ))
}
