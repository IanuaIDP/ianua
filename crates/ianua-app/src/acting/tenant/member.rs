//! An organization member acting in one of its tenants, by session or key.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::oauth::clients::api_key::ApiKey;
use ianua_domain::domains::organization::access::session_check::OrgSessionCheck;
use ianua_domain::domains::organization::members::control::{Carried, OrgControl};
use ianua_domain::domains::organization::members::tenant_authority::{
    KeyMaker, authority_in, authority_of_member_key,
};
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{OrgUserId, RoleId, SessionId};

use crate::acting::tenant::{Resolving, TenantActing};
use crate::error::AppError;
use crate::ports::authorization::{HeldRecords, Holder};

impl TenantActing {
    /// An organization member's session in this tenant, while its check
    /// admits it.
    pub(in crate::acting::tenant) async fn of_member_session(
        &self,
        at: &Resolving<'_>,
        member_id: &OrgUserId,
        session_id: &SessionId,
    ) -> Result<TenantAuthority, AppError> {
        let member = self.member(member_id).await?;
        let organization = self.organization(at.caller).await?;
        let session = self
            .ports
            .members
            .org_sessions
            .find_by_id(session_id)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        let check = OrgSessionCheck {
            organization: organization.standing(),
            member: &member,
            idle_timeout: organization.auth_config().idle_timeout_secs(),
            now: at.now,
        };
        let checked = check.checked(&session).ok_or(AppError::Unauthenticated)?;
        let control = OrgControl::new(organization.standing(), &member, Carried::Session(checked));
        let grants = self.grants(member_id, at.caller).await?;
        let records = self.granted_to(at, member_id, &grants).await?;
        authority_in(&records.access(at.caller.tenant_id()), &control, &grants)
            .map_err(AppError::from_domain)
    }

    /// A tenant API key an organization member made, for what they hold in
    /// the tenant now.
    pub(in crate::acting::tenant) async fn of_member_key(
        &self,
        at: &Resolving<'_>,
        key: &ApiKey<ResolvedTenant>,
        maker: &OrgUserId,
    ) -> Result<TenantAuthority, AppError> {
        let member = self.member(maker).await?;
        let organization = self.organization(at.caller).await?;
        let grants = self.grants(maker, at.caller).await?;
        let records = self.granted_to(at, maker, &grants).await?;
        let made_by = KeyMaker {
            member: &member,
            organization: &organization,
            grants: &grants,
        };
        authority_of_member_key(&records.access(at.caller.tenant_id()), key, made_by, at.now)
            .map_err(AppError::from_domain)
    }

    /// The records that decide what `member` holds in the tenant: the roles
    /// their tenant `grants` name.
    pub(in crate::acting::tenant) async fn granted_to(
        &self,
        at: &Resolving<'_>,
        member: &OrgUserId,
        grants: &[OrgTenantGrant],
    ) -> Result<HeldRecords, AppError> {
        let roles: Vec<RoleId> = grants.iter().map(|grant| *grant.role_id()).collect();
        self.held_by(at.caller, Holder::member(*member, &roles))
            .await
    }
}
