//! A tenant API key, acting with what its maker holds now.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::key_authority::authority_of_key;
use ianua_domain::message;
use ianua_domain::types::{ActorRef, ApiKeyId};

use crate::acting::tenant::{Resolving, TenantActing};
use crate::error::AppError;
use crate::ports::authorization::Holder;

impl TenantActing {
    /// A tenant API key, for what its maker holds now. One past its end or
    /// paused while the request ran signs in no one, the same as a wrong
    /// key.
    pub(in crate::acting::tenant) async fn of_key(
        &self,
        at: &Resolving<'_>,
        key_id: &ApiKeyId,
    ) -> Result<TenantAuthority, AppError> {
        let tenant = at.caller.tenant();
        let key = self
            .ports
            .tenant
            .api_keys
            .find_by_id(&tenant, key_id)
            .await
            .map_err(AppError::from_domain)?
            .filter(|key| key.is_active(at.now))
            .ok_or(AppError::Unauthenticated)?;
        match key.created_by() {
            ActorRef::User(maker) => {
                let records = self.held_by(at.caller, Holder::user(*maker)).await?;
                let maker = self.user(&tenant, maker).await?;
                authority_of_key(&records.access(at.caller.tenant_id()), &key, &maker, at.now)
                    .map_err(AppError::from_domain)
            }
            ActorRef::OrgUser(maker) => self.of_member_key(at, &key, maker).await,
            _ => Err(AppError::Forbidden(message!(
                "app-the-key-was-made-by-no",
                "the key was made by no one who can act in the tenant"
            ))),
        }
    }
}
