//! What a person bound to the directory holds in their tenant, worked out
//! from the tenant's records for the bind that proved them.
//!
//! LDAP has no sessions: a bind proves the person with their password over
//! a certificate in force for them, and opens nothing a later request could
//! name. So the bind itself is what is resolved here, once, when it is made.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::authentication::ldap_certificate::DirectoryBind;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::tenancy::ScopedTenant;

/// What a person bound to the directory holds in their tenant.
#[async_trait]
pub trait DirectoryAuthorities: Send + Sync {
    /// What `account`, proved by `bind`, holds in `tenant` now.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when `bind` proved someone else, or the
    ///   account may not act now.
    /// - `AppError::Internal` when the tenant's records cannot be read, or
    ///   name a role or group that is not there.
    async fn authority(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        bind: &DirectoryBind<ResolvedTenant>,
    ) -> Result<TenantAuthority, AppError>;
}

/// Works out what a bound person holds from the tenant's records, read
/// fresh for each bind.
pub struct DirectoryActing {
    access: Arc<dyn AccessRecordStore>,
}

impl DirectoryActing {
    /// A resolver reading the tenant's records from `access`.
    #[must_use]
    pub fn new(access: Arc<dyn AccessRecordStore>) -> Self {
        Self { access }
    }
}

#[async_trait]
impl DirectoryAuthorities for DirectoryActing {
    async fn authority(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        bind: &DirectoryBind<ResolvedTenant>,
    ) -> Result<TenantAuthority, AppError> {
        let records = self
            .access
            .load_held_by(tenant, Holder::user(*account.id()))
            .await
            .or_internal()?;
        records
            .access(**tenant)
            .authority_of(account, bind, clock::now())
            .map_err(AppError::from_domain)
    }
}
