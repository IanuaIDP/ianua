//! What reading one tenant and listing them both read: how each tenant's
//! setup stands.

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::setup::SetupStanding;

use crate::error::{AppError, OrInternal};
use crate::ports::tenant::TenantSetupStore;
use crate::use_cases::tenant::lifecycle::reading::get::TenantRead;

/// `tenant` with how its setup stands. The setup is read only while the
/// tenant is still provisioning; any other tenant's setup is over.
///
/// # Errors
///
/// - `AppError::Internal` when the setup cannot be read.
pub(super) async fn read_tenant(
    setups: &dyn TenantSetupStore,
    tenant: Tenant,
) -> Result<TenantRead, AppError> {
    if !SetupStanding::needs_setup(&tenant) {
        return Ok(TenantRead {
            setup: SetupStanding::Over,
            tenant,
        });
    }
    let setup = setups.find(tenant.id()).await.or_internal()?;
    Ok(TenantRead {
        setup: SetupStanding::of(&tenant, setup.as_ref()),
        tenant,
    })
}
