//! Get tenant label: what the metrics overview shows about the tenant it
//! covers, for whoever may read that overview.
//!
//! The overview is the tenant's own dashboard, read under `Metrics(View)`.
//! Its heading describes the tenant, so it reads that much of the tenant
//! under the same right: its slug and name, its primary domain, the
//! address notices go to, its timezone and locale, its status and when it
//! was made. Nothing of how people sign in to it or how it is protected.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MetricsAction, SystemPermission};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::types::{DisplayName, DomainName, Email, Locale, TenantSlug, Timezone};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Query;

/// What the metrics overview shows about the tenant it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantLabel {
    /// The tenant's slug.
    pub slug: TenantSlug,
    /// The name shown for it.
    pub display_name: DisplayName,
    /// The domain of its own it set as primary, if any.
    pub primary_domain: Option<DomainName>,
    /// Where notices about it go.
    pub contact_email: Email,
    /// The local time basis for scheduling and display.
    pub timezone: Timezone,
    /// The default language and regional formatting preference.
    pub locale: Locale,
    /// Where it stands in its life.
    pub status: TenantStatus,
    /// When it was provisioned.
    pub created_at: OffsetDateTime,
}

impl From<&Tenant> for TenantLabel {
    fn from(tenant: &Tenant) -> Self {
        Self {
            slug: tenant.slug().clone(),
            display_name: tenant.display_name().clone(),
            primary_domain: tenant.primary_domain().cloned(),
            contact_email: tenant.contact_email().clone(),
            timezone: tenant.timezone().clone(),
            locale: tenant.locale().clone(),
            status: tenant.status(),
            created_at: tenant.created_at(),
        }
    }
}

/// The ports [`GetTenantLabelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetTenantLabelPorts {
    /// Loads the workspace details shown in its public-facing label.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the label of the caller's tenant for its metrics overview.
pub struct GetTenantLabelUseCase {
    ports: GetTenantLabelPorts,
}

impl GetTenantLabelUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetTenantLabelPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetTenantLabelUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<TenantLabel, AppError>;

    /// The label of the tenant `ctx` acts in.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not read the tenant's
    ///   metrics.
    /// - `AppError::NotFound` if the tenant doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<TenantLabel, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Metrics(MetricsAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        Ok(TenantLabel::from(&tenant))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::TenantSettingsAction;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{block_on, test_ctx};

    fn reading(authorities: FakeTenantAuthorities) -> GetTenantLabelUseCase {
        GetTenantLabelUseCase::new(GetTenantLabelPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Ann, who may read her tenant's metrics but not its settings, opens
    /// the overview. Its heading names her tenant.
    #[test]
    fn a_metrics_reader_sees_the_tenants_label() {
        let uc = reading(FakeTenantAuthorities::holding(&[
            SystemPermission::Metrics(MetricsAction::View),
        ]));

        let label = block_on(uc.execute(&test_ctx(), ())).unwrap();

        let stored = test_tenant_for_ctx();
        assert_eq!(&label.slug, stored.slug());
        assert_eq!(&label.display_name, stored.display_name());
        assert_eq!(label.status, stored.status());
    }

    /// A tenant that no longer exists is not found.
    #[test]
    fn a_missing_tenant_is_not_found() {
        let uc = GetTenantLabelUseCase::new(GetTenantLabelPorts::fakes());

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Settings-view rights alone do not permit reading the tenant label used
    /// by its metrics overview.
    #[test]
    fn a_caller_without_the_metrics_right_is_refused() {
        let uc = reading(FakeTenantAuthorities::holding(&[
            SystemPermission::TenantSettings(TenantSettingsAction::View),
        ]));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant label for the metrics overview.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = reading(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
