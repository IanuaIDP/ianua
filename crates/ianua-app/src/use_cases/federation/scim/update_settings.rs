//! Update SCIM settings: what SCIM does with the users it creates and
//! removes.

use std::sync::Arc;

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::domains::federation::scim::{DirectorySettings, ScimActivation, ScimRemoval};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{RoleId, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::RoleStore;
use crate::ports::federation::ScimStore;
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_scim_endpoint;

/// What SCIM does with the users it creates and removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimSettings {
    /// The role every user SCIM creates starts with, on top of the tenant's
    /// defaults.
    pub default_role_id: Setting<RoleId>,
    /// Whether users SCIM creates are active at once, rather than first
    /// confirming their address.
    pub auto_activate: ScimActivation,
    /// Whether a user SCIM removes is deactivated and kept, rather than
    /// deleted.
    pub deactivate_on_remove: ScimRemoval,
}

/// The ports [`UpdateSettingsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateSettingsPorts {
    /// Loads and saves the tenant's SCIM endpoint.
    pub scim_store: Arc<dyn ScimStore>,
    /// Loads the default role.
    pub role_store: Arc<dyn RoleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a tenant's SCIM settings.
pub struct UpdateSettingsUseCase {
    ports: UpdateSettingsPorts,
}

impl UpdateSettingsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateSettingsPorts) -> Self {
        Self { ports }
    }

    /// The default role `settings` name, from the tenant's role store.
    async fn default_role(
        &self,
        tenant: &ScopedTenant,
        settings: &ScimSettings,
    ) -> Result<Setting<Role<ResolvedTenant>>, AppError> {
        let Setting::Set(id) = settings.default_role_id else {
            return Ok(Setting::Unset);
        };
        let role = existing_role(self.ports.role_store.as_ref(), tenant, &id).await?;
        Ok(Setting::Set(role))
    }
}

impl Command for UpdateSettingsUseCase {
    type Caller = CallerContext;
    type Input = ScimSettings;
    type Output = Result<(), AppError>;

    /// Applies `settings` to the tenant's SCIM endpoint and records
    /// `federation.scim_settings_updated`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not configure SCIM; or the
    ///   default role carries a permission they may not hand out, or any
    ///   built-in permission, since everyone SCIM creates gets it.
    /// - `AppError::NotFound` if SCIM was never set up, or the role is not
    ///   the tenant's.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        settings: ScimSettings,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::ConfigureScim)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut endpoint = existing_scim_endpoint(self.ports.scim_store.as_ref(), &tenant).await?;
        let role = self.default_role(&tenant, &settings).await?;
        endpoint
            .change_settings(&directory_settings(&settings, &role), &control)
            .map_err(AppError::from_domain)?;

        self.ports
            .scim_store
            .save(&tenant, &endpoint)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), endpoint.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// `settings` as the endpoint takes them, naming the loaded `role`.
fn directory_settings<'a>(
    settings: &ScimSettings,
    role: &'a Setting<Role<ResolvedTenant>>,
) -> DirectorySettings<'a, ResolvedTenant> {
    DirectorySettings {
        default_role: Setting::from_stored(role.value()),
        activation: settings.auto_activate,
        removal: settings.deactivate_on_remove,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole};
    use ianua_domain::domains::federation::scim::ScimEndpoint;
    use ianua_domain::types::{Enablement, Label};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeRoleStore;
    use crate::test_support::federation::{FakeScimStore, test_scim_endpoint};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Harness {
        use_case: UpdateSettingsUseCase,
        scim: Arc<FakeScimStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn role(id: RoleId, system_permissions: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id,
            name: Label::new("name", "Engineer").unwrap(),
            system_permissions,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn harness(authorities: FakeTenantAuthorities, roles: Vec<Role<ResolvedTenant>>) -> Harness {
        let tenant = test_ctx().tenant();
        let scim = Arc::new(FakeScimStore::holding(
            &tenant,
            test_scim_endpoint("hash:token", Enablement::Enabled),
        ));
        let use_case = UpdateSettingsUseCase::new(UpdateSettingsPorts {
            scim_store: scim.clone(),
            role_store: Arc::new(FakeRoleStore::holding(*tenant, roles)),
            tenant_authorities: Arc::new(authorities),
        });
        Harness {
            use_case,
            scim,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn plain_settings() -> ScimSettings {
        ScimSettings {
            default_role_id: Setting::Unset,
            auto_activate: ScimActivation::Immediate,
            deactivate_on_remove: ScimRemoval::Deactivate,
        }
    }

    fn update(h: &Harness, settings: ScimSettings) -> Result<(), AppError> {
        block_on(
            h.use_case
                .execute(&test_ctx(), &test_auditor(h.audit.clone()), settings),
        )
    }

    fn saved(h: &Harness) -> ScimEndpoint<ResolvedTenant> {
        block_on(h.scim.find(&test_ctx().tenant()))
            .unwrap()
            .unwrap()
    }

    /// Ann has SCIM give new users the Engineer role, wait for them to
    /// confirm their address, and delete whoever it removes. The settings
    /// are saved and the change is recorded.
    #[test]
    fn the_settings_are_saved_and_recorded() {
        let engineer = RoleId::new();
        let h = harness(
            FakeTenantAuthorities::holding_everything(),
            vec![role(engineer, Vec::new())],
        );

        update(
            &h,
            ScimSettings {
                default_role_id: Setting::Set(engineer),
                auto_activate: ScimActivation::AfterConfirmation,
                deactivate_on_remove: ScimRemoval::Delete,
                ..plain_settings()
            },
        )
        .unwrap();

        let endpoint = saved(&h);
        assert_eq!(endpoint.default_role_id(), Some(&engineer));
        assert_eq!(endpoint.auto_activate(), ScimActivation::AfterConfirmation);
        assert_eq!(endpoint.deactivate_on_remove(), ScimRemoval::Delete);
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["federation.scim_settings_updated"]
        );
    }

    /// Ann names a role her tenant does not have. It is not found.
    #[test]
    fn a_role_from_outside_the_tenant_is_not_found() {
        let h = harness(FakeTenantAuthorities::holding_everything(), Vec::new());

        let result = update(
            &h,
            ScimSettings {
                default_role_id: Setting::Set(RoleId::new()),
                ..plain_settings()
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Even a caller with every right cannot make a role carrying a built-in
    /// permission the SCIM default. The refusal leaves the default role unset.
    #[test]
    fn a_default_role_with_built_in_permissions_is_refused() {
        let admin = RoleId::new();
        let h = harness(
            FakeTenantAuthorities::holding_everything(),
            vec![role(admin, vec![SystemPermission::ManageScim])],
        );

        let result = update(
            &h,
            ScimSettings {
                default_role_id: Setting::Set(admin),
                ..plain_settings()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved(&h).default_role_id().is_none());
    }

    /// Managing federation does not permit changing SCIM removal settings.
    /// The refusal preserves deactivation instead of switching to deletion.
    #[test]
    fn a_caller_without_the_scim_right_is_refused() {
        let federation = [SystemPermission::Federation(FederationAction::Manage)];
        let h = harness(FakeTenantAuthorities::holding(&federation), Vec::new());

        let result = update(
            &h,
            ScimSettings {
                deactivate_on_remove: ScimRemoval::Delete,
                ..plain_settings()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved(&h).deactivate_on_remove(), ScimRemoval::Deactivate);
    }

    /// A caller without the SCIM configuration right receives a permission
    /// refusal when naming an unknown default role.
    #[test]
    fn a_caller_without_the_scim_right_learns_nothing_of_an_unknown_role() {
        let h = harness(FakeTenantAuthorities::holding(&[]), Vec::new());

        let result = update(
            &h,
            ScimSettings {
                default_role_id: Setting::Set(RoleId::new()),
                ..plain_settings()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann changes the settings of SCIM her tenant never set up. It is not
    /// found.
    #[test]
    fn settings_need_scim_to_be_set_up() {
        let use_case = UpdateSettingsUseCase::new(UpdateSettingsPorts {
            scim_store: Arc::new(FakeScimStore::empty()),
            ..UpdateSettingsPorts::fakes()
        });

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            plain_settings(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot change SCIM settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let h = harness(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Vec::new(),
        );

        let result = update(&h, plain_settings());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
