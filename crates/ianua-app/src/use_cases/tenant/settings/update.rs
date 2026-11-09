//! Update tenant settings: display name, contact email, timezone, locale
//! and primary domain. Only the fields a request names are changed.
//!
//! Sign-in settings, the JWT issuer among them, change through
//! [`UpdateAuthConfigUseCase`](crate::use_cases::tenant::settings::UpdateAuthConfigUseCase),
//! which asks for a fresh proof of the person.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use ianua_domain::domains::tenant::hosts::{PlatformAddressing, ReadableAddress};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{DisplayName, DomainName, Email, Locale, Setting, Timezone};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;

/// Fields to update. `None` means no change.
pub struct UpdateRequest {
    /// New display name, if changing.
    pub display_name: Option<DisplayName>,
    /// New contact email, if changing.
    pub contact_email: Option<Email>,
    /// New timezone, if changing.
    pub timezone: Option<Timezone>,
    /// New locale, if changing.
    pub locale: Option<Locale>,
    /// New primary domain, if changing: one the tenant has proved it owns.
    pub primary_domain: Option<DomainName>,
    /// Explicit consent to publishing readable names in DNS and certificates.
    pub readable_address: Option<ReadableAddress>,
}

impl UpdateRequest {
    /// Whether the request names no field at all.
    fn changes_nothing(&self) -> bool {
        self.display_name.is_none()
            && self.contact_email.is_none()
            && self.timezone.is_none()
            && self.locale.is_none()
            && self.primary_domain.is_none()
            && self.readable_address.is_none()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Loads and saves the workspace's editable details and primary hostname.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The tenant's registered domains, for a new primary domain.
    pub domains: Arc<dyn RegisteredDomainStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes the caller's tenant's profile settings.
pub struct UpdateUseCase {
    ports: UpdatePorts,
    addressing: PlatformAddressing,
}

impl UpdateUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts, addressing: PlatformAddressing) -> Self {
        Self { ports, addressing }
    }

    /// The proof that `tenant` owns `domain`, when the request names one.
    async fn owned_primary(
        &self,
        ctx: &CallerContext,
        tenant: &Tenant,
        domain: Option<&DomainName>,
    ) -> Result<Option<OwnedDomain>, AppError> {
        let Some(domain) = domain else {
            return Ok(None);
        };
        let registered = self
            .ports
            .domains
            .find_by_tenant_and_name(&ctx.tenant(), domain)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::NotFound(message!(
                    "tenant-the-tenant-has-no-such-domain",
                    "the tenant has no such domain"
                ))
            })?;
        let scope = ResolvedTenant::new(*tenant.id(), tenant.slug().clone());
        registered
            .owned_by(&scope)
            .map(Some)
            .map_err(AppError::from_domain)
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Changes the named settings of the tenant `ctx` acts in, recording one
    /// event per changed field (`TenantRenamed`, `TenantContactEmailChanged`,
    /// `TenantTimezoneChanged`, `TenantLocaleChanged`,
    /// `TenantPrimaryDomainChanged`), and nothing when no field is named.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without settings-change rights.
    /// - `AppError::Domain` for a closed tenant; `NotFound` for a missing tenant or unregistered domain.
    /// - `AppError::Conflict` for an unverified domain; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::Profile)
            .map_err(AppError::from_domain)?;
        if req.changes_nothing() {
            return Ok(());
        }
        ensure_readable_supported(req.readable_address, self.addressing)?;
        let mut tenant =
            existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        let primary = self
            .owned_primary(ctx, &tenant, req.primary_domain.as_ref())
            .await?;
        apply(&mut tenant, TenantControl::new(&authority), req, primary)
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

/// Refuses enabling names that the deployment cannot cover with certificates.
fn ensure_readable_supported(
    choice: Option<ReadableAddress>,
    shape: PlatformAddressing,
) -> Result<(), AppError> {
    if choice == Some(ReadableAddress::On) && shape != PlatformAddressing::Nested {
        return Err(AppError::from_domain(DomainError::invalid(message!(
            "tenant-readable-platform-addresses-require-nested-addressing",
            "readable platform addresses require nested addressing and per-tenant certificates"
        ))));
    }
    Ok(())
}

/// Applies every field `req` names to `tenant` as `by`, in field order, so
/// the tenant raises one record per change in that order.
fn apply(
    tenant: &mut Tenant,
    by: TenantControl<'_>,
    req: UpdateRequest,
    primary: Option<OwnedDomain>,
) -> Result<(), DomainError> {
    if let Some(name) = req.display_name {
        tenant.rename(by, name)?;
    }
    if let Some(email) = req.contact_email {
        tenant.change_contact_email(by, email)?;
    }
    if let Some(timezone) = req.timezone {
        tenant.change_timezone(by, timezone)?;
    }
    if let Some(locale) = req.locale {
        tenant.change_locale(by, locale)?;
    }
    if let Some(owned) = primary {
        tenant.change_primary_domain(by, Setting::Set(owned))?;
    }
    if let Some(choice) = req.readable_address {
        tenant.change_readable_address(by, choice)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomain,
        RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
    use ianua_domain::shared::clock;
    use ianua_domain::types::DomainId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::tenant::{
        FakeTenantStore, cfg, tenant_for_ctx_standing, test_tenant_for_ctx,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    struct Setup {
        uc: UpdateUseCase,
        tenants: Arc<FakeTenantStore>,
        domains: Arc<FakeDomainStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn over(tenant: Tenant, authorities: FakeTenantAuthorities) -> Self {
            let tenants = Arc::new(FakeTenantStore::holding(tenant));
            let domains = Arc::new(FakeDomainStore::empty());
            Self {
                uc: UpdateUseCase::new(
                    UpdatePorts {
                        tenant_store: tenants.clone(),
                        domains: domains.clone(),
                        tenant_authorities: Arc::new(authorities),
                    },
                    PlatformAddressing::Nested,
                ),
                tenants,
                domains,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::over(
                test_tenant_for_ctx(),
                FakeTenantAuthorities::holding_everything(),
            )
        }

        fn update_as(&self, ctx: &CallerContext, req: UpdateRequest) -> Result<(), AppError> {
            block_on(self.uc.execute(ctx, &test_auditor(self.audit.clone()), req))
        }

        fn update(&self, req: UpdateRequest) -> Result<(), AppError> {
            self.update_as(&test_ctx(), req)
        }

        fn stored(&self) -> Tenant {
            block_on(self.tenants.find_by_id(&test_ctx().tenant_id()))
                .unwrap()
                .unwrap()
        }

        fn registering(self, name: &str, proof: DomainProof) -> Self {
            let domain = RegisteredDomain::reconstitute(RegisteredDomainRow {
                id: DomainId::new(),
                domain: DomainName::new(name).unwrap(),
                connection: DomainConnection::SelfManaged,
                proof,
                dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
                tls_status: TlsStatus::NotRequired,
                created_at: clock::now() - time::Duration::hours(1),
            })
            .unwrap();
            block_on(self.domains.save(&test_ctx().tenant(), &domain)).unwrap();
            self
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn empty_req() -> UpdateRequest {
        UpdateRequest {
            display_name: None,
            contact_email: None,
            timezone: None,
            locale: None,
            primary_domain: None,
            readable_address: None,
        }
    }

    /// Ann opts into readable names and then withdraws consent. Both choices
    /// persist and each has its own audit record; the random label survives.
    #[test]
    fn readable_choices_are_saved_and_audited() {
        let setup = Setup::new();
        let label = setup.stored().platform_label().clone();
        for choice in [ReadableAddress::On, ReadableAddress::Off] {
            setup
                .update(UpdateRequest {
                    readable_address: Some(choice),
                    ..empty_req()
                })
                .unwrap();
            assert_eq!(setup.stored().readable_address(), choice);
        }
        assert_eq!(setup.stored().platform_label(), &label);
        assert_eq!(
            setup.recorded(),
            [
                "tenant.readable_address_changed",
                "tenant.readable_address_changed"
            ]
        );
    }

    /// Enabling readable names fails when the audit record cannot be written.
    #[test]
    fn a_readable_change_requires_its_audit_record() {
        let setup = Setup::new();
        let result = block_on(setup.uc.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            UpdateRequest {
                readable_address: Some(ReadableAddress::On),
                ..empty_req()
            },
        ));
        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// A flat deployment refuses to enable readable names. They stay disabled
    /// without an audit event, and explicitly disabling them still succeeds.
    #[test]
    fn a_flat_deployment_refuses_readable_names() {
        let mut setup = Setup::new();
        setup.uc.addressing = PlatformAddressing::Flat;
        let result = setup.update(UpdateRequest {
            readable_address: Some(ReadableAddress::On),
            ..empty_req()
        });
        assert!(result.is_err());
        assert_eq!(setup.stored().readable_address(), ReadableAddress::Off);
        assert!(setup.recorded().is_empty());
        setup
            .update(UpdateRequest {
                readable_address: Some(ReadableAddress::Off),
                ..empty_req()
            })
            .unwrap();
    }

    /// A caller without settings-update rights cannot enable readable names.
    /// They stay disabled and no change is recorded.
    #[test]
    fn a_viewer_cannot_enable_readable_names() {
        let setup = Setup::over(test_tenant_for_ctx(), FakeTenantAuthorities::holding(&[]));
        let result = setup.update(UpdateRequest {
            readable_address: Some(ReadableAddress::On),
            ..empty_req()
        });
        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().readable_address(), ReadableAddress::Off);
        assert!(setup.recorded().is_empty());
    }

    fn renaming() -> UpdateRequest {
        UpdateRequest {
            display_name: Some(DisplayName::new("New Name", &cfg().display_name).unwrap()),
            ..empty_req()
        }
    }

    fn making_primary(name: &str) -> UpdateRequest {
        UpdateRequest {
            primary_domain: Some(DomainName::new(name).unwrap()),
            ..empty_req()
        }
    }

    /// Ann renames Acme's tenant. The name is saved and the rename recorded.
    #[test]
    fn update_display_name_and_audits() {
        let setup = Setup::new();

        setup.update(renaming()).unwrap();

        assert_eq!(setup.stored().display_name().as_str(), "New Name");
        assert_eq!(setup.recorded(), vec!["tenant.renamed"]);
    }

    /// Ann changes where notices go. The address is saved and the change
    /// recorded.
    #[test]
    fn update_contact_email_and_audits() {
        let setup = Setup::new();
        let request = UpdateRequest {
            contact_email: Some(Email::new("new@acme.com").unwrap()),
            ..empty_req()
        };

        setup.update(request).unwrap();

        assert_eq!(setup.stored().contact_email().as_str(), "new@acme.com");
        assert_eq!(setup.recorded().len(), 1);
    }

    /// Ann changes three fields at once. Three events are recorded.
    #[test]
    fn update_multiple_fields_emits_multiple_events() {
        let setup = Setup::new();
        let request = UpdateRequest {
            timezone: Some(Timezone::new("Europe/Berlin").unwrap()),
            locale: Some(Locale::new("de-DE").unwrap()),
            ..renaming()
        };

        setup.update(request).unwrap();

        assert_eq!(setup.recorded().len(), 3);
    }

    /// A request that names no field saves and records nothing.
    #[test]
    fn update_no_fields_is_noop() {
        let setup = Setup::new();

        setup.update(empty_req()).unwrap();

        assert!(setup.recorded().is_empty());
    }

    /// Ann makes acme.com, which the tenant proved it owns, its primary
    /// domain. It is saved and the change recorded.
    #[test]
    fn a_proved_domain_becomes_primary() {
        let setup =
            Setup::new().registering("acme.com", DomainProof::Verified { at: clock::now() });

        setup.update(making_primary("acme.com")).unwrap();

        let stored = setup.stored();
        assert_eq!(
            stored.primary_domain().map(DomainName::as_str),
            Some("acme.com")
        );
        assert_eq!(setup.recorded(), vec!["tenant.primary_domain_changed"]);
    }

    /// An unregistered domain cannot become the tenant's primary domain.
    /// The domain is not found and no primary domain is set.
    #[test]
    fn a_domain_the_tenant_never_registered_is_refused() {
        let setup = Setup::new();

        let result = setup.update(making_primary("bank.com"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.stored().primary_domain().is_none());
    }

    /// A registered domain without ownership proof cannot become primary.
    /// The request conflicts and no change is recorded.
    #[test]
    fn an_unproved_domain_is_refused() {
        let setup = Setup::new().registering("bank.com", DomainProof::Unproved);

        let result = setup.update(making_primary("bank.com"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A suspended tenant takes no changes, and nothing is recorded.
    #[test]
    fn update_suspended_tenant_is_refused() {
        let tenant = tenant_for_ctx_standing(
            TenantStatus::Suspended,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setup = Setup::over(tenant, FakeTenantAuthorities::holding_everything());

        let result = setup.update(renaming());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A tenant that does not exist is not found.
    #[test]
    fn update_unknown_tenant_returns_not_found() {
        let uc = UpdateUseCase::new(UpdatePorts::fakes(), PlatformAddressing::Nested);

        let result = block_on(uc.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            renaming(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without settings-update rights cannot rename the tenant.
    /// The stored name stays unchanged.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::over(test_tenant_for_ctx(), FakeTenantAuthorities::holding(&[]));

        let result = setup.update(renaming());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().display_name().as_str(), "Acme");
    }

    /// A signed-out session cannot rename the tenant.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            test_tenant_for_ctx(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.update(renaming());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot rename the tenant.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.update_as(&operator_without_grant(), renaming());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
