//! Update mTLS config: replace the certificate authorities a tenant trusts
//! to sign client certificates.

use std::sync::Arc;

use ianua_domain::domains::tenant::access::network_security::{MtlsConfig, MtlsMode};
use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{CertificatePem, RevocationListPem};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::CertPemValidator;
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::fresh_proof::admin::{AdminProofSources, proved_admin};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;

/// The new trust anchor, with what the caller gave to prove who they are.
pub struct UpdateMtlsConfigRequest {
    /// Whether client certificates are off, accepted or required.
    pub mode: MtlsMode,
    /// The certificate authorities that sign client certificates.
    pub trusted_ca_certs: Vec<CertificatePem>,
    /// The lists of client certificates those authorities revoked. Empty,
    /// revocation is not checked.
    pub revocation_lists: Vec<RevocationListPem>,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`UpdateMtlsConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateMtlsConfigPorts {
    /// Loads and saves the workspace's trusted client-certificate settings.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Checks each certificate parses.
    pub cert_validator: Arc<dyn CertPemValidator>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Organization members, for a member changing the trust anchor.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member changing the trust anchor.
    pub organizations: Arc<dyn OrganizationStore>,
}

/// Replaces the caller's tenant's mTLS trust anchor.
pub struct UpdateMtlsConfigUseCase {
    ports: UpdateMtlsConfigPorts,
}

impl UpdateMtlsConfigUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateMtlsConfigPorts) -> Self {
        Self { ports }
    }

    /// Refuses a certificate that does not parse.
    fn ensure_certs_parse(&self, pems: &[CertificatePem]) -> Result<(), AppError> {
        pems.iter().try_for_each(|pem| {
            self.ports
                .cert_validator
                .validate_cert_pem(pem)
                .map_err(AppError::from_domain)
        })
    }

    /// Refuses a revocation list that does not parse, rather than letting
    /// it refuse every client certificate later in the handshake.
    fn ensure_lists_parse(&self, pems: &[RevocationListPem]) -> Result<(), AppError> {
        pems.iter().try_for_each(|pem| {
            self.ports
                .cert_validator
                .validate_revocation_list_pem(pem)
                .map_err(AppError::from_domain)
        })
    }

    /// The setting `asked` names, every certificate and list read.
    fn config_of(&self, asked: AskedMtls) -> Result<MtlsConfig, AppError> {
        self.ensure_certs_parse(&asked.trusted_ca_certs)?;
        self.ensure_lists_parse(&asked.revocation_lists)?;
        MtlsConfig::new(asked.mode, asked.trusted_ca_certs)
            .and_then(|config| config.with_revocation_lists(asked.revocation_lists))
            .map_err(AppError::from_domain)
    }
}

/// The setting a request asks for, apart from the caller's proof.
struct AskedMtls {
    mode: MtlsMode,
    trusted_ca_certs: Vec<CertificatePem>,
    revocation_lists: Vec<RevocationListPem>,
}

impl Command for UpdateMtlsConfigUseCase {
    type Caller = CallerContext;
    type Input = UpdateMtlsConfigRequest;
    type Output = Result<(), AppError>;

    /// Replaces the mTLS settings of the tenant `ctx` acts in and records
    /// `tenant.mtls_config_updated`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without mutual-TLS rights, through a key or for inadequate fresh proof.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Domain` for unreadable certificates/revocations, missing required certificates, lists with TLS off or beyond limits, or a closed tenant.
    /// - `AppError::NotFound` for a missing tenant; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateMtlsConfigRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::Mtls)
            .map_err(AppError::from_domain)?;
        let config = self.config_of(AskedMtls {
            mode: req.mode,
            trusted_ca_certs: req.trusted_ca_certs,
            revocation_lists: req.revocation_lists,
        })?;
        let sources = AdminProofSources {
            authorities: self.ports.tenant_authorities.as_ref(),
            proofs: self.ports.fresh_proofs.as_ref(),
            members: self.ports.org_users.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let admin = proved_admin(sources, ctx, req.proof).await?;
        let tenant_id = ctx.tenant();
        let mut tenant = existing_tenant(self.ports.tenant_store.as_ref(), &tenant_id).await?;
        tenant
            .update_mtls(TenantControl::new(&authority), admin.fresh(), config)
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::context::{CallerIdentity, Credential};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::organization::{
        org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    /// A validator that finds every certificate broken.
    struct RejectingValidator;

    impl CertPemValidator for RejectingValidator {
        fn validate_cert_pem(&self, _pem: &CertificatePem) -> Result<(), DomainError> {
            Err(DomainError::invalid("not a certificate"))
        }

        fn validate_revocation_list_pem(
            &self,
            _pem: &RevocationListPem,
        ) -> Result<(), DomainError> {
            Err(DomainError::invalid("not a revocation list"))
        }
    }

    struct Setup {
        uc: UpdateMtlsConfigUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: UpdateMtlsConfigPorts) -> Self {
            let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
            Self {
                uc: UpdateMtlsConfigUseCase::new(UpdateMtlsConfigPorts {
                    tenant_store: tenants.clone(),
                    ..ports
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn refusing(authorities: FakeTenantAuthorities) -> Self {
            Self::with(UpdateMtlsConfigPorts {
                tenant_authorities: Arc::new(authorities),
                ..UpdateMtlsConfigPorts::fakes()
            })
        }

        fn update_as(
            &self,
            ctx: &CallerContext,
            req: UpdateMtlsConfigRequest,
        ) -> Result<(), AppError> {
            block_on(self.uc.execute(ctx, &test_auditor(self.audit.clone()), req))
        }

        fn update(&self, req: UpdateMtlsConfigRequest) -> Result<(), AppError> {
            self.update_as(&test_ctx(), req)
        }

        fn stored_mode(&self) -> MtlsMode {
            block_on(self.tenants.find_by_id(&test_ctx().tenant_id()))
                .unwrap()
                .unwrap()
                .mtls()
                .mode()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn require_one_ca() -> UpdateMtlsConfigRequest {
        UpdateMtlsConfigRequest {
            mode: MtlsMode::Required,
            trusted_ca_certs: vec![CertificatePem::new(CA).unwrap()],
            revocation_lists: Vec::new(),
            proof: right_password(),
        }
    }

    const CRL: &str = "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n";

    /// Ann requires client certificates and gives her authority's
    /// revocation list. The setting keeps it, so the handshake checks it.
    #[test]
    fn a_revocation_list_is_kept_with_the_setting() {
        let setup = Setup::with(UpdateMtlsConfigPorts::fakes());
        let request = UpdateMtlsConfigRequest {
            revocation_lists: vec![RevocationListPem::new(CRL).unwrap()],
            ..require_one_ca()
        };

        setup.update(request).unwrap();

        let stored = block_on(setup.tenants.find_by_id(&test_ctx().tenant_id()))
            .unwrap()
            .unwrap();
        assert!(stored.mtls().checks_revocation());
    }

    /// An unreadable revocation list is refused when enabling mutual TLS.
    /// The tenant's mutual TLS remains disabled.
    #[test]
    fn a_revocation_list_that_does_not_parse_is_refused() {
        let setup = Setup::with(UpdateMtlsConfigPorts {
            cert_validator: Arc::new(ListRejectingValidator),
            ..UpdateMtlsConfigPorts::fakes()
        });
        let request = UpdateMtlsConfigRequest {
            revocation_lists: vec![RevocationListPem::new(CRL).unwrap()],
            ..require_one_ca()
        };

        let result = setup.update(request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.stored_mode(), MtlsMode::Disabled);
    }

    /// A validator taking every certificate and no revocation list.
    struct ListRejectingValidator;

    impl CertPemValidator for ListRejectingValidator {
        fn validate_cert_pem(&self, _pem: &CertificatePem) -> Result<(), DomainError> {
            Ok(())
        }

        fn validate_revocation_list_pem(
            &self,
            _pem: &RevocationListPem,
        ) -> Result<(), DomainError> {
            Err(DomainError::invalid("not a revocation list"))
        }
    }

    /// Ann, who proved herself just now, requires client certificates from
    /// one authority. The setting is saved and recorded.
    #[test]
    fn replaces_mtls_config_and_audits() {
        let setup = Setup::with(UpdateMtlsConfigPorts::fakes());

        setup.update(require_one_ca()).unwrap();

        assert_eq!(setup.stored_mode(), MtlsMode::Required);
        assert_eq!(setup.recorded(), vec!["tenant.mtls_config_updated"]);
    }

    /// Olivia, an owner of the organization signed in on its plane, types
    /// her password again and requires client certificates. The setting is
    /// saved.
    #[test]
    fn a_member_who_proves_herself_replaces_the_trust_anchor() {
        let organization_id = test_ctx().organization_id();
        let olivia = test_org_user(organization_id, "olivia@acme.test", OrgRole::Owner);
        let caller = CallerContext::new(
            CallerIdentity::OrgUser(*olivia.id()),
            Credential::OrgSession(test_session_id()),
            organization_id,
            test_ctx().tenant_id(),
            test_ctx().plan_limits().clone(),
        )
        .unwrap();
        let setup = Setup::with(UpdateMtlsConfigPorts {
            org_users: Arc::new(org_user_store_with([olivia])),
            organizations: org_store_with([test_org(organization_id, "acme")]),
            ..UpdateMtlsConfigPorts::fakes()
        });

        setup.update_as(&caller, require_one_ca()).unwrap();

        assert_eq!(setup.stored_mode(), MtlsMode::Required);
    }

    /// A certificate that does not parse is refused and nothing is saved.
    #[test]
    fn rejects_invalid_cert_pem_without_saving() {
        let setup = Setup::with(UpdateMtlsConfigPorts {
            cert_validator: Arc::new(RejectingValidator),
            ..UpdateMtlsConfigPorts::fakes()
        });

        let result = setup.update(require_one_ca());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.stored_mode(), MtlsMode::Disabled);
        assert!(setup.recorded().is_empty());
    }

    /// A tenant that does not exist is not found.
    #[test]
    fn update_nonexistent_tenant_returns_not_found() {
        let uc = UpdateMtlsConfigUseCase::new(UpdateMtlsConfigPorts::fakes());

        let result = block_on(uc.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            require_one_ca(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A wrong password cannot authorize a new mutual-TLS trust anchor.
    /// The tenant's mutual TLS remains disabled.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::with(UpdateMtlsConfigPorts::fakes());
        let request = UpdateMtlsConfigRequest {
            proof: wrong_password(),
            ..require_one_ca()
        };

        let result = setup.update(request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored_mode(), MtlsMode::Disabled);
    }

    /// A caller without mutual-TLS update rights cannot change the trusted
    /// certificate authorities.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::holding(&[]));

        let result = setup.update(require_one_ca());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot change the tenant's mutual-TLS settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.update(require_one_ca());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot change the tenant's
    /// trusted certificate authorities.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::with(UpdateMtlsConfigPorts::fakes());

        let result = setup.update_as(&operator_without_grant(), require_one_ca());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
