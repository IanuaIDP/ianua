//! Forgetting an organization's connection to one cloud.

use std::sync::Arc;

use ianua_domain::domains::organization::cloud::account::{CloudAccount, TenantsInCloud};
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::cloud::CloudAccountStore;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::organization::cloud_accounts::rights::ensure_may_connect;

/// The ports [`DisconnectUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisconnectPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// The organization's tenants, to count those still living in the
    /// cloud.
    pub tenants: Arc<dyn TenantStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Forgets an organization's connection to one cloud.
pub struct DisconnectUseCase {
    ports: DisconnectPorts,
}

impl DisconnectUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DisconnectPorts) -> Self {
        Self { ports }
    }
}

impl Command for DisconnectUseCase {
    type Caller = OrgCaller;
    type Input = CloudProvider;
    type Output = Result<(), AppError>;

    /// Forgets the connection of `caller`'s organization to `provider` and
    /// records `organization.cloud_account_disconnected`.
    ///
    /// Refused while a tenant of the organization still lives in that
    /// cloud. Dropping the grant would leave infrastructure we can no longer
    /// reach, still running and billing, and strand the tenants whose data
    /// is in it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization.
    /// - `AppError::Conflict` if tenants still run there, naming how many.
    /// - `AppError::Internal` on a storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        provider: CloudProvider,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_may_connect(&control, organization.id())?;
        let left = self
            .ports
            .tenants
            .count_in_cloud(organization.id(), provider)
            .await
            .or_internal()?;
        let disconnection = CloudAccount::disconnect(
            organization.id(),
            provider,
            TenantsInCloud::counted(left),
            &control,
        )
        .map_err(AppError::from_domain)?;
        self.ports
            .store
            .delete(organization.id(), disconnection.provider())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), disconnection.events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::ConnectionState;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;
    use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
    use ianua_domain::domains::tenant::compliance::CompliancePosture;
    use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
    use ianua_domain::domains::tenant::environment::TenantEnvironment;
    use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, NetworkHandle, NetworkPlacement, Placement,
        TenantResidency,
    };
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{
        DisplayName, Email, Locale, OrganizationId, Setting, TenantId, TenantSlug, Timezone,
    };

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{FakeCloudAccountStore, seeded_aws_connection};
    use crate::test_support::tenant::FakeTenantStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        store: Arc<FakeCloudAccountStore>,
        audit: Arc<FakeEventDispatcher>,
        uc: DisconnectUseCase,
    }

    impl Fixture {
        fn with(tenants: Vec<Tenant>, actors: FakeOrgActors) -> Self {
            let begun = seeded_aws_connection(acme(), ConnectionState::AwaitingCredential);
            let store = Arc::new(FakeCloudAccountStore::holding(begun));
            Self {
                uc: DisconnectUseCase::new(DisconnectPorts {
                    store: store.clone(),
                    tenants: Arc::new(FakeTenantStore::holding_all(tenants)),
                    org_actors: Arc::new(actors),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn disconnect(&self, provider: CloudProvider) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                provider,
            ))
        }

        fn still_connected(&self) -> bool {
            self.store.stored(&acme(), CloudProvider::Aws).is_some()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    fn owner() -> FakeOrgActors {
        FakeOrgActors::in_role(OrgRole::Owner)
    }

    /// Acme's production tenant, whose database lives in Acme's own AWS
    /// account.
    fn production_in_customer_aws() -> Tenant {
        let limits = DomainLimits::default();
        let now = clock::now();
        let residency = customer_aws_residency();
        Tenant::reconstitute(TenantRow {
            id: TenantId::new(),
            organization_id: acme(),
            slug: TenantSlug::new("production", &limits.slug).unwrap(),
            platform_label: ianua_domain::domains::tenant::hosts::PlatformLabel::new("k7f3q9")
                .unwrap(),
            readable_address: ianua_domain::domains::tenant::hosts::ReadableAddress::Off,
            display_name: DisplayName::new("Production", &limits.display_name).unwrap(),
            primary_domain: Setting::Unset,
            contact_email: Email::new("ops@acme.test").unwrap(),
            status: TenantStatus::Provisioning,
            hold: PlatformHold::Free,
            archival: Archival::NotArchived,
            compliance: CompliancePosture::default_from(&ComplianceLimits::default()),
            auth_config: TenantAuthConfig::default(),
            mtls: MtlsConfig::disabled(),
            timezone: Timezone::new("UTC").unwrap(),
            locale: Locale::new("en-US").unwrap(),
            residency,
            environment: TenantEnvironment::Production,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    /// Places a dedicated database in the customer's existing AWS network.
    fn customer_aws_residency() -> TenantResidency {
        TenantResidency::new(
            Placement::CustomerCloud {
                provider: CloudProvider::Aws,
                region: DeploymentRegion::EuCentral1,
                network: NetworkPlacement::Existing(NetworkHandle::new("prod-db").unwrap()),
            },
            IsolationLevel::DedicatedInstance,
        )
        .unwrap()
    }

    /// Olivia, an owner, disconnects Acme's AWS account, which no tenant
    /// lives in. It is forgotten and the disconnection recorded.
    #[test]
    fn disconnecting_forgets_a_connection_nothing_depends_on() {
        let fixture = Fixture::with(Vec::new(), owner());

        fixture.disconnect(CloudProvider::Aws).unwrap();

        assert!(!fixture.still_connected());
        assert_eq!(
            fixture.recorded(),
            vec!["organization.cloud_account_disconnected"]
        );
    }

    /// Olivia disconnects Acme's AWS account while production's database
    /// still lives there. Dropping the grant would strand a database we
    /// could no longer reach, so it is refused and the connection stays.
    #[test]
    fn disconnecting_is_refused_while_a_tenant_still_lives_there() {
        let fixture = Fixture::with(vec![production_in_customer_aws()], owner());

        let result = fixture.disconnect(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.still_connected());
    }

    /// Production lives in Acme's AWS account. Disconnecting Google Cloud
    /// is not held back by it: the guard counts by cloud.
    #[test]
    fn a_tenant_in_another_cloud_does_not_block_disconnecting_this_one() {
        let fixture = Fixture::with(vec![production_in_customer_aws()], owner());

        let result = fixture.disconnect(CloudProvider::Gcp);

        assert!(result.is_ok());
    }

    /// A plain member cannot disconnect AWS; the connection stays and no
    /// disconnection is recorded.
    #[test]
    fn a_plain_member_is_refused() {
        let fixture = Fixture::with(Vec::new(), FakeOrgActors::in_role(OrgRole::Member));

        let result = fixture.disconnect(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.still_connected());
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller cannot disconnect AWS, leaving its connection
    /// stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::with(Vec::new(), FakeOrgActors::refusing(Refusal::SignedOut));

        let result = fixture.disconnect(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.still_connected());
    }

    /// Refused organization authority prevents cloud disconnection.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let fixture = Fixture::with(Vec::new(), FakeOrgActors::refusing(Refusal::Forbidden));

        let result = fixture.disconnect(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
