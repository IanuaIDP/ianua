//! The first of three steps connecting an organization's own cloud account:
//! an external id is generated and the instructions embedding it handed
//! back. Nothing is granted yet.
//!
//! The steps are apart because the customer leaves in the middle of them:
//! this one ends in their cloud console, attaching the credential begins
//! when they come back, and verifying it proves it on the screen where it
//! was entered rather than three minutes into provisioning a tenant.

use std::sync::Arc;

use ianua_domain::domains::organization::cloud::account::{CloudAccount, CloudSetup};
use ianua_domain::domains::organization::cloud::credential::ExternalId;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrganizationId};
use time::OffsetDateTime;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::cloud::{CloudAccountStore, CloudProviderRegistry, ExternalIdGenerator};
use crate::use_case::Command;
use crate::use_cases::organization::cloud_accounts::rights::ensure_may_connect;

/// What the customer needs to grant us access.
pub struct ConnectionInstructions {
    /// The cloud being connected.
    pub provider: CloudProvider,
    /// The external id to place in the trust policy.
    ///
    /// Returned so the customer's console can be pre-filled with it. On its
    /// own it grants nothing, but it is still shown only to someone who may
    /// change the organization.
    pub external_id: ExternalId,
}

/// Which cloud to start connecting, and when.
pub struct BeginCloudConnectionRequest {
    /// The cloud being connected.
    pub provider: CloudProvider,
    /// When the connection is begun.
    pub now: OffsetDateTime,
}

/// The ports [`BeginCloudConnectionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BeginCloudConnectionPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// Which clouds this deployment can drive.
    pub registry: Arc<dyn CloudProviderRegistry>,
    /// Makes the shared secret that guards an `AssumeRole`.
    pub external_ids: Arc<dyn ExternalIdGenerator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Starts connecting an organization's cloud account.
pub struct BeginCloudConnectionUseCase {
    ports: BeginCloudConnectionPorts,
}

impl BeginCloudConnectionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BeginCloudConnectionPorts) -> Self {
        Self { ports }
    }

    /// Stores a fresh connection begun by `control` and returns the external
    /// id generated for it, with the connection as stored.
    async fn started(
        &self,
        organization_id: OrganizationId,
        request: &BeginCloudConnectionRequest,
        control: &OrgControl<'_>,
    ) -> Result<(ExternalId, CloudAccount), AppError> {
        let external_id = self.ports.external_ids.generate().or_internal()?;
        let setup = setup_for(request.provider, &external_id);
        let account = CloudAccount::begin(organization_id, setup, request.now, control)
            .map_err(AppError::from_domain)?;
        self.ports
            .store
            .save(&account, &external_id)
            .await
            .or_internal()?;
        Ok((external_id, account))
    }
}

impl Command for BeginCloudConnectionUseCase {
    type Caller = OrgCaller;
    type Input = BeginCloudConnectionRequest;
    type Output = Result<ConnectionInstructions, AppError>;

    /// Starts a connection and returns what the customer must do next.
    ///
    /// Running it again for a cloud already being connected returns the
    /// external id already made: it may sit in a trust policy the customer
    /// created, and replacing it would break an `AssumeRole` about to start
    /// working. A new connection records
    /// `organization.cloud_connection_started`; running it again records
    /// nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization.
    /// - `AppError::Domain` when this deployment has no adapter for that
    ///   cloud.
    /// - `AppError::Internal` on a storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: BeginCloudConnectionRequest,
    ) -> Result<ConnectionInstructions, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let organization_id = *organization.id();
        ensure_may_connect(&control, &organization_id)?;
        let provider = request.provider;
        self.ports
            .registry
            .factory(provider)
            .map_err(AppError::from_domain)?;
        let begun = self
            .ports
            .store
            .external_id(&organization_id, provider)
            .await
            .or_internal()?;
        if let Some(external_id) = begun {
            return Ok(instructions(provider, external_id));
        }
        let (external_id, mut account) = self.started(organization_id, &request, &control).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), account.take_events())
            .await
            .or_internal()?;
        Ok(instructions(provider, external_id))
    }
}

/// What the customer is told to do for `provider`, with `external_id`.
fn instructions(provider: CloudProvider, external_id: ExternalId) -> ConnectionInstructions {
    ConnectionInstructions {
        provider,
        external_id,
    }
}

/// What a connection to `provider` is begun with: for AWS, the external id
/// its trust policy must name.
fn setup_for(provider: CloudProvider, external_id: &ExternalId) -> CloudSetup {
    match provider {
        CloudProvider::Aws => CloudSetup::Aws {
            external_id: external_id.clone(),
        },
        CloudProvider::Gcp => CloudSetup::Gcp,
        CloudProvider::Azure => CloudSetup::Azure,
        CloudProvider::DigitalOcean => CloudSetup::DigitalOcean,
        CloudProvider::Kubernetes => CloudSetup::Kubernetes,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::ConnectionState;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{CountingExternalIds, FakeCloudAccountStore};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        store: Arc<FakeCloudAccountStore>,
        external_ids: Arc<CountingExternalIds>,
        audit: Arc<FakeEventDispatcher>,
        uc: BeginCloudConnectionUseCase,
    }

    impl Fixture {
        fn acting_as(actors: FakeOrgActors) -> Self {
            let store = Arc::new(FakeCloudAccountStore::default());
            let external_ids = Arc::new(CountingExternalIds::default());
            Self {
                uc: BeginCloudConnectionUseCase::new(BeginCloudConnectionPorts {
                    store: store.clone(),
                    external_ids: external_ids.clone(),
                    org_actors: Arc::new(actors),
                    ..BeginCloudConnectionPorts::fakes()
                }),
                store,
                external_ids,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn owner() -> Self {
            Self::acting_as(FakeOrgActors::in_role(OrgRole::Owner))
        }

        fn begin(&self, provider: CloudProvider) -> Result<ConnectionInstructions, AppError> {
            let request = BeginCloudConnectionRequest {
                provider,
                now: clock::now(),
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    /// Olivia, an owner, starts connecting Acme's AWS account. An external id
    /// is made, the connection waits for a credential, and the start is
    /// recorded.
    #[test]
    fn begin_issues_an_external_id_and_stores_an_unstarted_connection() {
        let fixture = Fixture::owner();

        let instructions = fixture.begin(CloudProvider::Aws).unwrap();

        assert_eq!(instructions.provider, CloudProvider::Aws);
        let account = fixture.store.stored(&acme(), CloudProvider::Aws).unwrap();
        assert_eq!(account.state(), &ConnectionState::AwaitingCredential);
        assert!(!account.is_usable());
        assert_eq!(
            fixture.recorded(),
            vec!["organization.cloud_connection_started"]
        );
    }

    /// Olivia starts connecting AWS twice. The second time hands back the
    /// external id already in her trust policy, makes no new one and records
    /// nothing new.
    #[test]
    fn beginning_twice_keeps_the_external_id_already_in_their_trust_policy() {
        let fixture = Fixture::owner();

        let first = fixture.begin(CloudProvider::Aws).unwrap();
        let second = fixture.begin(CloudProvider::Aws).unwrap();

        assert_eq!(first.external_id.as_str(), second.external_id.as_str());
        assert_eq!(fixture.external_ids.issued(), 1);
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// Olivia asks to connect Azure, which this deployment cannot drive. It
    /// is refused as invalid and nothing is stored.
    #[test]
    fn begin_refuses_a_cloud_this_deployment_cannot_drive() {
        let fixture = Fixture::owner();

        let result = fixture.begin(CloudProvider::Azure);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(fixture.store.count(), 0);
    }

    /// A plain member cannot begin a cloud connection; none is stored and
    /// no start is recorded.
    #[test]
    fn a_plain_member_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::in_role(OrgRole::Member));

        let result = fixture.begin(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.store.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller must authenticate before starting a connection.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = fixture.begin(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents starting a connection and
    /// leaves the store empty.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = fixture.begin(CloudProvider::Aws);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.store.count(), 0);
    }
}
