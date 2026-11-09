//! Fakes for reaching a customer's cloud: the connections an organization
//! keeps, a registry that serves AWS alone, and external ids that count.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::organization::cloud::account::{
    CloudAccount, CloudAccountRow, CloudBinding, CloudIdentity, CloudSetup, ConnectionState,
};
use ianua_domain::domains::organization::cloud::credential::{
    CloudCredential, ExternalId, RoleArn,
};
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

use crate::ports::cloud::{
    CloudAccountStore, CloudProviderFactory, CloudProviderRegistry, CredentialVerifier,
    ExternalIdGenerator, NetworkDiscovery,
};
use crate::test_support::Fake;

/// One connection an organization made, with the external id made for it.
struct HeldAccount {
    account: CloudAccount,
    external_id: ExternalId,
}

impl HeldAccount {
    fn is(&self, organization_id: &OrganizationId, provider: CloudProvider) -> bool {
        self.account.organization_id() == organization_id && self.account.provider() == provider
    }
}

/// In-memory store for the cloud connections organizations made, one per
/// organization and cloud. The external id is kept from the first save on,
/// never replaced.
#[derive(Default)]
pub struct FakeCloudAccountStore {
    accounts: Mutex<Vec<HeldAccount>>,
}

impl FakeCloudAccountStore {
    /// A store holding `account`, begun with [`seeded_external_id`].
    #[must_use]
    pub fn holding(account: CloudAccount) -> Self {
        Self {
            accounts: Mutex::new(vec![HeldAccount {
                account,
                external_id: seeded_external_id(),
            }]),
        }
    }

    /// How many connections are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.accounts.lock().unwrap().len()
    }

    /// The connection `organization_id` holds to `provider`, as last saved.
    #[must_use]
    pub fn stored(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Option<CloudAccount> {
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.is(organization_id, provider))
            .map(|held| held.account.clone())
    }
}

/// The external id every connection a test seeds was begun with.
///
/// # Panics
///
/// Never in practice: the id is fixed and valid.
#[must_use]
pub fn seeded_external_id() -> ExternalId {
    ExternalId::new("abcdefghijklmnopqrstuvwxyz012345").expect("a valid external id")
}

/// An AWS role assumed under [`seeded_external_id`].
///
/// # Panics
///
/// Never in practice: the role is fixed and valid.
#[must_use]
pub fn seeded_aws_credential() -> CloudCredential {
    CloudCredential::AwsAssumeRole {
        role_arn: RoleArn::new("arn:aws:iam::123456789012:role/Ianua").expect("a valid role"),
        external_id: seeded_external_id(),
    }
}

/// The account a fake cloud names when it accepts a credential.
///
/// # Panics
///
/// Never in practice: the account id is fixed and valid.
#[must_use]
pub fn seeded_cloud_identity() -> CloudIdentity {
    CloudIdentity::new("123456789012").expect("a valid account id")
}

/// `organization_id`'s AWS connection, begun with [`seeded_external_id`] and
/// standing in `state`, as storage holds it. A verified one is tied to the
/// account it names.
///
/// # Panics
///
/// Never in practice: the state's credential, if any, is
/// [`seeded_aws_credential`].
#[must_use]
pub fn seeded_aws_connection(
    organization_id: OrganizationId,
    state: ConnectionState,
) -> CloudAccount {
    let binding = match &state {
        ConnectionState::Verified { identity, .. } => CloudBinding::Bound(identity.clone()),
        ConnectionState::AwaitingCredential
        | ConnectionState::AwaitingVerification { .. }
        | ConnectionState::Failed { .. } => CloudBinding::Unbound,
    };
    let begun = clock::now() - time::Duration::hours(1);
    CloudAccount::reconstitute(CloudAccountRow {
        organization_id,
        setup: CloudSetup::Aws {
            external_id: seeded_external_id(),
        },
        state,
        binding,
        created_at: begun,
        updated_at: begun,
    })
    .expect("a seeded connection is a consistent row")
}

#[async_trait]
impl CloudAccountStore for FakeCloudAccountStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<Option<CloudAccount>, DomainError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.is(organization_id, provider))
            .map(|held| held.account.clone()))
    }

    async fn list_for_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<CloudAccount>, DomainError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.account.organization_id() == organization_id)
            .map(|held| held.account.clone())
            .collect())
    }

    async fn save(
        &self,
        account: &CloudAccount,
        external_id: &ExternalId,
    ) -> Result<(), DomainError> {
        let mut accounts = self.accounts.lock().unwrap();
        let held = accounts
            .iter_mut()
            .find(|held| held.is(account.organization_id(), account.provider()));
        match held {
            Some(held) => held.account = account.clone(),
            None => accounts.push(HeldAccount {
                account: account.clone(),
                external_id: external_id.clone(),
            }),
        }
        Ok(())
    }

    async fn external_id(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<Option<ExternalId>, DomainError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.is(organization_id, provider))
            .map(|held| held.external_id.clone()))
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<(), DomainError> {
        self.accounts
            .lock()
            .unwrap()
            .retain(|held| !held.is(organization_id, provider));
        Ok(())
    }
}

/// What the fake cloud says when asked to prove a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The credential checks out and the cloud names its account.
    Accepts,
    /// The cloud refuses the credential.
    Rejects,
    /// The cloud cannot be reached.
    Unreachable,
    /// The credential names something the customer got wrong, such as a
    /// cluster address nobody can reach.
    Correctable,
}

/// A registry that serves AWS alone, answering as `0` says, so the path for
/// a cloud this deployment does not drive is reachable in a test.
pub struct AwsOnlyRegistry(pub VerifyOutcome);

impl CloudProviderRegistry for AwsOnlyRegistry {
    fn factory(
        &self,
        provider: CloudProvider,
    ) -> Result<Arc<dyn CloudProviderFactory>, DomainError> {
        if provider != CloudProvider::Aws {
            return Err(DomainError::invalid(format!(
                "{provider:?} is not configured in this deployment"
            )));
        }
        Ok(Arc::new(FakeFactory(self.0)))
    }

    fn available(&self) -> Vec<CloudProvider> {
        vec![CloudProvider::Aws]
    }
}

/// External id generator that counts what it hands out, so a test shows a
/// second start reused the first id instead of making another.
#[derive(Default)]
pub struct CountingExternalIds {
    issued: Mutex<usize>,
}

impl CountingExternalIds {
    /// How many ids were handed out.
    #[must_use]
    pub fn issued(&self) -> usize {
        *self.issued.lock().unwrap()
    }
}

impl ExternalIdGenerator for CountingExternalIds {
    fn generate(&self) -> Result<ExternalId, DomainError> {
        let mut issued = self.issued.lock().unwrap();
        *issued += 1;
        Ok(ExternalId::new(format!(
            "external-id-padding-value-{:04}",
            *issued
        ))?)
    }
}

/// AWS, answering every credential as the outcome says.
struct FakeFactory(VerifyOutcome);

impl CloudProviderFactory for FakeFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }

    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier> {
        Arc::new(FakeVerifier(self.0))
    }

    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery> {
        Arc::new(EmptyDiscovery)
    }
}

/// A verifier answering every credential as the outcome says.
struct FakeVerifier(VerifyOutcome);

#[async_trait]
impl CredentialVerifier for FakeVerifier {
    async fn verify(&self, _credential: &CloudCredential) -> Result<CloudIdentity, DomainError> {
        match self.0 {
            VerifyOutcome::Accepts => Ok(CloudIdentity::new("123456789012")?),
            VerifyOutcome::Rejects => Err(DomainError::forbidden(
                "the trust policy does not name our account",
            )),
            VerifyOutcome::Unreachable => Err(DomainError::infra_msg("could not reach the cloud")),
            VerifyOutcome::Correctable => Err(DomainError::invalid("no cluster answers there")),
        }
    }
}

/// An account with no usable region or network.
struct EmptyDiscovery;

#[async_trait]
impl NetworkDiscovery for EmptyDiscovery {
    async fn regions(
        &self,
        _credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError> {
        Ok(Vec::new())
    }

    async fn networks(
        &self,
        _credential: &CloudCredential,
        _region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError> {
        Ok(Vec::new())
    }
}

impl Fake for Arc<dyn CloudAccountStore> {
    fn fake() -> Self {
        Arc::new(FakeCloudAccountStore::default())
    }
}

impl Fake for Arc<dyn CloudProviderRegistry> {
    fn fake() -> Self {
        Arc::new(AwsOnlyRegistry(VerifyOutcome::Accepts))
    }
}

impl Fake for Arc<dyn ExternalIdGenerator> {
    fn fake() -> Self {
        Arc::new(CountingExternalIds::default())
    }
}
