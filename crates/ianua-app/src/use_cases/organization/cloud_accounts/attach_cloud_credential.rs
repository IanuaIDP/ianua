//! The second step of connecting a cloud account: the credential the
//! customer granted is recorded on the connection they began. It proves
//! nothing yet.

use std::sync::Arc;

use ianua_domain::domains::organization::cloud::credential::CloudCredential;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::cloud::CloudAccountStore;
use crate::use_case::Command;
use crate::use_cases::organization::cloud_accounts::lookup::{
    begun_external_id, existing_cloud_account,
};

/// The credential the customer granted, and when it arrived.
pub struct AttachCloudCredentialRequest {
    /// The credential, which names its own cloud.
    pub credential: CloudCredential,
    /// When the credential is attached.
    pub now: OffsetDateTime,
}

/// The ports [`AttachCloudCredentialUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AttachCloudCredentialPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Records the credential a customer granted for a begun connection.
pub struct AttachCloudCredentialUseCase {
    ports: AttachCloudCredentialPorts,
}

impl AttachCloudCredentialUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AttachCloudCredentialPorts) -> Self {
        Self { ports }
    }
}

impl Command for AttachCloudCredentialUseCase {
    type Caller = OrgCaller;
    type Input = AttachCloudCredentialRequest;
    type Output = Result<(), AppError>;

    /// Records the credential the customer granted, and
    /// `organization.cloud_credential_attached`.
    ///
    /// It is not tried here; verifying it is the next step, kept apart so a
    /// cloud outage then leaves the credential stored and retryable. A new
    /// credential on a verified connection is a rotation, and leaves the
    /// connection unusable until it is proved again.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization.
    /// - `AppError::NotFound` when no connection to the credential's cloud
    ///   was begun. The external id is made there, so a credential arriving
    ///   first cannot name it.
    /// - `AppError::Domain` when an AWS role is assumed under another
    ///   external id than the connection was begun with.
    /// - `AppError::Internal` on a storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: AttachCloudCredentialRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let store = self.ports.store.as_ref();
        let provider = request.credential.provider();
        let external_id = begun_external_id(store, organization.id(), provider).await?;
        let mut account = existing_cloud_account(store, organization.id(), provider).await?;
        account
            .attach_credential(request.credential, request.now, &control)
            .map_err(AppError::from_domain)?;
        store.save(&account, &external_id).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), account.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::ConnectionState;
    use ianua_domain::domains::organization::cloud::credential::{
        CloudSecret, ExternalId, RoleArn,
    };
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
    use ianua_domain::shared::clock;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeCloudAccountStore, seeded_aws_connection, seeded_aws_credential, seeded_cloud_identity,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        store: Arc<FakeCloudAccountStore>,
        audit: Arc<FakeEventDispatcher>,
        uc: AttachCloudCredentialUseCase,
    }

    impl Fixture {
        fn with(store: FakeCloudAccountStore, actors: FakeOrgActors) -> Self {
            let store = Arc::new(store);
            Self {
                uc: AttachCloudCredentialUseCase::new(AttachCloudCredentialPorts {
                    store: store.clone(),
                    org_actors: Arc::new(actors),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn begun_by(actors: FakeOrgActors) -> Self {
            let begun = seeded_aws_connection(acme(), ConnectionState::AwaitingCredential);
            Self::with(FakeCloudAccountStore::holding(begun), actors)
        }

        fn attach(&self, credential: CloudCredential) -> Result<(), AppError> {
            let request = AttachCloudCredentialRequest {
                credential,
                now: clock::now(),
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn stored_state(&self) -> ConnectionState {
            self.store
                .stored(&acme(), CloudProvider::Aws)
                .unwrap()
                .state()
                .clone()
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

    /// Olivia, an owner, pastes the role she created for Acme's AWS
    /// connection. It is kept, waiting to be proved, and the attaching is
    /// recorded.
    #[test]
    fn attach_records_the_credential_and_awaits_verification() {
        let fixture = Fixture::begun_by(owner());

        fixture.attach(seeded_aws_credential()).unwrap();

        assert!(matches!(
            fixture.stored_state(),
            ConnectionState::AwaitingVerification { .. }
        ));
        assert_eq!(
            fixture.recorded(),
            vec!["organization.cloud_credential_attached"]
        );
    }

    /// Olivia pastes a role before starting any connection. There is no
    /// external id it could name, so it is not found.
    #[test]
    fn attach_before_begin_is_refused() {
        let fixture = Fixture::with(FakeCloudAccountStore::default(), owner());

        let result = fixture.attach(seeded_aws_credential());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Olivia pastes a DigitalOcean token while only AWS was begun. No
    /// DigitalOcean connection exists, so it is not found.
    #[test]
    fn attaching_a_credential_for_the_wrong_cloud_is_refused() {
        let fixture = Fixture::begun_by(owner());
        let token = CloudCredential::DigitalOceanToken {
            token: CloudSecret::new("dop_v1_x").unwrap(),
        };

        let result = fixture.attach(token);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A role using another external id is refused; Acme's connection
    /// remains waiting for a credential.
    #[test]
    fn a_role_under_another_external_id_is_refused() {
        let fixture = Fixture::begun_by(owner());
        let theirs = CloudCredential::AwsAssumeRole {
            role_arn: RoleArn::new("arn:aws:iam::999999999999:role/Theirs").unwrap(),
            external_id: ExternalId::new("zyxwvutsrqponmlkjihgfedcba543210").unwrap(),
        };

        let result = fixture.attach(theirs);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.stored_state(), ConnectionState::AwaitingCredential);
    }

    /// Olivia rotates the role of a verified connection. Until the new one
    /// is proved, the connection is not usable.
    #[test]
    fn rotating_a_credential_makes_a_verified_connection_unusable_until_reproved() {
        let verified = seeded_aws_connection(
            acme(),
            ConnectionState::Verified {
                credential: seeded_aws_credential(),
                at: clock::now(),
                identity: seeded_cloud_identity(),
            },
        );
        let fixture = Fixture::with(FakeCloudAccountStore::holding(verified), owner());

        fixture.attach(seeded_aws_credential()).unwrap();

        let stored = fixture.store.stored(&acme(), CloudProvider::Aws).unwrap();
        assert!(!stored.is_usable());
    }

    /// A plain member cannot attach a role; the connection keeps waiting
    /// for a credential and nothing is recorded.
    #[test]
    fn a_plain_member_is_refused() {
        let fixture = Fixture::begun_by(FakeOrgActors::in_role(OrgRole::Member));

        let result = fixture.attach(seeded_aws_credential());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.stored_state(), ConnectionState::AwaitingCredential);
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller must authenticate before attaching a credential.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::begun_by(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = fixture.attach(seeded_aws_credential());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents attaching a role.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let fixture = Fixture::begun_by(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = fixture.attach(seeded_aws_credential());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
