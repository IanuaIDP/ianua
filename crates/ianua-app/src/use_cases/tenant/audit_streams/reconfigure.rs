//! Reconfigure audit stream: rename a stream, point it somewhere else, or
//! change which records it sends.
//!
//! Pointing a stream somewhere else moves the tenant's records with it, so
//! it needs the same fresh proof of the person as adding one.

use std::sync::Arc;

use ianua_domain::domains::audit::streaming::StreamFilter;
use ianua_domain::domains::tenant::audit_streams::StreamSettings;
use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AuditStreamId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditStreamStore;
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::fresh_proof::admin::{AdminProofSources, proved_admin};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;
use crate::use_cases::tenant::audit_streams::destination::{
    StreamTarget, credentials_place, sealed_destination,
};
use crate::use_cases::tenant::audit_streams::lookup::{acting_tenant, existing_stream};

/// The stream's new name, destination and filter, all three at once as a
/// form saves them, with what the caller gave to prove who they are.
pub struct ReconfigureRequest {
    /// The saved audit destination whose settings will change.
    pub stream_id: AuditStreamId,
    /// What it is called.
    pub name: Label,
    /// Where records go, with its credentials as typed.
    pub target: StreamTarget,
    /// Which records go.
    pub filter: StreamFilter,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`ReconfigureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReconfigurePorts {
    /// Tenants, for the one the stream belongs to.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// Seals the destination's credentials before they are kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Organization members, for a member changing the stream.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member changing the stream.
    pub organizations: Arc<dyn OrganizationStore>,
}

/// Replaces an audit stream's name, destination and filter.
pub struct ReconfigureUseCase {
    ports: ReconfigurePorts,
}

impl ReconfigureUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ReconfigurePorts) -> Self {
        Self { ports }
    }

    /// The settings `name`, `target` and `filter` describe, the
    /// credentials sealed for `place`.
    async fn settings(
        &self,
        name: Label,
        target: StreamTarget,
        filter: StreamFilter,
        place: &SealedFor,
    ) -> Result<StreamSettings, AppError> {
        Ok(StreamSettings {
            name,
            destination: sealed_destination(self.ports.encryptor.as_ref(), target, place).await?,
            filter,
        })
    }

    /// Where the administrator changing the stream is proved again from.
    fn admin_sources(&self) -> AdminProofSources<'_> {
        AdminProofSources {
            authorities: self.ports.tenant_authorities.as_ref(),
            proofs: self.ports.fresh_proofs.as_ref(),
            members: self.ports.org_users.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        }
    }
}

impl Command for ReconfigureUseCase {
    type Caller = CallerContext;
    type Input = ReconfigureRequest;
    type Output = Result<(), AppError>;

    /// Replaces the name, destination and filter of the stream `request`
    /// names. A failing stream starts counting again, since the destination
    /// may be new. Records `tenant.audit_stream_changed` with the kinds of
    /// destination before and after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without compliance rights, through a key or for inadequate fresh proof.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::NotFound` for a missing tenant/stream; `Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ReconfigureRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::AuditStreaming)
            .map_err(AppError::from_domain)?;
        let admin = proved_admin(self.admin_sources(), ctx, request.proof).await?;
        let scope = acting_tenant(self.ports.tenant_store.as_ref(), ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.stream_store.as_ref();
        let mut stream = existing_stream(store, &tenant, &request.stream_id).await?;
        let place = credentials_place(&tenant, stream.id());
        let settings = self
            .settings(request.name, request.target, request.filter, &place)
            .await?;
        stream
            .reconfigure(
                settings,
                &scope,
                TenantControl::new(&authority),
                admin.fresh(),
            )
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &stream).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), stream.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::audit_streams::{AuditStream, StreamState};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{EventType, PublicHttpsUrl};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::tenant::{
        FakeAuditStreamStore, FakeTenantStore, audit_stream_in_state, test_tenant_for_ctx,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::tenant::audit_streams::destination::TypedAuthorization;

    struct Setup {
        uc: ReconfigureUseCase,
        streams: Arc<FakeAuditStreamStore>,
        audit: Arc<FakeEventDispatcher>,
        id: AuditStreamId,
    }

    impl Setup {
        fn over(stream: AuditStream<ResolvedTenant>, authorities: FakeTenantAuthorities) -> Self {
            let id = *stream.id();
            let streams = Arc::new(FakeAuditStreamStore::holding(
                test_ctx().tenant_id(),
                [stream],
            ));
            Self {
                uc: ReconfigureUseCase::new(ReconfigurePorts {
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    stream_store: streams.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..ReconfigurePorts::fakes()
                }),
                streams,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn new() -> Self {
            Self::over(
                audit_stream_in_state("SIEM", StreamFilter::everything(), StreamState::Active),
                FakeTenantAuthorities::holding_everything(),
            )
        }

        fn reconfigure_to(&self, id: AuditStreamId, proof: ReenteredProof) -> Result<(), AppError> {
            let request = ReconfigureRequest {
                stream_id: id,
                name: Label::new("name", "Security SIEM").unwrap(),
                target: StreamTarget::Http {
                    endpoint: PublicHttpsUrl::new("https://logs.acme.com/in").unwrap(),
                    authorization: TypedAuthorization::Unauthenticated,
                },
                filter: StreamFilter::only(vec![
                    EventType::parse("tenant.compliance_changed").unwrap(),
                ])
                .unwrap(),
                proof,
            };
            block_on(
                self.uc
                    .execute(&test_ctx(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn reconfigure(&self, proof: ReenteredProof) -> Result<(), AppError> {
            self.reconfigure_to(self.id, proof)
        }

        fn stored(&self) -> AuditStream<ResolvedTenant> {
            self.streams
                .stored(test_ctx().tenant_id(), &self.id)
                .unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann, who proved herself just now, renames the stream and narrows it
    /// to compliance changes. Both are kept and the change recorded.
    #[test]
    fn a_proved_admin_reconfigures_the_stream() {
        let setup = Setup::new();

        setup.reconfigure(right_password()).unwrap();

        let stored = setup.stored();
        assert_eq!(stored.name().as_str(), "Security SIEM");
        assert!(stored.filter().events().is_some());
        assert_eq!(setup.recorded(), vec!["tenant.audit_stream_changed"]);
    }

    /// The stream had failed twice. Pointed somewhere new, it counts again
    /// from nothing.
    #[test]
    fn a_failing_stream_starts_counting_again() {
        let failing = StreamState::Failing {
            since: ianua_domain::shared::clock::now(),
            failures: 2,
        };
        let setup = Setup::over(
            audit_stream_in_state("SIEM", StreamFilter::everything(), failing),
            FakeTenantAuthorities::holding_everything(),
        );

        setup.reconfigure(right_password()).unwrap();

        assert_eq!(setup.stored().state(), StreamState::Active);
    }

    /// Ann names a stream Acme does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let setup = Setup::new();

        let result = setup.reconfigure_to(AuditStreamId::new(), right_password());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A wrong password cannot authorize new stream settings. The stored
    /// stream keeps its name and no change is recorded.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::new();

        let result = setup.reconfigure(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().name().as_str(), "SIEM");
        assert!(setup.recorded().is_empty());
    }

    /// A caller without compliance rights cannot reconfigure the stream.
    /// Its stored name stays unchanged.
    #[test]
    fn a_caller_without_the_compliance_right_is_refused() {
        let setup = Setup::over(
            audit_stream_in_state("SIEM", StreamFilter::everything(), StreamState::Active),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = setup.reconfigure(right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().name().as_str(), "SIEM");
    }

    /// A signed-out session cannot reconfigure an audit stream.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            audit_stream_in_state("SIEM", StreamFilter::everything(), StreamState::Active),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.reconfigure(right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
