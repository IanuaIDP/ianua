//! Create audit stream: send a tenant's audit records to the SIEM it runs.
//!
//! A stream carries every record out of the platform. So adding one needs
//! the compliance right and the person proving who they are again just
//! now: Mallory, holding a stolen admin session, cannot quietly copy the
//! tenant's whole history to a server of her own.

use std::sync::Arc;

use ianua_domain::domains::audit::streaming::StreamFilter;
use ianua_domain::domains::tenant::audit_streams::{AuditStream, NewAuditStream};
use ianua_domain::domains::tenant::control::TenantControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AuditStreamId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditStreamStore;
use crate::ports::authentication::SecretEncryptor;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::fresh_proof::admin::{
    AdminProofSources, ProvedAdmin, proved_admin,
};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::limits::room::ensure_room_in_tenant;
use crate::use_case::Command;
use crate::use_cases::tenant::audit_streams::destination::{
    StreamTarget, credentials_place, sealed_destination,
};
use crate::use_cases::tenant::audit_streams::lookup::acting_tenant;

/// The stream to add, with what the caller gave to prove who they are.
pub struct CreateRequest {
    /// What it is called, such as "Splunk production".
    pub name: Label,
    /// Where records go, with its credentials as typed.
    pub target: StreamTarget,
    /// Which records go.
    pub filter: StreamFilter,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Tenants, for the one the stream belongs to.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where the tenant's streams are kept.
    pub stream_store: Arc<dyn AuditStreamStore>,
    /// Seals the destination's credentials before they are kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant's plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Organization members, for a member adding the stream.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member adding the stream.
    pub organizations: Arc<dyn OrganizationStore>,
}

/// Adds an audit stream to the caller's tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// Refuses another stream once the plan of the tenant `ctx` acts in has
    /// as many as it allows.
    ///
    /// # Errors
    ///
    /// `AppError::Forbidden` when the plan's audit stream limit is reached.
    async fn ensure_room_for_another(&self, ctx: &CallerContext) -> Result<(), AppError> {
        ensure_room_in_tenant(
            self.ports.limit_enforcer.as_ref(),
            ctx,
            ResourceKind::AuditStreams,
        )
        .await
    }

    /// The administrator `ctx` is, proved again just now by `proof`.
    ///
    /// # Errors
    ///
    /// The refusals of `proved_admin`: `AppError::Forbidden`,
    /// `AppError::StepUpRequired` or `AppError::AccountLocked` when `proof`
    /// does not prove them, `AppError::Internal` on lookup failure.
    async fn admin_proved_by(
        &self,
        ctx: &CallerContext,
        proof: ReenteredProof,
    ) -> Result<ProvedAdmin, AppError> {
        let sources = AdminProofSources {
            authorities: self.ports.tenant_authorities.as_ref(),
            proofs: self.ports.fresh_proofs.as_ref(),
            members: self.ports.org_users.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        proved_admin(sources, ctx, proof).await
    }

    /// What adding the stream `request` describes asks for, its
    /// credentials sealed, beside how many streams the tenant has.
    async fn new_stream(
        &self,
        ctx: &CallerContext,
        name: Label,
        target: StreamTarget,
        filter: StreamFilter,
    ) -> Result<NewAuditStream, AppError> {
        let existing = self
            .ports
            .stream_store
            .list(&ctx.tenant())
            .await
            .or_internal()?;
        let id = AuditStreamId::new();
        let place = credentials_place(&ctx.tenant(), &id);
        let destination = sealed_destination(self.ports.encryptor.as_ref(), target, &place).await?;
        Ok(NewAuditStream {
            id,
            name,
            destination,
            filter,
            existing_streams: existing.len(),
        })
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<AuditStreamId, AppError>;

    /// Adds the stream `request` describes to the tenant `ctx` acts in. It
    /// starts sending at once. Records `tenant.audit_stream_created`, naming
    /// the kind of destination and never its credentials.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without compliance rights, through a key, for inadequate fresh proof or a full plan.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Conflict` for the maximum stream count; `NotFound` for a missing tenant.
    /// - `AppError::Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<AuditStreamId, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ensure_room_for_another(ctx).await?;
        let admin = self.admin_proved_by(ctx, request.proof).await?;
        let scope = acting_tenant(self.ports.tenant_store.as_ref(), ctx).await?;
        let new = self
            .new_stream(ctx, request.name, request.target, request.filter)
            .await?;
        let mut stream =
            AuditStream::create(new, &scope, TenantControl::new(&authority), admin.fresh())
                .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        self.ports
            .stream_store
            .save(&tenant, &stream)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), stream.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*stream.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::{
        HttpAuthorization, StreamDestination, StreamHeaderName,
    };
    use ianua_domain::domains::authorization::permission::{ComplianceAction, SystemPermission};
    use ianua_domain::domains::tenant::audit_streams::MAX_AUDIT_STREAMS;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{HeaderName, PublicHttpsUrl};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeEncryptor, right_password, wrong_password};
    use crate::test_support::tenant::{
        FakeAuditStreamStore, FakeTenantStore, test_audit_stream, test_tenant_for_ctx,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::tenant::audit_streams::destination::TypedAuthorization;

    struct Setup {
        uc: CreateUseCase,
        streams: Arc<FakeAuditStreamStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn over(streams: FakeAuditStreamStore, authorities: FakeTenantAuthorities) -> Self {
            let streams = Arc::new(streams);
            Self {
                uc: CreateUseCase::new(CreatePorts {
                    tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    stream_store: streams.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..CreatePorts::fakes()
                }),
                streams,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::over(
                FakeAuditStreamStore::empty(),
                FakeTenantAuthorities::holding_everything(),
            )
        }

        fn create(&self, proof: ReenteredProof) -> Result<AuditStreamId, AppError> {
            block_on(self.uc.execute(
                &test_ctx(),
                &test_auditor(self.audit.clone()),
                request(proof),
            ))
        }

        fn kept(&self) -> usize {
            self.streams.count(test_ctx().tenant_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// The `authorization` header, which the collector reads its token from.
    fn authorization_header() -> StreamHeaderName {
        StreamHeaderName::new(HeaderName::new("authorization").unwrap()).unwrap()
    }

    /// Acme's Splunk-like collector, which wants a bearer token.
    fn request(proof: ReenteredProof) -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "SIEM").unwrap(),
            target: StreamTarget::Http {
                endpoint: PublicHttpsUrl::new("https://siem.acme.com/ingest").unwrap(),
                authorization: TypedAuthorization::Header {
                    name: authorization_header(),
                    value: Secret::new("Bearer collector-token"),
                },
            },
            filter: StreamFilter::everything(),
            proof,
        }
    }

    /// Ann, who proved herself just now, streams Acme's records to its
    /// SIEM. The stream is kept with its token sealed, and its creation
    /// recorded.
    #[test]
    fn a_proved_admin_adds_a_stream_with_its_token_sealed() {
        let setup = Setup::new();

        let id = setup.create(right_password()).unwrap();

        let stream = setup.streams.stored(test_ctx().tenant_id(), &id).unwrap();
        let StreamDestination::Http(target) = stream.destination() else {
            panic!("an HTTPS destination");
        };
        assert_eq!(
            *target.authorization(),
            HttpAuthorization::Header {
                name: authorization_header(),
                value: FakeEncryptor::sealed_for(
                    "Bearer collector-token",
                    &credentials_place(&test_ctx().tenant(), &id)
                ),
            }
        );
        assert_eq!(setup.recorded(), vec!["tenant.audit_stream_created"]);
    }

    /// Acme already keeps as many streams as a tenant may. Ann's next one
    /// is refused, and nothing is kept or recorded.
    #[test]
    fn a_tenant_with_every_stream_it_may_keep_is_refused() {
        let full = (0..MAX_AUDIT_STREAMS)
            .map(|n| test_audit_stream(&format!("stream {n}"), StreamFilter::everything()));
        let setup = Setup::over(
            FakeAuditStreamStore::holding(test_ctx().tenant_id(), full),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = setup.create(right_password());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.kept(), MAX_AUDIT_STREAMS);
        assert!(setup.recorded().is_empty());
    }

    /// A wrong password cannot authorize an audit stream. No stream is saved
    /// and no creation event is recorded.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::new();

        let result = setup.create(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kept(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// A compliance viewer cannot add an audit stream. No stream is saved.
    #[test]
    fn a_caller_without_the_compliance_right_is_refused() {
        let setup = Setup::over(
            FakeAuditStreamStore::empty(),
            FakeTenantAuthorities::holding(&[SystemPermission::Compliance(ComplianceAction::View)]),
        );

        let result = setup.create(right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kept(), 0);
    }

    /// A signed-out session cannot add an audit stream. No stream is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            FakeAuditStreamStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.create(right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.kept(), 0);
    }

    /// Acme already streams to as many places as its plan allows. Ann's
    /// next stream is refused, and nothing is kept or recorded.
    #[test]
    fn a_stream_past_the_plan_limit_is_refused() {
        let streams = Arc::new(FakeAuditStreamStore::empty());
        let setup = Setup {
            uc: CreateUseCase::new(CreatePorts {
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                stream_store: streams.clone(),
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                ..CreatePorts::fakes()
            }),
            streams,
            audit: Arc::new(FakeEventDispatcher::new()),
        };

        let result = setup.create(right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kept(), 0);
        assert!(setup.recorded().is_empty());
    }
}
