//! Declare resource type: add an entry to the tenant's permission catalogue.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::resource_type::{
    ActionDefinition, NewResourceType, ResourceType,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, ResourceTypeId, Text};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// Request to declare a resource type.
pub struct DeclareRequest {
    /// The key used in `resource:action`, unique within the tenant.
    pub key: PermissionSegment,
    /// The name an operator sees.
    pub display_name: Label,
    /// What the resource is, in the operator's words.
    pub description: Option<Text>,
    /// The verbs this resource accepts, with what each confers.
    pub actions: Vec<ActionDefinition>,
    /// The most sensitive data a resource of this type holds.
    pub data_class: DataClassLevel,
}

/// The ports [`DeclareUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeclarePorts {
    /// Loads and saves the catalogue.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// Enforces the plan's resource type limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Declares a resource type in the caller's tenant.
pub struct DeclareUseCase {
    ports: DeclarePorts,
}

impl DeclareUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeclarePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeclareUseCase {
    type Caller = CallerContext;
    type Input = DeclareRequest;
    type Output = Result<ResourceTypeId, AppError>;

    /// Declares the resource type `req` describes, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a full plan, missing role-creation rights or ungrantable ladder permissions.
    /// - `AppError::Conflict` for an existing key; `Domain` for a reserved key or malformed action ladder.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: DeclareRequest,
    ) -> Result<ResourceTypeId, AppError> {
        let tenant = ctx.tenant();
        let store = self.ports.resource_type_store.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::ResourceTypes)
            .await
            .map_err(AppError::from_domain)?;
        ensure_key_free(store, &tenant, &req.key).await?;
        let mut resource_type = declared(req, &authority)?;

        store.save(&tenant, &resource_type).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), resource_type.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*resource_type.id())
    }
}

/// Refuses a key the catalogue already declares.
async fn ensure_key_free(
    store: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
    key: &PermissionSegment,
) -> Result<(), AppError> {
    let existing = store.find_by_key(tenant, key).await.or_internal()?;
    match existing {
        Some(_) => Err(AppError::Conflict(message!(
            "authorization-is-already-declared-in-this-catalogue",
            format!("'{key}' is already declared in this catalogue")
        ))),
        None => Ok(()),
    }
}

/// The resource type `req` describes under a fresh id, declared by
/// `authority`.
fn declared(
    req: DeclareRequest,
    authority: &TenantAuthority,
) -> Result<ResourceType<ResolvedTenant>, AppError> {
    let params = NewResourceType {
        id: ResourceTypeId::new(),
        key: req.key,
        display_name: req.display_name,
        description: req.description,
        actions: req.actions,
        data_class: req.data_class,
    };
    ResourceType::create(params, &authority.standing()).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    fn action(key: &str, implies: &[&str]) -> ActionDefinition {
        ActionDefinition::new(
            segment(key),
            Label::new("test", key).unwrap(),
            implies.iter().map(|implied| segment(implied)).collect(),
        )
    }

    /// `project`, with `read` and a `write` that brings `read`.
    fn project() -> DeclareRequest {
        DeclareRequest {
            data_class: DataClassLevel::Internal,
            key: segment("project"),
            display_name: Label::new("test", "Project").unwrap(),
            description: None,
            actions: vec![action("read", &[]), action("write", &["read"])],
        }
    }

    fn ports_over(store: &Arc<FakeResourceTypeStore>) -> DeclarePorts {
        DeclarePorts {
            resource_type_store: store.clone(),
            ..DeclarePorts::fakes()
        }
    }

    fn declare(
        ports: DeclarePorts,
        sink: &Arc<FakeEventDispatcher>,
        req: DeclareRequest,
    ) -> Result<ResourceTypeId, AppError> {
        block_on(DeclareUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    fn quietly(ports: DeclarePorts, req: DeclareRequest) -> Result<ResourceTypeId, AppError> {
        declare(ports, &Arc::new(FakeEventDispatcher::new()), req)
    }

    /// Ann declares `project`. It is in the catalogue and the declaration
    /// is recorded.
    #[test]
    fn a_resource_type_is_declared_and_recorded() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        declare(ports_over(&store), &sink, project()).unwrap();

        assert_eq!(store.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.resource_type_declared"]
        );
    }

    /// Ann declares `project` twice. The second is refused as a conflict.
    #[test]
    fn a_key_already_declared_is_a_conflict() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        quietly(ports_over(&store), project()).unwrap();

        let result = quietly(ports_over(&store), project());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann declares a `write` that brings a `read` she never declared. The
    /// ladder is refused and nothing is saved.
    #[test]
    fn a_ladder_conferring_an_undeclared_action_is_refused() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        let req = DeclareRequest {
            data_class: DataClassLevel::Internal,
            actions: vec![action("write", &["read"])],
            ..project()
        };

        let result = quietly(ports_over(&store), req);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A full plan refuses another resource type and leaves the catalogue empty.
    #[test]
    fn a_resource_type_past_the_plan_limit_is_refused() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        let ports = DeclarePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_over(&store)
        };

        let result = quietly(ports, project());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Role creation permission alone cannot declare an action implying
    /// an app permission the caller lacks. No resource type is stored.
    #[test]
    fn a_ladder_handing_out_what_the_caller_may_not_is_refused() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        let ports = DeclarePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::Create),
            ])),
            ..ports_over(&store)
        };

        let result = quietly(ports, project());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Declaring a resource type without role creation permission is forbidden
    /// and leaves the catalogue empty.
    #[test]
    fn a_caller_who_may_not_create_roles_is_refused() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        let ports = DeclarePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&store)
        };

        let result = quietly(ports, project());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out session cannot declare a resource type; nothing is stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeResourceTypeStore::empty());
        let ports = DeclarePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = quietly(ports, project());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }
}
