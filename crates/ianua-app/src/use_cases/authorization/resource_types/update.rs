//! Update resource type: rename it, describe it, or redraw its action
//! ladder.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::resource_type::{ActionDefinition, ResourceTypeChange};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, ResourceTypeId, Text};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ResourceTypeStore;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::existing_resource_type;

/// Request to update a resource type.
///
/// The key is left out on purpose: every role and route refers to it, and
/// changing it in place would break each of them. Declare a new resource
/// type and retire this one.
pub struct UpdateRequest {
    /// Which resource type to update.
    pub id: ResourceTypeId,
    /// The name an operator sees.
    pub display_name: Label,
    /// What the resource is, in the operator's words.
    pub description: Option<Text>,
    /// The verbs this resource accepts, with what each confers.
    pub actions: Vec<ActionDefinition>,
    /// The most sensitive data a resource of this type holds.
    pub data_class: DataClassLevel,
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Loads and saves the catalogue.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a resource type of the caller's tenant.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Gives the resource type `req.id` the ladder, name and description
    /// `req` holds, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role-update rights, before reading the type.
    /// - `AppError::NotFound` for a type outside the tenant; `Domain` for a malformed replacement ladder.
    /// - `AppError::Forbidden` for ungrantable permissions added or removed; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let store = self.ports.resource_type_store.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::Update))
            .map_err(AppError::from_domain)?;
        let mut resource_type = existing_resource_type(store, &tenant, &req.id).await?;
        resource_type
            .update(change_of(req), &authority)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &resource_type).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), resource_type.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// The change `req` asks for, without the id it names.
fn change_of(req: UpdateRequest) -> ResourceTypeChange {
    ResourceTypeChange {
        display_name: req.display_name,
        description: req.description,
        actions: req.actions,
        data_class: req.data_class,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        PermissionSegment, RoleAction, SystemPermission,
    };
    use ianua_domain::domains::authorization::resource_type::{ResourceType, ResourceTypeRow};
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    fn label(value: &str) -> Label {
        Label::new("test", value).unwrap()
    }

    fn action(key: &str, implies: &[&str]) -> ActionDefinition {
        ActionDefinition::new(
            segment(key),
            label(key),
            implies.iter().map(|implied| segment(implied)).collect(),
        )
    }

    /// The catalogue `project`, named "Project", with `read` and a `write`
    /// that brings `read`.
    struct Catalogue {
        id: ResourceTypeId,
        store: Arc<FakeResourceTypeStore>,
    }

    impl Catalogue {
        fn with_project() -> Self {
            let now = clock::now();
            let id = ResourceTypeId::new();
            let project = ResourceType::reconstitute(ResourceTypeRow {
                data_class: DataClassLevel::Internal,
                id,
                key: segment("project"),
                display_name: label("Project"),
                description: None,
                actions: vec![action("read", &[]), action("write", &["read"])],
                created_at: now,
                updated_at: now,
            })
            .unwrap();
            let store = Arc::new(FakeResourceTypeStore::empty());
            block_on(store.save(&test_ctx().tenant(), &project)).unwrap();
            Self { id, store }
        }

        fn ports(&self) -> UpdatePorts {
            UpdatePorts {
                resource_type_store: self.store.clone(),
                ..UpdatePorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> UpdatePorts {
            UpdatePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn renaming(&self, actions: Vec<ActionDefinition>) -> UpdateRequest {
            UpdateRequest {
                data_class: DataClassLevel::Internal,
                id: self.id,
                display_name: label("Projects"),
                description: None,
                actions,
            }
        }

        fn name(&self) -> String {
            let saved = block_on(self.store.find_by_id(&test_ctx().tenant(), &self.id));
            saved.unwrap().unwrap().display_name().as_str().to_owned()
        }
    }

    fn same_ladder() -> Vec<ActionDefinition> {
        vec![action("read", &[]), action("write", &["read"])]
    }

    fn update(
        ports: UpdatePorts,
        sink: &Arc<FakeEventDispatcher>,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        block_on(UpdateUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    /// Ann renames `project` to "Projects". The new name is saved and the
    /// change is recorded.
    #[test]
    fn a_resource_type_is_updated_and_recorded() {
        let catalogue = Catalogue::with_project();
        let sink = Arc::new(FakeEventDispatcher::new());

        update(catalogue.ports(), &sink, catalogue.renaming(same_ladder())).unwrap();

        assert_eq!(catalogue.name(), "Projects");
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.resource_type_updated"]
        );
    }

    /// Ann redraws the ladder so `read` and `write` bring each other. The
    /// loop is refused, nothing is recorded and the old name stays.
    #[test]
    fn a_broken_ladder_is_refused_and_leaves_the_old_one() {
        let catalogue = Catalogue::with_project();
        let sink = Arc::new(FakeEventDispatcher::new());
        let looped = vec![action("read", &["write"]), action("write", &["read"])];

        let result = update(catalogue.ports(), &sink, catalogue.renaming(looped));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(sink.records.lock().unwrap().is_empty());
        assert_eq!(catalogue.name(), "Project");
    }

    /// Ann updates a resource type the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_resource_type_is_not_found() {
        let catalogue = Catalogue::with_project();
        let req = UpdateRequest {
            data_class: DataClassLevel::Internal,
            id: ResourceTypeId::new(),
            ..catalogue.renaming(same_ladder())
        };

        let result = update(
            catalogue.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            req,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Removing an implied permission the caller could not grant is forbidden.
    /// The attempted update leaves the resource type's name unchanged.
    #[test]
    fn a_ladder_taking_away_what_the_caller_could_not_give_is_refused() {
        let catalogue = Catalogue::with_project();
        let sam = catalogue.ports_holding(&[SystemPermission::Roles(RoleAction::Update)]);
        let flat = vec![action("read", &[]), action("write", &[])];

        let result = update(
            sam,
            &Arc::new(FakeEventDispatcher::new()),
            catalogue.renaming(flat),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(catalogue.name(), "Project");
    }

    /// Renaming a resource type without role update permission is forbidden
    /// and preserves its existing name.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let catalogue = Catalogue::with_project();

        let result = update(
            catalogue.ports_holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            catalogue.renaming(same_ladder()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(catalogue.name(), "Project");
    }

    /// Changing a resource type rejects a signed-out session as unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let catalogue = Catalogue::with_project();
        let ports = UpdatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..catalogue.ports()
        };

        let result = update(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            catalogue.renaming(same_ladder()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
