//! A tenant's catalogue of the things its own application protects.
//!
//! Custom permissions are typed by hand into roles and routes. So
//! `project:write` and `projects:write` become two permissions, and nothing
//! says which was meant. A resource type lets the app declare its
//! permissions once, and each use is checked against it.
//!
//! The app says it has projects, and that a project can be read, written
//! and administered. It also says that `admin` brings `write`, and `write`
//! brings `read`. This chain of actions is called the ladder.
//!
//! Without the ladder, every role must name every action it should give.
//! When the app adds `archive`, someone must remember which roles wanted it.

mod action_rules;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::resource_types::{
    ResourceTypeDeclared, ResourceTypeDeleted, ResourceTypeUpdated,
};
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::ladder::{reachable, widening};
use crate::domains::authorization::permission::{
    CustomPermission, PermissionSegment, RoleAction, SystemPermission,
};
use crate::domains::authorization::resource_type::action_rules::validate_actions;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{Label, ResourceTypeId, Text};

/// The most actions one resource type may declare.
///
/// This is not a storage limit. A resource with more verbs than this is
/// really several resources, and a person could not review its ladder.
pub(crate) const MAX_ACTIONS: usize = 64;

/// One verb a resource type accepts, and what holding it confers.
///
/// Stored as-is in the catalogue's `actions` column. Deserializing checks
/// each segment but not the ladder. [`ResourceType::create`],
/// [`ResourceType::update`] and [`ResourceType::reconstitute`] check the
/// ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionDefinition {
    key: PermissionSegment,
    display_name: Label,
    implies: Vec<PermissionSegment>,
}

impl ActionDefinition {
    /// Declares an action that confers the `implies` actions on the same
    /// resource. `implies` may be empty.
    #[must_use]
    pub fn new(
        key: PermissionSegment,
        display_name: Label,
        implies: Vec<PermissionSegment>,
    ) -> Self {
        Self {
            key,
            display_name,
            implies,
        }
    }

    /// The action key, as it appears in `resource:action`.
    #[must_use]
    pub fn key(&self) -> &PermissionSegment {
        &self.key
    }

    /// What an operator sees in place of the key.
    #[must_use]
    pub fn display_name(&self) -> &Label {
        &self.display_name
    }

    /// The actions this one directly confers, before any expansion.
    #[must_use]
    pub fn implies(&self) -> &[PermissionSegment] {
        &self.implies
    }
}

/// A [`ResourceType`] as storage holds it, read back through
/// [`ResourceType::reconstitute`].
pub struct ResourceTypeRow {
    /// The resource type's id.
    pub id: ResourceTypeId,
    /// The key used in `resource:action`.
    pub key: PermissionSegment,
    /// The name an operator sees.
    pub display_name: Label,
    /// What the resource is, in the operator's words.
    pub description: Option<Text>,
    /// The verbs this resource accepts.
    pub actions: Vec<ActionDefinition>,
    /// When it was declared.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
    /// The most sensitive data a resource of this type holds. A resource
    /// shared between agents is treated as holding it.
    pub data_class: DataClassLevel,
}

/// What a caller supplies to declare a resource type.
pub struct NewResourceType {
    /// The resource type's id.
    pub id: ResourceTypeId,
    /// The key used in `resource:action`.
    pub key: PermissionSegment,
    /// The name an operator sees.
    pub display_name: Label,
    /// What the resource is, in the operator's words.
    pub description: Option<Text>,
    /// The verbs this resource accepts.
    pub actions: Vec<ActionDefinition>,
    /// The most sensitive data a resource of this type holds. A resource
    /// shared between agents is treated as holding it.
    pub data_class: DataClassLevel,
}

/// What a caller supplies to change a resource type. The key is left out:
/// every role and route refers to it.
pub struct ResourceTypeChange {
    /// The name an operator sees.
    pub display_name: Label,
    /// What the resource is, in the operator's words.
    pub description: Option<Text>,
    /// The verbs this resource accepts, with what each confers.
    pub actions: Vec<ActionDefinition>,
    /// The most sensitive data a resource of this type holds.
    pub data_class: DataClassLevel,
}

/// A kind of thing a tenant's application protects, and the verbs it accepts.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
#[derive(Debug, Clone)]
pub struct ResourceType<T: TenantScope> {
    id: ResourceTypeId,
    key: PermissionSegment,
    display_name: Label,
    description: Option<Text>,
    actions: Vec<ActionDefinition>,
    data_class: DataClassLevel,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ResourceType<T> {
    /// Declares a resource type for `editor`. Raises
    /// `authorization.resource_type_declared`.
    ///
    /// The app permissions `editor` holds include what the catalogue's
    /// ladders already confer.
    ///
    /// Declaring a ladder hands out permissions. Roles may hold `orders:read`
    /// before `orders` exists. Sam declares `orders` with `read` conferring
    /// `refund`, and every holder of `orders:read` gains `refund`. So the
    /// editor must be allowed to create roles, and able to hand out
    /// everything each action confers beyond itself.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] without role-creation rights or when the
    /// ladder grants permissions the editor cannot delegate.
    /// Returns [`DomainError::Validation`] for a reserved or wildcard key, an action
    /// count outside `1..=MAX_ACTIONS`, wildcard or duplicate actions, self or unknown
    /// implications, or a cycle.
    pub fn create(
        params: NewResourceType,
        editor: &HeldByGranter<'_>,
    ) -> Result<Self, DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Create))?;
        params.key.ensure_not_reserved("resource_type_key")?;
        ensure_concrete("resource_type_key", &params.key)?;
        validate_actions(&params.actions)?;
        ensure_grantable(editor, &widening(&params.key, &[], &params.actions)?)?;

        let now = crate::shared::clock::now();
        let mut declared = Self {
            id: params.id,
            key: params.key,
            display_name: params.display_name,
            description: params.description,
            actions: params.actions,
            data_class: params.data_class,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        declared.raised.raise(ResourceTypeDeclared {
            resource_type_id: declared.id,
            key: declared.key.clone(),
            display_name: declared.display_name.clone(),
            action_count: declared.actions.len(),
            occurred_at: now,
        });
        Ok(declared)
    }

    /// Rebuilds a resource type from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has a reserved or
    ///   wildcard key.
    /// - [`DomainError::Infrastructure`] when it declares actions that
    ///   [`Self::create`] would refuse.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: ResourceTypeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            key: row.key,
            display_name: row.display_name,
            description: row.description,
            actions: row.actions,
            data_class: row.data_class,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ResourceTypeRow) -> Result<(), DomainError> {
        RowCheck::of("resource type")
            .holds(
                row.key.ensure_not_reserved("resource_type_key").is_ok()
                    && ensure_concrete("resource_type_key", &row.key).is_ok(),
                "a reserved or wildcard key",
            )
            .holds(
                validate_actions(&row.actions).is_ok(),
                "actions no resource type may declare",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The resource type's id.
    #[must_use]
    pub fn id(&self) -> &ResourceTypeId {
        &self.id
    }

    /// The key used in `resource:action`.
    #[must_use]
    pub fn key(&self) -> &PermissionSegment {
        &self.key
    }

    /// What an operator sees in place of the key.
    #[must_use]
    pub fn display_name(&self) -> &Label {
        &self.display_name
    }

    /// What the resource is, in the operator's words.
    #[must_use]
    pub fn description(&self) -> Option<&Text> {
        self.description.as_ref()
    }

    /// The verbs this resource accepts.
    #[must_use]
    pub fn actions(&self) -> &[ActionDefinition] {
        &self.actions
    }

    /// The most sensitive data a resource of this type holds.
    #[must_use]
    pub fn data_class(&self) -> DataClassLevel {
        self.data_class
    }

    /// When the resource type was declared.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the resource type last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether this resource type declares `action`.
    #[must_use]
    pub fn declares(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a.key.as_str() == action)
    }

    /// Every permission this resource type defines, one per declared action.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if a declared pair is not a valid
    ///   permission. The checks in [`Self::create`] make this unexpected.
    pub fn permissions(&self) -> Result<Vec<CustomPermission>, DomainError> {
        self.actions
            .iter()
            .map(|action| {
                CustomPermission::new(self.key.as_str(), action.key.as_str())
                    .map_err(DomainError::from)
            })
            .collect()
    }

    /// Everything holding `action` confers, the action itself included.
    ///
    /// Walks the ladder to its end. So granting `admin` yields `write` and
    /// `read` without either being stored on the role. An action this
    /// resource type does not declare confers nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if a declared pair is not a valid
    ///   permission. The checks in [`Self::create`] make this unexpected.
    pub fn expand(&self, action: &str) -> Result<Vec<CustomPermission>, DomainError> {
        if !self.declares(action) {
            return Ok(Vec::new());
        }
        reachable(&self.actions, action)
            .into_iter()
            .map(|key| CustomPermission::new(self.key.as_str(), key).map_err(DomainError::from))
            .collect()
    }

    /// Makes the changes `change` holds, for `editor`: the ladder first, so
    /// a refused ladder leaves everything as it was, then the name, the
    /// data class and the description. Raises
    /// `authorization.resource_type_updated` once, for the whole change.
    ///
    /// Taking a rung away harms as much as removing the resource, and
    /// lowering the data class lets a resource be shared more widely, so
    /// each part is checked as its own change would be.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    /// - [`DomainError::Validation`] in the action cases [`Self::create`]
    ///   lists.
    /// - [`DomainError::Forbidden`] when the new ladder confers, or stops
    ///   conferring, a permission the editor may not hand out.
    /// - [`DomainError::Forbidden`] when the data class is lowered and
    ///   `editor` is not cleared for the class the type has now.
    pub fn update(
        &mut self,
        change: ResourceTypeChange,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.redraw_actions(change.actions, &editor.standing())?;
        self.rename(change.display_name, editor)?;
        self.reclassify(change.data_class, editor)?;
        self.describe(change.description, editor)?;
        self.raised.raise(ResourceTypeUpdated {
            resource_type_id: self.id,
            key: self.key.clone(),
            display_name: self.display_name.clone(),
            action_count: self.actions.len(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes the name an operator sees, for `editor`. The key stays,
    /// because every role and route refers to it.
    ///
    /// A name hands nothing out, so an active break-glass grant counts.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    pub(crate) fn rename(
        &mut self,
        display_name: Label,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Update))?;
        self.display_name = display_name;
        self.touch();
        Ok(())
    }

    /// Replaces the description, for `editor`. A description hands nothing
    /// out, so an active break-glass grant counts.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    pub(crate) fn describe(
        &mut self,
        description: Option<Text>,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Update))?;
        self.description = description;
        self.touch();
        Ok(())
    }

    /// Sets how sensitive the data of this type's resources is, for
    /// `editor`.
    ///
    /// Raising the class only makes sharing stricter. Lowering it lets a
    /// resource be shared between agents under a channel opened for less
    /// sensitive data. Sam sees internal data only and lowers `payroll`
    /// from restricted to public, so an agent could pass payslips to one he
    /// runs. So lowering takes someone cleared for the class the type has
    /// now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not update roles.
    /// - [`DomainError::Forbidden`] when `class` is lower than now and
    ///   `editor` is not cleared for the class the type has now.
    pub(crate) fn reclassify(
        &mut self,
        class: DataClassLevel,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Update))?;
        if class < self.data_class && editor.data_clearance() < self.data_class {
            return Err(DomainError::forbidden(message!(
                "authorization-lowering-a-resource-type-s-data",
                "lowering a resource type's data class takes someone cleared for its class now"
            )));
        }
        self.data_class = class;
        self.touch();
        Ok(())
    }

    /// Replaces the permission ladder, requiring authority over both gains and losses.
    /// The editor's holdings include current catalogue implications. A refusal leaves the
    /// ladder intact; removing implied permissions needs authority just as adding them does.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without role-update rights or authority to delegate
    /// any permission newly conferred or removed from the ladder.
    /// [`DomainError::Validation`] for the action errors listed by [`Self::create`].
    pub(crate) fn redraw_actions(
        &mut self,
        actions: Vec<ActionDefinition>,
        editor: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Update))?;
        validate_actions(&actions)?;
        ensure_grantable(editor, &widening(&self.key, &self.actions, &actions)?)?;
        ensure_grantable(editor, &widening(&self.key, &actions, &self.actions)?)?;
        self.actions = actions;
        self.touch();
        Ok(())
    }

    /// Removes this resource type once `editor` may. Raises
    /// `authorization.resource_type_deleted`, taken once it is removed from
    /// storage.
    ///
    /// Every holder of an action loses what its ladder conferred. So only
    /// someone who may delete roles, and could hand out all the ladder
    /// confers, removes it. Sam may delete roles and holds `project:read`.
    /// Without this, he removes `project` and every holder of
    /// `project:admin` loses `write` and `read`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `editor` may not delete roles.
    /// - [`DomainError::Forbidden`] when the ladder confers a permission
    ///   `editor` may not hand out.
    /// - [`DomainError::Validation`] if a declared pair is not a valid
    ///   permission. The checks in [`Self::create`] make this unexpected.
    pub fn delete(&mut self, editor: &HeldByGranter<'_>) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::Roles(RoleAction::Delete))?;
        ensure_grantable(editor, &widening(&self.key, &[], &self.actions)?)?;
        self.raised.raise(ResourceTypeDeleted {
            resource_type_id: self.id,
            key: self.key.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl<T: TenantScope> Raises for ResourceType<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses `*` where a concrete name is required.
fn ensure_concrete(field: &'static str, segment: &PermissionSegment) -> Result<(), DomainError> {
    if segment.is_wildcard() {
        return Err(DomainError::invalid(message!(
            "authorization-must-name-something-not",
            format!("{field} must name something, not `*`")
        )));
    }
    Ok(())
}

/// Refuses a ladder change that confers, or stops conferring, what the
/// editor may not hand out.
///
/// Someone who may escalate hands out any app permission, as on a role.
fn ensure_grantable(
    editor: &HeldByGranter<'_>,
    changed: &[CustomPermission],
) -> Result<(), DomainError> {
    editor.ensure_may_hand_out(&[], changed).map_err(|_| {
        DomainError::forbidden(message!(
            "authorization-the-ladder-change-reaches-a-permission",
            "the ladder change reaches a permission you may not hand out"
        ))
    })
}

/// The permissions in `permissions` that the catalogue does not declare.
///
/// A wildcard resource is always accepted. `*:read` spans every resource, so
/// the catalogue cannot say whether it was meant. A wildcard action is
/// accepted once its resource is declared, because the resource is the part
/// that could be a typo.
///
/// This lists the permissions instead of giving a yes or no, so the caller
/// can name what was wrong. An operator who ticked twelve boxes then sees
/// which one is the problem.
#[must_use]
pub fn undeclared<T: TenantScope>(
    catalogue: &[ResourceType<T>],
    permissions: &[CustomPermission],
) -> Vec<CustomPermission> {
    permissions
        .iter()
        .filter(|permission| !is_declared(catalogue, permission))
        .cloned()
        .collect()
}

fn is_declared<T: TenantScope>(
    catalogue: &[ResourceType<T>],
    permission: &CustomPermission,
) -> bool {
    if permission.resource().is_wildcard() {
        return true;
    }

    let Some(resource_type) = catalogue
        .iter()
        .find(|entry| entry.key.as_str() == permission.resource().as_str())
    else {
        return false;
    };

    permission.action().is_wildcard() || resource_type.declares(permission.action().as_str())
}

/// Everything `held` confers once the catalogue's ladders are walked.
///
/// A held `project:admin` brings the `project:write` and `project:read` its
/// ladder implies. A permission the catalogue cannot expand is kept as it
/// is, so nothing held is lost. That covers a wildcard, an undeclared action
/// and an undeclared resource. The result is sorted and has no repeats.
///
/// # Errors
///
/// - [`DomainError::Validation`] if a declared pair is not a valid
///   permission. The catalogue's own checks make this unexpected.
pub fn conferred<T: TenantScope>(
    catalogue: &[ResourceType<T>],
    held: &[CustomPermission],
) -> Result<Vec<CustomPermission>, DomainError> {
    let mut all: Vec<CustomPermission> = Vec::with_capacity(held.len());
    for permission in held {
        all.push(permission.clone());
        let Some(resource_type) = catalogue
            .iter()
            .find(|entry| entry.key.as_str() == permission.resource().as_str())
        else {
            continue;
        };
        all.extend(resource_type.expand(permission.action().as_str())?);
    }
    all.sort_unstable_by_key(ToString::to_string);
    all.dedup();
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::DataAccessAction;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).expect("valid segment")
    }

    fn label(value: &str) -> Label {
        Label::new("test", value).expect("valid label")
    }

    fn action(key: &str, implies: &[&str]) -> ActionDefinition {
        ActionDefinition::new(
            segment(key),
            label(key),
            implies.iter().map(|k| segment(k)).collect(),
        )
    }

    fn resource_type(
        actions: Vec<ActionDefinition>,
    ) -> Result<ResourceType<ResolvedTenant>, DomainError> {
        ResourceType::create(
            NewResourceType {
                data_class: DataClassLevel::Internal,
                id: ResourceTypeId::new(),
                key: segment("project"),
                display_name: label("Project"),
                description: None,
                actions,
            },
            &editor(&holding(&["project:*"])),
        )
    }

    fn ladder() -> ResourceType<ResolvedTenant> {
        resource_type(vec![
            action("read", &[]),
            action("write", &["read"]),
            action("admin", &["write"]),
        ])
        .expect("valid ladder")
    }

    /// On the ladder admin, write, read, holding `admin` confers all three.
    /// `read` comes through `write` even though `admin` names only `write`.
    #[test]
    fn expanding_an_action_walks_the_whole_ladder() {
        let expanded = ladder().expand("admin").expect("expands");

        let written: Vec<String> = expanded.iter().map(ToString::to_string).collect();
        assert_eq!(
            written,
            vec!["project:admin", "project:read", "project:write"]
        );
    }

    /// On the same ladder, holding `read` confers only `project:read`.
    #[test]
    fn expanding_the_lowest_rung_confers_only_itself() {
        let expanded = ladder().expand("read").expect("expands");

        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].to_string(), "project:read");
    }

    /// Projects declare no `archive` action. Expanding `archive` confers
    /// nothing.
    #[test]
    fn an_undeclared_action_confers_nothing() {
        assert!(ladder().expand("archive").expect("expands").is_empty());
    }

    /// Projects declare read, write and admin. The type lists
    /// `project:read`, `project:write` and `project:admin`, in that order.
    #[test]
    fn permissions_lists_one_per_declared_action() {
        let listed: Vec<String> = ladder()
            .permissions()
            .expect("lists")
            .iter()
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            listed,
            vec!["project:read", "project:write", "project:admin"]
        );
    }

    /// A tenant declares projects with no actions. It is refused, since a
    /// resource nobody can act on protects nothing.
    #[test]
    fn create_rejects_a_resource_with_no_actions() {
        let error = resource_type(Vec::new()).expect_err("must reject");
        assert!(matches!(error, DomainError::Validation(_)));
    }

    /// A tenant declares `read` twice on projects. It is refused as declared
    /// twice.
    #[test]
    fn create_rejects_a_duplicated_action() {
        let error =
            resource_type(vec![action("read", &[]), action("read", &[])]).expect_err("must reject");
        assert!(error.to_string().contains("declared twice"));
    }

    /// A tenant declares `write` conferring `read`, but never declares
    /// `read`. It is refused.
    #[test]
    fn create_rejects_conferring_an_undeclared_action() {
        let error = resource_type(vec![action("write", &["read"])]).expect_err("must reject");
        assert!(error.to_string().contains("does not declare"));
    }

    /// A tenant declares `read` conferring `read`. It is refused.
    #[test]
    fn create_rejects_an_action_conferring_itself() {
        let error = resource_type(vec![action("read", &["read"])]).expect_err("must reject");
        assert!(error.to_string().contains("cannot confer itself"));
    }

    /// A tenant declares read to admin, admin to write and write to read.
    /// The loop is refused, since each action would confer all the others.
    #[test]
    fn create_rejects_a_ladder_that_loops() {
        let error = resource_type(vec![
            action("read", &["admin"]),
            action("write", &["read"]),
            action("admin", &["write"]),
        ])
        .expect_err("must reject");

        assert!(error.to_string().contains("loop"));
    }

    /// Declaring a resource with the reserved key `idp_admin` returns an error
    /// identifying it as reserved, even for an editor holding `*:*`.
    #[test]
    fn create_rejects_the_reserved_idp_key() {
        let error = ResourceType::<ResolvedTenant>::create(
            NewResourceType {
                data_class: DataClassLevel::Internal,
                id: ResourceTypeId::new(),
                key: segment("idp_admin"),
                display_name: label("Reserved"),
                description: None,
                actions: vec![action("read", &[])],
            },
            &editor(&holding(&["*:*"])),
        )
        .expect_err("must reject");

        assert!(error.to_string().contains("reserved"));
    }

    /// `admin` confers `write` and `share`, and both confer `read`. Expanding
    /// `admin` lists all four actions with `read` once.
    #[test]
    fn a_diamond_ladder_expands_each_rung_once() {
        let diamond = resource_type(vec![
            action("read", &[]),
            action("write", &["read"]),
            action("share", &["read"]),
            action("admin", &["write", "share"]),
        ])
        .expect("valid diamond");

        let expanded: Vec<String> = diamond
            .expand("admin")
            .expect("expands")
            .iter()
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            expanded,
            vec![
                "project:admin",
                "project:read",
                "project:share",
                "project:write"
            ]
        );
    }

    fn permission(resource: &str, action: &str) -> CustomPermission {
        CustomPermission::new(resource, action).expect("valid permission")
    }

    /// The catalogue declares projects with `write`. `project:write` is not
    /// reported as undeclared.
    #[test]
    fn a_declared_permission_passes() {
        let catalogue = vec![ladder()];

        assert!(undeclared(&catalogue, &[permission("project", "write")]).is_empty());
    }

    /// An operator types `projects:write` where the catalogue declares
    /// `project`. That permission is reported back, so the typo shows.
    #[test]
    fn a_misspelt_resource_is_reported() {
        let catalogue = vec![ladder()];

        let found = undeclared(&catalogue, &[permission("projects", "write")]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].to_string(), "projects:write");
    }

    /// Projects are declared but `archive` is not. `project:archive` is
    /// reported as undeclared.
    #[test]
    fn an_undeclared_action_on_a_declared_resource_is_reported() {
        let catalogue = vec![ladder()];

        let found = undeclared(&catalogue, &[permission("project", "archive")]);

        assert_eq!(found[0].to_string(), "project:archive");
    }

    /// `project:*` passes because projects are declared. `ticket:*` is
    /// reported, since tickets are not.
    #[test]
    fn a_wildcard_action_needs_only_its_resource_declared() {
        let catalogue = vec![ladder()];

        assert!(undeclared(&catalogue, &[permission("project", "*")]).is_empty());
        assert_eq!(
            undeclared(&catalogue, &[permission("ticket", "*")]).len(),
            1
        );
    }

    /// `*:read` and `*:*` pass against any catalogue. They span every
    /// resource, so the catalogue cannot call them a typo.
    #[test]
    fn a_wildcard_resource_is_always_accepted() {
        let catalogue = vec![ladder()];

        assert!(undeclared(&catalogue, &[permission("*", "read")]).is_empty());
        assert!(undeclared(&catalogue, &[permission("*", "*")]).is_empty());
    }

    /// A tenant has declared no resource types. `project:read` is reported
    /// as undeclared.
    #[test]
    fn an_empty_catalogue_declares_nothing() {
        let catalogue: Vec<ResourceType<ResolvedTenant>> = Vec::new();

        assert_eq!(
            undeclared(&catalogue, &[permission("project", "read")]).len(),
            1
        );
    }

    /// An operator ticks one declared and two undeclared permissions. Both
    /// undeclared ones are reported, so they can be fixed in one go.
    #[test]
    fn every_undeclared_permission_is_reported_not_just_the_first() {
        let catalogue = vec![ladder()];

        let found = undeclared(
            &catalogue,
            &[
                permission("project", "read"),
                permission("projects", "read"),
                permission("project", "archive"),
            ],
        );

        assert_eq!(found.len(), 2);
    }

    /// Ann marks projects as holding confidential data. Raising the class
    /// only makes sharing stricter, so updating roles is enough.
    #[test]
    fn raising_the_data_class_takes_the_right_to_update_roles() {
        let mut projects = ladder();
        let ann = anyone_holding(&[SystemPermission::Roles(RoleAction::Update)]);

        projects
            .reclassify(DataClassLevel::Confidential, ann)
            .unwrap();

        assert_eq!(projects.data_class(), DataClassLevel::Confidential);
    }

    /// A role editor with internal clearance cannot lower projects from
    /// confidential to public; the class stays confidential. An editor cleared
    /// for confidential data can make the same change to public.
    #[test]
    fn lowering_the_data_class_takes_someone_cleared_for_it() {
        let mut projects = ladder();
        projects
            .reclassify(
                DataClassLevel::Confidential,
                anyone_holding(&[SystemPermission::Roles(RoleAction::Update)]),
            )
            .unwrap();
        let sam = anyone_holding(&[SystemPermission::Roles(RoleAction::Update)]);
        let bob = anyone_holding(&[
            SystemPermission::Roles(RoleAction::Update),
            SystemPermission::Data(DataAccessAction::Confidential),
        ]);

        let by_sam = projects.reclassify(DataClassLevel::Public, sam);
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(projects.data_class(), DataClassLevel::Confidential);

        projects.reclassify(DataClassLevel::Public, bob).unwrap();
        assert_eq!(projects.data_class(), DataClassLevel::Public);
    }

    /// Raising the data class without role-update authority is forbidden and
    /// leaves projects classified as internal.
    #[test]
    fn changing_the_data_class_takes_the_right_to_update_roles() {
        let mut projects = ladder();

        let result = projects.reclassify(DataClassLevel::Restricted, anyone_holding(&[]));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(projects.data_class(), DataClassLevel::Internal);
    }

    /// An editor redraws the ladder so `read` and `write` confer each other.
    /// It is refused and the three old actions stay.
    #[test]
    fn redrawing_actions_rejects_a_ladder_that_loops_and_leaves_the_old_one() {
        let mut subject = ladder();

        let error = subject
            .redraw_actions(
                vec![action("read", &["write"]), action("write", &["read"])],
                &editor(&holding(&["project:*"])),
            )
            .expect_err("must reject");

        assert!(matches!(error, DomainError::Validation(_)));
        assert_eq!(subject.actions().len(), 3);
    }

    /// A tenant declares exactly [`MAX_ACTIONS`] actions, and that is
    /// accepted. One more is refused.
    #[test]
    fn a_catalogue_may_declare_exactly_the_maximum_number_of_actions() {
        let at_limit: Vec<ActionDefinition> = (0..MAX_ACTIONS)
            .map(|i| action(&format!("act{i}"), &[]))
            .collect();
        let over_limit: Vec<ActionDefinition> = (0..=MAX_ACTIONS)
            .map(|i| action(&format!("act{i}"), &[]))
            .collect();

        assert!(resource_type(at_limit).is_ok());
        assert!(resource_type(over_limit).is_err());
    }

    /// An operator renames projects to "Projects" and adds a description.
    /// Both show, and the key `project` that roles refer to stays.
    #[test]
    fn renaming_and_describing_take_effect_without_touching_the_key() {
        let mut subject = ladder();
        assert_eq!(subject.description(), None);

        subject.rename(label("Projects"), role_editor()).unwrap();
        subject
            .describe(
                Some(Text::new("description", "A unit of work").unwrap()),
                role_editor(),
            )
            .unwrap();

        assert_eq!(subject.display_name().as_str(), "Projects");
        assert_eq!(
            subject.description().map(Text::as_str),
            Some("A unit of work")
        );
        assert_eq!(subject.key().as_str(), "project");
    }

    /// On the ladder, `write` reports that it directly confers `read`, and
    /// `read` reports nothing. A wrong answer would take `read` from every
    /// role holding `write`.
    #[test]
    fn an_action_reports_what_it_directly_confers() {
        let subject = ladder();

        let write = subject
            .actions()
            .iter()
            .find(|a| a.key().as_str() == "write")
            .expect("the write action");

        assert_eq!(write.implies().len(), 1);
        assert_eq!(write.implies()[0].as_str(), "read");

        let read = subject
            .actions()
            .iter()
            .find(|a| a.key().as_str() == "read")
            .expect("the read action");
        assert!(read.implies().is_empty());
    }

    /// A new resource type has a real id. Renaming it five minutes later
    /// moves its update time to then and leaves its creation time alone.
    #[test]
    fn a_resource_type_carries_its_id_and_moves_its_timestamp_when_edited() {
        let mut subject = ladder();
        let created = subject.created_at();
        let later = subject.updated_at() + time::Duration::minutes(5);

        assert_ne!(*subject.id().as_uuid(), uuid::Uuid::nil());

        let _frozen = crate::shared::clock::freeze(later);
        subject.rename(label("Projects"), role_editor()).unwrap();

        assert_eq!(subject.updated_at(), later);
        assert_eq!(subject.created_at(), created);
    }

    mod conferred {
        use super::*;

        fn held(values: &[&str]) -> Vec<CustomPermission> {
            values
                .iter()
                .map(|value| CustomPermission::parse(value).expect("valid permission"))
                .collect()
        }

        fn written(permissions: &[CustomPermission]) -> Vec<String> {
            permissions.iter().map(ToString::to_string).collect()
        }

        /// A caller holds `project:admin`. What they hold expands to admin,
        /// read and write.
        #[test]
        fn a_held_action_brings_every_rung_below_it() {
            let all = conferred(&[ladder()], &held(&["project:admin"])).unwrap();

            assert_eq!(
                written(&all),
                ["project:admin", "project:read", "project:write"]
            );
        }

        /// A caller holds `project:*`, `billing:pay` and `project:archive`.
        /// None can be expanded, and all three are kept as they are.
        #[test]
        fn what_the_catalogue_cannot_expand_is_kept_as_held() {
            let all = conferred(
                &[ladder()],
                &held(&["project:*", "billing:pay", "project:archive"]),
            )
            .unwrap();

            assert_eq!(
                written(&all),
                ["billing:pay", "project:*", "project:archive"]
            );
        }

        /// A caller holds `project:write` and `project:read`, and `write`
        /// also confers `read`. The result lists `read` once.
        #[test]
        fn overlapping_holdings_are_listed_once() {
            let all = conferred(&[ladder()], &held(&["project:write", "project:read"])).unwrap();

            assert_eq!(written(&all), ["project:read", "project:write"]);
        }
    }

    fn holding(values: &[&str]) -> Vec<CustomPermission> {
        values
            .iter()
            .map(|value| CustomPermission::parse(value).expect("valid permission"))
            .collect()
    }

    const EDITS_ROLES: [SystemPermission; 3] = [
        SystemPermission::Roles(RoleAction::Create),
        SystemPermission::Roles(RoleAction::Update),
        SystemPermission::Roles(RoleAction::Delete),
    ];

    /// An editor who may create, update and delete roles, but not escalate,
    /// and holds `custom`.
    fn editor(custom: &[CustomPermission]) -> HeldByGranter<'_> {
        HeldByGranter::assumed(&EDITS_ROLES, custom)
    }

    /// The same editor, signed in, for a change that needs only the right.
    fn role_editor() -> &'static TenantAuthority {
        anyone_holding(&EDITS_ROLES)
    }

    /// Ann may update roles only through a break-glass grant during an
    /// incident. A name and a description hand nothing out, so she changes
    /// both. Redrawing the ladder would hand out what it confers, so that
    /// still needs standing rights.
    #[test]
    fn a_break_glass_grant_counts_for_renaming_and_describing() {
        let ann = TenantAuthority::in_emergency(&EDITS_ROLES);
        let mut subject = ladder();

        subject.rename(label("Projects"), ann).unwrap();
        subject
            .describe(Some(Text::new("description", "Incident").unwrap()), ann)
            .unwrap();
        let redrawn = subject.redraw_actions(read_confers_write(), &ann.standing());

        assert_eq!(subject.display_name().as_str(), "Projects");
        assert!(matches!(redrawn, Err(DomainError::Forbidden(_))));
    }

    /// User-management authority does not permit declaring a resource type,
    /// renaming projects or redrawing their ladder. Each attempt is forbidden,
    /// and the project name stays unchanged.
    #[test]
    fn shaping_the_catalogue_needs_a_role_right() {
        let manages_users = [SystemPermission::ManageUsers];
        let bob = HeldByGranter::assumed(&manages_users, &[]);
        let mut subject = ladder();

        let declared = ResourceType::<ResolvedTenant>::create(
            NewResourceType {
                data_class: DataClassLevel::Internal,
                id: ResourceTypeId::new(),
                key: segment("ticket"),
                display_name: label("Ticket"),
                description: None,
                actions: vec![action("read", &[])],
            },
            &bob,
        );
        let renamed = subject.rename(label("Tickets"), anyone_holding(&manages_users));
        let redrawn = subject.redraw_actions(read_confers_write(), &bob);

        for refused in [declared.map(|_| ()), renamed, redrawn] {
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(subject.display_name().as_str(), "Project");
    }

    /// Role-viewing authority does not permit changing a resource description.
    /// The refused update leaves the description absent.
    #[test]
    fn describing_a_resource_type_needs_the_right_to_update_roles() {
        let sam = anyone_holding(&[SystemPermission::Roles(RoleAction::View)]);
        let mut subject = ladder();

        let result = subject.describe(Some(Text::new("description", "Harmless").unwrap()), sam);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(subject.description(), None);
    }

    /// Ann may escalate and holds no app permission. She makes `read`
    /// confer `write`, as she could put `project:write` on a role. It is
    /// accepted.
    #[test]
    fn an_editor_who_may_escalate_redraws_any_ladder() {
        let ann = HeldByGranter::assumed(
            &[
                SystemPermission::Roles(RoleAction::Update),
                SystemPermission::Roles(RoleAction::Escalate),
            ],
            &[],
        );
        let mut subject = ladder();

        assert!(subject.redraw_actions(read_confers_write(), &ann).is_ok());
    }

    /// A role editor holding only `project:read` cannot delete the project
    /// ladder. An editor holding `project:*` can delete it.
    #[test]
    fn only_someone_who_could_give_what_a_ladder_confers_removes_it() {
        let mut subject = ladder();

        assert!(matches!(
            subject.delete(&editor(&holding(&["project:read"]))),
            Err(DomainError::Forbidden(_))
        ));
        assert!(subject.delete(&editor(&holding(&["project:*"]))).is_ok());
    }

    /// An editor holding only `project:read` cannot remove every implication
    /// from the ladder, and admin still implies write after refusal. An editor
    /// holding `project:*` can remove those implications.
    #[test]
    fn only_someone_who_could_give_what_a_ladder_drops_narrows_it() {
        let flat = || {
            vec![
                action("read", &[]),
                action("write", &[]),
                action("admin", &[]),
            ]
        };
        let mut subject = ladder();

        let by_sam = subject.redraw_actions(flat(), &editor(&holding(&["project:read"])));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(subject.actions()[2].implies()[0].as_str(), "write");
        assert!(
            subject
                .redraw_actions(flat(), &editor(&holding(&["project:*"])))
                .is_ok()
        );
    }

    fn read_confers_write() -> Vec<ActionDefinition> {
        vec![
            action("read", &["write"]),
            action("write", &[]),
            action("admin", &["write"]),
        ]
    }

    /// An editor holding only `project:read` cannot redraw the ladder to make
    /// read imply write. Read still implies no other action after refusal.
    #[test]
    fn redrawing_a_ladder_to_confer_more_needs_the_power_to_grant_it() {
        let mut subject = ladder();

        let refused =
            subject.redraw_actions(read_confers_write(), &editor(&holding(&["project:read"])));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(
            subject.actions()[0].implies().is_empty(),
            "the ladder is unchanged"
        );
    }

    /// Ann holds `project:write` and `project:read`, and makes `read` confer
    /// `write` while `write` no longer confers `read`. The change is
    /// accepted, since she may hand out what it adds and what it takes away.
    #[test]
    fn an_editor_who_may_grant_the_new_rung_may_redraw_the_ladder() {
        let mut subject = ladder();
        let ann = holding(&["project:write", "project:read"]);

        subject
            .redraw_actions(read_confers_write(), &editor(&ann))
            .unwrap();

        assert_eq!(subject.actions()[0].implies()[0].as_str(), "write");
    }

    /// An editor holding no app permission saves the ladder exactly as it
    /// is. It is accepted, since it confers nothing new.
    #[test]
    fn redrawing_a_ladder_the_same_way_needs_no_power_at_all() {
        let mut subject = ladder();

        let same = subject.redraw_actions(
            vec![
                action("read", &[]),
                action("write", &["read"]),
                action("admin", &["write"]),
            ],
            &editor(&[]),
        );

        assert!(same.is_ok());
    }

    /// Adding refund as an implication of admin is forbidden for an editor
    /// holding only `project:write`. It succeeds for one holding `project:refund`.
    #[test]
    fn a_new_rung_conferred_by_an_old_one_needs_the_power_to_grant_it() {
        let widened = vec![
            action("read", &[]),
            action("write", &["read"]),
            action("admin", &["write", "refund"]),
            action("refund", &[]),
        ];

        assert!(matches!(
            ladder().redraw_actions(widened.clone(), &editor(&holding(&["project:write"]))),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            ladder()
                .redraw_actions(widened, &editor(&holding(&["project:refund"])))
                .is_ok()
        );
    }

    /// Declaring the admin-to-write-to-read ladder is forbidden for an editor
    /// holding only `project:read`. Holding both read and write permits creation.
    #[test]
    fn declaring_a_ladder_needs_the_power_to_grant_what_it_confers() {
        let params = || NewResourceType {
            data_class: DataClassLevel::Internal,
            id: ResourceTypeId::new(),
            key: segment("project"),
            display_name: label("Project"),
            description: None,
            actions: vec![
                action("read", &[]),
                action("write", &["read"]),
                action("admin", &["write"]),
            ],
        };

        assert!(matches!(
            ResourceType::<ResolvedTenant>::create(params(), &editor(&holding(&["project:read"]))),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            ResourceType::<ResolvedTenant>::create(
                params(),
                &editor(&holding(&["project:read", "project:write"]))
            )
            .is_ok()
        );
    }

    /// Resource creation rejects a wildcard action, a ladder containing an
    /// implication to a wildcard action, and a wildcard resource key.
    #[test]
    fn a_ladder_must_name_concrete_verbs() {
        assert!(resource_type(vec![action("*", &[])]).is_err());
        assert!(resource_type(vec![action("read", &["*"]), action("*", &[])]).is_err());
        assert!(
            ResourceType::<ResolvedTenant>::create(
                NewResourceType {
                    data_class: DataClassLevel::Internal,
                    id: ResourceTypeId::new(),
                    key: segment("*"),
                    display_name: label("Everything"),
                    description: None,
                    actions: vec![action("read", &[])],
                },
                &editor(&holding(&["*:*"]))
            )
            .is_err()
        );
    }

    fn stored(resource: &ResourceType<ResolvedTenant>) -> ResourceTypeRow {
        ResourceTypeRow {
            data_class: resource.data_class,
            id: resource.id,
            key: resource.key.clone(),
            display_name: resource.display_name.clone(),
            description: resource.description.clone(),
            actions: resource.actions.clone(),
            created_at: resource.created_at,
            updated_at: resource.updated_at,
        }
    }

    /// A valid resource type is written to storage and read back. The row
    /// passes every check.
    #[test]
    fn a_stored_resource_type_reads_back() {
        assert!(ResourceType::<ResolvedTenant>::reconstitute(stored(&ladder())).is_ok());
    }

    /// One stored row declares `read` twice, and another has `read` confer
    /// an undeclared `publish`. Both are refused as corrupt rows.
    #[test]
    fn a_stored_resource_type_with_actions_no_ladder_may_declare_is_refused() {
        let mut twice = stored(&ladder());
        twice.actions.push(action("read", &[]));
        let mut undeclared = stored(&ladder());
        undeclared.actions = vec![action("read", &["publish"])];

        for row in [twice, undeclared] {
            assert!(refused_as_corrupt(
                &ResourceType::<ResolvedTenant>::reconstitute(row)
            ));
        }
    }

    /// A stored resource type is keyed `*`. Reading it back is refused as a
    /// corrupt row.
    #[test]
    fn a_stored_resource_type_with_a_wildcard_key_is_refused() {
        let mut row = stored(&ladder());
        row.key = segment("*");

        assert!(refused_as_corrupt(
            &ResourceType::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// The change an operator makes to `subject`: a new name, a
    /// description, the same ladder and a higher data class.
    fn a_change_to(subject: &ResourceType<ResolvedTenant>) -> ResourceTypeChange {
        ResourceTypeChange {
            display_name: label("Projects"),
            description: Some(Text::new("description", "A unit of work").unwrap()),
            actions: subject.actions().to_vec(),
            data_class: DataClassLevel::Confidential,
        }
    }

    /// Ann declares `project`. The declaration is raised with its key and
    /// how many actions it has.
    #[test]
    fn declaring_a_resource_type_is_raised() {
        let mut subject = ladder();

        let events = raised(&mut subject);

        assert_eq!(
            events[0].event_type().to_string(),
            "authorization.resource_type_declared"
        );
        assert_eq!(events[0].payload().get("action_count"), Some("3"));
    }

    /// Ann renames `project`, describes it and raises its class in one
    /// change, then removes it. One update is raised for the change, then
    /// the removal. The change takes effect as a whole.
    #[test]
    fn updating_and_removing_a_resource_type_are_raised() {
        let mut subject = ladder();
        raised_names(&mut subject);
        let change = a_change_to(&subject);

        subject.update(change, role_editor()).unwrap();
        subject.delete(&editor(&holding(&["project:*"]))).unwrap();

        assert_eq!(subject.display_name().as_str(), "Projects");
        assert_eq!(subject.data_class(), DataClassLevel::Confidential);
        assert_eq!(
            raised_names(&mut subject),
            [
                "authorization.resource_type_updated",
                "authorization.resource_type_deleted",
            ]
        );
    }

    /// Updating projects without role-update authority and deleting their
    /// ladder with only `project:read` are refused. Neither attempt raises an event.
    #[test]
    fn a_refused_resource_type_change_raises_nothing() {
        let mut subject = ladder();
        raised_names(&mut subject);
        let change = a_change_to(&subject);

        let updated = subject.update(change, anyone_holding(&[]));
        let deleted = subject.delete(&editor(&holding(&["project:read"])));

        assert!(updated.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut subject).is_empty());
    }

    /// `project` is read back from storage. Nothing is raised: reading
    /// changes nothing.
    #[test]
    fn a_resource_type_read_back_from_storage_has_raised_nothing() {
        let mut read = ResourceType::<ResolvedTenant>::reconstitute(stored(&ladder())).unwrap();

        assert!(raised_names(&mut read).is_empty());
    }
}
