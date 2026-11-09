//! Update user attribute: change a declaration people have already filled
//! in.
//!
//! What the aggregate can decide alone it decides: a control the kind cannot
//! show, a range that is not a range. What needs to know whether anybody is
//! affected is decided where the stored values can be counted.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::attribute::{
    AttributeControl, AttributeDefinition, AttributeKey, AttributeNamespace, AttributeVisibility,
    SchemaControlCheck,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{Label, Text};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{MetadataStore, UserAttributeStore, UserStore};
use crate::use_case::Command;
use crate::use_cases::identity::attributes::stranded::{Holders, ensure_nothing_stranded};
use crate::use_cases::identity::lookup::existing_attribute;

/// The changes to apply. Every field omitted is left as it was.
///
/// The internal name and the kind never appear here. The name is written
/// beside every stored value, so changing it would orphan them; the kind
/// decides which column those values live in, so changing it would misread
/// them. Both are asked for again as a new attribute.
#[derive(Debug, Clone, Default)]
pub struct Changes {
    /// A new display name.
    pub display_name: Option<Label>,
    /// New help text. `Some(None)` clears it.
    pub description: Option<Option<Text>>,
    /// A different control, within the ones the kind shows.
    pub control: Option<AttributeControl>,
    /// A replacement set of options.
    pub options: Option<Vec<Label>>,
    /// A new longest length.
    pub max_length: Option<Restriction<u32>>,
    /// A new lowest permitted value.
    pub minimum: Option<Restriction<f64>>,
    /// A new highest permitted value.
    pub maximum: Option<Restriction<f64>>,
    /// New querying and visibility settings.
    pub visibility: Option<AttributeVisibility>,
}

/// Changes to one declared attribute.
pub struct UpdateRequest {
    /// Which namespace the attribute is declared in.
    pub namespace: AttributeNamespace,
    /// The attribute's key.
    pub key: AttributeKey,
    /// What to change.
    pub changes: Changes,
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Reads and saves declarations.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// Counts who a narrowing change would affect.
    pub metadata_store: Arc<dyn MetadataStore>,
    /// Counts the tenant's users, which is what "everybody" means when an
    /// attribute is made required.
    pub user_store: Arc<dyn UserStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a declared attribute of the caller's tenant.
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
    type Output = Result<AttributeDefinition<ResolvedTenant>, AppError>;

    /// Applies `request.changes` to a declared attribute, for a caller who
    /// may change the schema.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without schema-change rights or clearance to remove sensitivity.
    /// - `AppError::NotFound` for an undeclared attribute; `Conflict` for stranded stored values or required values missing, with the affected count.
    /// - `AppError::Domain` for a change contradicting the attribute kind; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
        let UpdateRequest {
            namespace,
            key,
            changes,
        } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_change_schema()
            .map_err(AppError::from_domain)?;
        let store = self.ports.attribute_store.as_ref();
        let mut definition = existing_attribute(store, &tenant, namespace, &key).await?;
        let holders = Holders {
            values: self.ports.metadata_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            tenant: &tenant,
        };
        ensure_nothing_stranded(&holders, &definition, &changes).await?;
        apply(&mut definition, changes, &authority).map_err(AppError::from_domain)?;

        store.save(&tenant, &definition).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), definition.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(definition)
    }
}

/// Applies `changes` as one update of `definition`, which records it once.
fn apply(
    definition: &mut AttributeDefinition<ResolvedTenant>,
    changes: Changes,
    by: &TenantAuthority,
) -> Result<(), DomainError> {
    definition.update(by, |definition| edit(definition, changes, by))
}

/// Makes each of `changes`, as the aggregate allows `by` to make it.
fn edit(
    definition: &mut AttributeDefinition<ResolvedTenant>,
    changes: Changes,
    by: &TenantAuthority,
) -> Result<(), DomainError> {
    if let Some(display_name) = changes.display_name {
        definition.rename(display_name, by)?;
    }
    if let Some(description) = changes.description {
        definition.describe(description, by)?;
    }
    if let Some(control) = changes.control {
        definition.change_control(control, by)?;
    }
    if let Some(options) = changes.options {
        definition.replace_options(options, by)?;
    }
    if let Some(max_length) = changes.max_length {
        definition.change_max_length(max_length, by)?;
    }
    if changes.minimum.is_some() || changes.maximum.is_some() {
        let minimum = changes.minimum.unwrap_or_else(|| definition.minimum());
        let maximum = changes.maximum.unwrap_or_else(|| definition.maximum());
        definition.change_bounds(minimum, maximum, by)?;
    }
    if let Some(visibility) = changes.visibility {
        definition.change_visibility(visibility, by)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::attribute::AttributeKind;
    use ianua_domain::domains::identity::attribute::definition::Requirement;
    use ianua_domain::domains::identity::metadata_value::MetadataValue;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeMetadataStore, FakeUserAttributeStore, FakeUserStore, declaration, declared,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Makes a valid option label from the fixture's literal text.
    fn label(text: &str) -> Label {
        Label::new("option", text).unwrap()
    }

    /// A tenant declaring `size`, one of S, M or L, Bob holding M.
    struct Sizes {
        attributes: Arc<FakeUserAttributeStore>,
        values: Arc<FakeMetadataStore>,
        users: Arc<FakeUserStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Sizes {
        /// Seeds Bob's chosen size and the declaration he chose it from.
        fn new() -> Self {
            let mut params =
                declaration("size", AttributeNamespace::App, AttributeKind::SingleChoice);
            params.options = vec![label("S"), label("M"), label("L")];
            let bob = UserId::new();
            let values = Arc::new(FakeMetadataStore::empty());
            values.insert_app_value(
                &bob,
                Label::new("attribute_key", "size").unwrap(),
                MetadataValue::from("M"),
            );
            Self {
                attributes: Arc::new(FakeUserAttributeStore::holding(vec![declared(params)])),
                values,
                users: Arc::new(FakeUserStore::with_user(bob, "bob@acme.com")),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Wires these stored values and declarations into an authorized update.
        fn ports(&self) -> UpdatePorts {
            UpdatePorts {
                attribute_store: self.attributes.clone(),
                metadata_store: self.values.clone(),
                user_store: self.users.clone(),
                ..UpdatePorts::fakes()
            }
        }

        /// Changes the size declaration and records successful changes in the sink.
        fn change(
            &self,
            ports: UpdatePorts,
            changes: Changes,
        ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
            block_on(UpdateUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                UpdateRequest {
                    namespace: AttributeNamespace::App,
                    key: AttributeKey::new("size").unwrap(),
                    changes,
                },
            ))
        }
    }

    /// Ann renames `size` to "Shirt size". The new name is kept and the
    /// change recorded.
    #[test]
    fn a_rename_is_kept_and_recorded() {
        let sizes = Sizes::new();
        let changes = Changes {
            display_name: Some(Label::new("display_name", "Shirt size").unwrap()),
            ..Changes::default()
        };

        let changed = sizes.change(sizes.ports(), changes).unwrap();

        assert_eq!(changed.display_name().as_str(), "Shirt size");
        assert_eq!(
            sizes.sink.records.lock().unwrap().as_slice(),
            ["identity.attribute_updated"]
        );
    }

    /// Withdrawing Bob's size option conflicts and names the option and one
    /// affected person. No event is recorded, and the schema still offers M.
    #[test]
    fn an_option_somebody_holds_is_not_withdrawn() {
        let sizes = Sizes::new();
        let changes = Changes {
            options: Some(vec![label("S"), label("L")]),
            ..Changes::default()
        };

        let result = sizes.change(sizes.ports(), changes);

        assert!(
            matches!(result, Err(AppError::Conflict(message)) if message ==
                "Cannot withdraw options still in use: 'M'. Number of people affected: 1.")
        );
        assert!(sizes.sink.records.lock().unwrap().is_empty());
        assert!(
            sizes
                .change(sizes.ports(), Changes::default())
                .unwrap()
                .options()
                .contains(&label("M"))
        );
    }

    /// Removing sizes held by Bob and Carol conflicts, naming both options
    /// and both affected people. No update event is recorded.
    #[test]
    fn withdrawing_several_held_options_reports_every_affected_person() {
        let sizes = Sizes::new();
        let carol = UserId::new();
        sizes.users.add_active_user(carol, "carol@acme.com");
        sizes
            .values
            .insert_app_value(&carol, label("size"), MetadataValue::from("L"));
        let changes = Changes {
            options: Some(vec![label("S")]),
            ..Changes::default()
        };

        let result = sizes.change(sizes.ports(), changes);

        assert!(
            matches!(result, Err(AppError::Conflict(message)) if message ==
            "Cannot withdraw options still in use: 'M', 'L'. Number of people affected: 2.")
        );
        assert!(sizes.sink.records.lock().unwrap().is_empty());
    }

    /// Carol's stored text prevents a one-character limit. The conflict
    /// reports the limit and one affected person; the declaration remains
    /// unrestricted, and no update event is recorded.
    #[test]
    fn shortening_a_text_limit_reports_the_limit_and_affected_count() {
        let sizes = Sizes::new();
        let params = declaration("size", AttributeNamespace::App, AttributeKind::Text);
        block_on(
            sizes
                .attributes
                .save(&test_ctx().tenant(), &declared(params)),
        )
        .unwrap();
        let carol = UserId::new();
        sizes.users.add_active_user(carol, "carol@acme.com");
        sizes
            .values
            .insert_app_value(&carol, label("size"), MetadataValue::from("XL"));
        let changes = Changes {
            max_length: Some(Restriction::To(1)),
            ..Changes::default()
        };

        let result = sizes.change(sizes.ports(), changes);

        assert!(
            matches!(result, Err(AppError::Conflict(message)) if message ==
            "Cannot shorten the character limit to 1 while longer values are stored. Number of people affected: 1.")
        );
        assert!(sizes.sink.records.lock().unwrap().is_empty());
        assert_eq!(
            sizes
                .change(sizes.ports(), Changes::default())
                .unwrap()
                .max_length(),
            Restriction::Unrestricted
        );
    }

    /// Nobody holds L. Ann withdraws L, and it goes.
    #[test]
    fn an_option_nobody_holds_is_withdrawn() {
        let sizes = Sizes::new();
        let changes = Changes {
            options: Some(vec![label("S"), label("M")]),
            ..Changes::default()
        };

        let changed = sizes.change(sizes.ports(), changes).unwrap();

        assert_eq!(changed.options().len(), 2);
    }

    /// Carol's missing size prevents making the attribute required. The
    /// conflict reports one affected person, records no update event and
    /// leaves the declaration optional.
    #[test]
    fn an_attribute_some_lack_is_not_made_required() {
        let sizes = Sizes::new();
        sizes.users.add_active_user(UserId::new(), "carol@acme.com");
        let changes = Changes {
            visibility: Some(AttributeVisibility {
                required: Requirement::Required,
                ..AttributeVisibility::default()
            }),
            ..Changes::default()
        };

        let result = sizes.change(sizes.ports(), changes);

        assert!(
            matches!(result, Err(AppError::Conflict(message)) if message ==
            "Cannot make this attribute required while values are missing. Number of people affected: 1.")
        );
        assert!(sizes.sink.records.lock().unwrap().is_empty());
        assert!(
            !sizes
                .change(sizes.ports(), Changes::default())
                .unwrap()
                .required()
        );
    }

    /// A tenant declaring `rating`, a decimal with no bounds, Bob holding
    /// 4.5.
    fn rated() -> Sizes {
        let params = declaration("rating", AttributeNamespace::App, AttributeKind::Decimal);
        let bob = UserId::new();
        let values = Arc::new(FakeMetadataStore::empty());
        values.insert_app_value(
            &bob,
            Label::new("attribute_key", "rating").unwrap(),
            MetadataValue::Number(4.5),
        );
        Sizes {
            attributes: Arc::new(FakeUserAttributeStore::holding(vec![declared(params)])),
            values,
            users: Arc::new(FakeUserStore::with_user(bob, "bob@acme.com")),
            sink: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Changes the numeric declaration while retaining the fixture's audit sink.
    fn change_rating(
        sizes: &Sizes,
        changes: Changes,
    ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
        block_on(UpdateUseCase::new(sizes.ports()).execute(
            &test_ctx(),
            &test_auditor(sizes.sink.clone()),
            UpdateRequest {
                namespace: AttributeNamespace::App,
                key: AttributeKey::new("rating").unwrap(),
                changes,
            },
        ))
    }

    /// Bob rated 4.5. Ann raises the lowest rating to 5. It is refused,
    /// naming one person, and nothing is recorded.
    #[test]
    fn a_minimum_above_a_held_value_is_refused() {
        let sizes = rated();
        let changes = Changes {
            minimum: Some(Restriction::To(5.0)),
            ..Changes::default()
        };

        let result = change_rating(&sizes, changes);

        assert!(
            matches!(result, Err(AppError::Conflict(message)) if message ==
                "Cannot set the minimum to 5 while lower values are stored. Number of people affected: 1.")
        );
        assert!(sizes.sink.records.lock().unwrap().is_empty());
    }

    /// Bob rated 4.5. Ann lowers the highest rating to 4. It is refused.
    #[test]
    fn a_maximum_below_a_held_value_is_refused() {
        let sizes = rated();
        let changes = Changes {
            maximum: Some(Restriction::To(4.0)),
            ..Changes::default()
        };

        let result = change_rating(&sizes, changes);

        assert!(
            matches!(result, Err(AppError::Conflict(message)) if message ==
            "Cannot set the maximum to 4 while higher values are stored. Number of people affected: 1.")
        );
        assert!(sizes.sink.records.lock().unwrap().is_empty());
    }

    /// Bob rated 4.5. Ann bounds ratings between 1 and 5, which his fits.
    /// The bounds are kept.
    #[test]
    fn bounds_every_held_value_fits_are_kept() {
        let sizes = rated();
        let changes = Changes {
            minimum: Some(Restriction::To(1.0)),
            maximum: Some(Restriction::To(5.0)),
            ..Changes::default()
        };

        let changed = change_rating(&sizes, changes).unwrap();

        assert_eq!(changed.minimum(), Restriction::To(1.0));
        assert_eq!(changed.maximum(), Restriction::To(5.0));
    }

    /// Ann changes an attribute the tenant never declared. It is not found.
    #[test]
    fn an_undeclared_attribute_is_not_found() {
        let sizes = Sizes::new();
        let ports = UpdatePorts {
            attribute_store: Arc::new(FakeUserAttributeStore::empty()),
            ..sizes.ports()
        };

        let result = sizes.change(ports, Changes::default());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// User-viewing rights do not permit renaming the size attribute.
    #[test]
    fn a_caller_who_may_not_change_the_schema_is_refused() {
        let sizes = Sizes::new();
        let ports = UpdatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..sizes.ports()
        };
        let changes = Changes {
            display_name: Some(Label::new("display_name", "Gone").unwrap()),
            ..Changes::default()
        };

        let result = sizes.change(ports, changes);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A viewer's request to remove a held size returns forbidden instead
    /// of revealing the conflict's affected-person count.
    #[test]
    fn a_caller_who_may_not_change_the_schema_learns_nothing_of_who_holds_values() {
        let sizes = Sizes::new();
        let ports = UpdatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..sizes.ports()
        };
        let changes = Changes {
            options: Some(vec![label("S"), label("L")]),
            ..Changes::default()
        };

        let result = sizes.change(ports, changes);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A viewer's update request for an undeclared attribute returns
    /// forbidden instead of revealing that the declaration is missing.
    #[test]
    fn a_caller_who_may_not_change_the_schema_learns_nothing_of_an_undeclared_one() {
        let sizes = Sizes::new();
        let ports = UpdatePorts {
            attribute_store: Arc::new(FakeUserAttributeStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..sizes.ports()
        };

        let result = sizes.change(ports, Changes::default());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot update the size declaration.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let sizes = Sizes::new();
        let ports = UpdatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..sizes.ports()
        };

        let result = sizes.change(ports, Changes::default());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
