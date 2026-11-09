//! Versioned message schemas, for generated types and validation.
//!
//! A schema describes the shape of a message. Each has a name such as
//! `OrderCreated`, a format such as JSON Schema, and a version history.
//! Published messages are not checked against these versions.

use std::collections::BTreeSet;
use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::MessagingAction;
use crate::domains::messaging::control::{CreatedBy, MessagingControl, MessagingCreator};
use crate::domains::messaging::events::{SchemaDeleted, SchemaEvolved, SchemaRegistered};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{EventLabel, EventSchemaId, Label};

/// The schema language a schema is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SchemaFormat {
    /// JSON Schema, draft 2020-12.
    JsonSchema,
    /// Apache Avro.
    Avro,
    /// Protocol Buffers.
    Protobuf,
}

/// How a new version must relate to the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CompatibilityMode {
    /// No check. Any schema is accepted.
    None,
    /// New schema can read data written by the previous schema.
    Backward,
    /// Previous schema can read data written by the new schema.
    Forward,
    /// Both backward and forward compatible.
    Full,
}

impl CompatibilityMode {
    /// Checks a new version's required fields against the version before it.
    ///
    /// Backward compatibility refuses dropping a required field. Data
    /// written before would no longer fit the new schema. Forward
    /// compatibility refuses adding one. Data written after would not fit
    /// the old one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the mode is backward or full and
    ///   a required field was dropped. The message names the field.
    /// - [`DomainError::Validation`] when the mode is forward or full and a
    ///   required field was added. The message names the field.
    pub fn check(self, change: &RequiredFieldsChange) -> Result<(), DomainError> {
        let backward = matches!(self, Self::Backward | Self::Full);
        if let Some(field) = backward.then(|| change.dropped()).flatten() {
            return Err(DomainError::invalid(message!(
                "messaging-backward-incompatible-required-field-was-removed",
                format!("backward incompatible: required field '{field}' was removed")
            )));
        }
        let forward = matches!(self, Self::Forward | Self::Full);
        if let Some(field) = forward.then(|| change.added()).flatten() {
            return Err(DomainError::invalid(message!(
                "messaging-forward-incompatible-new-required-field-was",
                format!("forward incompatible: new required field '{field}' was added")
            )));
        }
        Ok(())
    }
}

/// The largest schema definition stored, in bytes.
pub(crate) const MAX_DEFINITION_BYTES: usize = 65_536;

/// The most versions one schema may hold.
pub(crate) const MAX_VERSIONS: usize = 1000;

text_value! {
    /// A schema definition's text, not blank and at most
    /// `MAX_DEFINITION_BYTES`.
    ///
    /// Whether it is well formed for its format is checked where it is
    /// parsed. This type holds only the limits that do not depend on the
    /// format.
    pub struct SchemaDefinition;
}

impl TextValue for SchemaDefinition {
    const FIELD: &'static str = "definition";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_blank().max_bytes(MAX_DEFINITION_BYTES)
    }
}

/// The fields a schema version requires, read from its definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequiredFields(BTreeSet<String>);

impl FromIterator<String> for RequiredFields {
    fn from_iter<I: IntoIterator<Item = String>>(fields: I) -> Self {
        Self(fields.into_iter().collect())
    }
}

/// How the required fields change from the latest version to a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredFieldsChange {
    /// The latest version's required fields.
    pub before: RequiredFields,
    /// The new version's required fields.
    pub after: RequiredFields,
}

impl RequiredFieldsChange {
    /// The first field required before and no longer.
    fn dropped(&self) -> Option<&str> {
        let mut dropped = self.before.0.difference(&self.after.0);
        dropped.next().map(String::as_str)
    }

    /// The first field required now and not before.
    fn added(&self) -> Option<&str> {
        let mut added = self.after.0.difference(&self.before.0);
        added.next().map(String::as_str)
    }
}

/// A single version of a schema.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SchemaVersion {
    /// Version number, counting 1, 2, 3 and on.
    pub version: u32,
    /// The schema definition: a JSON Schema string, Avro JSON, or a
    /// `.proto` file.
    pub definition: SchemaDefinition,
    /// When this version was registered.
    pub created_at: OffsetDateTime,
}

/// What a new event schema is registered from.
pub struct RegisterSchemaParams {
    /// Human-readable name, such as `OrderCreated`.
    pub name: Label,
    /// Machine-readable identifier, such as `order-created`.
    pub schema_name: Label,
    /// Optional description.
    pub description: Option<Label>,
    /// Schema format.
    pub format: SchemaFormat,
    /// Compatibility mode for new versions.
    pub compatibility: CompatibilityMode,
    /// Initial schema definition.
    pub definition: SchemaDefinition,
}

/// An event schema as storage holds it.
pub struct EventSchemaRow {
    /// Unique identifier.
    pub id: EventSchemaId,
    /// Human-readable name.
    pub name: Label,
    /// Machine-readable identifier.
    pub schema_name: Label,
    /// Optional description.
    pub description: Option<Label>,
    /// Schema format.
    pub format: SchemaFormat,
    /// Compatibility mode.
    pub compatibility: CompatibilityMode,
    /// All versions, ordered by version number.
    pub versions: Vec<SchemaVersion>,
    /// The service that created this schema.
    pub created_by: CreatedBy,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last modified.
    pub updated_at: OffsetDateTime,
}

/// A versioned event schema within a tenant.
///
/// Topics do not point to it. Each topic carries its own schema. Versions
/// are only ever added. A published version never changes.
#[derive(Debug)]
pub struct EventSchema<T: TenantScope> {
    id: EventSchemaId,
    name: Label,
    schema_name: Label,
    description: Option<Label>,
    format: SchemaFormat,
    compatibility: CompatibilityMode,
    versions: Vec<SchemaVersion>,
    created_by: CreatedBy,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> EventSchema<T> {
    /// Registers a new schema with its initial version, recording the
    /// person or consumer `creator` names as its creator. Raises
    /// `messaging.schema_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person, or the consumer's
    ///   roles, do not give the right to create in messaging.
    pub fn register(
        params: RegisterSchemaParams,
        creator: MessagingCreator<'_>,
    ) -> Result<Self, DomainError> {
        let created_by = creator.ensure_may_create()?;
        let now = crate::shared::clock::now();
        let mut schema = Self {
            id: EventSchemaId::new(),
            name: params.name,
            schema_name: params.schema_name,
            description: params.description,
            format: params.format,
            compatibility: params.compatibility,
            versions: vec![SchemaVersion {
                version: 1,
                definition: params.definition,
                created_at: now,
            }],
            created_by,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        schema.raised.raise(SchemaRegistered {
            schema_id: schema.id,
            schema_name: schema.schema_name.clone(),
            occurred_at: now,
        });
        Ok(schema)
    }

    /// Rebuilds an event schema from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row holds no versions.
    /// - [`DomainError::Infrastructure`] when the versions do not run 1, 2,
    ///   3 and on.
    /// - [`DomainError::Infrastructure`] when a version is older than the
    ///   schema.
    /// - [`DomainError::Infrastructure`] when the row holds more than
    ///   `MAX_VERSIONS` versions.
    /// - [`DomainError::Infrastructure`] when the row changed before it was
    ///   registered.
    pub fn reconstitute(row: EventSchemaRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            schema_name: row.schema_name,
            description: row.description,
            format: row.format,
            compatibility: row.compatibility,
            versions: row.versions,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &EventSchemaRow) -> Result<(), DomainError> {
        RowCheck::of("event schema")
            .holds(
                versions_in_sequence(row),
                "versions missing, out of sequence, or older than the schema",
            )
            .holds(
                row.versions.len() <= MAX_VERSIONS,
                "more versions than a schema may hold",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was registered",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &EventSchemaId {
        &self.id
    }

    /// Human-readable name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Machine-readable identifier.
    #[must_use]
    pub fn schema_name(&self) -> &Label {
        &self.schema_name
    }

    /// Optional description.
    #[must_use]
    pub fn description(&self) -> Option<&Label> {
        self.description.as_ref()
    }

    /// Schema format.
    #[must_use]
    pub fn format(&self) -> SchemaFormat {
        self.format
    }

    /// Compatibility mode for new versions.
    #[must_use]
    pub fn compatibility(&self) -> CompatibilityMode {
        self.compatibility
    }

    /// All versions, ordered by version number.
    #[must_use]
    pub fn versions(&self) -> &[SchemaVersion] {
        &self.versions
    }

    /// The latest version number, or 0 with no versions.
    #[must_use]
    pub fn latest_version(&self) -> u32 {
        self.versions.last().map(|v| v.version).unwrap_or(0)
    }

    /// The latest schema definition.
    #[must_use]
    pub fn latest_definition(&self) -> Option<&SchemaDefinition> {
        self.versions.last().map(|v| &v.definition)
    }

    /// Who registered this schema.
    #[must_use]
    pub fn created_by(&self) -> &CreatedBy {
        &self.created_by
    }

    /// Adds a new version, numbered one past the latest.
    ///
    /// A published version can never be changed.
    ///
    /// `change` is how the required fields change, when the definitions can
    /// be compared. A JSON Schema always can. So a JSON Schema held to a
    /// compatibility mode must be given the change. Only Avro, Protobuf, or
    /// a schema with no mode takes a version unchecked.
    ///
    /// The latest version is what services generate their types from, so
    /// adding one needs the full messaging right. Raises
    /// `messaging.schema_evolved` with the version before and after.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person does not manage
    ///   messaging.
    /// - [`DomainError::Validation`] when the schema already holds
    ///   `MAX_VERSIONS`.
    /// - [`DomainError::Validation`] when the change breaks the
    ///   compatibility mode.
    /// - [`DomainError::Validation`] when a JSON Schema held to a mode is
    ///   given no change to check.
    pub fn add_version(
        &mut self,
        definition: SchemaDefinition,
        change: VersionChange<'_>,
        control: &MessagingControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Manage)?;
        if self.versions.len() >= MAX_VERSIONS {
            return Err(DomainError::invalid(message!(
                "messaging-a-schema-may-hold-at-most",
                format!("a schema may hold at most {MAX_VERSIONS} versions")
            )));
        }
        self.ensure_compatible(change)?;
        let now = crate::shared::clock::now();
        let previous_version = self.latest_version();
        let new_version = previous_version.saturating_add(1);
        self.versions.push(SchemaVersion {
            version: new_version,
            definition,
            created_at: now,
        });
        self.updated_at = now;
        self.raised.raise(SchemaEvolved {
            schema_id: self.id,
            schema_label: self.label(),
            previous_version,
            new_version,
            occurred_at: now,
        });
        Ok(())
    }

    /// Deletes this schema once the person may delete in messaging. Raises
    /// `messaging.schema_deleted`, taken once the schema is removed from
    /// storage.
    ///
    /// Services generate their types from it. Sam may publish to topics.
    /// Without this check, he deletes `order-created` and the next build of
    /// every service that reads orders fails.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete in
    ///   messaging.
    pub fn delete(&mut self, control: &MessagingControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(MessagingAction::Delete)?;
        self.raised.raise(SchemaDeleted {
            schema_id: self.id,
            schema_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// How the audit trail names this schema: by its machine name, copied
    /// so the entry stays readable once the schema is gone.
    fn label(&self) -> EventLabel {
        EventLabel::of(self.schema_name.as_str())
    }

    fn ensure_compatible(&self, change: VersionChange<'_>) -> Result<(), DomainError> {
        match change {
            VersionChange::Compared(fields) => self.compatibility.check(fields),
            VersionChange::NotComparable => self.ensure_uncheckable(),
        }
    }

    /// Refuses an unchecked version where one could and should be checked.
    fn ensure_uncheckable(&self) -> Result<(), DomainError> {
        let comparable = match self.format {
            SchemaFormat::JsonSchema => true,
            SchemaFormat::Avro | SchemaFormat::Protobuf => false,
        };
        if comparable && self.compatibility != CompatibilityMode::None {
            return Err(DomainError::invalid(message!(
                "messaging-a-json-schema-held-to-a",
                "a JSON Schema held to a compatibility mode needs its field change checked"
            )));
        }
        Ok(())
    }
}

/// What a new version changes, as far as it can be told.
#[derive(Debug, Clone, Copy)]
pub enum VersionChange<'a> {
    /// The required fields before and after.
    Compared(&'a RequiredFieldsChange),
    /// The definitions cannot be compared.
    NotComparable,
}

impl<T: TenantScope> Raises for EventSchema<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for EventSchema<T> {
    type Id = EventSchemaId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Whether the stored versions run 1, 2, 3 and on, with none registered
/// before the schema.
fn versions_in_sequence(row: &EventSchemaRow) -> bool {
    !row.versions.is_empty()
        && row.versions.iter().zip(1..).all(|(version, number)| {
            version.version == number && row.created_at <= version.created_at
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::messaging::control::MessagingCreator::{Consumer, Person};
    use crate::domains::messaging::fixtures::{
        creating_service, holding, messaging_admin, messaging_viewer, publishing_service,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};

    fn def(text: &str) -> SchemaDefinition {
        SchemaDefinition::new(text).unwrap()
    }

    /// Adds `definition` to `schema` as someone who manages messaging.
    fn add(
        schema: &mut EventSchema<ResolvedTenant>,
        definition: SchemaDefinition,
        change: VersionChange<'_>,
    ) -> Result<(), DomainError> {
        schema.add_version(definition, change, &messaging_admin())
    }

    fn fields(names: &[&str]) -> RequiredFields {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn change(before: &[&str], after: &[&str]) -> RequiredFieldsChange {
        RequiredFieldsChange {
            before: fields(before),
            after: fields(after),
        }
    }

    fn order_created() -> RegisterSchemaParams {
        RegisterSchemaParams {
            name: label("Order Created"),
            schema_name: label("order-created"),
            description: Some(label("Emitted when a new order is placed")),
            format: SchemaFormat::JsonSchema,
            compatibility: CompatibilityMode::Backward,
            definition: def(
                r#"{"type":"object","properties":{"order_id":{"type":"string"},"amount":{"type":"number"}},"required":["order_id","amount"]}"#,
            ),
        }
    }

    /// `params`, registered by a service that may create in messaging.
    fn registered(params: RegisterSchemaParams) -> EventSchema<ResolvedTenant> {
        EventSchema::register(params, Consumer(&creating_service())).unwrap()
    }

    fn test_schema() -> EventSchema<ResolvedTenant> {
        registered(order_created())
    }

    /// A service with publishing permission alone cannot register a schema.
    #[test]
    fn a_service_without_the_create_right_registers_no_schema() {
        let result = EventSchema::<ResolvedTenant>::register(
            order_created(),
            Consumer(&publishing_service()),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A service registers `order-created` as a backward compatible JSON
    /// Schema. It keeps the names, format and mode it was given, and its
    /// definition becomes version 1.
    #[test]
    fn register_creates_with_version_1() {
        let schema = test_schema();
        assert_eq!(schema.name().as_str(), "Order Created");
        assert_eq!(schema.schema_name().as_str(), "order-created");
        assert_eq!(schema.format(), SchemaFormat::JsonSchema);
        assert_eq!(schema.compatibility(), CompatibilityMode::Backward);
        assert_eq!(schema.latest_version(), 1);
        assert_eq!(
            schema.latest_definition(),
            Some(&order_created().definition)
        );
    }

    /// A new version adds an optional `currency` field and keeps the same
    /// required fields. It is accepted as version 2 and becomes the latest
    /// definition.
    #[test]
    fn add_version_increments() {
        let mut schema = test_schema();
        add(
            &mut schema,
            def(r#"{"type":"object","properties":{"order_id":{"type":"string"},"amount":{"type":"number"},"currency":{"type":"string"}},"required":["order_id","amount"]}"#),
            VersionChange::Compared(&change(&["order_id", "amount"], &["order_id", "amount"])),
        )
        .unwrap();

        assert_eq!(schema.latest_version(), 2);
        assert_eq!(schema.versions().len(), 2);
        assert!(
            schema
                .latest_definition()
                .is_some_and(|definition| definition.as_str().contains("currency"))
        );
    }

    /// Two versions are added after the first. The list holds them as 1, 2
    /// and 3, in that order.
    #[test]
    fn versions_are_ordered() {
        let mut schema = test_schema();
        let same = change(&["order_id"], &["order_id"]);
        add(&mut schema, def("v2"), VersionChange::Compared(&same)).unwrap();
        add(&mut schema, def("v3"), VersionChange::Compared(&same)).unwrap();

        assert_eq!(schema.versions()[0].version, 1);
        assert_eq!(schema.versions()[1].version, 2);
        assert_eq!(schema.versions()[2].version, 3);
    }

    /// A backward compatible schema requires `order_id` and `amount`. A new
    /// version that requires only `order_id` is refused with a message
    /// naming `amount`, and the schema stays at version 1.
    #[test]
    fn a_backward_schema_refuses_dropping_a_required_field() {
        let mut schema = test_schema();

        let result = add(
            &mut schema,
            def("{}"),
            VersionChange::Compared(&change(&["order_id", "amount"], &["order_id"])),
        );

        assert!(
            matches!(result, Err(DomainError::Validation(msg)) if msg.to_string().contains("amount"))
        );
        assert_eq!(schema.latest_version(), 1);
    }

    /// In forward mode, requiring a new field `b` is refused, since older
    /// readers would not expect it. Dropping `b` again is allowed.
    #[test]
    fn a_forward_schema_refuses_adding_a_required_field() {
        let mode = CompatibilityMode::Forward;

        assert!(mode.check(&change(&["a"], &["a", "b"])).is_err());
        assert!(mode.check(&change(&["a", "b"], &["a"])).is_ok());
    }

    /// In full mode, adding a required field and dropping one are both
    /// refused. Keeping the same required fields is allowed.
    #[test]
    fn a_full_schema_refuses_either_change() {
        let mode = CompatibilityMode::Full;

        assert!(mode.check(&change(&["a"], &["a", "b"])).is_err());
        assert!(mode.check(&change(&["a", "b"], &["a"])).is_err());
        assert!(mode.check(&change(&["a"], &["a"])).is_ok());
    }

    /// A backward compatible JSON Schema rejects a version marked as not
    /// comparable and remains at version one.
    #[test]
    fn a_json_schema_with_a_mode_needs_its_change_checked() {
        let mut schema = test_schema();

        let result = add(&mut schema, def("{}"), VersionChange::NotComparable);

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(schema.latest_version(), 1);
    }

    /// A viewer cannot add a schema version, even with unchanged required
    /// fields. The schema remains at version one.
    #[test]
    fn a_viewer_cannot_add_a_schema_version() {
        let mut schema = test_schema();
        let same = change(&["order_id", "amount"], &["order_id", "amount"]);

        let result = schema.add_version(
            def("{}"),
            VersionChange::Compared(&same),
            &messaging_viewer(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(schema.latest_version(), 1);
    }

    /// A schema is filled to [`MAX_VERSIONS`]. One more version is refused
    /// and the count stays at the limit.
    #[test]
    fn a_schema_holds_at_most_the_maximum_number_of_versions() {
        let mut schema = test_schema();
        let same = change(&["order_id"], &["order_id"]);
        for _ in 1..MAX_VERSIONS {
            add(&mut schema, def("next"), VersionChange::Compared(&same)).unwrap();
        }

        let result = add(
            &mut schema,
            def("one too many"),
            VersionChange::Compared(&same),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(schema.versions().len(), MAX_VERSIONS);
    }

    /// A definition of only spaces and newlines is refused. One of exactly
    /// [`MAX_DEFINITION_BYTES`] is allowed and one byte more is refused.
    #[test]
    fn a_definition_must_hold_something_and_fit_the_limit() {
        assert!(SchemaDefinition::new("  \n ").is_err());
        assert!(SchemaDefinition::new("x".repeat(MAX_DEFINITION_BYTES)).is_ok());
        assert!(SchemaDefinition::new("x".repeat(MAX_DEFINITION_BYTES + 1)).is_err());
    }

    /// An Avro schema is registered with no description. It is accepted
    /// and reports no description.
    #[test]
    fn a_schema_may_have_no_description() {
        let schema = registered(RegisterSchemaParams {
            name: label("Simple"),
            schema_name: label("simple"),
            description: None,
            format: SchemaFormat::Avro,
            compatibility: CompatibilityMode::None,
            definition: def("{}"),
        });
        assert!(schema.description().is_none());
        assert_eq!(schema.format(), SchemaFormat::Avro);
    }

    /// A schema is written to a row through its public accessors and read
    /// back. It keeps its name and its single version.
    #[test]
    fn reconstitute_preserves_versions() {
        let schema = test_schema();
        let row = EventSchemaRow {
            id: *schema.id(),
            name: schema.name().clone(),
            schema_name: schema.schema_name().clone(),
            description: schema.description().cloned(),
            format: schema.format(),
            compatibility: schema.compatibility(),
            versions: schema.versions().to_vec(),
            created_by: schema.created_by().clone(),
            created_at: schema.created_at(),
            updated_at: schema.updated_at(),
        };

        let restored = EventSchema::<ResolvedTenant>::reconstitute(row).unwrap();
        assert_eq!(restored.latest_version(), 1);
        assert_eq!(restored.name().as_str(), "Order Created");
    }

    /// A schema is registered in each of JSON Schema, Avro and Protobuf.
    /// Each one reports the format it was given.
    #[test]
    fn all_formats_roundtrip() {
        for format in [
            SchemaFormat::JsonSchema,
            SchemaFormat::Avro,
            SchemaFormat::Protobuf,
        ] {
            let schema = registered(RegisterSchemaParams {
                name: label("Test"),
                schema_name: label("test"),
                description: None,
                format,
                compatibility: CompatibilityMode::Full,
                definition: def("{}"),
            });
            assert_eq!(schema.format(), format);
        }
    }

    /// A schema is registered under each of the four compatibility modes.
    /// Each one reports the mode it was given.
    #[test]
    fn all_compatibility_modes() {
        for mode in [
            CompatibilityMode::None,
            CompatibilityMode::Backward,
            CompatibilityMode::Forward,
            CompatibilityMode::Full,
        ] {
            let schema = registered(RegisterSchemaParams {
                name: label("Test"),
                schema_name: label("test"),
                description: None,
                format: SchemaFormat::JsonSchema,
                compatibility: mode,
                definition: def("{}"),
            });
            assert_eq!(schema.compatibility(), mode);
        }
    }

    /// A service registers a schema with a description. The schema gets a
    /// fresh id, records that service as its creator and keeps the
    /// description.
    #[test]
    fn a_schema_carries_its_id_owner_and_description() {
        let owner = creating_service();

        let schema =
            EventSchema::<ResolvedTenant>::register(order_created(), Consumer(&owner)).unwrap();

        assert!(!schema.id().as_uuid().is_nil());
        assert_eq!(Aggregate::id(&schema), schema.id());
        assert_eq!(schema.created_by(), &CreatedBy::Consumer(*owner.id()));
        assert_eq!(
            schema.description().map(Label::as_str),
            Some("Emitted when a new order is placed")
        );
    }

    /// Ann may create in messaging and registers `order-created` herself.
    /// The schema records her as its creator. Sam, who may only view
    /// messaging, registers none.
    #[test]
    fn a_person_with_the_create_right_registers_a_schema() {
        let ann = holding(&[SystemPermission::Messaging(MessagingAction::Create)]);

        let schema =
            EventSchema::<ResolvedTenant>::register(order_created(), Person(&ann)).unwrap();
        let by_viewer =
            EventSchema::<ResolvedTenant>::register(order_created(), Person(&messaging_viewer()));

        assert_eq!(schema.created_by(), &CreatedBy::Person(ann.by().clone()));
        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
    }

    /// A publisher cannot delete a schema, while a messaging administrator can.
    #[test]
    fn deleting_a_schema_needs_the_delete_right() {
        let mut schema = test_schema();
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        assert!(matches!(
            schema.delete(&publisher),
            Err(DomainError::Forbidden(_))
        ));
        assert!(schema.delete(&messaging_admin()).is_ok());
    }

    /// A service registers `order-created`. The registration is raised.
    #[test]
    fn registering_raises_messaging_schema_registered() {
        let mut schema = test_schema();

        assert_eq!(raised_names(&mut schema), ["messaging.schema_registered"]);
    }

    /// Ann adds a second version to `order-created`. The new version is
    /// raised with the step from version 1 to 2.
    #[test]
    fn a_new_version_raises_the_version_step() {
        let mut schema = test_schema();
        raised_names(&mut schema);

        add(
            &mut schema,
            def(r#"{"type":"object"}"#),
            VersionChange::Compared(&change(&["order_id", "amount"], &["order_id", "amount"])),
        )
        .unwrap();

        let events = raised(&mut schema);
        assert_eq!(
            events[0].event_type().to_string(),
            "messaging.schema_evolved"
        );
        let payload = events[0].payload();
        let Some(FieldValue::Change(step)) = payload.value("version") else {
            panic!("version is not a change");
        };
        assert_eq!((step.from(), step.to()), (Some("1"), Some("2")));
    }

    /// Ann deletes `order-created`. The deletion is raised. Sam, who may
    /// only publish, is refused and raises nothing.
    #[test]
    fn deleting_raises_messaging_schema_deleted_and_a_refusal_raises_nothing() {
        let mut schema = test_schema();
        raised_names(&mut schema);
        let publisher = holding(&[SystemPermission::Messaging(MessagingAction::Publish)]);

        schema.delete(&publisher).unwrap_err();
        let after_refusal = raised_names(&mut schema);
        schema.delete(&messaging_admin()).unwrap();

        assert!(after_refusal.is_empty());
        assert_eq!(raised_names(&mut schema), ["messaging.schema_deleted"]);
    }

    fn stored(schema: &EventSchema<ResolvedTenant>) -> EventSchemaRow {
        EventSchemaRow {
            id: schema.id,
            name: schema.name.clone(),
            schema_name: schema.schema_name.clone(),
            description: schema.description.clone(),
            format: schema.format,
            compatibility: schema.compatibility,
            versions: schema.versions.clone(),
            created_by: schema.created_by.clone(),
            created_at: schema.created_at,
            updated_at: schema.updated_at,
        }
    }

    /// A freshly registered schema, stored as it is, passes the row checks
    /// when read back.
    #[test]
    fn a_stored_schema_reads_back() {
        assert!(EventSchema::<ResolvedTenant>::reconstitute(stored(&test_schema())).is_ok());
    }

    /// A stored row whose first version is numbered 2, and a row with no
    /// versions, are both refused as corrupt. Otherwise the next version
    /// would get a wrong number.
    #[test]
    fn a_stored_schema_with_versions_out_of_sequence_is_refused() {
        let mut gap = stored(&test_schema());
        gap.versions[0].version = 2;
        let mut none = stored(&test_schema());
        none.versions.clear();

        for row in [gap, none] {
            assert!(refused_as_corrupt(
                &EventSchema::<ResolvedTenant>::reconstitute(row)
            ));
        }
    }

    /// A stored schema with one version beyond [`MAX_VERSIONS`] is refused
    /// as corrupt even when its version numbers are consecutive.
    #[test]
    fn a_stored_schema_with_more_than_the_maximum_versions_is_refused() {
        let mut row = stored(&test_schema());
        let first = row.versions[0].clone();
        let extra = (2..).take(MAX_VERSIONS).map(|version| SchemaVersion {
            version,
            ..first.clone()
        });
        row.versions.extend(extra);

        assert!(refused_as_corrupt(
            &EventSchema::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A backward schema dropping `amount` and a forward one adding
    /// `currency` each name that field in the refusal.
    #[test]
    fn a_compatibility_refusal_names_the_field() {
        let dropped = CompatibilityMode::Backward
            .check(&change(&["order_id", "amount"], &["order_id"]))
            .unwrap_err();
        let added = CompatibilityMode::Forward
            .check(&change(&["order_id"], &["order_id", "currency"]))
            .unwrap_err();

        assert!(dropped.to_string().contains("'amount'"));
        assert!(added.to_string().contains("'currency'"));
    }
}
