//! One declared custom user attribute.

mod record;
mod rules;
mod value_check;
mod visibility;

use std::marker::PhantomData;

use time::OffsetDateTime;
pub use visibility::*;

use crate::domains::identity::attribute::control::AttributeControl;
use crate::domains::identity::attribute::key::AttributeKey;
use crate::domains::identity::attribute::kind::AttributeKind;
use crate::domains::identity::attribute::namespace::AttributeNamespace;
use crate::domains::identity::attribute::schema_control::SchemaControlCheck;
use crate::domains::identity::attribute::value_type::ValueType;
use crate::domains::identity::metadata_value::MetadataValue;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::shared::model::restriction::Restriction;
use crate::shared::model::row_check::RowCheck;
use crate::types::{AttributeDefinitionId, Label, Preference, Text};

/// Largest number of options a choice attribute may offer.
///
/// The limit is about form design, not storage. With more options than this,
/// a dropdown is really a lookup table, and the person filling the form is no
/// longer picking.
pub(crate) const MAX_OPTIONS: usize = 200;

/// Highest maximum length a text attribute may declare. It is what the value
/// column holds before it turns into document storage.
pub(crate) const MAX_LENGTH_LIMIT: u32 = 4_096;

/// The most bytes one value may hold, all list items together.
///
/// A value is stored and sent with every token that carries the attribute.
/// So its size in bytes is what counts, not how many characters it shows.
pub(crate) const MAX_VALUE_BYTES: usize = 16_384;

/// What an administrator gives to declare an attribute.
///
/// It is a struct, not a long parameter list. So adding a field cannot
/// swap two booleans at every caller without anyone noticing.
#[derive(Debug, Clone)]
pub struct DeclareAttribute {
    /// The internal name, which never changes.
    pub key: AttributeKey,
    /// Which namespace the attribute belongs to.
    pub namespace: AttributeNamespace,
    /// What kind of thing it holds. It never changes once declared.
    pub kind: AttributeKind,
    /// The control to show: one picked, or the kind's default.
    pub control: Preference<AttributeControl>,
    /// What an administrator called it.
    pub display_name: Label,
    /// Help text shown beside the control.
    pub description: Option<Text>,
    /// The options to pick from, for the kinds that draw from a list.
    pub options: Vec<Label>,
    /// Longest allowed text, for the kinds that take text.
    pub max_length: Restriction<u32>,
    /// Lowest allowed value, for the number kinds.
    pub minimum: Restriction<f64>,
    /// Highest allowed value, for the number kinds.
    pub maximum: Restriction<f64>,
    /// How the attribute may be queried and who may see it.
    pub visibility: AttributeVisibility,
}

/// An attribute definition as storage keeps it, checked again by
/// [`AttributeDefinition::reconstitute`].
#[derive(Debug, Clone)]
pub struct AttributeDefinitionRow {
    /// The definition's id.
    pub id: AttributeDefinitionId,
    /// The internal name, which never changes.
    pub key: AttributeKey,
    /// Which namespace the attribute belongs to.
    pub namespace: AttributeNamespace,
    /// What kind of thing it holds.
    pub kind: AttributeKind,
    /// The control to show.
    pub control: AttributeControl,
    /// What an administrator called it.
    pub display_name: Label,
    /// Help text shown beside the control.
    pub description: Option<Text>,
    /// The options to pick from.
    pub options: Vec<Label>,
    /// Longest allowed text.
    pub max_length: Restriction<u32>,
    /// Lowest allowed value.
    pub minimum: Restriction<f64>,
    /// Highest allowed value.
    pub maximum: Restriction<f64>,
    /// How the attribute may be queried and who may see it.
    pub visibility: AttributeVisibility,
    /// Whether the attribute is hidden pending deletion.
    pub archived: AttributeUse,
    /// When it was declared.
    pub created_at: OffsetDateTime,
    /// When it was last changed.
    pub updated_at: OffsetDateTime,
}

/// A custom user attribute a tenant has declared.
///
/// Only a declared attribute can hold values, be filtered or be sorted. A
/// user list can be filtered or sorted only by an attribute that exists,
/// whose type says which column holds it, and that was opened for querying.
/// Nothing about an undeclared key reaches a query.
///
/// Two fields never change once declared. Every stored value names the key,
/// so renaming it would cut them all off. The kind decides which column the
/// values live in, so changing it would misread stored data. To change
/// either, declare a new attribute.
#[derive(Debug, Clone)]
pub struct AttributeDefinition<T: TenantScope> {
    id: AttributeDefinitionId,
    key: AttributeKey,
    namespace: AttributeNamespace,
    kind: AttributeKind,
    control: AttributeControl,
    display_name: Label,
    description: Option<Text>,
    options: Vec<Label>,
    max_length: Restriction<u32>,
    minimum: Restriction<f64>,
    maximum: Restriction<f64>,
    visibility: AttributeVisibility,
    archived: AttributeUse,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AttributeDefinition<T> {
    /// Declares an attribute, for someone `by` names who may change the
    /// schema. Raises `identity.attribute_declared`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] without schema-change rights.
    /// Returns [`DomainError::Validation`] for a control incompatible with its kind,
    /// options on a typed kind or empty, excessive (`MAX_OPTIONS`) or duplicate choices,
    /// unsupported or out-of-range length limits (`1..=MAX_LENGTH_LIMIT`),
    /// unsupported, nonfinite or inverted bounds, or unsupported sorting.
    pub fn declare(
        params: DeclareAttribute,
        by: &impl SchemaControlCheck,
    ) -> Result<Self, DomainError> {
        by.ensure_may_change_schema()?;
        let control = *params.control.or_inherit(&params.kind.default_control());
        let now = crate::shared::clock::now();
        let mut definition = Self {
            id: AttributeDefinitionId::new(),
            key: params.key,
            namespace: params.namespace,
            kind: params.kind,
            control,
            display_name: params.display_name,
            description: params.description,
            options: params.options,
            max_length: params.max_length,
            minimum: params.minimum,
            maximum: params.maximum,
            visibility: params.visibility,
            archived: AttributeUse::InUse,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        definition.ensure_fits_its_kind()?;
        definition.raise_declared();
        Ok(definition)
    }

    /// Rebuilds a definition from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row breaks a rule
    ///   [`declare`](Self::declare) keeps, such as a control, options, length
    ///   limit, bounds or sorting its kind does not allow.
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was declared.
    pub fn reconstitute(row: AttributeDefinitionRow) -> Result<Self, DomainError> {
        let definition = Self {
            id: row.id,
            key: row.key,
            namespace: row.namespace,
            kind: row.kind,
            control: row.control,
            display_name: row.display_name,
            description: row.description,
            options: row.options,
            max_length: row.max_length,
            minimum: row.minimum,
            maximum: row.maximum,
            visibility: row.visibility,
            archived: row.archived,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        definition.ensure_consistent()?;
        Ok(definition)
    }

    /// Refuses a stored definition its kind does not allow, or one that
    /// changed before it was declared, as a corrupt row.
    fn ensure_consistent(&self) -> Result<(), DomainError> {
        RowCheck::of("attribute definition")
            .holds(
                self.ensure_fits_its_kind().is_ok(),
                "a declaration its kind does not allow",
            )
            .in_order(
                self.created_at,
                self.updated_at,
                "changed before it was declared",
            )
            .finish()
    }

    /// Refuses a control, options, length limit, bounds or sorting this
    /// attribute's kind does not allow.
    fn ensure_fits_its_kind(&self) -> Result<(), DomainError> {
        rules::check_control(self.kind, self.control)?;
        rules::check_options(self.kind, &self.options)?;
        rules::check_max_length(self.kind, self.max_length)?;
        rules::check_bounds(self.kind, self.minimum, self.maximum)?;
        rules::check_sortable(self.kind, self.visibility)
    }

    /// The definition's id.
    #[must_use]
    pub fn id(&self) -> &AttributeDefinitionId {
        &self.id
    }

    /// The internal name, which never changes.
    #[must_use]
    pub fn key(&self) -> &AttributeKey {
        &self.key
    }

    /// Which namespace the attribute belongs to.
    #[must_use]
    pub fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    /// What kind of thing it holds.
    #[must_use]
    pub fn kind(&self) -> AttributeKind {
        self.kind
    }

    /// Where its values are stored, and so which column a query reads.
    #[must_use]
    pub fn value_type(&self) -> ValueType {
        self.kind.value_type()
    }

    /// The control a client shows.
    #[must_use]
    pub fn control(&self) -> AttributeControl {
        self.control
    }

    /// What an administrator called it.
    #[must_use]
    pub fn display_name(&self) -> &Label {
        &self.display_name
    }

    /// Help text shown beside the control.
    #[must_use]
    pub fn description(&self) -> Option<&Text> {
        self.description.as_ref()
    }

    /// The options to pick from, empty when values are typed.
    #[must_use]
    pub fn options(&self) -> &[Label] {
        &self.options
    }

    /// Longest allowed text.
    #[must_use]
    pub fn max_length(&self) -> Restriction<u32> {
        self.max_length
    }

    /// Lowest allowed value.
    #[must_use]
    pub fn minimum(&self) -> Restriction<f64> {
        self.minimum
    }

    /// Highest allowed value.
    #[must_use]
    pub fn maximum(&self) -> Restriction<f64> {
        self.maximum
    }

    /// How the attribute may be queried and who may see it.
    #[must_use]
    pub fn visibility(&self) -> AttributeVisibility {
        self.visibility
    }

    /// Whether every user must hold a value.
    #[must_use]
    pub fn required(&self) -> bool {
        self.visibility.required == Requirement::Required
    }

    /// Whether reading, filtering or sorting needs more than the right to
    /// view users.
    #[must_use]
    pub fn sensitive(&self) -> bool {
        self.visibility.sensitive == AttributeSensitivity::Sensitive
    }

    /// Whether the attribute is hidden pending deletion.
    #[must_use]
    pub fn archived(&self) -> bool {
        self.archived == AttributeUse::Archived
    }

    /// When it was declared.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it was last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether a user list may be filtered by this attribute now.
    ///
    /// An archived attribute gives `false` whatever it was declared with.
    /// Hiding it must hide it from queries too. Otherwise a filter would keep
    /// working on a field nobody can see.
    #[must_use]
    pub fn is_filterable(&self) -> bool {
        self.visibility.filterable == Filtering::Filterable && !self.archived()
    }

    /// Whether a user list may be sorted by this attribute now.
    ///
    /// It must be declared sortable, in use, and of a kind that can be
    /// sorted.
    #[must_use]
    pub fn is_sortable(&self) -> bool {
        self.visibility.sortable == Sorting::Sortable
            && !self.archived()
            && self.kind.is_orderable()
    }

    /// Whether the attribute is returned with each user in a listing. An
    /// archived attribute never is.
    #[must_use]
    pub fn is_listed(&self) -> bool {
        self.visibility.listed == Listing::Listed && !self.archived()
    }

    /// Makes the changes `edit` makes as one update, for someone `by` names
    /// who may change the schema. Raises `identity.attribute_updated` once,
    /// however many facets `edit` changed, and nothing when `edit` refuses.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    /// - Whatever `edit` refuses with.
    pub fn update(
        &mut self,
        by: &impl SchemaControlCheck,
        edit: impl FnOnce(&mut Self) -> Result<(), DomainError>,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        edit(self)?;
        self.raise_updated();
        Ok(())
    }

    /// Records that the attribute was deleted, with the `values_discarded`
    /// values stored under it, once both are gone from storage. Raises
    /// `identity.attribute_deleted`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    pub fn delete(
        &mut self,
        values_discarded: u64,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        self.raise_deleted(values_discarded);
        Ok(())
    }

    /// Renames the attribute as an administrator sees it. The internal name
    /// stays, so nothing stored is affected.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    pub fn rename(
        &mut self,
        display_name: Label,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        self.display_name = display_name;
        self.touch();
        Ok(())
    }

    /// Replaces the help text.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    pub fn describe(
        &mut self,
        description: Option<Text>,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        self.description = description;
        self.touch();
        Ok(())
    }

    /// Changes the control a client shows.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    /// - [`DomainError::Validation`] when the kind does not list that
    ///   control.
    pub fn change_control(
        &mut self,
        control: AttributeControl,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        rules::check_control(self.kind, control)?;
        self.control = control;
        self.touch();
        Ok(())
    }

    /// Replaces the options a choice attribute offers.
    ///
    /// This type cannot see whether anyone holds an option being removed.
    /// The use case counts holders first and refuses for them. This checks
    /// that the attribute draws from a list at all, and that the new list is
    /// usable.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    /// - [`DomainError::Validation`] when the kind takes typed values.
    /// - [`DomainError::Validation`] when the list is empty, longer than
    ///   `MAX_OPTIONS`, or offers one option twice.
    pub fn replace_options(
        &mut self,
        options: Vec<Label>,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        rules::check_options(self.kind, &options)?;
        self.options = options;
        self.touch();
        Ok(())
    }

    /// The options this attribute offers now that `proposed` leaves out. A
    /// caller uses them to find who still holds one.
    #[must_use]
    pub fn options_withdrawn_by(&self, proposed: &[Label]) -> Vec<Label> {
        self.options
            .iter()
            .filter(|current| !proposed.contains(current))
            .cloned()
            .collect()
    }

    /// Changes the longest allowed text.
    ///
    /// The use case checks whether stored values are already longer than a
    /// shorter limit, since it can count them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    /// - [`DomainError::Validation`] when the kind allows no length limit.
    /// - [`DomainError::Validation`] when the limit is outside 1 to
    ///   `MAX_LENGTH_LIMIT`.
    pub fn change_max_length(
        &mut self,
        max_length: Restriction<u32>,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        rules::check_max_length(self.kind, max_length)?;
        self.max_length = max_length;
        self.touch();
        Ok(())
    }

    /// Changes the allowed range.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    /// - [`DomainError::Validation`] when the kind allows no bounds.
    /// - [`DomainError::Validation`] when a bound is not finite.
    /// - [`DomainError::Validation`] when the lowest value is above the
    ///   highest.
    pub fn change_bounds(
        &mut self,
        minimum: Restriction<f64>,
        maximum: Restriction<f64>,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        rules::check_bounds(self.kind, minimum, maximum)?;
        self.minimum = minimum;
        self.maximum = maximum;
        self.touch();
        Ok(())
    }

    /// Changes how the attribute may be queried and who may see it.
    ///
    /// When a value becomes required, the use case checks that every user
    /// already holds one.
    ///
    /// Marking a sensitive attribute ordinary shows it to everyone who may
    /// view users. So only someone `by` clears for sensitive attributes may
    /// do it. Sam may edit the schema but not read salaries. Without this
    /// check, he makes `salary` ordinary and reads it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    /// - [`DomainError::Forbidden`] when the change makes a sensitive
    ///   attribute ordinary and `by` is not cleared for sensitive ones.
    /// - [`DomainError::Validation`] when sorting is asked of a kind that
    ///   cannot be sorted.
    pub fn change_visibility(
        &mut self,
        visibility: AttributeVisibility,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        let lowers = self.sensitive() && visibility.sensitive == AttributeSensitivity::Ordinary;
        if lowers && !by.clearance().admits_sensitive() {
            return Err(DomainError::forbidden(message!(
                "identity-only-someone-who-may-read-sensitive",
                "only someone who may read sensitive attributes marks one ordinary"
            )));
        }
        rules::check_sortable(self.kind, visibility)?;
        self.visibility = visibility;
        self.touch();
        Ok(())
    }

    /// Hides the attribute and keeps what anyone stored under it. Raises
    /// `identity.attribute_archived`.
    ///
    /// This is the first step of deleting. Values are kept, so an archive
    /// made by mistake is undone by [`restore`](Self::restore) with nothing
    /// lost. Removing the values is a separate step.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    pub fn archive(&mut self, by: &impl SchemaControlCheck) -> Result<(), DomainError> {
        self.mark_use(AttributeUse::Archived, by)
    }

    /// Brings an archived attribute back into use. Raises
    /// `identity.attribute_restored`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the schema.
    pub fn restore(&mut self, by: &impl SchemaControlCheck) -> Result<(), DomainError> {
        self.mark_use(AttributeUse::InUse, by)
    }

    /// Hides the attribute or brings it back, as `archived` says, for
    /// someone `by` names who may change the schema.
    fn mark_use(
        &mut self,
        archived: AttributeUse,
        by: &impl SchemaControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_schema()?;
        self.archived = archived;
        self.touch();
        self.raise_use();
        Ok(())
    }

    /// Checks a value against an active declaration, testing item count and byte size
    /// before type, format and declared limits to bound the cost of refusing large values.
    ///
    /// # Errors
    /// [`DomainError::Validation`] for an archived attribute or a size, type, format,
    /// length, range or option violation. Errors name the attribute and rule, never its value.
    pub fn validate(&self, value: &MetadataValue) -> Result<(), DomainError> {
        value_check::check(self, value)
    }

    /// Sets the change time to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::authority::TenantAuthority;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::{anyone_holding, user_editor};

    type Attribute = AttributeDefinition<ResolvedTenant>;

    fn key(name: &str) -> AttributeKey {
        AttributeKey::new(name).unwrap()
    }

    fn label(name: &str) -> Label {
        Label::new("option", name).unwrap()
    }

    /// A declaration with everything at its least surprising setting, for a
    /// test to vary one facet of.
    fn declaration(name: &str, kind: AttributeKind) -> DeclareAttribute {
        DeclareAttribute {
            key: key(name),
            namespace: AttributeNamespace::App,
            kind,
            control: Preference::Inherited,
            display_name: Label::new("display_name", name).unwrap(),
            description: None,
            options: Vec::new(),
            max_length: Restriction::Unrestricted,
            minimum: Restriction::Unrestricted,
            maximum: Restriction::Unrestricted,
            visibility: AttributeVisibility::default(),
        }
    }

    fn declare(name: &str, kind: AttributeKind) -> Attribute {
        Attribute::declare(declaration(name, kind), user_editor()).unwrap()
    }

    /// Someone who may change the schema and sees sensitive attributes too.
    fn cleared_editor() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::ManageUsers])
    }

    fn choice(name: &str, options: &[&str]) -> Attribute {
        let mut params = declaration(name, AttributeKind::SingleChoice);
        params.options = options.iter().map(|o| label(o)).collect();
        Attribute::declare(params, user_editor()).unwrap()
    }

    fn message(error: &DomainError) -> String {
        error.to_string()
    }

    /// A salary attribute declared with no control gets a currency input.
    /// Declared with a number input, it keeps that.
    #[test]
    fn a_declaration_takes_the_kinds_control_unless_one_is_chosen() {
        assert_eq!(
            declare("salary", AttributeKind::Money).control(),
            AttributeControl::CurrencyInput
        );

        let mut params = declaration("salary", AttributeKind::Money);
        params.control = Preference::Own(AttributeControl::NumberInput);

        assert_eq!(
            Attribute::declare(params, user_editor()).unwrap().control(),
            AttributeControl::NumberInput
        );
    }

    /// A salary attribute asks to be shown as a toggle. The declaration is
    /// refused, saying it cannot be shown that way.
    #[test]
    fn a_control_the_kind_cannot_render_is_refused() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.control = Preference::Own(AttributeControl::Toggle);

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("cannot be shown as toggle"));
    }

    /// A single-choice department with no options is refused. A list needs
    /// at least one option to pick.
    #[test]
    fn a_choice_attribute_needs_options() {
        let params = declaration("dept", AttributeKind::SingleChoice);

        let error = Attribute::declare(params, user_editor()).unwrap_err();

        assert!(message(&error).contains("options must list between 1 and"));
    }

    /// A money attribute given the options "high" and "low" is refused,
    /// since its values are typed.
    #[test]
    fn a_typed_attribute_must_not_carry_options() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.options = vec![label("high"), label("low")];

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("takes typed values"));
    }

    /// A department offering "sales" twice is refused.
    #[test]
    fn the_same_option_offered_twice_is_refused() {
        let mut params = declaration("dept", AttributeKind::SingleChoice);
        params.options = vec![label("sales"), label("sales")];

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("twice"));
    }

    /// A choice with 201 options is refused. With exactly 200, the limit, it
    /// is accepted.
    #[test]
    fn more_options_than_a_person_can_choose_from_is_refused() {
        let mut params = declaration("dept", AttributeKind::SingleChoice);
        params.options = (0..=MAX_OPTIONS).map(|i| label(&format!("o{i}"))).collect();

        assert!(Attribute::declare(params.clone(), user_editor()).is_err());

        params.options.pop();
        assert!(
            Attribute::declare(params, user_editor()).is_ok(),
            "the limit itself is fine"
        );
    }

    /// An age attribute given a maximum length of 3 is refused. A whole
    /// number has no text to limit.
    #[test]
    fn a_length_limit_on_something_with_no_text_is_refused() {
        let mut params = declaration("age", AttributeKind::WholeNumber);
        params.max_length = Restriction::To(3);

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("no text to limit"));
    }

    /// A bio with a maximum length of 0 is refused, since it could never
    /// hold any text.
    #[test]
    fn a_length_limit_of_zero_would_accept_nothing() {
        let mut params = declaration("bio", AttributeKind::Text);
        params.max_length = Restriction::To(0);

        assert!(Attribute::declare(params, user_editor()).is_err());
    }

    /// A bio limited to 4097 characters is refused. A limit of exactly 4096
    /// is accepted.
    #[test]
    fn a_length_limit_beyond_what_an_attribute_holds_is_refused() {
        let mut params = declaration("bio", AttributeKind::Text);
        params.max_length = Restriction::To(MAX_LENGTH_LIMIT + 1);
        assert!(Attribute::declare(params.clone(), user_editor()).is_err());

        params.max_length = Restriction::To(MAX_LENGTH_LIMIT);
        assert!(Attribute::declare(params, user_editor()).is_ok());
    }

    /// A text bio given a lowest value of 0 is refused. Text has no range.
    #[test]
    fn bounds_on_something_that_is_not_a_number_are_refused() {
        let mut params = declaration("bio", AttributeKind::Text);
        params.minimum = Restriction::To(0.0);

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("no range"));
    }

    /// A salary with lowest 100 and highest 10 is refused, since no value
    /// could fit.
    #[test]
    fn a_lowest_value_above_the_highest_is_refused() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.minimum = Restriction::To(100.0);
        params.maximum = Restriction::To(10.0);

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("above the highest"));
    }

    /// A salary whose lowest value is NaN or infinity is refused.
    #[test]
    fn a_bound_that_is_not_a_finite_number_is_refused() {
        for bound in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut params = declaration("salary", AttributeKind::Money);
            params.minimum = Restriction::To(bound);

            assert!(
                Attribute::declare(params, user_editor()).is_err(),
                "{bound} was accepted as a bound"
            );
        }
    }

    /// A salary with only a lowest value of 0 is accepted, and its highest
    /// stays open.
    #[test]
    fn one_bound_on_its_own_is_allowed() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.minimum = Restriction::To(0.0);

        let declared = Attribute::declare(params, user_editor()).unwrap();
        assert_eq!(declared.minimum(), Restriction::To(0.0));
        assert_eq!(declared.maximum(), Restriction::Unrestricted);
    }

    /// A tags attribute declared sortable is refused. A list of tags has no
    /// place in a sort order.
    #[test]
    fn ordering_by_a_list_is_refused_at_declaration() {
        let mut params = declaration("tags", AttributeKind::Tags);
        params.visibility.sortable = Sorting::Sortable;

        let error = Attribute::declare(params, user_editor()).unwrap_err();
        assert!(message(&error).contains("no order"));
    }

    /// A salary declared with defaults is optional, not sensitive, not
    /// filterable, not sortable, not listed and in use. Declaring it shows
    /// nothing nobody asked for.
    #[test]
    fn a_declaration_exposes_nothing_that_was_not_asked_for() {
        let declared = declare("salary", AttributeKind::Money);

        assert!(!declared.required());
        assert!(!declared.sensitive());
        assert!(!declared.is_filterable());
        assert!(!declared.is_sortable());
        assert!(!declared.is_listed());
        assert!(!declared.archived());
    }

    /// A sensitive, required salary from 0 to 1,000,000 with a description
    /// and every query option on reads back exactly so.
    #[test]
    fn a_declaration_reads_back_as_it_was_written() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.namespace = AttributeNamespace::App;
        params.minimum = Restriction::To(0.0);
        params.maximum = Restriction::To(1_000_000.0);
        params.description = Some(Text::new("description", "Gross annual salary").unwrap());
        params.visibility = AttributeVisibility {
            required: Requirement::Required,
            sensitive: AttributeSensitivity::Sensitive,
            filterable: Filtering::Filterable,
            sortable: Sorting::Sortable,
            listed: Listing::Listed,
        };

        let declared = Attribute::declare(params, user_editor()).unwrap();

        assert_eq!(declared.key().as_str(), "salary");
        assert_eq!(declared.kind(), AttributeKind::Money);
        assert_eq!(declared.value_type(), ValueType::Number);
        assert_eq!(declared.namespace(), AttributeNamespace::App);
        assert_eq!(declared.minimum(), Restriction::To(0.0));
        assert_eq!(declared.maximum(), Restriction::To(1_000_000.0));
        assert_eq!(
            declared.description().map(Text::as_str),
            Some("Gross annual salary")
        );
        assert!(declared.required());
        assert!(declared.sensitive());
        assert!(declared.is_filterable());
        assert!(declared.is_sortable());
        assert!(declared.is_listed());
    }

    /// A department with two options is stored and loaded. It keeps its id,
    /// key, options and control.
    #[test]
    fn a_declaration_survives_reconstitution() {
        let declared = choice("dept", &["sales", "support"]);

        let restored = Attribute::reconstitute(AttributeDefinitionRow {
            id: *declared.id(),
            key: declared.key().clone(),
            namespace: declared.namespace(),
            kind: declared.kind(),
            control: declared.control(),
            display_name: declared.display_name().clone(),
            description: declared.description().cloned(),
            options: declared.options().to_vec(),
            max_length: declared.max_length(),
            minimum: declared.minimum(),
            maximum: declared.maximum(),
            visibility: declared.visibility(),
            archived: AttributeUse::from(declared.archived()),
            created_at: declared.created_at(),
            updated_at: declared.updated_at(),
        })
        .unwrap();

        assert_eq!(restored.id(), declared.id());
        assert_eq!(restored.key(), declared.key());
        assert_eq!(restored.options().len(), 2);
        assert_eq!(restored.control(), declared.control());
    }

    /// A salary accepts 45000. It refuses the text "45000" and the value
    /// true.
    #[test]
    fn a_value_of_the_wrong_type_is_refused() {
        let salary = declare("salary", AttributeKind::Money);

        assert!(salary.validate(&MetadataValue::from(45_000_i64)).is_ok());
        assert!(salary.validate(&MetadataValue::from("45000")).is_err());
        assert!(salary.validate(&MetadataValue::from(true)).is_err());
    }

    /// An email attribute called "contact" refuses "nope". The error names
    /// the attribute and says an email was expected.
    #[test]
    fn a_value_failing_the_kinds_format_is_refused() {
        let contact = declare("contact", AttributeKind::Email);

        assert!(
            contact
                .validate(&MetadataValue::from("ada@example.com"))
                .is_ok()
        );

        let error = contact.validate(&MetadataValue::from("nope")).unwrap_err();
        assert!(message(&error).contains("contact"), "{error}");
        assert!(message(&error).contains("email"), "{error}");
    }

    /// A nickname limited to five accepts "ééééé", which is ten bytes. It
    /// refuses six characters. Counting bytes would halve the field for
    /// people whose names use accents.
    #[test]
    fn a_length_limit_counts_characters_rather_than_bytes() {
        let mut params = declaration("nickname", AttributeKind::Text);
        params.max_length = Restriction::To(5);
        let nickname = Attribute::declare(params, user_editor()).unwrap();

        assert!(nickname.validate(&MetadataValue::from("Zoë")).is_ok());
        assert!(
            nickname.validate(&MetadataValue::from("éééé é")).is_err(),
            "six characters is over the limit"
        );
        assert!(
            nickname.validate(&MetadataValue::from("ééééé")).is_ok(),
            "five characters is ten bytes and still five characters"
        );
    }

    /// Tags limited to four characters accept "red" and "blue". They refuse
    /// a list that also holds "purple".
    #[test]
    fn a_length_limit_reaches_every_item_of_a_list() {
        let mut params = declaration("tags", AttributeKind::Tags);
        params.max_length = Restriction::To(4);
        let tags = Attribute::declare(params, user_editor()).unwrap();

        assert!(
            tags.validate(&MetadataValue::from(vec![
                "red".to_owned(),
                "blue".to_owned()
            ]))
            .is_ok()
        );
        assert!(
            tags.validate(&MetadataValue::from(vec![
                "red".to_owned(),
                "purple".to_owned()
            ]))
            .is_err()
        );
    }

    /// A salary from 0 to 100 accepts 0, 50 and 100. It refuses -0.01 and
    /// 100.01.
    #[test]
    fn a_value_outside_the_declared_range_is_refused() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.minimum = Restriction::To(0.0);
        params.maximum = Restriction::To(100.0);
        let salary = Attribute::declare(params, user_editor()).unwrap();

        assert!(salary.validate(&MetadataValue::Number(50.0)).is_ok());
        assert!(salary.validate(&MetadataValue::Number(0.0)).is_ok());
        assert!(salary.validate(&MetadataValue::Number(100.0)).is_ok());
        assert!(salary.validate(&MetadataValue::Number(-0.01)).is_err());
        assert!(salary.validate(&MetadataValue::Number(100.01)).is_err());
    }

    /// A department offering sales and support refuses "finance". The error
    /// says the department does not offer that value.
    #[test]
    fn a_choice_outside_the_offered_options_is_refused() {
        let dept = choice("dept", &["sales", "support"]);

        assert!(dept.validate(&MetadataValue::from("sales")).is_ok());

        let error = dept.validate(&MetadataValue::from("finance")).unwrap_err();
        assert!(message(&error).contains("'dept' does not offer that value"));
    }

    /// Rejecting a choice containing a forged log line does not echo the
    /// line break or its claim that an admin was granted.
    #[test]
    fn a_refused_choice_is_not_repeated_back() {
        let dept = choice("dept", &["sales", "support"]);

        let error = dept
            .validate(&MetadataValue::from("x\nlevel=INFO msg=\"admin granted\""))
            .unwrap_err();

        assert!(!message(&error).contains("admin granted"));
        assert!(!message(&error).contains('\n'));
    }

    /// Ten large Unicode tags exceed the combined byte budget and are
    /// rejected with an error identifying their byte size.
    #[test]
    fn a_value_larger_than_the_byte_budget_is_refused() {
        let mut params = declaration("tags", AttributeKind::Tags);
        params.max_length = Restriction::Unrestricted;
        let tags = Attribute::declare(params, user_editor()).unwrap();
        let heavy: Vec<String> = (0..10)
            .map(|i| format!("{i}{}", "\u{1F600}".repeat(1_000)))
            .collect();

        let error = tags
            .validate(&MetadataValue::StringArray(heavy))
            .unwrap_err();

        assert!(message(&error).contains("bytes"));
    }

    /// A tags value with 201 items is refused by its count. The count is
    /// checked before any item is read, so a huge list is cheap to refuse.
    #[test]
    fn an_overlong_list_is_refused_by_its_count() {
        let tags = declare("tags", AttributeKind::Tags);
        let many: Vec<String> = (0..=MAX_OPTIONS).map(|i| i.to_string()).collect();

        let error = tags
            .validate(&MetadataValue::StringArray(many))
            .unwrap_err();

        assert!(message(&error).contains("items"));
    }

    /// Skills offering rust and sql accept both. A list that also picks
    /// "cobol" is refused.
    #[test]
    fn every_item_of_a_multiple_choice_must_be_offered() {
        let mut params = declaration("skills", AttributeKind::MultipleChoice);
        params.options = vec![label("rust"), label("sql")];
        let skills = Attribute::declare(params, user_editor()).unwrap();

        assert!(
            skills
                .validate(&MetadataValue::from(vec![
                    "rust".to_owned(),
                    "sql".to_owned()
                ]))
                .is_ok()
        );
        assert!(
            skills
                .validate(&MetadataValue::from(vec![
                    "rust".to_owned(),
                    "cobol".to_owned()
                ]))
                .is_err()
        );
    }

    /// `annual_salary` refuses "lots". The error names `'annual_salary'`, so
    /// an administrator knows which field to fix.
    #[test]
    fn the_error_names_the_attribute_that_refused_the_value() {
        let salary = declare("annual_salary", AttributeKind::Money);
        let error = salary.validate(&MetadataValue::from("lots")).unwrap_err();

        assert!(
            message(&error).contains("'annual_salary'"),
            "an administrator has to know which field: {error}"
        );
    }

    /// `dept` is renamed "Department". The display name changes and the key
    /// stays `dept`, since values are stored under it.
    #[test]
    fn renaming_leaves_the_internal_name_alone() {
        let mut dept = declare("dept", AttributeKind::Text);
        dept.rename(
            Label::new("display_name", "Department").unwrap(),
            user_editor(),
        )
        .unwrap();

        assert_eq!(dept.display_name().as_str(), "Department");
        assert_eq!(dept.key().as_str(), "dept", "values are stored under this");
    }

    /// A user viewer cannot declare, rename or archive an attribute; the
    /// department keeps its display name and remains in use.
    #[test]
    fn only_someone_who_may_update_users_changes_the_schema() {
        let sam = anyone_holding(&[SystemPermission::Users(UserAction::View)]);
        let mut dept = declare("dept", AttributeKind::Text);
        let params = declaration("clearance_level", AttributeKind::Text);

        let declared = Attribute::declare(params, sam);
        let renamed = dept.rename(Label::new("display_name", "Team").unwrap(), sam);
        let archived = dept.archive(sam);

        assert!(matches!(declared, Err(DomainError::Forbidden(_))));
        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert!(matches!(archived, Err(DomainError::Forbidden(_))));
        assert_eq!(dept.display_name().as_str(), "dept");
        assert!(!dept.archived());
    }

    /// A user viewer cannot add attribute help text; the department's
    /// description remains absent.
    #[test]
    fn describing_an_attribute_needs_the_right_to_update_users() {
        let sam = anyone_holding(&[SystemPermission::Users(UserAction::View)]);
        let mut dept = declare("dept", AttributeKind::Text);
        let help = Text::new("description", "Put your manager here").unwrap();

        let result = dept.describe(Some(help), sam);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(dept.description(), None);
    }

    /// A department moves to radio buttons. A later move to a currency input
    /// is refused and leaves the radio buttons in place.
    #[test]
    fn the_control_can_be_changed_within_what_the_kind_renders() {
        let mut dept = choice("dept", &["sales"]);

        assert!(
            dept.change_control(AttributeControl::RadioGroup, user_editor())
                .is_ok()
        );
        assert_eq!(dept.control(), AttributeControl::RadioGroup);

        assert!(
            dept.change_control(AttributeControl::CurrencyInput, user_editor())
                .is_err()
        );
        assert_eq!(
            dept.control(),
            AttributeControl::RadioGroup,
            "a refused change must not half-apply"
        );
    }

    /// A department offers sales, support and legal. A new list without
    /// support reports support as removed. Adding an option removes none.
    #[test]
    fn the_options_a_change_would_withdraw_are_reported() {
        let dept = choice("dept", &["sales", "support", "legal"]);

        let withdrawn = dept.options_withdrawn_by(&[label("sales"), label("legal")]);
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(withdrawn[0].as_str(), "support");

        assert!(
            dept.options_withdrawn_by(&[
                label("sales"),
                label("support"),
                label("legal"),
                label("new")
            ])
            .is_empty(),
            "adding an option withdraws none"
        );
    }

    /// Replacing a department's options with none, or with "a" twice, is
    /// refused and keeps the old list. Replacing them with "a" and "b" works.
    #[test]
    fn replacing_the_options_still_checks_they_are_usable() {
        let mut dept = choice("dept", &["sales"]);

        assert!(
            dept.replace_options(Vec::new(), user_editor()).is_err(),
            "a choice needs one"
        );
        assert!(
            dept.replace_options(vec![label("a"), label("a")], user_editor())
                .is_err(),
            "still no duplicates"
        );
        assert_eq!(dept.options().len(), 1, "a refused change must not apply");

        assert!(
            dept.replace_options(vec![label("a"), label("b")], user_editor())
                .is_ok()
        );
        assert_eq!(dept.options().len(), 2);
    }

    /// A bio refuses a limit of 0 and takes 200. An age refuses any length
    /// limit and stays unlimited.
    #[test]
    fn a_length_limit_changes_only_on_text_and_within_bounds() {
        let mut bio = declare("bio", AttributeKind::Text);
        let mut age = declare("age", AttributeKind::WholeNumber);

        assert!(
            bio.change_max_length(Restriction::To(0), user_editor())
                .is_err()
        );
        assert!(
            age.change_max_length(Restriction::To(10), user_editor())
                .is_err()
        );
        bio.change_max_length(Restriction::To(200), user_editor())
            .unwrap();

        assert_eq!(bio.max_length(), Restriction::To(200));
        assert_eq!(age.max_length(), Restriction::Unrestricted);
    }

    /// An age refuses 65 to 18 and a NaN bound, then takes 18 to 65. A text
    /// bio refuses any bound.
    #[test]
    fn a_range_changes_only_on_numbers_and_only_into_a_range() {
        let mut age = declare("age", AttributeKind::WholeNumber);
        let mut bio = declare("bio", AttributeKind::Text);

        assert!(
            age.change_bounds(Restriction::To(65.0), Restriction::To(18.0), user_editor())
                .is_err()
        );
        assert!(
            age.change_bounds(
                Restriction::To(f64::NAN),
                Restriction::Unrestricted,
                user_editor()
            )
            .is_err()
        );
        assert!(
            bio.change_bounds(
                Restriction::To(1.0),
                Restriction::Unrestricted,
                user_editor()
            )
            .is_err()
        );
        age.change_bounds(Restriction::To(18.0), Restriction::To(65.0), user_editor())
            .unwrap();

        assert_eq!(age.minimum(), Restriction::To(18.0));
        assert_eq!(age.maximum(), Restriction::To(65.0));
    }

    /// Tags can be made filterable. Making them sortable is refused and
    /// leaves them filterable as before.
    #[test]
    fn visibility_can_be_changed_but_not_into_ordering_a_list() {
        let mut tags = declare("tags", AttributeKind::Tags);

        assert!(
            tags.change_visibility(
                AttributeVisibility {
                    filterable: Filtering::Filterable,
                    ..AttributeVisibility::default()
                },
                user_editor()
            )
            .is_ok()
        );
        assert!(tags.is_filterable());

        assert!(
            tags.change_visibility(
                AttributeVisibility {
                    sortable: Sorting::Sortable,
                    ..AttributeVisibility::default()
                },
                user_editor()
            )
            .is_err()
        );
        assert!(tags.is_filterable(), "a refused change must not apply");
    }

    /// An archived salary cannot be filtered, sorted, listed or given a new
    /// value. Its declared settings are kept, so restoring it brings all of
    /// that back.
    #[test]
    fn archiving_closes_every_surface_without_discarding_anything() {
        let mut params = declaration("salary", AttributeKind::Money);
        params.visibility = AttributeVisibility {
            filterable: Filtering::Filterable,
            sortable: Sorting::Sortable,
            listed: Listing::Listed,
            ..AttributeVisibility::default()
        };
        let mut salary = Attribute::declare(params, user_editor()).unwrap();

        assert!(salary.is_filterable() && salary.is_sortable() && salary.is_listed());

        salary.archive(user_editor()).unwrap();

        assert!(salary.archived());
        assert!(!salary.is_filterable(), "a filter would outlive the field");
        assert!(!salary.is_sortable());
        assert!(!salary.is_listed());
        assert!(
            salary.validate(&MetadataValue::from(1_i64)).is_err(),
            "nothing new is stored under a withdrawn attribute"
        );
        assert_eq!(
            salary.visibility().filterable,
            Filtering::Filterable,
            "what was declared is remembered, so restoring puts it back"
        );

        salary.restore(user_editor()).unwrap();
        assert!(salary.is_filterable() && salary.is_sortable() && salary.is_listed());
        assert!(salary.validate(&MetadataValue::from(1_i64)).is_ok());
    }

    /// A stored tags attribute claims to be sortable. That cannot be
    /// declared, so the row is refused as corrupt.
    #[test]
    fn a_stored_list_claiming_to_be_ordered_is_refused() {
        let tags = declare("tags", AttributeKind::Tags);

        let claimed = Attribute::reconstitute(AttributeDefinitionRow {
            id: *tags.id(),
            key: tags.key().clone(),
            namespace: tags.namespace(),
            kind: AttributeKind::Tags,
            control: tags.control(),
            display_name: tags.display_name().clone(),
            description: None,
            options: Vec::new(),
            max_length: Restriction::Unrestricted,
            minimum: Restriction::Unrestricted,
            maximum: Restriction::Unrestricted,
            visibility: AttributeVisibility {
                sortable: Sorting::Sortable,
                ..AttributeVisibility::default()
            },
            archived: AttributeUse::InUse,
            created_at: tags.created_at(),
            updated_at: tags.updated_at(),
        });

        assert!(refused_as_corrupt(&claimed));
    }

    /// A department is declared, then renamed an hour later. Its change time
    /// moves to the rename and its creation time stays.
    #[test]
    fn a_change_records_when_it_happened() {
        let start = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut dept = {
            let _frozen = crate::shared::clock::freeze(start);
            declare("dept", AttributeKind::Text)
        };

        assert_eq!(dept.created_at(), start);
        assert_eq!(dept.updated_at(), start);

        let later = start + time::Duration::hours(1);
        {
            let _frozen = crate::shared::clock::freeze(later);
            dept.rename(Label::new("display_name", "Team").unwrap(), user_editor())
                .unwrap();
        }

        assert_eq!(dept.updated_at(), later);
        assert_eq!(dept.created_at(), start, "declaring happened once");
    }

    /// A bio with no declared length accepts 4096 characters and refuses
    /// 4097. Its value goes with every token, so it is never unlimited.
    #[test]
    fn a_text_attribute_without_a_declared_length_is_still_bounded() {
        let bio = declare("bio", AttributeKind::Text);
        let at_limit = "x".repeat(MAX_LENGTH_LIMIT as usize);
        let over = "x".repeat(MAX_LENGTH_LIMIT as usize + 1);

        assert!(bio.validate(&MetadataValue::String(at_limit)).is_ok());
        assert!(bio.validate(&MetadataValue::String(over)).is_err());
    }

    /// Tags refuse 201 items and refuse "a" twice. "a" and "b" pass.
    #[test]
    fn a_list_value_is_bounded_and_holds_no_repeats() {
        let tags = declare("tags", AttributeKind::Tags);
        let too_many = (0..=MAX_OPTIONS).map(|i| format!("t{i}")).collect();

        assert!(
            tags.validate(&MetadataValue::StringArray(too_many))
                .is_err()
        );
        assert!(
            tags.validate(&MetadataValue::StringArray(vec![
                "a".to_owned(),
                "a".to_owned()
            ]))
            .is_err()
        );
        assert!(
            tags.validate(&MetadataValue::StringArray(vec![
                "a".to_owned(),
                "b".to_owned()
            ]))
            .is_ok()
        );
    }

    fn stored(definition: &Attribute) -> AttributeDefinitionRow {
        AttributeDefinitionRow {
            id: definition.id,
            key: definition.key.clone(),
            namespace: definition.namespace,
            kind: definition.kind,
            control: definition.control,
            display_name: definition.display_name.clone(),
            description: definition.description.clone(),
            options: definition.options.clone(),
            max_length: definition.max_length,
            minimum: definition.minimum,
            maximum: definition.maximum,
            visibility: definition.visibility,
            archived: definition.archived,
            created_at: definition.created_at,
            updated_at: definition.updated_at,
        }
    }

    /// A tier choice with gold and silver, stored as declared, loads without
    /// error.
    #[test]
    fn a_stored_definition_reads_back() {
        let definition = choice("tier", &["gold", "silver"]);

        assert!(Attribute::reconstitute(stored(&definition)).is_ok());
    }

    /// A stored age with options, and a stored nickname with a lowest
    /// value, are both refused as corrupt. Loading checks the same rules as
    /// declaring.
    #[test]
    fn a_stored_definition_its_kind_does_not_allow_is_refused() {
        let mut options_on_a_number = stored(&declare("age", AttributeKind::WholeNumber));
        options_on_a_number.options = vec![label("one")];
        let mut bounds_on_text = stored(&declare("nickname", AttributeKind::Text));
        bounds_on_text.minimum = Restriction::To(1.0);

        for row in [options_on_a_number, bounds_on_text] {
            assert!(refused_as_corrupt(&Attribute::reconstitute(row)));
        }
    }

    /// An editor without sensitive clearance cannot expose salary as
    /// ordinary. It stays sensitive until a cleared editor changes it.
    #[test]
    fn only_someone_cleared_for_it_marks_a_sensitive_attribute_ordinary() {
        let mut salary = declare("salary", AttributeKind::Money);
        salary
            .change_visibility(
                AttributeVisibility {
                    sensitive: AttributeSensitivity::Sensitive,
                    ..AttributeVisibility::default()
                },
                user_editor(),
            )
            .unwrap();

        let by_sam = salary.change_visibility(AttributeVisibility::default(), user_editor());
        let still_sensitive = salary.sensitive();
        let by_cleared = salary.change_visibility(AttributeVisibility::default(), cleared_editor());

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(still_sensitive);
        assert!(by_cleared.is_ok());
        assert!(!salary.sensitive());
    }

    /// A money attribute rejects NaN and both infinities as invalid values.
    #[test]
    fn a_number_that_is_not_finite_is_refused() {
        let salary = declare("salary", AttributeKind::Money);

        for odd in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(salary.validate(&MetadataValue::Number(odd)).is_err());
        }
    }
}
