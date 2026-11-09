//! A tenant's declared custom user attributes, and the checks every query on
//! one goes through.

use crate::domains::identity::attribute::definition::{AttributeDefinition, MAX_VALUE_BYTES};
use crate::domains::identity::attribute::key::AttributeKey;
use crate::domains::identity::attribute::kind::AttributeKind;
use crate::domains::identity::attribute::namespace::{AttributeNamespace, AttributeWriter};
use crate::domains::identity::attribute::operator::{AttributeOperator, OperandArity};
use crate::domains::identity::attribute::resolved::{
    AttributeClearance, AttributeFilterRequest, AttributeSortRequest, Comparison,
    ResolvedAttributeFilter, ResolvedAttributeSort,
};
use crate::domains::identity::attribute::value_type::ValueType;
use crate::domains::identity::metadata_value::MetadataValue;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// Most values a single filter may compare against.
///
/// A longer list is not a person filtering a user list. Each value also costs
/// a bound parameter on every row checked.
pub(crate) const MAX_FILTER_OPERANDS: usize = 100;

/// Every custom attribute a tenant has declared.
///
/// It is also the only way from a caller's request to something a query can
/// run. [`resolve_filter`](MetadataSchema::resolve_filter) and
/// [`resolve_sort`](MetadataSchema::resolve_sort) are the only code that
/// builds the resolved types. So a filter that reaches an adapter was checked
/// here. The attribute exists, is in use and was opened for querying. The
/// caller may see it, and its type can answer the comparison.
#[derive(Debug, Clone)]
pub struct MetadataSchema<T: TenantScope> {
    attributes: Vec<AttributeDefinition<T>>,
}

/// A comparison as it was typed. It is an operator and its operands as text.
#[derive(Clone, Copy)]
pub struct TextCondition<'a> {
    /// How to compare.
    pub operator: AttributeOperator,
    /// The operands, still as text.
    pub values: &'a [String],
}

impl<T: TenantScope> MetadataSchema<T> {
    /// Collects declared attributes into a schema.
    #[must_use]
    pub fn new(attributes: Vec<AttributeDefinition<T>>) -> Self {
        Self { attributes }
    }

    /// A tenant that has declared nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            attributes: Vec::new(),
        }
    }

    /// Every declared attribute, archived ones included.
    #[must_use]
    pub fn attributes(&self) -> &[AttributeDefinition<T>] {
        &self.attributes
    }

    /// Whether nothing has been declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// The attributes still in use. A form offers these.
    pub fn in_use(&self) -> impl Iterator<Item = &AttributeDefinition<T>> {
        self.attributes.iter().filter(|a| !a.archived())
    }

    /// The attributes in one namespace that are still in use.
    pub fn in_use_within(
        &self,
        namespace: AttributeNamespace,
    ) -> impl Iterator<Item = &AttributeDefinition<T>> {
        self.in_use().filter(move |a| a.namespace() == namespace)
    }

    /// The attributes a listing carries with each user, for a caller with
    /// `clearance`.
    ///
    /// A sensitive one is included only for someone allowed to read it. So
    /// the listing keeps the rule, not whoever shows it.
    pub fn listed(
        &self,
        clearance: AttributeClearance,
    ) -> impl Iterator<Item = &AttributeDefinition<T>> {
        self.attributes
            .iter()
            .filter(move |a| a.is_listed() && (clearance.admits_sensitive() || !a.sensitive()))
    }

    /// Finds a declaration by namespace and key.
    ///
    /// Both are needed. A `tier` a person keeps and a `tier` the billing
    /// system keeps are different attributes with the same name.
    #[must_use]
    pub fn find(
        &self,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Option<&AttributeDefinition<T>> {
        self.attributes
            .iter()
            .find(|a| a.namespace() == namespace && a.key() == key)
    }

    /// Whether a value stored under `key` may be shown to a caller with
    /// `clearance`.
    ///
    /// A value under a key nobody declared is never shown. It would be a
    /// field no form can show and no filter can find. A sensitive value is
    /// shown only to a caller allowed to read it.
    #[must_use]
    pub fn shows(
        &self,
        namespace: AttributeNamespace,
        key: &str,
        clearance: AttributeClearance,
    ) -> bool {
        AttributeKey::new(key)
            .ok()
            .and_then(|key| self.find(namespace, &key))
            .is_some_and(|declared| clearance.admits_sensitive() || !declared.sensitive())
    }

    /// The attributes in `namespace` that every user must hold a value for.
    pub fn required_within(
        &self,
        namespace: AttributeNamespace,
    ) -> impl Iterator<Item = &AttributeDefinition<T>> {
        self.in_use_within(namespace).filter(|a| a.required())
    }

    /// Checks a custom-attribute write against its declared key and writer's namespace.
    /// Undeclared keys cannot hide data outside the product's attribute controls.
    ///
    /// # Errors
    /// [`DomainError::Validation`] for undeclared or archived attributes or invalid values.
    /// [`DomainError::Forbidden`] when [`AttributeNamespace::ensure_writable_by`] refuses.
    pub fn validate_value(
        &self,
        namespace: AttributeNamespace,
        key: &AttributeKey,
        value: &MetadataValue,
        writer: AttributeWriter,
    ) -> Result<(), DomainError> {
        namespace.ensure_writable_by(writer)?;
        self.declaration(namespace, key)?.validate(value)
    }

    /// Checks a requested filter and records it as one a query may run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the attribute is not declared, is
    ///   archived, or was not opened for filtering.
    /// - [`DomainError::Forbidden`] when the attribute is sensitive and the
    ///   caller may not read it.
    /// - [`DomainError::Validation`] when its type cannot be compared with
    ///   that operator.
    /// - [`DomainError::Validation`] when the number of operands does not
    ///   suit the operator, or is over `MAX_FILTER_OPERANDS`.
    /// - [`DomainError::Validation`] when an operand is the wrong type.
    pub fn resolve_filter(
        &self,
        request: &AttributeFilterRequest,
        clearance: AttributeClearance,
    ) -> Result<ResolvedAttributeFilter, DomainError> {
        let declaration = self.declaration(request.namespace, &request.key)?;

        if !declaration.is_filterable() {
            return Err(DomainError::invalid(message!(
                "identity-is-not-available-for-filtering",
                format!("'{}' is not available for filtering", request.key)
            )));
        }

        Self::check_clearance(declaration, clearance, "filtered by")?;

        let value_type = declaration.value_type();

        if !request.operator.applies_to(value_type) {
            return Err(DomainError::invalid(message!(
                "identity-holds-and-cannot-be-filtered-that",
                format!(
                    "'{}' holds {} and cannot be filtered that way",
                    request.key,
                    value_type.describe()
                )
            )));
        }

        Self::check_operands(request, value_type)?;
        Self::check_operand_values(request, declaration.kind())?;

        Ok(ResolvedAttributeFilter::new(
            request.namespace,
            request.key.clone(),
            value_type,
            Comparison {
                operator: request.operator,
                operands: request.operands.clone(),
            },
        ))
    }

    /// Checks a filter whose values came as text, as a query string carries
    /// them.
    ///
    /// The declaration's type is used to read the values and then to check
    /// them. So a caller never has to guess what `50000` is before knowing
    /// what it is compared with.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the attribute is not declared or is
    ///   archived.
    /// - [`DomainError::Validation`] when a value cannot be read as the
    ///   attribute's type.
    /// - Every error [`resolve_filter`](Self::resolve_filter) gives, including
    ///   [`DomainError::Forbidden`].
    pub fn resolve_filter_from_text(
        &self,
        namespace: AttributeNamespace,
        key: &AttributeKey,
        condition: TextCondition<'_>,
        clearance: AttributeClearance,
    ) -> Result<ResolvedAttributeFilter, DomainError> {
        let TextCondition { operator, values } = condition;
        let value_type = self.declaration(namespace, key)?.value_type();

        let operands = values
            .iter()
            .map(|text| {
                value_type.parse_value(text).ok_or_else(|| {
                    DomainError::invalid(message!(
                        "identity-holds-and-is-not-one",
                        format!(
                            "'{key}' holds {} and '{text}' is not one",
                            value_type.describe()
                        )
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.resolve_filter(
            &AttributeFilterRequest {
                namespace,
                key: key.clone(),
                operator,
                operands,
            },
            clearance,
        )
    }

    /// Checks a requested sort and records it as one a query may run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the attribute is not declared or is
    ///   archived.
    /// - [`DomainError::Validation`] when it was not opened for sorting, or
    ///   holds a list, which cannot be sorted.
    /// - [`DomainError::Forbidden`] when the attribute is sensitive and the
    ///   caller may not read it.
    pub fn resolve_sort(
        &self,
        request: &AttributeSortRequest,
        clearance: AttributeClearance,
    ) -> Result<ResolvedAttributeSort, DomainError> {
        let declaration = self.declaration(request.namespace, &request.key)?;

        if !declaration.is_sortable() {
            return Err(DomainError::invalid(message!(
                "identity-is-not-available-for-sorting",
                format!("'{}' is not available for sorting", request.key)
            )));
        }

        Self::check_clearance(declaration, clearance, "sorted by")?;

        Ok(ResolvedAttributeSort::new(
            request.namespace,
            request.key.clone(),
            declaration.value_type(),
            request.direction,
        ))
    }

    /// The declaration behind a key. An undeclared or archived key is an
    /// error.
    fn declaration(
        &self,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<&AttributeDefinition<T>, DomainError> {
        let declaration = self.find(namespace, key).ok_or_else(|| {
            DomainError::invalid(message!(
                "identity-no-attribute-named-has-been-declared",
                format!("no attribute named '{key}' has been declared")
            ))
        })?;

        if declaration.archived() {
            return Err(DomainError::invalid(message!(
                "identity-is-no-longer-in-use-2",
                format!("'{key}' is no longer in use")
            )));
        }

        Ok(declaration)
    }

    /// Refuses a sensitive attribute to a caller who may only view users.
    fn check_clearance(
        declaration: &AttributeDefinition<T>,
        clearance: AttributeClearance,
        action: &str,
    ) -> Result<(), DomainError> {
        if declaration.sensitive() && !clearance.admits_sensitive() {
            return Err(DomainError::forbidden(message!(
                "identity-holds-sensitive-information-and-cannot-be",
                format!(
                    "'{}' holds sensitive information and cannot be {action} without permission to read it",
                    declaration.key()
                )
            )));
        }

        Ok(())
    }

    /// Checks that the number and type of a filter's values suit its
    /// operator.
    fn check_operands(
        request: &AttributeFilterRequest,
        value_type: ValueType,
    ) -> Result<(), DomainError> {
        let count = request.operands.len();

        match request.operator.arity() {
            OperandArity::None if count > 0 => {
                return Err(DomainError::invalid(message!(
                    "identity-compares-against-no-value",
                    format!("'{}' compares against no value", request.key)
                )));
            }
            OperandArity::One if count != 1 => {
                return Err(DomainError::invalid(message!(
                    "identity-compares-against-exactly-one-value",
                    format!("'{}' compares against exactly one value", request.key)
                )));
            }
            OperandArity::Many if count == 0 => {
                return Err(DomainError::invalid(message!(
                    "identity-compares-against-at-least-one-value",
                    format!("'{}' compares against at least one value", request.key)
                )));
            }
            OperandArity::Many if count > MAX_FILTER_OPERANDS => {
                return Err(DomainError::invalid(message!(
                    "identity-at-most-values-may-be-compared",
                    format!("at most {MAX_FILTER_OPERANDS} values may be compared against at once")
                )));
            }
            OperandArity::None | OperandArity::One | OperandArity::Many => {}
        }

        Self::check_operand_types(request, value_type)
    }

    /// Checks each filter value is one the attribute could hold: finite, no
    /// larger than a stored value, and, for a date, spelled as dates are
    /// stored.
    ///
    /// A "contains" filter takes any text, since it looks inside values.
    fn check_operand_values(
        request: &AttributeFilterRequest,
        kind: AttributeKind,
    ) -> Result<(), DomainError> {
        for operand in &request.operands {
            let too_large = operand
                .as_str()
                .is_some_and(|text| text.len() > MAX_VALUE_BYTES);
            let not_finite = matches!(operand, MetadataValue::Number(n) if !n.is_finite());
            if too_large || not_finite {
                return Err(DomainError::invalid(message!(
                    "identity-cannot-be-compared-with-that-value",
                    format!("'{}' cannot be compared with that value", request.key)
                )));
            }
            if request.operator != AttributeOperator::Contains {
                kind.check_filter_value(operand).map_err(|_| {
                    DomainError::invalid(message!(
                        "identity-cannot-be-compared-with-that-value",
                        format!("'{}' cannot be compared with that value", request.key)
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Checks each value against the column it will be compared with.
    ///
    /// A list attribute is compared against the text items its lists hold,
    /// not a whole list, so its operands are text. "Contains" always takes
    /// text.
    fn check_operand_types(
        request: &AttributeFilterRequest,
        value_type: ValueType,
    ) -> Result<(), DomainError> {
        let expected = match value_type {
            ValueType::TextArray => ValueType::Text,
            scalar @ (ValueType::Text
            | ValueType::Integer
            | ValueType::Number
            | ValueType::Boolean) => scalar,
        };

        let comparing_text = matches!(request.operator, AttributeOperator::Contains);

        for operand in &request.operands {
            let acceptable = if comparing_text {
                operand.is_string()
            } else {
                expected.accepts(operand)
            };

            if !acceptable {
                return Err(DomainError::invalid(message!(
                    "identity-is-compared-against",
                    format!(
                        "'{}' is compared against {}",
                        request.key,
                        expected.describe()
                    )
                )));
            }
        }

        Ok(())
    }
}

impl<T: TenantScope> Default for MetadataSchema<T> {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::identity::attribute::control::AttributeControl;
    use crate::domains::identity::attribute::definition::{
        AttributeSensitivity, AttributeVisibility, DeclareAttribute, Filtering, Listing,
        Requirement, Sorting,
    };
    use crate::domains::identity::attribute::kind::AttributeKind;
    use crate::domains::identity::attribute::resolved::SortDirection;
    use crate::domains::identity::attribute::schema::{ValueType, *};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::restriction::Restriction;
    use crate::test_support::authority::user_editor;
    use crate::types::{Label, Preference};

    type Attribute = AttributeDefinition<ResolvedTenant>;
    type Schema = MetadataSchema<ResolvedTenant>;

    fn key(name: &str) -> AttributeKey {
        AttributeKey::new(name).unwrap()
    }

    fn label(name: &str) -> Label {
        Label::new("option", name).unwrap()
    }

    /// Declares an attribute open for querying, which is what most of these
    /// tests need before they can vary the interesting facet.
    fn queryable(name: &str, kind: AttributeKind) -> Attribute {
        build(name, kind, |params| {
            params.visibility = AttributeVisibility {
                filterable: Filtering::Filterable,
                sortable: if kind.is_orderable() {
                    Sorting::Sortable
                } else {
                    Sorting::NotSortable
                },
                ..AttributeVisibility::default()
            };
        })
    }

    fn build(
        name: &str,
        kind: AttributeKind,
        adjust: impl FnOnce(&mut DeclareAttribute),
    ) -> Attribute {
        let mut params = DeclareAttribute {
            key: key(name),
            namespace: AttributeNamespace::App,
            kind,
            control: Preference::Inherited,
            display_name: Label::new("display_name", name).unwrap(),
            description: None,
            options: if kind.requires_options() {
                vec![label("sales"), label("support")]
            } else {
                Vec::new()
            },
            max_length: Restriction::Unrestricted,
            minimum: Restriction::Unrestricted,
            maximum: Restriction::Unrestricted,
            visibility: AttributeVisibility::default(),
        };
        adjust(&mut params);
        Attribute::declare(params, user_editor()).unwrap()
    }

    fn filter(
        name: &str,
        operator: AttributeOperator,
        operands: Vec<MetadataValue>,
    ) -> AttributeFilterRequest {
        AttributeFilterRequest {
            namespace: AttributeNamespace::App,
            key: key(name),
            operator,
            operands,
        }
    }

    fn sort(name: &str) -> AttributeSortRequest {
        AttributeSortRequest {
            namespace: AttributeNamespace::App,
            key: key(name),
            direction: SortDirection::Ascending,
        }
    }

    fn message(error: &DomainError) -> String {
        error.to_string()
    }

    /// A shared `tier` key resolves separately by namespace, finding the
    /// user's text declaration and the application's money declaration.
    #[test]
    fn the_same_key_in_two_namespaces_is_two_attributes() {
        let schema = Schema::new(vec![
            build("tier", AttributeKind::Text, |p| {
                p.namespace = AttributeNamespace::User;
            }),
            build("tier", AttributeKind::Money, |p| {
                p.namespace = AttributeNamespace::App;
            }),
        ]);

        assert_eq!(
            schema
                .find(AttributeNamespace::User, &key("tier"))
                .unwrap()
                .kind(),
            AttributeKind::Text
        );
        assert_eq!(
            schema
                .find(AttributeNamespace::App, &key("tier"))
                .unwrap()
                .kind(),
            AttributeKind::Money
        );
    }

    /// Only `dept` is declared, in the app namespace. Looking up `salary`
    /// finds nothing, and neither does `dept` in the user namespace.
    #[test]
    fn an_undeclared_key_is_found_nowhere() {
        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);

        assert!(
            schema
                .find(AttributeNamespace::App, &key("salary"))
                .is_none()
        );
        assert!(
            schema
                .find(AttributeNamespace::User, &key("dept"))
                .is_none(),
            "the same key in the other namespace is a different attribute"
        );
    }

    /// A tenant that declared nothing has no attributes in use and none
    /// listed, even for a caller with sensitive clearance.
    #[test]
    fn an_empty_schema_holds_nothing() {
        let schema = Schema::empty();

        assert!(schema.is_empty());
        assert_eq!(schema.in_use().count(), 0);
        assert_eq!(schema.listed(AttributeClearance::Sensitive).count(), 0);
    }

    /// A schema with one current and one archived attribute keeps both, so
    /// stored values remain. A form is offered only the current one.
    #[test]
    fn archived_attributes_are_kept_but_not_offered() {
        let mut archived = queryable("old", AttributeKind::Text);
        archived.archive(user_editor()).unwrap();
        let schema = Schema::new(vec![queryable("current", AttributeKind::Text), archived]);

        assert_eq!(schema.attributes().len(), 2, "kept, so values survive");
        assert_eq!(schema.in_use().count(), 1, "not offered on a form");
    }

    /// `dept` is declared listed and `salary` is not. A user list carries
    /// only `dept` with each user.
    #[test]
    fn the_listed_attributes_are_the_ones_a_directory_carries() {
        let listed = build("dept", AttributeKind::Text, |p| {
            p.visibility.listed = Listing::Listed;
        });
        let schema = Schema::new(vec![listed, queryable("salary", AttributeKind::Money)]);

        let carried: Vec<&str> = schema
            .listed(AttributeClearance::Directory)
            .map(|a| a.key().as_str())
            .collect();
        assert_eq!(carried, ["dept"]);
    }

    /// A listed sensitive salary is omitted at directory clearance and
    /// included at sensitive clearance.
    #[test]
    fn a_sensitive_listed_attribute_reaches_only_a_cleared_caller() {
        let salary = build("salary", AttributeKind::Money, |p| {
            p.visibility.listed = Listing::Listed;
            p.visibility.sensitive = AttributeSensitivity::Sensitive;
        });
        let schema = Schema::new(vec![salary]);

        assert_eq!(schema.listed(AttributeClearance::Directory).count(), 0);
        assert_eq!(schema.listed(AttributeClearance::Sensitive).count(), 1);
    }

    /// `dept` is required in the app namespace and `theme` is optional in the
    /// user namespace. Each namespace reports only its own required ones.
    #[test]
    fn the_required_attributes_are_reported_per_namespace() {
        let schema = Schema::new(vec![
            build("dept", AttributeKind::Text, |p| {
                p.namespace = AttributeNamespace::App;
                p.visibility.required = Requirement::Required;
            }),
            build("theme", AttributeKind::Text, |p| {
                p.namespace = AttributeNamespace::User;
            }),
        ]);

        assert_eq!(schema.required_within(AttributeNamespace::App).count(), 1);
        assert_eq!(schema.required_within(AttributeNamespace::User).count(), 0);
    }

    /// A value under the undeclared key `whatever` is refused. Stored, it
    /// could not be shown, sorted, filtered, reviewed or erased.
    #[test]
    fn a_value_under_an_undeclared_key_is_refused() {
        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);

        let error = schema
            .validate_value(
                AttributeNamespace::App,
                &key("whatever"),
                &MetadataValue::from("x"),
                AttributeWriter::Administrator,
            )
            .unwrap_err();

        assert!(message(&error).contains("no attribute named 'whatever'"));
    }

    /// A declared salary takes 45000 and refuses "a lot". The value is
    /// checked against the declaration it goes under.
    #[test]
    fn a_value_is_checked_against_the_declaration_it_is_stored_under() {
        let schema = Schema::new(vec![queryable("salary", AttributeKind::Money)]);

        assert!(
            schema
                .validate_value(
                    AttributeNamespace::App,
                    &key("salary"),
                    &MetadataValue::from(45_000_i64),
                    AttributeWriter::Administrator
                )
                .is_ok()
        );
        assert!(
            schema
                .validate_value(
                    AttributeNamespace::App,
                    &key("salary"),
                    &MetadataValue::from("a lot"),
                    AttributeWriter::Administrator
                )
                .is_err()
        );
    }

    /// A value for the archived attribute `old` is refused as no longer in
    /// use.
    #[test]
    fn nothing_new_is_stored_under_an_archived_attribute() {
        let mut archived = queryable("old", AttributeKind::Text);
        archived.archive(user_editor()).unwrap();
        let schema = Schema::new(vec![archived]);

        let error = schema
            .validate_value(
                AttributeNamespace::App,
                &key("old"),
                &MetadataValue::from("x"),
                AttributeWriter::Administrator,
            )
            .unwrap_err();

        assert!(message(&error).contains("no longer in use"));
    }

    /// A filter "salary greater than 1000" on a filterable salary resolves.
    /// It keeps the key, the number type, the operator and one operand.
    #[test]
    fn a_declared_filterable_attribute_resolves() {
        let schema = Schema::new(vec![queryable("salary", AttributeKind::Money)]);

        let resolved = schema
            .resolve_filter(
                &filter(
                    "salary",
                    AttributeOperator::GreaterThan,
                    vec![MetadataValue::Number(1000.0)],
                ),
                AttributeClearance::Directory,
            )
            .unwrap();

        assert_eq!(resolved.key().as_str(), "salary");
        assert_eq!(resolved.value_type(), ValueType::Number);
        assert_eq!(resolved.operator(), AttributeOperator::GreaterThan);
        assert_eq!(resolved.operands().len(), 1);
    }

    /// Undeclared names, including database-like field names, cannot
    /// resolve to filters even with sensitive clearance.
    #[test]
    fn no_filter_can_be_resolved_for_an_undeclared_key() {
        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);

        for attempt in ["salary", "value_text", "id", "password_hash"] {
            let error = schema
                .resolve_filter(
                    &filter(
                        attempt,
                        AttributeOperator::Is,
                        vec![MetadataValue::from("x")],
                    ),
                    AttributeClearance::Sensitive,
                )
                .unwrap_err();

            assert!(
                message(&error).contains("no attribute named"),
                "{attempt} resolved: {error}"
            );
        }
    }

    /// A salary declared without filtering cannot be filtered, even by a
    /// presence test with full clearance.
    #[test]
    fn an_attribute_not_opened_for_filtering_will_not_resolve() {
        let schema = Schema::new(vec![build("salary", AttributeKind::Money, |_| {})]);

        let error = schema
            .resolve_filter(
                &filter("salary", AttributeOperator::IsPresent, Vec::new()),
                AttributeClearance::Sensitive,
            )
            .unwrap_err();

        assert!(message(&error).contains("not available for filtering"));
    }

    /// A filter on the archived attribute `old` is refused as no longer in
    /// use.
    #[test]
    fn an_archived_attribute_will_not_resolve() {
        let mut archived = queryable("old", AttributeKind::Text);
        archived.archive(user_editor()).unwrap();
        let schema = Schema::new(vec![archived]);

        let error = schema
            .resolve_filter(
                &filter("old", AttributeOperator::IsPresent, Vec::new()),
                AttributeClearance::Sensitive,
            )
            .unwrap_err();

        assert!(message(&error).contains("no longer in use"));
    }

    /// Filtering sensitive income is forbidden at directory clearance;
    /// the same request resolves with sensitive clearance.
    #[test]
    fn a_sensitive_attribute_cannot_be_filtered_without_clearance() {
        let schema = Schema::new(vec![build("income", AttributeKind::Money, |p| {
            p.visibility = AttributeVisibility {
                filterable: Filtering::Filterable,
                sensitive: AttributeSensitivity::Sensitive,
                ..AttributeVisibility::default()
            };
        })]);

        let request = filter(
            "income",
            AttributeOperator::GreaterThan,
            vec![MetadataValue::Number(100_000.0)],
        );

        let error = schema
            .resolve_filter(&request, AttributeClearance::Directory)
            .unwrap_err();
        assert!(matches!(error, DomainError::Forbidden(_)), "{error}");
        assert!(message(&error).contains("sensitive"), "{error}");

        assert!(
            schema
                .resolve_filter(&request, AttributeClearance::Sensitive)
                .is_ok(),
            "clearance is what makes it possible, not a different request"
        );
    }

    /// "Salary contains 000" is refused. A number cannot be compared that
    /// way.
    #[test]
    fn an_operator_the_type_cannot_answer_is_refused() {
        let schema = Schema::new(vec![queryable("salary", AttributeKind::Money)]);

        let error = schema
            .resolve_filter(
                &filter(
                    "salary",
                    AttributeOperator::Contains,
                    vec![MetadataValue::from("000")],
                ),
                AttributeClearance::Directory,
            )
            .unwrap_err();

        assert!(message(&error).contains("cannot be filtered that way"));
    }

    /// "Tags has any red" resolves. "Tags is red" is refused.
    #[test]
    fn a_list_attribute_answers_only_the_list_comparisons() {
        let schema = Schema::new(vec![queryable("tags", AttributeKind::Tags)]);

        assert!(
            schema
                .resolve_filter(
                    &filter(
                        "tags",
                        AttributeOperator::HasAny,
                        vec![MetadataValue::from("red")]
                    ),
                    AttributeClearance::Directory,
                )
                .is_ok()
        );

        assert!(
            schema
                .resolve_filter(
                    &filter(
                        "tags",
                        AttributeOperator::Is,
                        vec![MetadataValue::from("red")]
                    ),
                    AttributeClearance::Directory,
                )
                .is_err()
        );
    }

    /// Resolves a department comparison with ordinary directory clearance.
    fn department_filter(
        schema: &Schema,
        operator: AttributeOperator,
        operands: Vec<MetadataValue>,
    ) -> Result<ResolvedAttributeFilter, DomainError> {
        schema.resolve_filter(
            &filter("dept", operator, operands),
            AttributeClearance::Directory,
        )
    }

    /// "Dept is present" works with no value and is refused with one. "Dept
    /// is" is refused with no value and with two.
    #[test]
    fn a_presence_test_takes_no_value_and_a_comparison_takes_one() {
        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);

        assert!(department_filter(&schema, AttributeOperator::IsPresent, Vec::new()).is_ok());

        assert!(
            department_filter(
                &schema,
                AttributeOperator::IsPresent,
                vec![MetadataValue::from("x")],
            )
            .is_err(),
            "a presence test compares against nothing"
        );

        assert!(
            department_filter(&schema, AttributeOperator::Is, Vec::new()).is_err(),
            "an equality test needs something to equal"
        );

        assert!(
            department_filter(
                &schema,
                AttributeOperator::Is,
                vec![MetadataValue::from("a"), MetadataValue::from("b")],
            )
            .is_err(),
            "an equality test takes exactly one"
        );
    }

    /// "Dept is one of" is refused with no values and with 101. With exactly
    /// 100 values it resolves.
    #[test]
    fn a_list_comparison_needs_at_least_one_value_and_not_too_many() {
        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);

        assert!(department_filter(&schema, AttributeOperator::IsOneOf, Vec::new()).is_err());

        let many: Vec<MetadataValue> = (0..=MAX_FILTER_OPERANDS)
            .map(|i| MetadataValue::from(i.to_string()))
            .collect();

        assert!(
            department_filter(&schema, AttributeOperator::IsOneOf, many.clone()).is_err(),
            "a caller cannot bind an unbounded list"
        );

        assert!(
            department_filter(
                &schema,
                AttributeOperator::IsOneOf,
                many[..MAX_FILTER_OPERANDS].to_vec(),
            )
            .is_ok(),
            "the limit itself is fine"
        );
    }

    /// "Salary greater than lots" is refused. The error says salary is
    /// compared against a number.
    #[test]
    fn a_value_of_the_wrong_type_is_refused_as_an_operand() {
        let schema = Schema::new(vec![queryable("salary", AttributeKind::Money)]);

        let error = schema
            .resolve_filter(
                &filter(
                    "salary",
                    AttributeOperator::GreaterThan,
                    vec![MetadataValue::from("lots")],
                ),
                AttributeClearance::Directory,
            )
            .unwrap_err();

        assert!(message(&error).contains("compared against"));
    }

    /// Tags accept "has all" with "red" and "blue" as two text values. A
    /// whole list given as one operand is refused, since a list is compared
    /// item by item.
    #[test]
    fn a_list_is_compared_against_the_items_it_holds() {
        let schema = Schema::new(vec![queryable("tags", AttributeKind::Tags)]);

        assert!(
            schema
                .resolve_filter(
                    &filter(
                        "tags",
                        AttributeOperator::HasAll,
                        vec![MetadataValue::from("red"), MetadataValue::from("blue")]
                    ),
                    AttributeClearance::Directory
                )
                .is_ok()
        );

        assert!(
            schema
                .resolve_filter(
                    &filter(
                        "tags",
                        AttributeOperator::HasAny,
                        vec![MetadataValue::from(vec!["red".to_owned()])]
                    ),
                    AttributeClearance::Directory
                )
                .is_err()
        );
    }

    /// "Dept contains sup" resolves even though "sup" is not an option. A
    /// filter value is a piece to match, not a value to store, so only its
    /// type is checked.
    #[test]
    fn a_filter_value_is_not_held_to_the_stored_values_constraints() {
        let schema = Schema::new(vec![build("dept", AttributeKind::SingleChoice, |p| {
            p.options = vec![label("sales"), label("support")];
            p.visibility.filterable = Filtering::Filterable;
        })]);

        assert!(
            schema
                .resolve_filter(
                    &filter(
                        "dept",
                        AttributeOperator::Contains,
                        vec![MetadataValue::from("sup")]
                    ),
                    AttributeClearance::Directory
                )
                .is_ok(),
            "searching for a fragment of an option is not choosing a value"
        );
    }

    /// A sort by a sortable salary resolves with its key, the number type
    /// and ascending order.
    #[test]
    fn a_declared_sortable_attribute_resolves() {
        let schema = Schema::new(vec![queryable("salary", AttributeKind::Money)]);

        let resolved = schema
            .resolve_sort(&sort("salary"), AttributeClearance::Directory)
            .unwrap();

        assert_eq!(resolved.key().as_str(), "salary");
        assert_eq!(resolved.value_type(), ValueType::Number);
        assert_eq!(resolved.direction(), SortDirection::Ascending);
    }

    /// A descending sort by salary stays descending once resolved.
    #[test]
    fn a_descending_sort_resolves_descending() {
        let schema = Schema::new(vec![queryable("salary", AttributeKind::Money)]);
        let mut request = sort("salary");
        request.direction = SortDirection::Descending;

        let resolved = schema
            .resolve_sort(&request, AttributeClearance::Directory)
            .unwrap();

        assert_eq!(resolved.direction(), SortDirection::Descending);
    }

    /// Undeclared salary and database-like keys cannot resolve to sorts,
    /// even with sensitive clearance.
    #[test]
    fn no_sort_can_be_resolved_for_an_undeclared_key() {
        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);

        for attempt in ["salary", "value_text", "created_at"] {
            assert!(
                schema
                    .resolve_sort(&sort(attempt), AttributeClearance::Sensitive)
                    .is_err(),
                "{attempt} resolved"
            );
        }
    }

    /// A salary opened for filtering but not sorting cannot be sorted by.
    #[test]
    fn an_attribute_not_opened_for_sorting_will_not_resolve() {
        let schema = Schema::new(vec![build("salary", AttributeKind::Money, |p| {
            p.visibility.filterable = Filtering::Filterable;
        })]);

        let error = schema
            .resolve_sort(&sort("salary"), AttributeClearance::Sensitive)
            .unwrap_err();

        assert!(message(&error).contains("not available for sorting"));
    }

    /// A sort by tags is refused. A list cannot be sorted on.
    #[test]
    fn a_list_attribute_will_not_resolve_a_sort() {
        let schema = Schema::new(vec![queryable("tags", AttributeKind::Tags)]);

        assert!(
            schema
                .resolve_sort(&sort("tags"), AttributeClearance::Sensitive)
                .is_err()
        );
    }

    /// Sorting sensitive income is refused at directory clearance and
    /// succeeds with sensitive clearance.
    #[test]
    fn a_sensitive_attribute_cannot_be_sorted_without_clearance() {
        let schema = Schema::new(vec![build("income", AttributeKind::Money, |p| {
            p.visibility = AttributeVisibility {
                sortable: Sorting::Sortable,
                sensitive: AttributeSensitivity::Sensitive,
                ..AttributeVisibility::default()
            };
        })]);

        assert!(
            schema
                .resolve_sort(&sort("income"), AttributeClearance::Directory)
                .is_err()
        );
        assert!(
            schema
                .resolve_sort(&sort("income"), AttributeClearance::Sensitive)
                .is_ok()
        );
    }

    /// A sort by the archived attribute `old` is refused.
    #[test]
    fn an_archived_attribute_will_not_resolve_a_sort() {
        let mut archived = queryable("old", AttributeKind::Text);
        archived.archive(user_editor()).unwrap();
        let schema = Schema::new(vec![archived]);

        assert!(
            schema
                .resolve_sort(&sort("old"), AttributeClearance::Sensitive)
                .is_err()
        );
    }

    /// Filters using the scalar, list and presence comparisons of the declared schema.
    fn typed_filter_requests() -> [AttributeFilterRequest; 5] {
        [
            filter(
                "dept",
                AttributeOperator::Is,
                vec![MetadataValue::from("x")],
            ),
            filter(
                "salary",
                AttributeOperator::LessThanOrEqual,
                vec![MetadataValue::Number(1.0)],
            ),
            filter(
                "active",
                AttributeOperator::IsNot,
                vec![MetadataValue::from(true)],
            ),
            filter(
                "tags",
                AttributeOperator::HasAny,
                vec![MetadataValue::from("red")],
            ),
            filter("dept", AttributeOperator::IsAbsent, Vec::new()),
        ]
    }

    /// Five filters on text, money, yes/no and tags each resolve with the
    /// caller's values kept only as operands. Everything else comes from
    /// closed enums, so caller input is always bound, never written into SQL.
    #[test]
    fn a_resolved_filter_carries_the_callers_values_only_as_operands() {
        let schema = Schema::new(vec![
            queryable("dept", AttributeKind::Text),
            queryable("salary", AttributeKind::Money),
            queryable("active", AttributeKind::YesNo),
            queryable("tags", AttributeKind::Tags),
        ]);

        for request in typed_filter_requests() {
            let resolved = schema
                .resolve_filter(&request, AttributeClearance::Sensitive)
                .unwrap();

            assert_eq!(resolved.operator(), request.operator);
            assert_eq!(resolved.operands(), request.operands.as_slice());
        }
    }

    /// SQL-shaped attribute keys fail construction, while SQL-shaped text
    /// remains a valid operand for a declared department filter.
    #[test]
    fn a_hostile_key_cannot_even_be_asked_for() {
        assert!(AttributeKey::new("value_text FROM users--").is_err());
        assert!(AttributeKey::new("dept' OR '1'='1").is_err());

        let schema = Schema::new(vec![queryable("dept", AttributeKind::Text)]);
        assert!(
            schema
                .resolve_filter(
                    &filter(
                        "dept",
                        AttributeOperator::Is,
                        vec![MetadataValue::from("' OR 1=1--")]
                    ),
                    AttributeClearance::Directory
                )
                .is_ok(),
            "a hostile *value* is ordinary data and is bound, not refused"
        );
    }

    /// A department shown as radio buttons is filtered by its text type.
    /// Where a query reads follows the type, not how the form looks.
    #[test]
    fn a_control_is_never_consulted_by_a_query() {
        let schema = Schema::new(vec![build("dept", AttributeKind::SingleChoice, |p| {
            p.options = vec![label("sales")];
            p.control = Preference::Own(AttributeControl::RadioGroup);
            p.visibility.filterable = Filtering::Filterable;
        })]);

        let resolved = schema
            .resolve_filter(
                &filter(
                    "dept",
                    AttributeOperator::Is,
                    vec![MetadataValue::from("sales")],
                ),
                AttributeClearance::Directory,
            )
            .unwrap();

        assert_eq!(
            resolved.value_type(),
            ValueType::Text,
            "where it is stored follows the type, whatever the form looks like"
        );
    }

    /// NaN salary operands and 20,000-byte department operands are refused
    /// before a filter can be resolved.
    #[test]
    fn a_filter_value_no_attribute_could_hold_is_refused() {
        let schema = Schema::new(vec![
            queryable("salary", AttributeKind::Money),
            queryable("dept", AttributeKind::Text),
        ]);

        let not_a_number = schema.resolve_filter(
            &filter(
                "salary",
                AttributeOperator::GreaterThan,
                vec![MetadataValue::Number(f64::NAN)],
            ),
            AttributeClearance::Directory,
        );
        let huge = schema.resolve_filter(
            &filter(
                "dept",
                AttributeOperator::Is,
                vec![MetadataValue::from("x".repeat(20_000))],
            ),
            AttributeClearance::Directory,
        );

        assert!(not_a_number.is_err());
        assert!(huge.is_err());
    }
}
