//! Filters and sorts that have been checked against the declared schema.
//!
//! A custom attribute reaches a query only in one of these shapes, and code
//! outside this module cannot build them. Their fields are private. Their
//! constructors are visible only inside the attribute module, where
//! [`MetadataSchema`](crate::domains::identity::attribute::schema::MetadataSchema) makes them. So holding
//! one shows the attribute was declared and opened for querying. It also
//! shows the caller may see it, and that its type can answer the question.
//!
//! An adapter has nothing to check again and no way to skip a check. It maps
//! the value type to where it is stored, binds the key and the operands, and
//! runs the query.

use crate::domains::identity::attribute::key::AttributeKey;
use crate::domains::identity::attribute::namespace::AttributeNamespace;
use crate::domains::identity::attribute::operator::AttributeOperator;
use crate::domains::identity::attribute::value_type::ValueType;
use crate::domains::identity::metadata_value::MetadataValue;

/// How much of a user's custom attributes the caller may see.
///
/// It is checked while a filter is built, not afterwards. So a filter on a
/// salary cannot be built without the right to read salaries. Say Sam may
/// not read salaries. He could filter the user list to `income > 100000` and
/// count the results. That tells him the value without reading the field. So
/// filtering needs the same right as reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeClearance {
    /// May see the attributes an ordinary user list shows.
    Directory,
    /// May also see the attributes marked sensitive.
    Sensitive,
}

impl AttributeClearance {
    /// Whether an attribute marked `sensitive` may be seen.
    #[must_use]
    pub fn admits_sensitive(self) -> bool {
        matches!(self, Self::Sensitive)
    }
}

/// A filter a caller asked for, before it is checked.
#[derive(Debug, Clone)]
pub struct AttributeFilterRequest {
    /// Which namespace the attribute is in.
    pub namespace: AttributeNamespace,
    /// The attribute's internal name.
    pub key: AttributeKey,
    /// The comparison to make.
    pub operator: AttributeOperator,
    /// The values to compare against. Empty for a presence test.
    pub operands: Vec<MetadataValue>,
}

/// A sort a caller asked for, before it is checked.
#[derive(Debug, Clone)]
pub struct AttributeSortRequest {
    /// Which namespace the attribute is in.
    pub namespace: AttributeNamespace,
    /// The attribute's internal name.
    pub key: AttributeKey,
    /// Which way to sort.
    pub direction: SortDirection,
}

/// A filter on a custom attribute, checked against the schema.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedAttributeFilter {
    namespace: AttributeNamespace,
    key: AttributeKey,
    value_type: ValueType,
    operator: AttributeOperator,
    operands: Vec<MetadataValue>,
}

/// An operator and the typed values it compares against.
pub(super) struct Comparison {
    /// How to compare.
    pub(super) operator: AttributeOperator,
    /// The values to compare against.
    pub(super) operands: Vec<MetadataValue>,
}

impl ResolvedAttributeFilter {
    /// Records a filter the schema has checked.
    pub(super) fn new(
        namespace: AttributeNamespace,
        key: AttributeKey,
        value_type: ValueType,
        comparison: Comparison,
    ) -> Self {
        let Comparison { operator, operands } = comparison;
        Self {
            namespace,
            key,
            value_type,
            operator,
            operands,
        }
    }

    /// Which namespace to look in. Bound, never written into SQL.
    #[must_use]
    pub fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    /// The attribute's internal name. Bound, never written into SQL.
    #[must_use]
    pub fn key(&self) -> &AttributeKey {
        &self.key
    }

    /// Where the attribute's values are stored, and so which column to read.
    #[must_use]
    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    /// The comparison to make.
    #[must_use]
    pub fn operator(&self) -> AttributeOperator {
        self.operator
    }

    /// The values to compare against. Bound, never written into SQL.
    #[must_use]
    pub fn operands(&self) -> &[MetadataValue] {
        &self.operands
    }
}

/// Which way a sort by an attribute runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    /// Smallest first.
    Ascending,
    /// Largest first.
    Descending,
}

/// A sort by a custom attribute, checked against the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAttributeSort {
    namespace: AttributeNamespace,
    key: AttributeKey,
    value_type: ValueType,
    direction: SortDirection,
}

impl ResolvedAttributeSort {
    /// Records a sort the schema has checked.
    pub(super) fn new(
        namespace: AttributeNamespace,
        key: AttributeKey,
        value_type: ValueType,
        direction: SortDirection,
    ) -> Self {
        Self {
            namespace,
            key,
            value_type,
            direction,
        }
    }

    /// Which namespace to look in. Bound, never written into SQL.
    #[must_use]
    pub fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    /// The attribute's internal name. Bound, never written into SQL.
    #[must_use]
    pub fn key(&self) -> &AttributeKey {
        &self.key
    }

    /// Where the attribute's values are stored.
    #[must_use]
    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    /// Which way to sort.
    #[must_use]
    pub fn direction(&self) -> SortDirection {
        self.direction
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller with sensitive clearance may see a sensitive attribute. One
    /// with only directory clearance may not.
    #[test]
    fn only_sensitive_clearance_admits_a_sensitive_attribute() {
        assert!(AttributeClearance::Sensitive.admits_sensitive());
        assert!(!AttributeClearance::Directory.admits_sensitive());
    }

    /// Sorts by `tier` ascending and descending each keep their direction
    /// and the text value type.
    #[test]
    fn a_resolved_sort_keeps_the_direction_it_was_given() {
        let ascending = ResolvedAttributeSort::new(
            AttributeNamespace::App,
            AttributeKey::new("tier").unwrap(),
            ValueType::Text,
            SortDirection::Ascending,
        );
        let descending = ResolvedAttributeSort::new(
            AttributeNamespace::App,
            AttributeKey::new("tier").unwrap(),
            ValueType::Text,
            SortDirection::Descending,
        );

        assert_eq!(ascending.direction(), SortDirection::Ascending);
        assert_eq!(descending.direction(), SortDirection::Descending);
        assert_eq!(ascending.value_type(), ValueType::Text);
    }

    /// A filter built for each of the five value types reports that type.
    /// The column a query reads comes from it, not from anything the caller
    /// sent.
    #[test]
    fn a_resolved_filter_keeps_the_value_type_it_was_resolved_with() {
        for value_type in [
            ValueType::Text,
            ValueType::Integer,
            ValueType::Number,
            ValueType::Boolean,
            ValueType::TextArray,
        ] {
            let filter = ResolvedAttributeFilter::new(
                AttributeNamespace::User,
                AttributeKey::new("field").unwrap(),
                value_type,
                Comparison {
                    operator: AttributeOperator::IsPresent,
                    operands: Vec::new(),
                },
            );

            assert_eq!(filter.value_type(), value_type);
        }
    }
}
