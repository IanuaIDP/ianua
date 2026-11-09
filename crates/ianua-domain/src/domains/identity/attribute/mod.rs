//! Custom user attributes: the fields a tenant adds to its own users.
//!
//! A tenant's users need more than the fields the platform has. One tenant
//! wants a department and a cost centre, the next an employee number and a
//! shirt size. These cannot be guessed ahead of time. So the tenant declares
//! them, and their values are stored beside the user.
//!
//! They must be declared first. A key nobody declared cannot be shown on a
//! form, sorted, filtered, reviewed or erased. Values under it would be
//! hidden from every part of the product meant to manage them.
//!
//! The pieces, from what an administrator picks down to what a query runs:
//!
//! - [`AttributeKind`] is the one choice they make, such as money, a date or
//!   one of a list. Everything else follows from it.
//! - [`ValueType`] is where the kind's values are stored. It names the one
//!   column a query may read.
//! - [`AttributeControl`] is the form control a client shows. No query reads
//!   it.
//! - [`AttributeOperator`] is a comparison a filter may make, from a closed
//!   set.
//! - [`AttributeDefinition`] is one declared attribute. It holds what an
//!   administrator set and refuses settings the kind does not allow.
//! - [`MetadataSchema`] is all of them together. Every query on an attribute
//!   is checked by it.
//!
//! # How a caller's filter becomes SQL
//!
//! Only through [`MetadataSchema::resolve_filter`], the only code that
//! builds a [`ResolvedAttributeFilter`]. Holding one shows the attribute was
//! declared, is in use and was opened for filtering. It also shows the
//! caller's [`AttributeClearance`] allows it, and that its type can answer
//! the question.
//!
//! What reaches the query is split in two. The column name and the
//! comparison are fixed strings, picked by matching a closed enum, and are
//! written into the SQL text. The attribute key and every value the caller
//! sent are bound as parameters and never appear in it. There is nothing
//! else, so caller input never becomes SQL.

pub mod control;
pub mod definition;
pub mod key;
pub mod kind;
pub mod metadata_change;
pub mod namespace;
pub mod operator;
pub mod resolved;
pub mod schema;
pub mod schema_control;
pub mod value_type;

pub use control::AttributeControl;
pub use definition::{
    AttributeDefinition, AttributeDefinitionRow, AttributeVisibility, DeclareAttribute,
};
pub use key::AttributeKey;
pub use kind::{AttributeKind, KindSpec, OptionSupport};
pub use namespace::{AttributeNamespace, AttributeWriter};
pub use operator::{AttributeOperator, OperandArity};
pub use resolved::{
    AttributeClearance, AttributeFilterRequest, AttributeSortRequest, ResolvedAttributeFilter,
    ResolvedAttributeSort,
};
pub use schema::MetadataSchema;
pub use schema_control::SchemaControlCheck;
pub use value_type::ValueType;
