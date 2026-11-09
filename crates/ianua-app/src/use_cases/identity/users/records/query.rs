//! Turning what a caller asked a user listing for into the filter and order
//! the store runs, checked against the tenant's declared attributes with the
//! clearance the caller holds.

use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::attribute::schema::TextCondition;
use ianua_domain::domains::identity::attribute::{
    AttributeClearance, AttributeKey, AttributeNamespace, AttributeOperator, AttributeSortRequest,
    MetadataSchema, ResolvedAttributeFilter,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{GroupId, RoleId};

use crate::error::AppError;
use crate::listing::SortOrder;
use crate::ports::identity::{
    TimeSpan, UserAttributeStore, UserFilter, UserOrdering, UserSortField,
};
use crate::tenancy::ScopedTenant;
use crate::use_cases::identity::attributes::declared_schema::declared_schema;

/// A comparison on one custom attribute, as the caller typed it.
pub struct AttributeCondition {
    /// Which namespace the attribute is in.
    pub namespace: AttributeNamespace,
    /// The attribute's internal name.
    pub key: AttributeKey,
    /// How to compare.
    pub operator: AttributeOperator,
    /// The operands, still as text.
    pub values: Vec<String>,
}

/// What a listing is narrowed to.
#[derive(Default)]
pub struct UserCriteria {
    /// Only users in this status.
    pub status: Option<UserStatus>,
    /// Only users whose address contains this, ignoring case.
    pub email_contains: Option<String>,
    /// Only users whose name contains this, ignoring case.
    pub name_contains: Option<String>,
    /// Only users holding this role, directly or through a group.
    pub role: Option<RoleId>,
    /// Only members of this group.
    pub group: Option<GroupId>,
    /// Only users whose last sign-in falls in this span.
    pub last_login: TimeSpan,
    /// Only users created in this span.
    pub created: TimeSpan,
    /// Only users whose custom attributes meet every condition.
    pub attributes: Vec<AttributeCondition>,
}

/// The order a listing is asked for.
pub enum ListOrder {
    /// By columns of the user row.
    Column(SortOrder<UserSortField>),
    /// By one of the tenant's custom attributes.
    Attribute(AttributeSortRequest),
}

impl Default for ListOrder {
    fn default() -> Self {
        Self::Column(SortOrder::default())
    }
}

/// What a listing is narrowed to, and the order it is asked for.
pub(in crate::use_cases::identity) struct UserQuery {
    /// What the users are narrowed to.
    pub(in crate::use_cases::identity) criteria: UserCriteria,
    /// The order they are returned in.
    pub(in crate::use_cases::identity) order: ListOrder,
}

/// The filter and order the store runs for `query`, each attribute in it
/// checked against the tenant's schema for `clearance`.
///
/// The schema is read only when an attribute is named.
///
/// # Errors
///
/// - `AppError::Domain` when an attribute is not declared, archived, not
///   opened for filtering or sorting, or cannot answer the comparison.
/// - `AppError::Forbidden` when an attribute is sensitive and `clearance`
///   does not admit it.
/// - `AppError::Internal` when the schema cannot be read.
pub(in crate::use_cases::identity) async fn resolved_query(
    schemas: &dyn UserAttributeStore,
    tenant: &ScopedTenant,
    query: UserQuery,
    clearance: AttributeClearance,
) -> Result<(UserFilter, UserOrdering), AppError> {
    let UserQuery { criteria, order } = query;
    let schema = schema_for(schemas, tenant, &criteria, &order).await?;
    let attributes = criteria
        .attributes
        .iter()
        .map(|condition| resolved_filter(&schema, condition, clearance))
        .collect::<Result<Vec<_>, _>>()?;
    let ordering = match order {
        ListOrder::Column(sort) => UserOrdering::Column(sort),
        ListOrder::Attribute(request) => UserOrdering::Attribute(
            schema
                .resolve_sort(&request, clearance)
                .map_err(AppError::from_domain)?,
        ),
    };
    let filter = UserFilter {
        status: criteria.status,
        email_contains: criteria.email_contains,
        name_contains: criteria.name_contains,
        role: criteria.role,
        group: criteria.group,
        last_login: criteria.last_login,
        created: criteria.created,
        ids: None,
        invitation: None,
        attributes,
    };
    Ok((filter, ordering))
}

/// The tenant's schema, or an empty one when no attribute is named.
async fn schema_for(
    schemas: &dyn UserAttributeStore,
    tenant: &ScopedTenant,
    criteria: &UserCriteria,
    order: &ListOrder,
) -> Result<MetadataSchema<ResolvedTenant>, AppError> {
    let names_attribute =
        !criteria.attributes.is_empty() || matches!(order, ListOrder::Attribute(_));
    if !names_attribute {
        return Ok(MetadataSchema::empty());
    }
    declared_schema(schemas, tenant).await
}

/// `condition`, checked against `schema` for `clearance`.
fn resolved_filter(
    schema: &MetadataSchema<ResolvedTenant>,
    condition: &AttributeCondition,
    clearance: AttributeClearance,
) -> Result<ResolvedAttributeFilter, AppError> {
    schema
        .resolve_filter_from_text(
            condition.namespace,
            &condition.key,
            TextCondition {
                operator: condition.operator,
                values: &condition.values,
            },
            clearance,
        )
        .map_err(AppError::from_domain)
}
