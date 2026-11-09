//! Reading a user listing's custom-attribute filters and its order out of
//! the query string.
//!
//! A filter is `attr=<namespace>.<key>:<operator>[:<value>]`, for instance
//! `attr=app.department:is:sales`, `attr=app.salary:greater_than:50000` or
//! `attr=user.skills:has_all:rust,sql`. An order is `sort=<column>` as for
//! any listing, or `sort=attr:<namespace>.<key>`, with a leading `-` for
//! descending.
//!
//! Nothing here decides whether a filter or an order is allowed. It turns
//! text into which attribute, which comparison and which values; the app
//! checks them against the tenant's declared schema and the caller's
//! clearance.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::identity::UserSortField;
use ianua_app::use_cases::identity::users::{AttributeCondition, ListOrder};
use ianua_domain::domains::identity::attribute::resolved::SortDirection;
use ianua_domain::domains::identity::attribute::{
    AttributeKey, AttributeNamespace, AttributeOperator, AttributeSortRequest, OperandArity,
};
use ianua_domain::message;
use serde::Deserialize;

use crate::dto::identity::users::UserFilterParams;
use crate::error::ApiError;
use crate::extractors::pagination::Paging;
use crate::extractors::query::{Query, QueryRefusal};

/// The prefix marking a sort as naming a custom attribute rather than a
/// column of the user row.
const SORT_PREFIX: &str = "attr:";

/// Separates the values of a comparison against a list.
const VALUE_SEPARATOR: char = ',';

/// The filters, custom attributes, ordering and page requested for users.
pub(crate) struct UserListing {
    /// Filters on the account's built-in fields.
    pub filter: UserFilterParams,
    /// Comparisons against the tenant's declared custom attributes.
    pub attributes: Vec<AttributeCondition>,
    /// Ordering by built-in fields or one custom attribute.
    pub order: ListOrder,
    /// The checked cursor and page size.
    pub page: PageRequest,
}

impl<S: Send + Sync> FromRequestParts<S> for UserListing {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(filter) = Query::<UserFilterParams>::from_request_parts(parts, state).await?;
        let AttributeConditions(attributes) =
            AttributeConditions::from_request_parts(parts, state).await?;
        let UserOrder(order) = UserOrder::from_request_parts(parts, state).await?;
        let Paging(page) = Paging::from_request_parts(parts, state).await?;
        Ok(Self {
            filter,
            attributes,
            order,
            page,
        })
    }
}

/// Every `attr=` filter of a request, each split into its parts.
///
/// Read straight off the query string rather than through `Query<T>`: the
/// form decoder behind it cannot gather a repeated key into a list, so
/// `?attr=a&attr=b` would refuse the whole request.
pub(crate) struct AttributeConditions(pub Vec<AttributeCondition>);

impl<S: Send + Sync> FromRequestParts<S> for AttributeConditions {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or_default();
        url::form_urlencoded::parse(query.as_bytes())
            .filter(|(key, _)| key == "attr")
            .map(|(_, term)| condition(&term))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

impl utoipa::IntoParams for AttributeConditions {
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<utoipa::openapi::path::ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        vec![query_parameter(
            "attr",
            "Filter by a custom attribute, `<namespace>.<key>:<operator>[:<value>]`, such as \
             `app.department:is:sales`. Repeat to require every filter. A comparison against a \
             list takes comma-separated values.",
        )]
    }
}

/// The order a user listing is asked for: by columns of the user row, or by
/// one custom attribute.
pub(crate) struct UserOrder(pub ListOrder);

/// The raw `sort` parameter, read before it is known whether it names a
/// column or an attribute.
#[derive(Deserialize)]
struct SortParam {
    sort: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for UserOrder {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(param) = Query::<SortParam>::from_request_parts(parts, state).await?;
        let Some(token) = param.sort.as_deref().filter(|token| {
            token
                .trim_start_matches(['-', '+'])
                .starts_with(SORT_PREFIX)
        }) else {
            let columns = SortOrder::<UserSortField>::parse(param.sort.as_deref())
                .map_err(ApiError::validation)?;
            return Ok(Self(ListOrder::Column(columns)));
        };
        Ok(Self(ListOrder::Attribute(attribute_sort(token)?)))
    }
}

impl utoipa::IntoParams for UserOrder {
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<utoipa::openapi::path::ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        let description = format!(
            "Comma-separated sort fields, applied left to right, or one custom attribute as \
             `attr:<namespace>.<key>`. Prefix with `-` for descending order. Allowed fields: {}.",
            <UserSortField as ianua_app::listing::SortField>::allowed_tokens().join(", ")
        );
        vec![query_parameter("sort", &description)]
    }
}

/// An optional query string parameter, described for the document.
fn query_parameter(name: &str, description: &str) -> utoipa::openapi::path::Parameter {
    use utoipa::openapi::Required;
    use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
    use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};

    ParameterBuilder::new()
        .name(name)
        .parameter_in(ParameterIn::Query)
        .required(Required::False)
        .description(Some(description))
        .schema(Some(Schema::Object(
            ObjectBuilder::new().schema_type(Type::String).build(),
        )))
        .build()
}

/// One `attr=` term split into its three parts. Only the first two colons
/// separate them, so a value may hold a colon.
fn condition(term: &str) -> Result<AttributeCondition, ApiError> {
    let mut parts = term.splitn(3, ':');
    let target = parts.next().unwrap_or_default();
    let Some(operator) = parts.next() else {
        return Err(malformed(
            term,
            "expected <namespace>.<key>:<operator>[:<value>]",
        ));
    };
    let (namespace, key) = attribute_named(target, term)?;
    let operator = AttributeOperator::parse(operator).ok_or_else(|| {
        malformed(
            term,
            &format!("'{operator}' is not a comparison; see the attribute listing"),
        )
    })?;
    Ok(AttributeCondition {
        namespace,
        key,
        operator,
        values: values(operator, parts.next()),
    })
}

/// The values of a term. A comparison against a list splits on commas; one
/// against a single value does not, so a department called "Sales, EMEA"
/// stays findable.
fn values(operator: AttributeOperator, written: Option<&str>) -> Vec<String> {
    let Some(written) = written else {
        return Vec::new();
    };
    if operator.arity() != OperandArity::Many {
        return vec![written.to_owned()];
    }
    written
        .split(VALUE_SEPARATOR)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The attribute order a `[-]attr:<namespace>.<key>` token asks for.
fn attribute_sort(token: &str) -> Result<AttributeSortRequest, ApiError> {
    let direction = match token.starts_with('-') {
        true => SortDirection::Descending,
        false => SortDirection::Ascending,
    };
    let target = token
        .trim_start_matches(['-', '+'])
        .strip_prefix(SORT_PREFIX)
        .ok_or_else(|| malformed(token, "expected attr:<namespace>.<key>"))?;
    let (namespace, key) = attribute_named(target, token)?;
    Ok(AttributeSortRequest {
        namespace,
        key,
        direction,
    })
}

/// Splits `<namespace>.<key>`. Both halves are needed: the same name may be
/// declared in each namespace, as two different attributes.
fn attribute_named(
    target: &str,
    term: &str,
) -> Result<(AttributeNamespace, AttributeKey), ApiError> {
    let Some((namespace, key)) = target.split_once('.') else {
        return Err(malformed(
            term,
            "expected <namespace>.<key> before the operator",
        ));
    };
    let namespace = AttributeNamespace::parse(namespace)
        .ok_or_else(|| malformed(term, "namespace must be 'user' or 'app'"))?;
    let key = AttributeKey::new(key).map_err(|e| malformed(term, &e.to_string()))?;
    Ok((namespace, key))
}

/// A malformed term, named so the caller can see which.
fn malformed(term: &str, why: &str) -> ApiError {
    ApiError::validation(message!(
        "api-is-not-a-valid-attribute-filter",
        format!("'{term}' is not a valid attribute filter: {why}")
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;

    /// The condition a term reads as, failing the test when it is refused.
    fn parsed(term: &str) -> AttributeCondition {
        accepted(condition(term)).expect("the term should parse")
    }

    /// The parsed value, or nothing when it was refused.
    fn accepted<T>(parsed: Result<T, ApiError>) -> Option<T> {
        parsed.ok()
    }

    /// Ann filters for the sales department: the term reads as the app's
    /// `department` attribute, the `is` comparison and the value `sales`.
    #[test]
    fn a_term_splits_into_attribute_comparison_and_value() {
        let condition = parsed("app.department:is:sales");

        assert_eq!(condition.namespace, AttributeNamespace::App);
        assert_eq!(condition.key.as_str(), "department");
        assert_eq!(condition.operator, AttributeOperator::Is);
        assert_eq!(condition.values, vec!["sales".to_owned()]);
    }

    /// Asking only whether an attribute is set carries no value.
    #[test]
    fn a_presence_test_takes_no_value() {
        assert!(parsed("app.department:is_present").values.is_empty());
    }

    /// A comparison against a list reads each comma-separated value on its
    /// own.
    #[test]
    fn a_list_comparison_splits_on_commas() {
        assert_eq!(parsed("user.skills:has_all:rust, sql").values.len(), 2);
    }

    /// A department called "Sales, EMEA:west" stays one value, commas and
    /// colons included.
    #[test]
    fn a_single_valued_comparison_keeps_its_commas_and_colons() {
        assert_eq!(
            parsed("app.department:is:Sales, EMEA:west").values,
            vec!["Sales, EMEA:west".to_owned()]
        );
    }

    /// Incomplete filters, unsupported namespaces or comparisons, and invalid
    /// keys are rejected, including a key containing SQL syntax.
    #[test]
    fn a_malformed_term_is_refused() {
        for term in [
            "",
            "department",
            "department:is:sales",
            "nowhere.department:is:x",
            "app.Department:is:x",
            "app.department:equals:x",
            "app.:is:x",
            "app.value_text; DROP TABLE users--:is:x",
        ] {
            assert!(condition(term).is_err(), "{term:?} was accepted");
        }
    }

    /// A sort names a custom attribute only when it starts with `attr:`,
    /// with or without a minus; anything else is a column.
    #[tokio::test]
    async fn a_sort_token_names_an_attribute_only_with_the_prefix() {
        for (token, attribute) in [
            ("attr:app.department", true),
            ("-attr:app.department", true),
            ("created_at", false),
            ("-email", false),
        ] {
            let (mut parts, ()) = Request::builder()
                .uri(format!("/?sort={token}"))
                .body(())
                .unwrap()
                .into_parts();
            let order = UserOrder::from_request_parts(&mut parts, &())
                .await
                .ok()
                .expect("the sort query is valid");

            assert_eq!(matches!(order.0, ListOrder::Attribute(_)), attribute);
        }
    }

    /// A minus in front sorts by the attribute from highest to lowest.
    #[test]
    fn a_leading_minus_sorts_an_attribute_descending() {
        let sort =
            accepted(attribute_sort("-attr:app.department")).expect("the token should parse");

        assert_eq!(sort.direction, SortDirection::Descending);
        assert_eq!(sort.key.as_str(), "department");
    }

    /// A sort with the prefix but no proper `<namespace>.<key>` after it is
    /// refused.
    #[test]
    fn a_sort_naming_no_attribute_is_refused() {
        for token in ["attr:bad", "attr:", "attr:elsewhere.key"] {
            assert!(attribute_sort(token).is_err(), "{token:?} was accepted");
        }
    }
}
