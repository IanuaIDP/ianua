//! How a user listing's filter narrows the users table.
//!
//! Every condition is a fixed piece of SQL chosen by matching a closed
//! enum, with exactly one value bound. A condition that needs several
//! values, such as an attribute's namespace, key and operands, binds them
//! as one text array and reads its items. A role or group filter reads the
//! authorization tables inside the tenant the transaction was given for
//! row-level security, `app.current_tenant_id`, so it uses the indexes that
//! lead with the tenant.

use ianua_app::ports::identity::{InvitationState, TimeSpan, UserFilter};
use ianua_domain::domains::identity::attribute::{
    AttributeOperator, ResolvedAttributeFilter, ValueType,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use uuid::Uuid;

use crate::postgres::foundation::paging::PageQuery;
use crate::postgres::foundation::stored::StoredWord as _;

/// Users given the role straight, or through a group they are in, or
/// through a group above one they are in, since a group holds its parent's
/// roles too. An assignment or membership that has run out counts for
/// nothing.
const HOLDING_ROLE: &str = "users.id IN (\
    WITH RECURSIVE wanted AS (SELECT ?::uuid AS role_id), \
    carrying AS (\
        SELECT given.group_id AS id FROM group_roles given, wanted \
        WHERE given.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND given.role_id = wanted.role_id \
        UNION \
        SELECT child.id FROM groups child JOIN carrying ON child.parent_id = carrying.id \
        WHERE child.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) \
    SELECT held.principal_id FROM role_assignments held, wanted \
    WHERE held.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND held.principal_kind = 'user' \
    AND held.role_id = wanted.role_id \
    AND (held.expires_at IS NULL OR held.expires_at > now()) \
    UNION \
    SELECT member.principal_id FROM group_memberships member \
    JOIN carrying ON member.group_id = carrying.id \
    WHERE member.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND member.principal_kind = 'user' \
    AND (member.expires_at IS NULL OR member.expires_at > now()))";

/// Members of the group, or of a group below it. A membership that has run
/// out counts for nothing.
const IN_GROUP: &str = "users.id IN (\
    WITH RECURSIVE below AS (\
        SELECT top.id FROM groups top WHERE top.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND top.id = ? \
        UNION \
        SELECT child.id FROM groups child JOIN below ON child.parent_id = below.id \
        WHERE child.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) \
    SELECT member.principal_id FROM group_memberships member \
    JOIN below ON member.group_id = below.id \
    WHERE member.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND member.principal_kind = 'user' \
    AND (member.expires_at IS NULL OR member.expires_at > now()))";

/// A condition on whether a user holds a value for one attribute that
/// meets `$predicate`. The bound array holds the namespace, the key, then
/// the operands, from its third item on.
macro_rules! holding {
    ($predicate:literal) => {
        concat!(
            "users.id IN (SELECT m.user_id FROM user_metadata m, (SELECT ?::text[] AS a) p \
             WHERE m.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND m.namespace = p.a[1] AND m.key = p.a[2]",
            $predicate,
            ")"
        )
    };
}

/// `listed` narrowed to the users of `tenant` that `filter` keeps.
///
/// # Errors
///
/// Returns `DomainError::Validation` when an attribute filter compares its
/// type in a way no column answers, which a filter the schema resolved
/// never does.
pub(super) fn narrowed<R>(
    listed: PageQuery<'static, R>,
    tenant: &TenantId,
    filter: &UserFilter,
) -> Result<PageQuery<'static, R>, DomainError> {
    let mut query = listed.filter("users.tenant_id = ?", *tenant.as_uuid());
    if let Some(status) = filter.status {
        query = query.filter("users.status = ?", status.word());
    }
    if let Some(part) = &filter.email_contains {
        query = query.filter("users.email ILIKE ?", like_pattern(part));
    }
    if let Some(part) = &filter.name_contains {
        query = query.filter("users.name_search ILIKE ?", like_pattern(part));
    }
    if let Some(role) = filter.role {
        query = query.filter(HOLDING_ROLE, *role.as_uuid());
    }
    if let Some(group) = filter.group {
        query = query.filter(IN_GROUP, *group.as_uuid());
    }
    if let Some(ids) = &filter.ids {
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        query = query.filter("users.id = ANY(?)", ids);
    }
    query = in_span(query, &LAST_LOGIN, filter.last_login);
    query = in_span(query, &CREATED, filter.created);
    if let Some(invitation) = filter.invitation {
        let condition = match invitation.state {
            InvitationState::Pending => PENDING_INVITATION,
            InvitationState::Expired => EXPIRED_INVITATION,
        };
        query = query.filter(condition, invitation.at);
    }
    filter.attributes.iter().try_fold(query, holding_value)
}

/// Users with a stored-pending invitation whose link still works.
const PENDING_INVITATION: &str = "EXISTS (SELECT 1 FROM invitations invite \
    WHERE invite.tenant_id = users.tenant_id AND invite.user_id = users.id \
    AND invite.status = 'pending' AND invite.expires_at > ?)";

/// Users with a stored-pending invitation whose link has expired.
const EXPIRED_INVITATION: &str = "EXISTS (SELECT 1 FROM invitations invite \
    WHERE invite.tenant_id = users.tenant_id AND invite.user_id = users.id \
    AND invite.status = 'pending' AND invite.expires_at <= ?)";

/// The two ends of a span of time on one column.
struct SpanBounds {
    from: &'static str,
    until: &'static str,
}

/// A span on the last sign-in. A user who never signed in falls in no
/// span with an end, as `NULL` meets no comparison.
const LAST_LOGIN: SpanBounds = SpanBounds {
    from: "users.last_login_at >= ?",
    until: "users.last_login_at < ?",
};

/// A span on when the user was created.
const CREATED: SpanBounds = SpanBounds {
    from: "users.created_at >= ?",
    until: "users.created_at < ?",
};

/// `query` narrowed to the moments of `span`, by `bounds`.
fn in_span<R>(
    query: PageQuery<'static, R>,
    bounds: &SpanBounds,
    span: TimeSpan,
) -> PageQuery<'static, R> {
    let query = match span.from {
        None => query,
        Some(at) => query.filter(bounds.from, at),
    };
    match span.until {
        None => query,
        Some(at) => query.filter(bounds.until, at),
    }
}

/// `query` narrowed to the users whose value meets `filter`.
fn holding_value<R>(
    query: PageQuery<'static, R>,
    filter: &ResolvedAttributeFilter,
) -> Result<PageQuery<'static, R>, DomainError> {
    let condition = condition_of(filter.value_type(), filter.operator())?;
    let mut bound = vec![
        filter.namespace().as_str().to_owned(),
        filter.key().as_str().to_owned(),
    ];
    bound.extend(operand_texts(filter));
    Ok(query.filter(condition, bound))
}

/// The operands of `filter` as the text the condition casts them from.
fn operand_texts(filter: &ResolvedAttributeFilter) -> Vec<String> {
    if filter.operator() == AttributeOperator::Contains {
        return filter
            .operands()
            .iter()
            .filter_map(MetadataValue::as_str)
            .map(like_pattern)
            .collect();
    }
    filter.operands().iter().flat_map(texts_of).collect()
}

/// The texts one operand is bound as.
fn texts_of(value: &MetadataValue) -> Vec<String> {
    match value {
        MetadataValue::String(text) => vec![text.clone()],
        MetadataValue::Integer(number) => vec![number.to_string()],
        MetadataValue::Number(number) => vec![number.to_string()],
        MetadataValue::Bool(flag) => vec![flag.to_string()],
        MetadataValue::StringArray(items) => items.clone(),
        MetadataValue::Null => Vec::new(),
    }
}

/// The condition comparing an attribute of `value_type` with `operator`.
fn condition_of(
    value_type: ValueType,
    operator: AttributeOperator,
) -> Result<&'static str, DomainError> {
    let condition = match (value_type, operator) {
        (_, AttributeOperator::IsPresent) => Some(holding!("")),
        (_, AttributeOperator::IsAbsent) => Some(ABSENT),
        (ValueType::Text, _) => text_condition(operator),
        (ValueType::Integer, _) => integer_condition(operator),
        (ValueType::Number, _) => number_condition(operator),
        (ValueType::Boolean, AttributeOperator::Is) => {
            Some(holding!(" AND m.value_bool = p.a[3]::boolean"))
        }
        (ValueType::Boolean, AttributeOperator::IsNot) => {
            Some(holding!(" AND m.value_bool <> p.a[3]::boolean"))
        }
        (ValueType::TextArray, AttributeOperator::HasAny) => {
            Some(holding!(" AND m.value_array && p.a[3:]"))
        }
        (ValueType::TextArray, AttributeOperator::HasAll) => {
            Some(holding!(" AND m.value_array @> p.a[3:]"))
        }
        (ValueType::Boolean | ValueType::TextArray, _) => None,
    };
    condition.ok_or_else(|| {
        DomainError::invalid(message!(
            "infra-an-attribute-holding-cannot-be-filtered",
            format!(
                "an attribute holding {} cannot be filtered with {}",
                value_type.describe(),
                operator.as_str()
            )
        ))
    })
}

/// The users holding no value for the attribute.
const ABSENT: &str = "users.id NOT IN (SELECT m.user_id FROM user_metadata m, \
    (SELECT ?::text[] AS a) p \
    WHERE m.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid AND m.namespace = p.a[1] AND m.key = p.a[2])";

fn text_condition(operator: AttributeOperator) -> Option<&'static str> {
    Some(match operator {
        AttributeOperator::Is => holding!(" AND m.value_text = p.a[3]"),
        AttributeOperator::IsNot => holding!(" AND m.value_text <> p.a[3]"),
        AttributeOperator::Contains => holding!(" AND m.value_text ILIKE p.a[3]"),
        AttributeOperator::IsOneOf => holding!(" AND m.value_text = ANY(p.a[3:])"),
        AttributeOperator::GreaterThan => holding!(" AND m.value_text > p.a[3]"),
        AttributeOperator::GreaterThanOrEqual => holding!(" AND m.value_text >= p.a[3]"),
        AttributeOperator::LessThan => holding!(" AND m.value_text < p.a[3]"),
        AttributeOperator::LessThanOrEqual => holding!(" AND m.value_text <= p.a[3]"),
        AttributeOperator::HasAny
        | AttributeOperator::HasAll
        | AttributeOperator::IsPresent
        | AttributeOperator::IsAbsent => return None,
    })
}

fn integer_condition(operator: AttributeOperator) -> Option<&'static str> {
    Some(match operator {
        AttributeOperator::Is => holding!(" AND m.value_int = p.a[3]::bigint"),
        AttributeOperator::IsNot => holding!(" AND m.value_int <> p.a[3]::bigint"),
        AttributeOperator::IsOneOf => holding!(" AND m.value_int = ANY(p.a[3:]::bigint[])"),
        AttributeOperator::GreaterThan => holding!(" AND m.value_int > p.a[3]::bigint"),
        AttributeOperator::GreaterThanOrEqual => holding!(" AND m.value_int >= p.a[3]::bigint"),
        AttributeOperator::LessThan => holding!(" AND m.value_int < p.a[3]::bigint"),
        AttributeOperator::LessThanOrEqual => holding!(" AND m.value_int <= p.a[3]::bigint"),
        AttributeOperator::Contains
        | AttributeOperator::HasAny
        | AttributeOperator::HasAll
        | AttributeOperator::IsPresent
        | AttributeOperator::IsAbsent => return None,
    })
}

/// A number attribute may hold a whole number, kept in the integer column,
/// so it is read from whichever column holds it.
fn number_condition(operator: AttributeOperator) -> Option<&'static str> {
    Some(match operator {
        AttributeOperator::Is => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) = p.a[3]::float8")
        }
        AttributeOperator::IsNot => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) <> p.a[3]::float8")
        }
        AttributeOperator::IsOneOf => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) = ANY(p.a[3:]::float8[])")
        }
        AttributeOperator::GreaterThan => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) > p.a[3]::float8")
        }
        AttributeOperator::GreaterThanOrEqual => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) >= p.a[3]::float8")
        }
        AttributeOperator::LessThan => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) < p.a[3]::float8")
        }
        AttributeOperator::LessThanOrEqual => {
            holding!(" AND coalesce(m.value_float, m.value_int::float8) <= p.a[3]::float8")
        }
        AttributeOperator::Contains
        | AttributeOperator::HasAny
        | AttributeOperator::HasAll
        | AttributeOperator::IsPresent
        | AttributeOperator::IsAbsent => return None,
    })
}

/// The `ILIKE` pattern finding `part` anywhere, with the wildcards the
/// caller typed read as plain characters. Without it a search for `%`
/// matches everybody.
fn like_pattern(part: &str) -> String {
    let escaped: String = part
        .chars()
        .flat_map(|character| {
            let escape = matches!(character, '%' | '_' | '\\').then_some('\\');
            escape.into_iter().chain(std::iter::once(character))
        })
        .collect();
    format!("%{escaped}%")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Search patterns escape percent, underscore and backslash so these
    /// characters are matched literally inside a substring search.
    #[test]
    fn a_search_reads_wildcards_as_plain_characters() {
        assert_eq!(like_pattern("50%_off\\"), "%50\\%\\_off\\\\%");
    }

    /// A greater-than comparison on a boolean attribute returns validation
    /// failure instead of generating a SQL condition.
    #[test]
    fn a_comparison_no_column_answers_is_refused() {
        let refused = condition_of(ValueType::Boolean, AttributeOperator::GreaterThan);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }
}
