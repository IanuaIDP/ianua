//! How a SCIM filter narrows the users and groups tables.
//!
//! Every comparison is a fixed piece of SQL chosen by matching the
//! attribute and the operator, with the value bound. An attribute whose
//! case is ignored compares lower case with lower case, an address with an
//! address already kept in lower case, and a `co` or `sw` with `ILIKE`;
//! one whose case counts compares as it is, with `LIKE`. Either way the
//! wildcards a directory sends are matched as the characters they are.

use ianua_app::listing::SortDirection;
use ianua_app::ports::federation::{
    ScimFilterValue, ScimGroupAttribute, ScimOperator, ScimQuery, ScimUserAttribute, ScimUserSort,
};

use crate::postgres::foundation::paging::picks::Picks;

/// The three comparisons of one attribute.
struct Comparisons {
    equals: &'static str,
    contains: &'static str,
    starts_with: &'static str,
}

impl Comparisons {
    /// The comparison `operator` makes.
    fn by(&self, operator: ScimOperator) -> &'static str {
        match operator {
            ScimOperator::Equals => self.equals,
            ScimOperator::Contains => self.contains,
            ScimOperator::StartsWith => self.starts_with,
        }
    }
}

const USER_NAME: Comparisons = Comparisons {
    equals: "users.email = lower(?)",
    contains: "users.email ILIKE ?",
    starts_with: "users.email ILIKE ?",
};

const DISPLAY_NAME: Comparisons = Comparisons {
    equals: "lower(users.display_name) = lower(?)",
    contains: "users.display_name ILIKE ?",
    starts_with: "users.display_name ILIKE ?",
};

const EXTERNAL_ID: Comparisons = Comparisons {
    equals: "users.external_id = ?",
    contains: "users.external_id LIKE ?",
    starts_with: "users.external_id LIKE ?",
};

const GIVEN_NAME: Comparisons = Comparisons {
    equals: "lower(users.given_name) = lower(?)",
    contains: "users.given_name ILIKE ?",
    starts_with: "users.given_name ILIKE ?",
};

const FAMILY_NAME: Comparisons = Comparisons {
    equals: "lower(users.family_name) = lower(?)",
    contains: "users.family_name ILIKE ?",
    starts_with: "users.family_name ILIKE ?",
};

const DEPARTMENT: Comparisons = Comparisons {
    equals: "lower(users.department) = lower(?)",
    contains: "users.department ILIKE ?",
    starts_with: "users.department ILIKE ?",
};

const EMPLOYEE_NUMBER: Comparisons = Comparisons {
    equals: "users.employee_number = ?",
    contains: "users.employee_number LIKE ?",
    starts_with: "users.employee_number LIKE ?",
};

const GROUP_NAME: Comparisons = Comparisons {
    equals: "lower(groups.name) = lower(?)",
    contains: "groups.name ILIKE ?",
    starts_with: "groups.name ILIKE ?",
};

/// The comparisons of a user attribute.
fn user_comparisons(attribute: ScimUserAttribute) -> &'static Comparisons {
    match attribute {
        ScimUserAttribute::UserName => &USER_NAME,
        ScimUserAttribute::DisplayName => &DISPLAY_NAME,
        ScimUserAttribute::ExternalId => &EXTERNAL_ID,
        ScimUserAttribute::GivenName => &GIVEN_NAME,
        ScimUserAttribute::FamilyName => &FAMILY_NAME,
        ScimUserAttribute::Department => &DEPARTMENT,
        ScimUserAttribute::EmployeeNumber => &EMPLOYEE_NUMBER,
    }
}

/// The comparisons of a group attribute.
fn group_comparisons(attribute: ScimGroupAttribute) -> &'static Comparisons {
    match attribute {
        ScimGroupAttribute::DisplayName => &GROUP_NAME,
    }
}

/// The users `query` picks, as a filter on the users table.
pub(super) fn user_picks(query: &ScimQuery<ScimUserAttribute>) -> Picks {
    picks_of(query, user_comparisons)
}

/// The groups `query` picks, as a filter on the groups table.
pub(super) fn group_picks(query: &ScimQuery<ScimGroupAttribute>) -> Picks {
    picks_of(query, group_comparisons)
}

/// `query` as a filter, each comparison taken from `comparisons`.
fn picks_of<A: Copy>(query: &ScimQuery<A>, comparisons: fn(A) -> &'static Comparisons) -> Picks {
    match query {
        ScimQuery::All => Picks::All,
        ScimQuery::Compare {
            attribute,
            operator,
            value,
        } => Picks::Holds(
            comparisons(*attribute).by(*operator),
            bound(*operator, value),
        ),
        ScimQuery::And(left, right) => Picks::And(
            Box::new(picks_of(left, comparisons)),
            Box::new(picks_of(right, comparisons)),
        ),
        ScimQuery::Or(left, right) => Picks::Or(
            Box::new(picks_of(left, comparisons)),
            Box::new(picks_of(right, comparisons)),
        ),
    }
}

/// The text bound for `value` under `operator`: the value itself, or a
/// pattern holding it anywhere or at the start.
fn bound(operator: ScimOperator, value: &ScimFilterValue) -> String {
    match operator {
        ScimOperator::Equals => value.as_str().to_owned(),
        ScimOperator::Contains => format!("%{}%", escaped(value.as_str())),
        ScimOperator::StartsWith => format!("{}%", escaped(value.as_str())),
    }
}

/// `text` with the wildcards of a `LIKE` pattern read as plain characters.
fn escaped(text: &str) -> String {
    text.chars()
        .flat_map(|character| {
            let escape = matches!(character, '%' | '_' | '\\').then_some('\\');
            escape.into_iter().chain(std::iter::once(character))
        })
        .collect()
}

/// The columns a user listing is ordered by, the id last: oldest first by
/// default, or by an attribute, those with no value for it last.
pub(super) fn user_order(sort: ScimUserSort) -> [(&'static str, SortDirection); 2] {
    let ScimUserSort::By(attribute, direction) = sort else {
        return [
            ("users.created_at", SortDirection::Asc),
            ("users.id", SortDirection::Asc),
        ];
    };
    [
        (user_column(attribute), direction),
        ("users.id", SortDirection::Asc),
    ]
}

/// The column a user attribute is kept in.
fn user_column(attribute: ScimUserAttribute) -> &'static str {
    match attribute {
        ScimUserAttribute::UserName => "users.email",
        ScimUserAttribute::DisplayName => "users.display_name",
        ScimUserAttribute::ExternalId => "users.external_id",
        ScimUserAttribute::GivenName => "users.given_name",
        ScimUserAttribute::FamilyName => "users.family_name",
        ScimUserAttribute::Department => "users.department",
        ScimUserAttribute::EmployeeNumber => "users.employee_number",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> ScimFilterValue {
        ScimFilterValue::new(text).unwrap()
    }

    /// A contains filter escapes wildcard characters and backslashes;
    /// starts-with adds its trailing wildcard and equality keeps the input.
    #[test]
    fn a_pattern_reads_wildcards_as_plain_characters() {
        assert_eq!(
            bound(ScimOperator::Contains, &value("a_n%\\")),
            "%a\\_n\\%\\\\%"
        );
        assert_eq!(bound(ScimOperator::StartsWith, &value("ann")), "ann%");
        assert_eq!(bound(ScimOperator::Equals, &value("Ann%")), "Ann%");
    }

    /// `userName eq "x" or externalId sw "4"` keeps its shape, each
    /// comparison the one its attribute's case asks for.
    #[test]
    fn a_filter_keeps_its_shape_and_each_attributes_case() {
        let query = ScimQuery::Or(
            Box::new(ScimQuery::Compare {
                attribute: ScimUserAttribute::UserName,
                operator: ScimOperator::Equals,
                value: value("Ann@Acme.example"),
            }),
            Box::new(ScimQuery::Compare {
                attribute: ScimUserAttribute::ExternalId,
                operator: ScimOperator::StartsWith,
                value: value("4"),
            }),
        );

        let picks = user_picks(&query);

        assert_eq!(
            picks,
            Picks::Or(
                Box::new(Picks::Holds(
                    "users.email = lower(?)",
                    "Ann@Acme.example".to_owned()
                )),
                Box::new(Picks::Holds("users.external_id LIKE ?", "4%".to_owned())),
            )
        );
    }
}
