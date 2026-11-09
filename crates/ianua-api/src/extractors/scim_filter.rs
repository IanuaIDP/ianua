//! SCIM filters (RFC 7644 section 3.4.2.2), read into the app's terms.
//!
//! The forms read are `attribute op "value"` with `eq`, `co` or `sw`,
//! joined by `and` and `or` (`and` binding tighter) and grouped with
//! parentheses. Any other operator, `not`, a value that is not a string,
//! or a value path such as `emails[type eq "work"]` is an `invalidFilter`.
//!
//! An attribute this service does not keep matches nobody: a provider
//! looking a user up by it is told there is none.

use std::iter::Peekable;
use std::str::Chars;

use ianua_app::ports::federation::{
    ScimFilterValue, ScimGroupAttribute, ScimOperator, ScimQuery, ScimUserAttribute,
};

use crate::dto::scim::ENTERPRISE_PATH;
use crate::error::scim::ScimApiError;

/// The longest filter read.
const MAX_FILTER_CHARS: usize = 2048;

/// How deep parentheses may nest.
const MAX_DEPTH: usize = 16;

/// A filter as written, its attributes lower-cased and not yet matched to
/// what a resource keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilterExpr {
    /// `attribute op "value"`.
    Compare {
        /// The attribute path, lower-cased.
        attribute: String,
        /// How it is compared.
        operator: ScimOperator,
        /// What it is compared with.
        value: ScimFilterValue,
    },
    /// Both hold.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Either holds.
    Or(Box<FilterExpr>, Box<FilterExpr>),
}

impl FilterExpr {
    /// Reads `filter`.
    ///
    /// # Errors
    ///
    /// `invalidFilter` for a form this service does not read, a filter
    /// longer than 2048 characters, or parentheses nested deeper than 16.
    pub(crate) fn parse(filter: &str) -> Result<Self, ScimApiError> {
        if filter.chars().count() > MAX_FILTER_CHARS {
            return Err(ScimApiError::invalid_filter("the filter is too long"));
        }
        let mut parser = Parser {
            tokens: tokens(filter)?,
            at: 0,
            depth: 0,
        };
        let expr = parser.any_of()?;
        if parser.at != parser.tokens.len() {
            return Err(unsupported(filter));
        }
        Ok(expr)
    }

    /// The query this filter makes over the attributes `attribute` knows,
    /// or `None` when it can match nothing: a comparison on an attribute
    /// not kept matches nobody, so `and` with one matches nobody and `or`
    /// with one is the other side alone.
    #[must_use]
    pub(crate) fn resolve<A>(&self, attribute: fn(&str) -> Option<A>) -> Option<ScimQuery<A>> {
        match self {
            Self::Compare {
                attribute: name,
                operator,
                value,
            } => attribute(name).map(|known| ScimQuery::Compare {
                attribute: known,
                operator: *operator,
                value: value.clone(),
            }),
            Self::And(left, right) => Some(ScimQuery::And(
                Box::new(left.resolve(attribute)?),
                Box::new(right.resolve(attribute)?),
            )),
            Self::Or(left, right) => either(left.resolve(attribute), right.resolve(attribute)),
        }
    }
}

/// `left or right`, where a side that matches nothing drops out.
fn either<A>(left: Option<ScimQuery<A>>, right: Option<ScimQuery<A>>) -> Option<ScimQuery<A>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(ScimQuery::Or(Box::new(left), Box::new(right))),
        (Some(one), None) | (None, Some(one)) => Some(one),
        (None, None) => None,
    }
}

/// The user attribute a lower-cased path names, if this service keeps it.
#[must_use]
pub(crate) fn user_attribute(path: &str) -> Option<ScimUserAttribute> {
    let enterprise = path
        .strip_prefix(ENTERPRISE_PATH)
        .and_then(|rest| rest.strip_prefix(':'));
    match enterprise.unwrap_or(path) {
        "username" | "emails" | "emails.value" => Some(ScimUserAttribute::UserName),
        "displayname" => Some(ScimUserAttribute::DisplayName),
        "externalid" => Some(ScimUserAttribute::ExternalId),
        "name.givenname" => Some(ScimUserAttribute::GivenName),
        "name.familyname" => Some(ScimUserAttribute::FamilyName),
        "department" => Some(ScimUserAttribute::Department),
        "employeenumber" => Some(ScimUserAttribute::EmployeeNumber),
        _ => None,
    }
}

/// The group attribute a lower-cased path names, if this service keeps it.
#[must_use]
pub(crate) fn group_attribute(path: &str) -> Option<ScimGroupAttribute> {
    match path {
        "displayname" => Some(ScimGroupAttribute::DisplayName),
        _ => None,
    }
}

/// One piece of a filter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// Begins a grouped expression that overrides operator precedence.
    Open,
    /// Ends the current grouped expression.
    Close,
    /// An attribute path, an operator or `and`/`or`.
    Word(String),
    /// A quoted string, unescaped.
    Text(String),
}

/// The pieces of `filter`.
fn tokens(filter: &str) -> Result<Vec<Token>, ScimApiError> {
    let mut chars = filter.chars().peekable();
    let mut found = Vec::new();
    while let Some(&next) = chars.peek() {
        match next {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' | ')' => {
                chars.next();
                found.push(if next == '(' {
                    Token::Open
                } else {
                    Token::Close
                });
            }
            '"' => {
                chars.next();
                found.push(Token::Text(quoted(&mut chars)?));
            }
            _ => found.push(Token::Word(word(&mut chars))),
        }
    }
    Ok(found)
}

/// The rest of a quoted string, its closing quote taken, `\` escaping the
/// character after it.
fn quoted(chars: &mut Peekable<Chars<'_>>) -> Result<String, ScimApiError> {
    let mut text = String::new();
    while let Some(next) = chars.next() {
        match next {
            '"' => return Ok(text),
            '\\' => text.push(chars.next().ok_or_else(unterminated)?),
            other => text.push(other),
        }
    }
    Err(unterminated())
}

/// The word starting here, up to a space, a parenthesis or a quote.
fn word(chars: &mut Peekable<Chars<'_>>) -> String {
    let mut text = String::new();
    while let Some(&next) = chars.peek() {
        if next.is_whitespace() || matches!(next, '(' | ')' | '"') {
            break;
        }
        text.push(next);
        chars.next();
    }
    text
}

/// Reads tokens into a [`FilterExpr`], `or` over `and` over comparisons.
struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}

impl Parser {
    /// Filters joined by `or`.
    fn any_of(&mut self) -> Result<FilterExpr, ScimApiError> {
        let mut left = self.all_of()?;
        while self.keyword("or") {
            let right = self.all_of()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// Filters joined by `and`.
    fn all_of(&mut self) -> Result<FilterExpr, ScimApiError> {
        let mut left = self.term()?;
        while self.keyword("and") {
            let right = self.term()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// A filter in parentheses, or one comparison.
    fn term(&mut self) -> Result<FilterExpr, ScimApiError> {
        if self.tokens.get(self.at) != Some(&Token::Open) {
            return self.comparison();
        }
        self.at += 1;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ScimApiError::invalid_filter("the filter nests too deep"));
        }
        let inner = self.any_of()?;
        if self.next() != Some(Token::Close) {
            return Err(ScimApiError::invalid_filter("a parenthesis is not closed"));
        }
        self.depth -= 1;
        Ok(inner)
    }

    /// `attribute op "value"`.
    fn comparison(&mut self) -> Result<FilterExpr, ScimApiError> {
        let (Some(Token::Word(attribute)), Some(Token::Word(op)), Some(Token::Text(value))) =
            (self.next(), self.next(), self.next())
        else {
            return Err(ScimApiError::invalid_filter(
                "a comparison is written attribute op \"value\"",
            ));
        };
        if attribute.contains('[') {
            return Err(ScimApiError::invalid_filter("value paths are not read"));
        }
        Ok(FilterExpr::Compare {
            attribute: attribute.to_ascii_lowercase(),
            operator: operator(&op)?,
            value: ScimFilterValue::new(value).map_err(ScimApiError::invalid_filter)?,
        })
    }

    /// Takes the next token when it is the word `name`, in any case.
    fn keyword(&mut self, name: &str) -> bool {
        let found = matches!(
            self.tokens.get(self.at),
            Some(Token::Word(word)) if word.eq_ignore_ascii_case(name)
        );
        if found {
            self.at += 1;
        }
        found
    }

    /// Takes the next token.
    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }
}

/// The operator `op` names, in any case.
fn operator(op: &str) -> Result<ScimOperator, ScimApiError> {
    match op.to_ascii_lowercase().as_str() {
        "eq" => Ok(ScimOperator::Equals),
        "co" => Ok(ScimOperator::Contains),
        "sw" => Ok(ScimOperator::StartsWith),
        other => Err(ScimApiError::invalid_filter(format!(
            "the operator {other} is not supported; use eq, co or sw"
        ))),
    }
}

/// A quoted string with no closing quote.
fn unterminated() -> ScimApiError {
    ScimApiError::invalid_filter("a quoted value is not closed")
}

/// A filter in a form this service does not read.
fn unsupported(filter: &str) -> ScimApiError {
    ScimApiError::invalid_filter(format!("unsupported filter: {filter}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The comparison `attribute op "value"`, as the parser writes it.
    fn compare(attribute: &str, operator: ScimOperator, value: &str) -> FilterExpr {
        FilterExpr::Compare {
            attribute: attribute.to_owned(),
            operator,
            value: ScimFilterValue::new(value).unwrap(),
        }
    }

    /// Okta looks Ada up by her address, writing `Eq` in mixed case; the
    /// comparison is read with the attribute lower-cased.
    #[test]
    fn an_eq_comparison_is_read_in_any_case() {
        let expr = FilterExpr::parse(r#"userName Eq "ada@acme.com""#)
            .ok()
            .unwrap();

        assert_eq!(
            expr,
            compare("username", ScimOperator::Equals, "ada@acme.com")
        );
    }

    /// `and` binds tighter than `or`, so `a or b and c` is `a or (b and c)`.
    #[test]
    fn and_binds_tighter_than_or() {
        let expr = FilterExpr::parse(r#"a eq "1" or b co "2" and c sw "3""#)
            .ok()
            .unwrap();

        assert_eq!(
            expr,
            FilterExpr::Or(
                Box::new(compare("a", ScimOperator::Equals, "1")),
                Box::new(FilterExpr::And(
                    Box::new(compare("b", ScimOperator::Contains, "2")),
                    Box::new(compare("c", ScimOperator::StartsWith, "3")),
                )),
            )
        );
    }

    /// Parentheses group a filter, and a quote inside a value is escaped.
    #[test]
    fn parentheses_group_and_quotes_escape() {
        let expr = FilterExpr::parse(r#"(a eq "say \"hi\"" or b eq "x") and c eq "y""#)
            .ok()
            .unwrap();

        assert!(matches!(expr, FilterExpr::And(left, _) if matches!(*left, FilterExpr::Or(..))));
    }

    /// Operators, forms and values this service does not read are refused.
    #[test]
    fn unsupported_forms_are_invalid_filters() {
        for filter in [
            r#"userName ne "ada""#,
            "userName pr",
            "userName eq ada",
            r#"not (userName eq "ada")"#,
            r#"emails[type eq "work"] eq "x""#,
            r#"(userName eq "ada""#,
            r#"userName eq "ada" junk"#,
            r#"userName eq """#,
            r#"userName eq "open"#,
        ] {
            assert!(FilterExpr::parse(filter).is_err(), "{filter}");
        }
    }

    /// Seventeen levels of parentheses exceed the filter's nesting limit.
    #[test]
    fn deep_nesting_is_refused() {
        let filter = format!("{}a eq \"1\"{}", "(".repeat(17), ")".repeat(17));

        assert!(FilterExpr::parse(&filter).is_err());
    }

    /// A comparison on an attribute not kept drops out of an `or`, and
    /// leaves an `and` matching nobody.
    #[test]
    fn unkept_attributes_drop_out_of_or_and_empty_an_and() {
        let either = FilterExpr::parse(r#"title eq "x" or userName eq "a@b.c""#)
            .ok()
            .unwrap();
        let both = FilterExpr::parse(r#"title eq "x" and userName eq "a@b.c""#)
            .ok()
            .unwrap();

        assert!(matches!(
            either.resolve(user_attribute),
            Some(ScimQuery::Compare {
                attribute: ScimUserAttribute::UserName,
                ..
            })
        ));
        assert!(both.resolve(user_attribute).is_none());
    }

    /// The enterprise fields are read by their short and their full names.
    #[test]
    fn enterprise_fields_are_read_by_either_name() {
        let full = format!("{ENTERPRISE_PATH}:department");

        assert_eq!(user_attribute(&full), Some(ScimUserAttribute::Department));
        assert_eq!(
            user_attribute("department"),
            Some(ScimUserAttribute::Department)
        );
        assert_eq!(user_attribute("title"), None);
    }
}
