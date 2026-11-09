//! Which of a person's attributes a SAML app is sent, under the names the
//! app reads them by.
//!
//! An app gets only what its statements name. Okta and Entra call these
//! attribute statements: `email` under `http://schemas.xmlsoap.org/...`,
//! the display name under `displayName`, and so on.

use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::Label;

/// The most statements one app may hold.
const MAX_STATEMENTS: usize = 64;

/// The longest SAML attribute name accepted.
const MAX_ATTRIBUTE_NAME_BYTES: usize = 256;

/// One of a person's attributes this platform can send an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAttribute {
    /// Their address.
    Email,
    /// The name shown for them.
    DisplayName,
    /// The language they chose, when they chose one.
    Locale,
    /// The timezone they chose, when they chose one.
    Timezone,
    /// Their account's id in this tenant.
    AccountId,
    /// The names of the roles they hold.
    Roles,
    /// The names of the groups they belong to.
    Groups,
}

impl AccountAttribute {
    /// The stable name it is stored and sent under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::DisplayName => "display_name",
            Self::Locale => "locale",
            Self::Timezone => "timezone",
            Self::AccountId => "account_id",
            Self::Roles => "roles",
            Self::Groups => "groups",
        }
    }
}

/// How an attribute's name is to be read, SAML's `NameFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeNameFormat {
    /// The app reads the name as it likes.
    Unspecified,
    /// A plain name, such as `email`.
    Basic,
    /// A URI, such as `urn:oid:0.9.2342.19200300.100.1.3`.
    Uri,
}

impl AttributeNameFormat {
    /// The URN SAML names the format by.
    #[must_use]
    pub fn urn(self) -> &'static str {
        match self {
            Self::Unspecified => "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
            Self::Basic => "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
            Self::Uri => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        }
    }
}

text_value! {
    /// The name a SAML app reads an attribute by, such as `email` or
    /// `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`.
    pub struct SamlAttributeName;
}

impl TextValue for SamlAttributeName {
    const FIELD: &'static str = "attribute_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(MAX_ATTRIBUTE_NAME_BYTES)
            .no_control_chars()
            .no_invisible_chars()
    }
}

/// One attribute an app is sent, and the name it is sent under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeStatement {
    /// Which of the person's attributes is sent.
    pub source: AccountAttribute,
    /// The name the app reads it by.
    pub name: SamlAttributeName,
    /// How that name is to be read.
    pub name_format: AttributeNameFormat,
}

/// Every attribute an app is sent, each under a name of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeStatements {
    statements: Vec<AttributeStatement>,
}

impl AttributeStatements {
    /// The statements in `statements`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when two statements send under one
    ///   name, which would leave the app to pick one, or when there are
    ///   more than 64.
    pub fn new(statements: Vec<AttributeStatement>) -> Result<Self, DomainError> {
        validate_count("attribute_statements", statements.len(), 0..=MAX_STATEMENTS)?;
        if let Some(twice) = first_repeat(statements.iter().map(|statement| &statement.name)) {
            return Err(DomainError::invalid(message!(
                "federation-two-attributes-are-sent-under-give",
                format!(
                    "two attributes are sent under {}; give each its own name",
                    twice.as_str()
                )
            )));
        }
        Ok(Self { statements })
    }

    /// What a new app is sent: the address as `email` and the display name
    /// as `displayName`, the names most apps read.
    ///
    /// # Errors
    ///
    /// - Never fails in practice: both names pass their rules.
    pub fn standard() -> Result<Self, DomainError> {
        Self::new(vec![
            AttributeStatement {
                source: AccountAttribute::Email,
                name: SamlAttributeName::new("email")?,
                name_format: AttributeNameFormat::Basic,
            },
            AttributeStatement {
                source: AccountAttribute::DisplayName,
                name: SamlAttributeName::new("displayName")?,
                name_format: AttributeNameFormat::Basic,
            },
        ])
    }

    /// The statements, in order.
    #[must_use]
    pub fn statements(&self) -> &[AttributeStatement] {
        &self.statements
    }

    /// Whether these send an attribute `before` did not.
    pub(crate) fn releases_beyond(&self, before: &Self) -> bool {
        self.statements.iter().any(|statement| {
            !before
                .statements
                .iter()
                .any(|was| was.source == statement.source)
        })
    }

    /// What `user` is sent under these statements. `held` names their
    /// roles and groups. An attribute with no value, such as a locale the
    /// person never chose, is left out.
    #[must_use]
    pub fn released<T: TenantScope>(
        &self,
        user: &User<T>,
        held: &HeldNames<'_>,
    ) -> Vec<ReleasedAttribute> {
        self.statements
            .iter()
            .map(|statement| ReleasedAttribute {
                name: statement.name.clone(),
                name_format: statement.name_format,
                values: values_of(statement.source, user, held),
            })
            .filter(|released| !released.values.is_empty())
            .collect()
    }
}

/// The names of the roles and groups a person holds, for the statements
/// that send them.
#[derive(Debug, Clone, Copy)]
pub struct HeldNames<'a> {
    /// The roles they hold, by name.
    pub roles: &'a [Label],
    /// The groups they belong to, by name.
    pub groups: &'a [Label],
}

/// The values `user` has for `source`.
fn values_of<T: TenantScope>(
    source: AccountAttribute,
    user: &User<T>,
    held: &HeldNames<'_>,
) -> Vec<String> {
    match source {
        AccountAttribute::Email => vec![user.email().as_str().to_owned()],
        AccountAttribute::DisplayName => vec![user.display_name().as_str().to_owned()],
        AccountAttribute::Locale => user
            .locale()
            .value()
            .map(|locale| locale.as_str().to_owned())
            .into_iter()
            .collect(),
        AccountAttribute::Timezone => user
            .timezone()
            .value()
            .map(|timezone| timezone.as_str().to_owned())
            .into_iter()
            .collect(),
        AccountAttribute::AccountId => vec![user.id().to_string()],
        AccountAttribute::Roles => names(held.roles),
        AccountAttribute::Groups => names(held.groups),
    }
}

fn names(labels: &[Label]) -> Vec<String> {
    labels
        .iter()
        .map(|label| label.as_str().to_owned())
        .collect()
}

/// One attribute as it goes into an assertion: its name and its values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedAttribute {
    name: SamlAttributeName,
    name_format: AttributeNameFormat,
    values: Vec<String>,
}

impl ReleasedAttribute {
    /// The name the app reads it by.
    #[must_use]
    pub fn name(&self) -> &SamlAttributeName {
        &self.name
    }

    /// How that name is to be read.
    #[must_use]
    pub fn name_format(&self) -> AttributeNameFormat {
        self.name_format
    }

    /// Its values, each written as one `AttributeValue`.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// An attribute `name` holding `values`, for tests that write
    /// assertions.
    #[cfg(test)]
    pub(crate) fn of(name: &str, values: &[&str]) -> Self {
        Self {
            name: SamlAttributeName::new(name).expect("a test passes a valid name"),
            name_format: AttributeNameFormat::Basic,
            values: values.iter().map(|value| (*value).to_owned()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::{label, user};
    use crate::types::UserId;

    fn ann() -> User<ResolvedTenant> {
        user(UserId::new(), "ann@acme.com")
    }

    fn statement(source: AccountAttribute, name: &str) -> AttributeStatement {
        AttributeStatement {
            source,
            name: SamlAttributeName::new(name).unwrap(),
            name_format: AttributeNameFormat::Basic,
        }
    }

    /// Mapping both email and roles to the same output name fails attribute
    /// statement validation.
    #[test]
    fn two_attributes_under_one_name_are_refused() {
        let result = AttributeStatements::new(vec![
            statement(AccountAttribute::Email, "email"),
            statement(AccountAttribute::Roles, "email"),
        ]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A new app is sent the address as `email` and the display name as
    /// `displayName`, and nothing else.
    #[test]
    fn a_new_app_gets_the_address_and_the_display_name() {
        let standard = AttributeStatements::standard().unwrap();

        let sources: Vec<_> = standard.statements().iter().map(|s| s.source).collect();
        assert_eq!(
            sources,
            [AccountAttribute::Email, AccountAttribute::DisplayName]
        );
    }

    /// Ann holds the roles "editor" and "billing". An app sent `roles` gets
    /// both names under one attribute, and her address under another.
    #[test]
    fn an_app_is_sent_exactly_what_its_statements_name() {
        let ann = ann();
        let roles = [label("editor"), label("billing")];
        let statements = AttributeStatements::new(vec![
            statement(AccountAttribute::Email, "mail"),
            statement(AccountAttribute::Roles, "memberOf"),
        ])
        .unwrap();

        let released = statements.released(
            &ann,
            &HeldNames {
                roles: &roles,
                groups: &[],
            },
        );

        assert_eq!(released.len(), 2);
        assert_eq!(released[0].name().as_str(), "mail");
        assert_eq!(released[0].values(), ["ann@acme.com"]);
        assert_eq!(released[1].values(), ["editor", "billing"]);
    }

    /// Ann belongs to no group and never chose a locale. The `groups` and
    /// `locale` statements send nothing rather than an empty attribute.
    #[test]
    fn an_attribute_with_no_value_is_left_out() {
        let ann = ann();
        let statements = AttributeStatements::new(vec![
            statement(AccountAttribute::Groups, "groups"),
            statement(AccountAttribute::Locale, "locale"),
        ])
        .unwrap();

        let released = statements.released(
            &ann,
            &HeldNames {
                roles: &[],
                groups: &[],
            },
        );

        assert!(released.is_empty());
    }

    /// Sending a new attribute releases beyond the old statements; renaming
    /// one already sent does not.
    #[test]
    fn only_a_new_attribute_releases_beyond_the_old_statements() {
        let before = AttributeStatements::standard().unwrap();
        let renamed =
            AttributeStatements::new(vec![statement(AccountAttribute::Email, "mail")]).unwrap();
        let wider =
            AttributeStatements::new(vec![statement(AccountAttribute::Roles, "roles")]).unwrap();

        assert!(!renamed.releases_beyond(&before));
        assert!(wider.releases_beyond(&before));
    }
}
