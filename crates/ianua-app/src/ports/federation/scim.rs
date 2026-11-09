//! SCIM provisioning: the endpoint's configuration, its bearer tokens, and
//! the filters a directory finds users and groups by.

use async_trait::async_trait;
use ianua_domain::domains::authorization::group::Group;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::TokenHash;

use crate::listing::SortDirection;
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving SCIM endpoint configuration.
#[async_trait]
pub trait ScimStore: Send + Sync + TenantScoped {
    /// Loads the tenant's SCIM endpoint, if configured.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ScimEndpoint<ResolvedTenant>>, DomainError>;

    /// Saves the tenant's SCIM endpoint configuration.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes when `endpoint` last synced, and nothing else: its token and
    /// settings stay as stored.
    ///
    /// A provisioning call holds the endpoint it signed in with. Saving all
    /// of it would undo a change an administrator made meanwhile, and could
    /// switch back on an endpoint they had just switched off.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save_last_sync(
        &self,
        tenant_id: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// The longest value a SCIM filter compares with.
const MAX_FILTER_VALUE_CHARS: usize = 512;

/// The text a SCIM filter compares an attribute with, such as `ann` in
/// `userName sw "ann"`.
///
/// It is compared as data, never read as a pattern: the adapter binds it,
/// and escapes any wildcard it holds, so `%` matches a `%`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimFilterValue(String);

impl ScimFilterValue {
    /// `value`, once it holds something and is not too long.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if `value` is empty or longer than
    /// 512 characters.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let length = value.chars().count();
        if length == 0 || length > MAX_FILTER_VALUE_CHARS {
            return Err(DomainError::invalid(message!(
                "app-a-scim-filter-compares-with-1",
                "a SCIM filter compares with 1 to 512 characters"
            )));
        }
        Ok(Self(value))
    }

    /// The text as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a SCIM filter compares an attribute with its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimOperator {
    /// `eq`: the whole value.
    Equals,
    /// `co`: anywhere in the value.
    Contains,
    /// `sw`: at the start of the value.
    StartsWith,
}

/// Whether case counts when an attribute is compared, as SCIM's
/// `caseExact` says for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimCase {
    /// `Ann` and `ann` differ.
    Exact,
    /// `Ann` and `ann` are alike.
    Ignored,
}

impl ScimOperator {
    /// Whether `stored` matches `wanted` this way, with case counted as
    /// `case` says.
    #[must_use]
    pub fn holds(self, stored: &str, wanted: &ScimFilterValue, case: ScimCase) -> bool {
        let (stored, wanted) = match case {
            ScimCase::Exact => (stored.to_owned(), wanted.as_str().to_owned()),
            ScimCase::Ignored => (stored.to_lowercase(), wanted.as_str().to_lowercase()),
        };
        match self {
            Self::Equals => stored == wanted,
            Self::Contains => stored.contains(&wanted),
            Self::StartsWith => stored.starts_with(&wanted),
        }
    }
}

/// A SCIM filter over attributes of kind `A`: everything, one comparison,
/// or two filters joined by `and` or `or`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimQuery<A> {
    /// No filter.
    All,
    /// `attribute op "value"`.
    Compare {
        /// The attribute compared.
        attribute: A,
        /// How it is compared.
        operator: ScimOperator,
        /// What it is compared with.
        value: ScimFilterValue,
    },
    /// Both filters hold.
    And(Box<ScimQuery<A>>, Box<ScimQuery<A>>),
    /// Either filter holds.
    Or(Box<ScimQuery<A>>, Box<ScimQuery<A>>),
}

/// The user attributes a SCIM filter or sort may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimUserAttribute {
    /// `userName`, the sign-in address. Case is ignored.
    UserName,
    /// `displayName`. Case is ignored.
    DisplayName,
    /// `externalId`, the directory's own id. Case counts.
    ExternalId,
    /// `name.givenName`. Case is ignored.
    GivenName,
    /// `name.familyName`. Case is ignored.
    FamilyName,
    /// The enterprise `department`. Case is ignored.
    Department,
    /// The enterprise `employeeNumber`. Case counts.
    EmployeeNumber,
}

impl ScimUserAttribute {
    /// Whether case counts when this attribute is compared.
    #[must_use]
    pub fn case(self) -> ScimCase {
        match self {
            Self::ExternalId | Self::EmployeeNumber => ScimCase::Exact,
            Self::UserName
            | Self::DisplayName
            | Self::GivenName
            | Self::FamilyName
            | Self::Department => ScimCase::Ignored,
        }
    }
}

/// The group attributes a SCIM filter may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimGroupAttribute {
    /// `displayName`. Case is ignored.
    DisplayName,
}

/// The most entries a directory gets on one SCIM page.
const MOST_SCIM_COUNT: u64 = 100;

/// The entries a directory gets when it names no `count`, or zero.
const USUAL_SCIM_COUNT: u64 = 20;

/// The furthest a directory may start into a listing.
///
/// Adapters bind the start as a signed 64-bit integer, so an unbounded
/// `startIndex` would wrap and turn a query parameter into a 500.
const FURTHEST_SCIM_START: u64 = 1_000_000;

/// Which stretch of a SCIM listing a directory asks for, by position.
///
/// SCIM is the one listing paged by position rather than by
/// [`Cursor`](crate::listing::Cursor): RFC 7644, section 3.4.2.4, has a
/// directory send `startIndex` and `count` and read `totalResults`, and
/// provisioning clients page that way. Every other list is keyset paged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimWindow {
    skip: u64,
    count: u64,
}

impl ScimWindow {
    /// The stretch starting at the 1-based `start_index` and holding at
    /// most `count` entries. A start below 1 reads as 1; zero entries reads
    /// as the usual 20, and more than 100 as 100.
    #[must_use]
    pub fn new(start_index: u64, count: u64) -> Self {
        let count = match count {
            0 => USUAL_SCIM_COUNT,
            asked => asked.min(MOST_SCIM_COUNT),
        };
        Self {
            skip: start_index.saturating_sub(1).min(FURTHEST_SCIM_START),
            count,
        }
    }

    /// A single entry from the start, for a listing whose answer is empty
    /// anyway.
    #[must_use]
    pub fn single() -> Self {
        Self { skip: 0, count: 1 }
    }

    /// How many matching entries come before the stretch.
    #[must_use]
    pub fn skip(self) -> u64 {
        self.skip
    }

    /// The most entries the stretch holds.
    #[must_use]
    pub fn count(self) -> u64 {
        self.count
    }

    /// The stretch of `items`, already in order, and how many there are in
    /// all.
    #[must_use]
    pub fn cut<T>(self, items: Vec<T>) -> ScimPage<T> {
        let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let skip = usize::try_from(self.skip).unwrap_or(usize::MAX);
        let take = usize::try_from(self.count).unwrap_or(usize::MAX);
        ScimPage {
            items: items.into_iter().skip(skip).take(take).collect(),
            total,
        }
    }
}

/// One stretch of a SCIM listing, with how many entries match in all, as
/// SCIM's `totalResults` reports.
#[derive(Debug, Clone, PartialEq)]
pub struct ScimPage<T> {
    /// The entries in the stretch.
    pub items: Vec<T>,
    /// How many entries match the filter in all.
    pub total: u64,
}

impl<T> ScimPage<T> {
    /// The same stretch with every entry turned into another type.
    #[must_use]
    pub fn map<U>(self, convert: impl FnMut(T) -> U) -> ScimPage<U> {
        ScimPage {
            items: self.items.into_iter().map(convert).collect(),
            total: self.total,
        }
    }
}

/// How a SCIM user listing is ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimUserSort {
    /// Oldest first, as the store keeps them.
    Default,
    /// By this attribute, this way. Users with no value for it come last.
    By(ScimUserAttribute, SortDirection),
}

/// Dyn-safe port finding the users a SCIM filter picks.
#[async_trait]
pub trait ScimUserQueries: Send + Sync + TenantScoped {
    /// The users of the tenant `query` picks, ordered by `sort`, in
    /// `window`, with how many it picks in all.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        query: &ScimQuery<ScimUserAttribute>,
        sort: ScimUserSort,
        window: ScimWindow,
    ) -> Result<ScimPage<User<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port finding the groups a SCIM filter picks.
#[async_trait]
pub trait ScimGroupQueries: Send + Sync + TenantScoped {
    /// The groups the tenant's directory keeps that `query` picks, oldest
    /// first, in `window`, with how many it picks in all. Groups a person
    /// keeps in the dashboard are never picked. `displayName` compares
    /// ignoring case.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        query: &ScimQuery<ScimGroupAttribute>,
        window: ScimWindow,
    ) -> Result<ScimPage<Group<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for generating and hashing SCIM bearer tokens.
#[async_trait]
pub trait ScimTokenGenerator: Send + Sync {
    /// Generates a new random bearer token and returns `(raw_token, hash)`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// Whether `presented` is the token `hash` was made from, compared in
    /// constant time.
    fn verify(&self, presented: &Secret, hash: &TokenHash) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Okta asks for entries from the 21st on, ten at a time. Twenty
    /// matching entries come before the stretch.
    #[test]
    fn a_start_index_counts_from_one() {
        let window = ScimWindow::new(21, 10);

        assert_eq!((window.skip(), window.count()), (20, 10));
    }

    /// A request for 5,000 entries from index zero is bounded to 100 from the first entry.
    #[test]
    fn a_window_is_bounded() {
        let window = ScimWindow::new(0, 5000);

        assert_eq!((window.skip(), window.count()), (0, 100));
    }

    /// A stretch cut from five entries holds the ones asked for, and
    /// reports all five as the total.
    #[test]
    fn a_cut_keeps_the_total() {
        let page = ScimWindow::new(2, 2).cut(vec![1, 2, 3, 4, 5]);

        assert_eq!((page.items, page.total), (vec![2, 3], 5));
    }
}
