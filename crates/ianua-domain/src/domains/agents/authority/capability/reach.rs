//! The URL paths and the apps a delegation may reach.

use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CanonicalPath, PathPrefix, ServiceId};

/// The URL path prefixes a delegation is limited to.
///
/// The proxy denies any request whose path is not under one of them. So a
/// delegation can name which records an agent may touch, not only which
/// kinds of action. Ann lets her agent reach `/accounts/4821`, and it cannot
/// read any other account.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<String>", into = "Vec<String>")
)]
pub struct ResourceScope {
    prefixes: Vec<PathPrefix>,
}

#[cfg(feature = "serde")]
impl TryFrom<Vec<String>> for ResourceScope {
    type Error = DomainError;

    /// Loads a stored scope through [`ResourceScope::new`], so a stored
    /// relative or `..` prefix is refused.
    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl From<ResourceScope> for Vec<String> {
    fn from(scope: ResourceScope) -> Self {
        scope
            .prefixes
            .into_iter()
            .map(|prefix| prefix.as_str().to_owned())
            .collect()
    }
}

impl ResourceScope {
    /// The most path prefixes one scope may list. This keeps a token that
    /// carries the scope small.
    pub const MAX_PREFIXES: usize = 64;

    /// Builds a scope from absolute path prefixes, sorted and with repeats
    /// removed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a prefix is not a valid
    ///   [`PathPrefix`], such as one that does not start with `/`.
    /// - [`DomainError::Validation`] when the list is empty or longer than
    ///   [`Self::MAX_PREFIXES`].
    pub fn new(prefixes: impl IntoIterator<Item = String>) -> Result<Self, DomainError> {
        let mut out = prefixes
            .into_iter()
            .map(PathPrefix::new)
            .collect::<Result<Vec<_>, _>>()?;
        validate_count("resource_scope", out.len(), 1..=Self::MAX_PREFIXES)?;
        out.sort_unstable();
        out.dedup();
        Ok(Self { prefixes: out })
    }

    /// The path prefixes, sorted.
    #[must_use]
    pub fn prefixes(&self) -> &[PathPrefix] {
        &self.prefixes
    }

    /// Whether `path` falls under one of the prefixes.
    ///
    /// A prefix matches only whole path segments. So `/accounts/48` never
    /// matches a request to `/accounts/4821`.
    #[must_use]
    pub fn permits(&self, path: &CanonicalPath) -> bool {
        self.prefixes.iter().any(|prefix| prefix.covers(path))
    }

    /// Whether every prefix here lies under some prefix of `other`.
    ///
    /// A sub-delegation may narrow the paths it reaches but never widen them.
    #[must_use]
    pub fn subset_of(&self, other: &Self) -> bool {
        self.prefixes
            .iter()
            .all(|p| other.prefixes.iter().any(|wider| p.within(wider)))
    }
}

/// The apps an agent may call through the gateway, named by the tenant's
/// service ids.
///
/// An app accepts a token only when the token names the app's audience. So an
/// agent's task token names the audience of each app listed here. An agent
/// whose delegation lists no app reaches no app that requires sign-in,
/// whatever its permissions say.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<ServiceId>", into = "Vec<ServiceId>")
)]
pub struct AppReach {
    services: Vec<ServiceId>,
}

#[cfg(feature = "serde")]
impl TryFrom<Vec<ServiceId>> for AppReach {
    type Error = DomainError;

    fn try_from(value: Vec<ServiceId>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl From<AppReach> for Vec<ServiceId> {
    fn from(apps: AppReach) -> Self {
        apps.services
    }
}

impl AppReach {
    /// The most apps one delegation may name.
    pub const MAX_APPS: usize = 64;

    /// Builds the list from service ids, sorted and with repeats removed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when, after repeats are removed, the list
    ///   is empty or longer than [`Self::MAX_APPS`].
    pub fn new(services: impl IntoIterator<Item = ServiceId>) -> Result<Self, DomainError> {
        let mut services: Vec<ServiceId> = services.into_iter().collect();
        services.sort_unstable_by_key(|id| *id.as_uuid());
        services.dedup();
        validate_count("apps", services.len(), 1..=Self::MAX_APPS)?;
        Ok(Self { services })
    }

    /// The services named, sorted by id.
    #[must_use]
    pub fn services(&self) -> &[ServiceId] {
        &self.services
    }

    /// Whether every app here is also in `other`.
    ///
    /// A sub-delegation may drop apps but never add one.
    #[must_use]
    pub fn subset_of(&self, other: &Self) -> bool {
        self.services.iter().all(|s| other.services.contains(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permits(scope: &ResourceScope, path: &str) -> bool {
        scope.permits(&CanonicalPath::new(path).unwrap())
    }

    /// A scope for one account and reports accepts those paths and their
    /// descendants, but refuses a partial account match, the parent account
    /// path and an unrelated admin path.
    #[test]
    fn resource_scope_matches_on_path_boundaries() {
        let scope =
            ResourceScope::new(["/accounts/4821".to_owned(), "/reports".to_owned()]).unwrap();
        assert!(permits(&scope, "/accounts/4821"));
        assert!(permits(&scope, "/accounts/4821/invoices"));
        assert!(permits(&scope, "/reports/nightly"));
        assert!(
            !permits(&scope, "/accounts/48210"),
            "must not match on a partial segment"
        );
        assert!(!permits(&scope, "/accounts"));
        assert!(!permits(&scope, "/admin"));
    }

    /// A scope with the relative prefix `accounts`, the climbing prefix
    /// `/a/../b`, or no prefix at all is refused.
    #[test]
    fn resource_scope_rejects_relative_or_traversing_paths() {
        assert!(ResourceScope::new(["accounts".to_owned()]).is_err());
        assert!(ResourceScope::new(["/a/../b".to_owned()]).is_err());
        assert!(ResourceScope::new(Vec::<String>::new()).is_err());
    }

    /// A single-account scope is a subset of the accounts scope; the
    /// broader accounts scope is not a subset of the single-account scope.
    #[test]
    fn resource_scope_subset_is_the_attenuation_law() {
        let broad = ResourceScope::new(["/accounts".to_owned()]).unwrap();
        let narrow = ResourceScope::new(["/accounts/4821".to_owned()]).unwrap();
        assert!(narrow.subset_of(&broad));
        assert!(!broad.subset_of(&narrow));
    }

    /// A scope built from `/accounts/48` and `/orders` gives back those two
    /// prefixes. It allows `/orders/1` but not `/accounts/4821`.
    #[test]
    fn a_resource_scope_reports_the_prefixes_it_confines_to() {
        let scope = ResourceScope::new(["/accounts/48".to_owned(), "/orders".to_owned()]).unwrap();

        assert_eq!(
            scope
                .prefixes()
                .iter()
                .map(PathPrefix::as_str)
                .collect::<Vec<_>>(),
            ["/accounts/48", "/orders"]
        );
        assert!(permits(&scope, "/orders/1"));
        assert!(!permits(&scope, "/accounts/4821"));
    }

    /// A scope written as `/reports/` allows `/reports` and `/reports/2026`.
    /// The gateway's paths never end in `/`, yet the prefix still reaches
    /// them, and it still refuses `/reportsx`.
    #[test]
    fn a_prefix_written_with_a_trailing_slash_reaches_its_resources() {
        let scope = ResourceScope::new(["/reports/".to_owned()]).unwrap();

        assert!(permits(&scope, "/reports"));
        assert!(permits(&scope, "/reports/2026"));
        assert!(!permits(&scope, "/reportsx"));
    }

    /// A scope of `/` allows `/` itself and any deeper path such as
    /// `/accounts/48`.
    #[test]
    fn the_root_prefix_reaches_every_path() {
        let scope = ResourceScope::new(["/".to_owned()]).unwrap();

        assert!(permits(&scope, "/"));
        assert!(permits(&scope, "/accounts/48"));
    }

    /// Deserialization refuses a relative path scope and one containing
    /// parent traversal, while accepting an absolute reports scope.
    #[cfg(feature = "serde")]
    #[test]
    fn a_relative_resource_scope_is_refused() {
        assert!(serde_json::from_str::<ResourceScope>(r#"["reports/"]"#).is_err());
        assert!(serde_json::from_str::<ResourceScope>(r#"["/a/../b"]"#).is_err());
        assert!(serde_json::from_str::<ResourceScope>(r#"["/reports/"]"#).is_ok());
    }

    /// The scope `/reports/` is saved as JSON and loaded again. It comes back
    /// equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_resource_scope_reads_back_what_it_writes() {
        let scope = ResourceScope::new(["/reports/".to_owned()]).unwrap();

        let json = serde_json::to_string(&scope).unwrap();

        assert_eq!(serde_json::from_str::<ResourceScope>(&json).unwrap(), scope);
    }

    /// A list of two apps is saved as JSON and loaded again. It comes back
    /// equal, in the same order.
    #[cfg(feature = "serde")]
    #[test]
    fn app_reach_reads_back_what_it_writes() {
        let apps = AppReach::new([ServiceId::new(), ServiceId::new()]).unwrap();

        let json = serde_json::to_string(&apps).unwrap();

        assert_eq!(serde_json::from_str::<AppReach>(&json).unwrap(), apps);
    }
}
