use crate::domains::authorization::authority::Holdings;
use crate::domains::authorization::permission::{CustomPermission, SystemPermission};
use crate::types::{PermissionName, Scope};

/// What authentication and authorization a route requires.
///
/// The proxy checks it before forwarding to the upstream. A caller who does
/// not meet it is refused before the request reaches the backend.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RoutePolicy {
    /// No sign-in needed. Anyone may reach the route.
    Public,

    /// The caller must be signed in with a valid session or token. No role
    /// or permission is needed.
    Authenticated,

    /// The caller must hold at least one of these system permissions, the
    /// ones for `IdP` admin work.
    RequireSystemPermission(Vec<SystemPermission>),

    /// The caller must hold at least one of these custom permissions, the
    /// ones the tenant's app defines.
    RequireCustomPermission(Vec<CustomPermission>),

    /// The caller must present a valid API key or OAuth client token
    /// with at least one of the specified scopes.
    RequireScope(Vec<Scope>),
}

/// A signed-in caller as a route's policy reads it: what it holds, from
/// where it holds it.
#[derive(Debug, Clone, Copy)]
pub enum RouteCaller<'a> {
    /// A person, holding what the tenant's records give them.
    Person(&'a Holdings),
    /// A consumer, holding what its roles give it and the scopes its
    /// credential carries.
    Consumer {
        /// What its roles give it.
        holdings: &'a Holdings,
        /// The scopes its API key or token carries.
        scopes: &'a [Scope],
    },
    /// An agent, holding only what both its task token names and the one
    /// whose authority it acts on still holds: the person it acts for, or
    /// itself. A permission its delegator lost since the token was minted
    /// is lost to the agent too.
    Agent {
        /// What the task token names: what the delegation handed it.
        token: &'a [PermissionName],
        /// What the one it acts for holds now.
        authority: &'a Holdings,
    },
}

/// How a signed-in caller stands against a route's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStanding {
    /// The caller meets it.
    Met,
    /// The route asks for one of a list of permissions or scopes, and the
    /// list is empty, so nothing can meet it.
    NothingListed,
    /// The caller holds none of the permissions the route lists.
    PermissionMissing,
    /// The caller carries none of the scopes the route lists, or is not a
    /// caller that carries scopes at all.
    ScopeMissing,
}

impl RoutePolicy {
    /// Whether this policy allows unauthenticated access.
    #[must_use]
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Whether this policy requires any form of authentication.
    #[must_use]
    pub fn requires_auth(&self) -> bool {
        !self.is_public()
    }

    /// How a signed-in `caller` stands against this policy.
    ///
    /// A public or signed-in route asks nothing more. A permission route
    /// asks for one of its permissions, and one listing none lets nobody
    /// through. A scope belongs to an API key or an OAuth client's token,
    /// never to a person or an agent, so a scope route lets only a consumer
    /// carrying one of its scopes through.
    #[must_use]
    pub fn standing_of(&self, caller: RouteCaller<'_>) -> PolicyStanding {
        match self {
            Self::Public | Self::Authenticated => PolicyStanding::Met,
            Self::RequireSystemPermission(wanted) => {
                one_of(wanted, |permission| holds_system(caller, permission))
            }
            Self::RequireCustomPermission(wanted) => {
                one_of(wanted, |permission| holds_custom(caller, permission))
            }
            Self::RequireScope(wanted) => scope_standing(wanted, caller),
        }
    }
}

/// How a caller holding `held` stands against a list of permissions it must
/// hold one of.
fn one_of<T>(wanted: &[T], held: impl Fn(&T) -> bool) -> PolicyStanding {
    if wanted.is_empty() {
        return PolicyStanding::NothingListed;
    }
    if wanted.iter().any(held) {
        return PolicyStanding::Met;
    }
    PolicyStanding::PermissionMissing
}

/// How `caller` stands against a list of scopes it must carry one of.
fn scope_standing(wanted: &[Scope], caller: RouteCaller<'_>) -> PolicyStanding {
    if wanted.is_empty() {
        return PolicyStanding::NothingListed;
    }
    let RouteCaller::Consumer { scopes, .. } = caller else {
        return PolicyStanding::ScopeMissing;
    };
    if wanted.iter().any(|scope| scopes.contains(scope)) {
        return PolicyStanding::Met;
    }
    PolicyStanding::ScopeMissing
}

/// Whether `caller` holds `permission`, as it is or through a wider one.
fn holds_system(caller: RouteCaller<'_>, permission: &SystemPermission) -> bool {
    match caller {
        RouteCaller::Person(holdings) | RouteCaller::Consumer { holdings, .. } => {
            holdings.holds(*permission)
        }
        RouteCaller::Agent { token, authority } => {
            permission.held_in(token) && authority.holds(*permission)
        }
    }
}

/// Whether `caller` holds `permission`, as it is or through a wildcard.
fn holds_custom(caller: RouteCaller<'_>, permission: &CustomPermission) -> bool {
    match caller {
        RouteCaller::Person(holdings) | RouteCaller::Consumer { holdings, .. } => {
            holdings.holds_custom(permission)
        }
        RouteCaller::Agent { token, authority } => {
            permission.held_in(token) && authority.holds_custom(permission)
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::domains::authorization::permission::UserAction;

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const MANAGE_USERS: SystemPermission = SystemPermission::Users(UserAction::Manage);
    const UPDATE_USERS: SystemPermission = SystemPermission::Users(UserAction::Update);

    fn custom(text: &str) -> CustomPermission {
        CustomPermission::parse(text).unwrap()
    }

    fn named(names: &[&str]) -> Vec<PermissionName> {
        names
            .iter()
            .map(|name| PermissionName::new(*name).unwrap())
            .collect()
    }

    fn scope(name: &str) -> Scope {
        Scope::new(name).unwrap()
    }

    /// A public route needs no sign-in. Signed-in, scope and permission
    /// routes all need one, even with empty lists, so an anonymous request
    /// never reaches them.
    #[test]
    fn only_a_public_policy_needs_no_authentication() {
        assert!(!RoutePolicy::Public.requires_auth());
        assert!(RoutePolicy::Authenticated.requires_auth());
        assert!(RoutePolicy::RequireScope(Vec::new()).requires_auth());
        assert!(RoutePolicy::RequireSystemPermission(Vec::new()).requires_auth());
    }

    /// A public or signed-in route lets a person through holding nothing.
    #[test]
    fn a_signed_in_person_meets_a_public_or_signed_in_route() {
        let none = Holdings::default();

        assert_eq!(
            RoutePolicy::Public.standing_of(RouteCaller::Person(&none)),
            PolicyStanding::Met
        );
        assert_eq!(
            RoutePolicy::Authenticated.standing_of(RouteCaller::Person(&none)),
            PolicyStanding::Met
        );
    }

    /// A person holding a wider system permission meets a route asking for
    /// a narrower one of the same area.
    #[test]
    fn a_wider_system_permission_meets_a_narrower_one() {
        let policy = RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]);
        let manager = Holdings::of(vec![MANAGE_USERS], Vec::new());

        assert_eq!(
            policy.standing_of(RouteCaller::Person(&manager)),
            PolicyStanding::Met
        );
    }

    /// A user viewer lacks the update permission required by the route.
    #[test]
    fn a_person_without_the_permission_is_refused() {
        let policy = RoutePolicy::RequireSystemPermission(vec![UPDATE_USERS]);
        let viewer = Holdings::of(vec![VIEW_USERS], Vec::new());

        assert_eq!(
            policy.standing_of(RouteCaller::Person(&viewer)),
            PolicyStanding::PermissionMissing
        );
    }

    /// A held custom wildcard meets a route asking for one action of that
    /// resource; another resource's permission does not.
    #[test]
    fn a_custom_wildcard_meets_its_resource_only() {
        let policy = RoutePolicy::RequireCustomPermission(vec![custom("orders:read")]);
        let orders = Holdings::of(Vec::new(), vec![custom("orders:*")]);
        let invoices = Holdings::of(Vec::new(), vec![custom("invoices:*")]);

        assert_eq!(
            policy.standing_of(RouteCaller::Person(&orders)),
            PolicyStanding::Met
        );
        assert_eq!(
            policy.standing_of(RouteCaller::Person(&invoices)),
            PolicyStanding::PermissionMissing
        );
    }

    /// Empty system-permission, custom-permission and scope requirements
    /// report nothing listed even for an administrator with all permissions.
    #[test]
    fn an_empty_list_lets_nobody_through() {
        let admin = Holdings::of(SystemPermission::all().to_vec(), vec![custom("*:*")]);
        let everyone = RouteCaller::Person(&admin);

        for policy in [
            RoutePolicy::RequireSystemPermission(Vec::new()),
            RoutePolicy::RequireCustomPermission(Vec::new()),
            RoutePolicy::RequireScope(Vec::new()),
        ] {
            assert_eq!(policy.standing_of(everyone), PolicyStanding::NothingListed);
        }
    }

    /// A scope requirement admits a consumer carrying the requested scope.
    /// Another scope, a person and an agent all report a missing scope.
    #[test]
    fn only_a_consumer_carrying_the_scope_meets_a_scope_route() {
        let policy = RoutePolicy::RequireScope(vec![scope("orders:read")]);
        let none = Holdings::default();
        let carried = [scope("orders:read")];
        let other = [scope("orders:write")];
        let agent = named(&["idp:users:view"]);

        assert_eq!(
            policy.standing_of(RouteCaller::Consumer {
                holdings: &none,
                scopes: &carried,
            }),
            PolicyStanding::Met
        );
        assert_eq!(
            policy.standing_of(RouteCaller::Consumer {
                holdings: &none,
                scopes: &other,
            }),
            PolicyStanding::ScopeMissing
        );
        assert_eq!(
            policy.standing_of(RouteCaller::Person(&none)),
            PolicyStanding::ScopeMissing
        );
        assert_eq!(
            policy.standing_of(RouteCaller::Agent {
                token: &agent,
                authority: &none,
            }),
            PolicyStanding::ScopeMissing
        );
    }

    /// An agent's token names `idp:users:manage` and `orders:*`, and Ann,
    /// whom it acts for, holds both. It meets a route asking to view users
    /// or read orders, and not one asking for a right its token does not
    /// name, though Ann holds that too.
    #[test]
    fn an_agent_holds_what_its_token_names() {
        let token = named(&["idp:users:manage", "orders:*"]);
        let ann = Holdings::of(SystemPermission::all().to_vec(), vec![custom("*:*")]);
        let agent = RouteCaller::Agent {
            token: &token,
            authority: &ann,
        };

        assert_eq!(
            RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]).standing_of(agent),
            PolicyStanding::Met
        );
        assert_eq!(
            RoutePolicy::RequireCustomPermission(vec![custom("orders:read")]).standing_of(agent),
            PolicyStanding::Met
        );
        assert_eq!(
            RoutePolicy::RequireSystemPermission(vec![SystemPermission::ManagePolicy])
                .standing_of(agent),
            PolicyStanding::PermissionMissing
        );
    }

    /// An agent's token grants no effective system or custom permission when
    /// the authority it acts for currently holds none.
    #[test]
    fn an_agent_loses_what_the_one_it_acts_for_lost() {
        let token = named(&["idp:users:manage", "orders:*"]);
        let ann_now = Holdings::default();
        let agent = RouteCaller::Agent {
            token: &token,
            authority: &ann_now,
        };

        assert_eq!(
            RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]).standing_of(agent),
            PolicyStanding::PermissionMissing
        );
        assert_eq!(
            RoutePolicy::RequireCustomPermission(vec![custom("orders:read")]).standing_of(agent),
            PolicyStanding::PermissionMissing
        );
    }

    fn rights() -> impl Strategy<Value = Vec<SystemPermission>> {
        proptest::sample::subsequence(SystemPermission::ALL_VARIANTS, 0..8)
    }

    proptest! {
        /// Whatever the token names and whatever the one it acts for holds,
        /// an agent meets a route asking for a right exactly when both its
        /// token and its authority carry it: never more than either.
        #[test]
        fn an_agent_holds_no_more_than_its_token_and_its_authority(
            token in rights(),
            authority in rights(),
            wanted in proptest::sample::select(SystemPermission::ALL_VARIANTS),
        ) {
            let names = Holdings::of(token.clone(), Vec::new()).names();
            let held = Holdings::of(authority, Vec::new());
            let agent = RouteCaller::Agent {
                token: &names,
                authority: &held,
            };

            let met = RoutePolicy::RequireSystemPermission(vec![wanted]).standing_of(agent)
                == PolicyStanding::Met;

            prop_assert_eq!(met, wanted.held_in(&names) && held.holds(wanted));
            prop_assert!(!met || token.iter().any(|right| right.implies(&wanted)));
        }
    }
}
