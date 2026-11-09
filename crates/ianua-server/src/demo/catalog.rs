//! What the demonstration organization holds: a logistics company with
//! three tenants, the people in each and the teams they work in, the roles
//! those teams carry, a few services behind routes, a webhook, a model
//! provider and two agents, and a place its notifications are posted.
//!
//! Fixed, never drawn at random, so a second run finds everything the
//! first made by name. Every address is under `example.com`, which no mail
//! or web request can reach.

use ianua_domain::domains::authorization::permission::{
    AgentAction, RoutingAction, SystemPermission, UserAction,
};

/// The organization's name; its slug is made from it.
pub(super) const ORGANIZATION: &str = "Northwind Logistics";

/// The slug the install use case makes from [`ORGANIZATION`].
pub(super) const ORGANIZATION_SLUG: &str = "northwind-logistics";

/// The owner's address, which is also how they sign in.
pub(super) const OWNER_EMAIL: &str = "olivia.hart@northwind.example.com";

/// The owner's name.
pub(super) const OWNER_NAME: &str = "Olivia Hart";

/// The password of every demo account, printed when the seeder is done:
/// a development convenience the configuration keeps out of production.
pub(super) const PASSWORD: &str = "Harbor-Lantern-4417";

/// The domain every demo person's address is under.
pub(super) const MAIL_DOMAIN: &str = "northwind.example.com";

/// What the seeder says it is, in every record it leaves.
pub(super) const USER_AGENT: &str = "ianua demo seeder";

/// The time zone every tenant starts in.
pub(super) const TIMEZONE: &str = "Europe/Amsterdam";

/// The language every tenant starts with.
pub(super) const LOCALE: &str = "en-US";

/// A tenant of the organization.
pub(super) struct TenantSeed {
    /// The display label used when the demo tenant is created.
    pub(super) name: &'static str,
    /// Its slug, made from the name.
    pub(super) slug: &'static str,
    /// The account fixtures to create inside this tenant's isolation boundary.
    pub(super) people: &'static [PersonSeed],
}

/// The tenants. The first is the one the organization is founded with.
pub(super) const TENANTS: [TenantSeed; 3] = [
    TenantSeed {
        name: "Production",
        slug: "production",
        people: PEOPLE.split_at(10).0,
    },
    TenantSeed {
        name: "EU Region",
        slug: "eu-region",
        people: PEOPLE.split_at(10).1.split_at(6).0,
    },
    TenantSeed {
        name: "Customer Portal",
        slug: "customer-portal",
        people: PEOPLE.split_at(16).1,
    },
];

/// A role the tenant's teams carry.
pub(super) struct RoleSeed {
    /// Its name, which the starting roles do not use.
    pub(super) name: &'static str,
    /// What it grants.
    pub(super) permissions: &'static [SystemPermission],
}

/// The roles, one for each team in [`TEAMS`], in the same order.
pub(super) const ROLES: [RoleSeed; 4] = [
    RoleSeed {
        name: "Operations Lead",
        permissions: &[
            SystemPermission::ManageUsers,
            SystemPermission::ManageRoles,
            SystemPermission::ViewAuditLog,
        ],
    },
    RoleSeed {
        name: "Developer",
        permissions: &[
            SystemPermission::ManageRouting,
            SystemPermission::ManageWebhooks,
            SystemPermission::ManageAgents,
            SystemPermission::ViewMetrics,
        ],
    },
    RoleSeed {
        name: "Support",
        permissions: &[
            SystemPermission::Users(UserAction::View),
            SystemPermission::Routing(RoutingAction::View),
            SystemPermission::ViewAuditLog,
        ],
    },
    RoleSeed {
        name: "Auditor",
        permissions: &[
            SystemPermission::ViewAuditLog,
            SystemPermission::ExportAuditLog,
            SystemPermission::Agents(AgentAction::View),
        ],
    },
];

/// The teams, each a group carrying the role of the same place in
/// [`ROLES`].
pub(super) const TEAMS: [&str; 4] = [
    "Operations",
    "Engineering",
    "Customer Support",
    "Compliance",
];

/// A person in a tenant.
pub(super) struct PersonSeed {
    /// Their first name.
    pub(super) first: &'static str,
    /// Their last name.
    pub(super) last: &'static str,
    /// Their team's place in [`TEAMS`].
    pub(super) team: usize,
}

const fn person(first: &'static str, last: &'static str, team: usize) -> PersonSeed {
    PersonSeed { first, last, team }
}

/// Everyone, split between the tenants by [`TENANTS`].
const PEOPLE: &[PersonSeed] = &[
    person("Liam", "Becker", 0),
    person("Sofia", "Jansen", 1),
    person("Noah", "Okafor", 1),
    person("Emma", "Lindqvist", 2),
    person("Mateo", "Rossi", 2),
    person("Aisha", "Rahman", 3),
    person("Lucas", "Moreau", 1),
    person("Mia", "Novak", 2),
    person("Ethan", "Kowalski", 0),
    person("Hana", "Sato", 1),
    person("Jonas", "Weber", 0),
    person("Clara", "Dubois", 1),
    person("Felix", "Andersen", 2),
    person("Ines", "Ferreira", 3),
    person("Omar", "Haddad", 1),
    person("Lea", "Schmidt", 2),
    person("Daniel", "Murphy", 0),
    person("Priya", "Nair", 1),
    person("Tomas", "Horvat", 2),
    person("Yara", "Costa", 2),
    person("Ben", "Fischer", 3),
    person("Nora", "Berg", 1),
];

/// A backend the tenant's routes forward to, and the route in front of
/// it.
pub(super) struct ServiceSeed {
    /// The service's name.
    pub(super) name: &'static str,
    /// Where it is reached.
    pub(super) url: &'static str,
    /// The audience a token must name to sign in on its route.
    pub(super) audience: &'static str,
    /// The route's name.
    pub(super) route: &'static str,
    /// The path the route answers.
    pub(super) path: &'static str,
    /// The route's place among the others, lower first.
    pub(super) priority: u16,
}

/// The services, each behind one route.
pub(super) const SERVICES: [ServiceSeed; 3] = [
    ServiceSeed {
        name: "Orders",
        url: "https://orders.example.com",
        audience: "orders-api",
        route: "Orders API",
        path: "/api/orders/*",
        priority: 10,
    },
    ServiceSeed {
        name: "Customers",
        url: "https://customers.example.com",
        audience: "customers-api",
        route: "Customers API",
        path: "/api/customers/*",
        priority: 20,
    },
    ServiceSeed {
        name: "Reports",
        url: "https://reports.example.com",
        audience: "reports",
        route: "Reports",
        path: "/reports/*",
        priority: 30,
    },
];

/// The pipeline every route runs.
pub(super) const PIPELINE: &str = "Default";

/// Where each tenant's webhook posts, its slug after the last slash.
pub(super) const WEBHOOK_BASE: &str = "https://hooks.example.com/ianua";

/// What the webhook is for.
pub(super) const WEBHOOK_DESCRIPTION: &str =
    "Tells the warehouse system about new people and roles";

/// The model provider agents run on.
pub(super) struct ProviderSeed {
    /// The display label used when connecting the demo model endpoint.
    pub(super) name: &'static str,
    /// Where it answers.
    pub(super) endpoint: &'static str,
    /// The model asked for.
    pub(super) model: &'static str,
    /// Its key, made up: the connect use case seals it for its place.
    pub(super) key: &'static str,
}

/// The model provider.
pub(super) const PROVIDER: ProviderSeed = ProviderSeed {
    name: "Northwind Models",
    endpoint: "https://models.example.com/v1",
    model: "llama-3.1-70b-instruct",
    key: "demo-model-key-not-a-real-one",
};

/// An agent of the tenant.
pub(super) struct AgentSeed {
    /// The display label shown for this seeded machine identity.
    pub(super) name: &'static str,
    /// What it does.
    pub(super) description: &'static str,
}

/// The agents.
pub(super) const AGENTS: [AgentSeed; 2] = [
    AgentSeed {
        name: "Shipment Tracker",
        description: "Answers where a shipment is and when it lands",
    },
    AgentSeed {
        name: "Invoice Assistant",
        description: "Drafts invoices from delivered orders",
    },
];

/// The place the organization's notifications are posted.
pub(super) const DESTINATION: &str = "Operations Webhook";

/// Where it posts.
pub(super) const DESTINATION_URL: &str = "https://hooks.example.com/ianua/notifications";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every person lands in exactly one tenant, and on a team that exists.
    #[test]
    fn every_person_lands_in_one_tenant_on_a_team_that_exists() {
        let placed: usize = TENANTS.iter().map(|tenant| tenant.people.len()).sum();

        assert_eq!(placed, PEOPLE.len());
        assert!(PEOPLE.iter().all(|person| person.team < TEAMS.len()));
    }

    /// Every demo role name differs from each tenant starting-role name.
    #[test]
    fn no_demo_role_takes_a_starting_role_name() {
        use ianua_domain::domains::authorization::role::starting::StartingRole;

        for starting in StartingRole::ALL {
            assert!(ROLES.iter().all(|role| role.name != starting.name()));
        }
    }
}
