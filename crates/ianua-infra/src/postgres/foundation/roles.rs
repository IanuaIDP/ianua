//! The roles the platform connects as.
//!
//! Migrations run as the database's owner, but the app itself connects as an
//! ordinary role that owns nothing and cannot bypass row-level security. A
//! superuser or a table's owner skips the policies without a word, so an app
//! connected as one would read every tenant's rows while every test of
//! isolation passed.
//!
//! The app's role reads and writes the rows of every table, but holds no
//! update or delete on the audit records and no delete on the chains'
//! anchors, so whoever holds it cannot remove a record by any setting. The
//! retention purge connects as a role of its own, which holds only what the
//! purge needs: reading and removing audit records, reading and writing
//! the chains' anchors, and reading which tenants live in a schema of their
//! own. Row-level security still holds it to the one tenant its transaction
//! is scoped to. Neither role is a member of the other, so neither can
//! become the other.
//!
//! The gateway faces the internet, so it connects as a third role, made
//! when a gateway is deployed, that holds as little as the gateway needs:
//! it reads the configuration it serves, inserts its request records and
//! the events of its inbox, and changes only the few columns its checks
//! mark (when an app session was last used, an approval spent, an agent's
//! exposure raised). It holds nothing on the audit trail or the outbox,
//! never reads a private signing key, and changes no configuration. The
//! one private key it reads is its own: the tenant's assertion keys, which
//! sign only the identity it hands upstreams and which it cannot write.
//!
//! The nameservers answer anyone on the internet over UDP, so they connect
//! as a fourth role, made when nameservers are deployed, that only reads:
//! the zones tenants delegated to us, their records, and of each claim on
//! a name only who holds it and whether it was proved. It writes nothing
//! and reads no other table.
//!
//! A role's name cannot be bound as a value, so it is checked against the
//! names the platform makes and quoted, never pasted in as given.

use ianua_domain::shared::errors::DomainError;
use sqlx::PgPool;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The schema the platform's own tables live in.
const PLATFORM_SCHEMA: &str = "public";

/// A role the platform signs in as, and its password.
pub struct LoginRole<'a> {
    /// The role's name: lowercase ASCII letters, digits and underscores.
    pub name: &'a str,
    /// The role's password.
    pub password: &'a str,
}

/// The roles the platform signs in as.
pub struct PlatformRoles<'a> {
    /// The role the app connects as.
    pub app: LoginRole<'a>,
    /// The role the audit retention purge connects as.
    pub audit_purge: LoginRole<'a>,
    /// The role the gateway connects as, or `None` where no gateway is
    /// deployed, so no such role is made.
    pub gateway: Option<LoginRole<'a>>,
    /// The role the nameservers connect as, or `None` where no nameserver
    /// reads the database, so no such role is made.
    pub nameserver: Option<LoginRole<'a>>,
}

impl PlatformRoles<'_> {
    /// Whether two of the roles share a name, so one would hold the other's
    /// grants.
    fn share_a_name(&self) -> bool {
        let names: Vec<&str> = [
            Some(self.app.name),
            Some(self.audit_purge.name),
            self.gateway.as_ref().map(|role| role.name),
            self.nameserver.as_ref().map(|role| role.name),
        ]
        .into_iter()
        .flatten()
        .collect();
        names
            .iter()
            .enumerate()
            .any(|(index, name)| names.iter().take(index).any(|earlier| earlier == name))
    }
}

/// The tables of a tenant's configuration the gateway reads, kept in every
/// database a tenant lives in: what it routes and forwards to, the stages
/// it runs, the credentials, sessions, roles and groups it checks callers
/// against, the agents, delegations and approvals it gates actions on, the
/// assertion keys it signs upstream identities with, the look its error
/// pages wear, and where it ships request records.
const GATEWAY_READS: &[&str] = &[
    "tenant_branding",
    "log_shipping_targets",
    "services",
    "service_sign_in_hosts",
    "routes",
    "stream_routes",
    "egress_policies",
    "pipelines",
    "wasm_modules",
    "classification_rule_sets",
    "consumers",
    "registered_domains",
    "users",
    "sessions",
    "api_keys",
    "oauth_clients",
    "oauth_access_tokens",
    "roles",
    "role_assignments",
    "groups",
    "group_roles",
    "group_memberships",
    "break_glass_grants",
    "resource_types",
    "policy_versions",
    "agents",
    "agent_credentials",
    "agent_tools",
    "agent_delegations",
    "delegation_resources",
    "delegation_sources",
    "delegation_provenance",
    "agent_approvals",
    "agent_approval_delegators",
    "agent_exposure",
    "assertion_keys",
];

/// The tables the gateway reads that only the platform's database keeps:
/// which tenants there are and where each lives, the hostnames claimed and
/// the certificates served on them, the ACME answers it serves, the ports
/// stream routes listen on, and the roles organization members are granted
/// in tenants, for an agent acting for a member.
const GATEWAY_PLATFORM_READS: &[&str] = &[
    "tenants",
    "organizations",
    "org_tenant_grants",
    "tenant_databases",
    "domain_claims",
    "domain_certificates",
    "platform_certificates",
    "acme_challenges",
    "stream_route_ports",
];

/// The columns of a signing key the gateway reads: its public half, to
/// check what the platform signed, and never the sealed private key.
const SIGNING_KEY_PUBLIC_PARTS: &str =
    "tenant_id, kid, algorithm, public_key, status, rotated_at, expires_at, created_at";

/// The columns of a trusted device the gateway reads for a device posture
/// check: whose it is and whether it is still trusted, never the digest of
/// its secret, its name or where it was last used.
const DEVICE_STANDING_PARTS: &str = "tenant_id, id, user_id, status";

/// The columns of a second factor the gateway reads, to see whether its
/// holder could lift a frozen session: whose it is and whether it is
/// confirmed, never its secret.
const FACTOR_STANDING_PARTS: &str = "tenant_id, user_id, status";

/// The columns of a connector the gateway reads to let its link in and to
/// note when it saw it: never the digest of its enrollment code.
const CONNECTOR_TUNNEL_PARTS: &str =
    "tenant_id, id, scope, public_key, status, enrolled_at, last_seen_at";

/// The columns of an organization member the gateway reads, to judge an
/// agent acting for them: who they are, whose member, in what role and
/// status, never their address or password hash.
const MEMBER_REACH_PARTS: &str = "id, organization_id, role, status";

/// The columns of a claim on a name the nameservers read: who holds it and
/// whether it was proved, never the registration behind it or its dates.
const CLAIM_STANDING_PARTS: &str = "tenant_id, hostname, verified";

/// Makes the app's role, the audit purge's, the gateway's and the
/// nameservers' on the database `owner` reaches, each when it is missing,
/// and gives each what it may do and nothing more. Runs after the
/// migrations, as the grants name the tables they made.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a name is not one the
/// platform makes, two roles have one name, or the database refuses, as
/// it does before the audit tables are made.
pub async fn ensure_roles(owner: &PgPool, roles: &PlatformRoles<'_>) -> Result<(), DomainError> {
    if roles.share_a_name() {
        return Err(DomainError::infra_msg(
            "the app, the audit purge, the gateway and the nameservers must sign in as roles of their own",
        ));
    }
    let app = ensured(owner, &roles.app).await?;
    let purge = ensured(owner, &roles.audit_purge).await?;
    let statements = app_grants(&app)
        .into_iter()
        .chain(audit_kept_from(PLATFORM_SCHEMA, &app))
        .chain(audit_purge_grants(PLATFORM_SCHEMA, &purge))
        .chain([format!(
            "GRANT SELECT ON {PLATFORM_SCHEMA}.tenant_databases TO {purge}"
        )]);
    for statement in statements {
        run(owner, &statement).await?;
    }
    if let Some(gateway) = &roles.gateway {
        ensure_gateway(owner, gateway).await?;
    }
    let Some(nameserver) = &roles.nameserver else {
        return Ok(());
    };
    let nameserver = ensured(owner, nameserver).await?;
    for statement in nameserver_grants(PLATFORM_SCHEMA, &nameserver) {
        run(owner, &statement).await?;
    }
    Ok(())
}

/// Makes the gateway's role `gateway` when it is missing, with its grants.
async fn ensure_gateway(owner: &PgPool, gateway: &LoginRole<'_>) -> Result<(), DomainError> {
    let gateway = ensured(owner, gateway).await?;
    let statements = gateway_grants(PLATFORM_SCHEMA, &gateway)
        .into_iter()
        .chain([gateway_platform_reads(&gateway)]);
    for statement in statements {
        run(owner, &statement).await?;
    }
    Ok(())
}

/// Whether the role `databases` sign in as can neither change nor remove
/// an audit record, for a start-up that refuses to run with an audit trail
/// its own role could rewrite.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the database cannot be
/// reached or the audit tables are not made yet.
pub async fn audit_sealed_from(databases: &Databases) -> Result<bool, DomainError> {
    scoped(databases, RowScope::Unscoped, async |connection| {
        sqlx::query_scalar::<_, bool>(
            "SELECT NOT (has_table_privilege('public.audit_records', 'UPDATE') \
                      OR has_table_privilege('public.audit_records', 'DELETE') \
                      OR has_table_privilege('public.audit_records', 'TRUNCATE'))",
        )
        .fetch_one(connection)
        .await
    })
    .await
}

/// Makes `role` on the database `owner` reaches when it is missing, and
/// answers its name quoted.
async fn ensured(owner: &PgPool, role: &LoginRole<'_>) -> Result<String, DomainError> {
    let name = checked_name(role.name)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(role.name)
            .fetch_one(owner)
            .await
            .map_err(DomainError::infra)?;
    if exists {
        return Ok(name);
    }
    let password = role.password.replace('\'', "''");
    let created = format!(
        "CREATE ROLE {name} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '{password}'"
    );
    run(owner, &created).await?;
    Ok(name)
}

/// What the app's role may do: reach the schema, and read and write rows of
/// every table and sequence, including those made by later migrations.
fn app_grants(name: &str) -> [String; 4] {
    [
        format!("GRANT USAGE ON SCHEMA {PLATFORM_SCHEMA} TO {name}"),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {PLATFORM_SCHEMA} TO {name}"
        ),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {PLATFORM_SCHEMA} TO {name}"),
        format!(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {PLATFORM_SCHEMA} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {name}"
        ),
    ]
}

/// What the app's role `role` is never let do in `schema`, after its
/// grants on every table there: change or remove an audit record, or move
/// or remove a chain's anchor.
pub(crate) fn audit_kept_from(schema: &str, role: &str) -> [String; 2] {
    [
        format!("REVOKE UPDATE, DELETE, TRUNCATE ON {schema}.audit_records FROM {role}"),
        format!("REVOKE UPDATE, DELETE, TRUNCATE ON {schema}.audit_chain_anchors FROM {role}"),
    ]
}

/// What the audit purge's role `role` may do in `schema`, and nothing
/// more: reach it, read and remove audit records, and read and write the
/// chains' anchors.
pub(crate) fn audit_purge_grants(schema: &str, role: &str) -> [String; 4] {
    [
        format!("REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {role}"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!("GRANT SELECT, DELETE ON {schema}.audit_records TO {role}"),
        format!("GRANT SELECT, INSERT, UPDATE ON {schema}.audit_chain_anchors TO {role}"),
    ]
}

/// What the gateway's role `role` may do in `schema`, and nothing more:
/// reach it, read the configuration it serves, the public half of the
/// signing keys, the standing of trusted devices and what a connector's link
/// is judged by, insert its request records and the events of its inbox,
/// and change only the columns its checks mark. Whatever it held before is
/// taken away first, so a table dropped from the list is closed to it.
pub(crate) fn gateway_grants(schema: &str, role: &str) -> [String; 13] {
    let reads = gateway_read_tables(schema);
    [
        format!("REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {role}"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!("GRANT SELECT ON {reads} TO {role}"),
        format!("GRANT SELECT ({SIGNING_KEY_PUBLIC_PARTS}) ON {schema}.signing_keys TO {role}"),
        format!(
            "GRANT SELECT ({DEVICE_STANDING_PARTS}) ON {schema}.trusted_devices TO {role}; \
             GRANT SELECT ({FACTOR_STANDING_PARTS}) ON {schema}.mfa_enrollments TO {role}"
        ),
        format!("GRANT SELECT ({CONNECTOR_TUNNEL_PARTS}) ON {schema}.connectors TO {role}"),
        format!(
            "GRANT INSERT ON {schema}.gateway_events, {schema}.proxy_request_records, \
             {schema}.stream_records TO {role}"
        ),
        format!(
            "GRANT SELECT (tenant_id, correlation_id, closed_reason, closed_at), \
             UPDATE (closed_reason, closed_at) ON {schema}.proxy_request_records TO {role}"
        ),
        format!(
            "GRANT UPDATE (last_active_at, status, last_used_network, last_used_latitude, \
             last_used_longitude, last_used_country, last_used_at) ON {schema}.sessions TO {role}"
        ),
        format!("GRANT UPDATE (last_seen_at) ON {schema}.connectors TO {role}"),
        format!("GRANT UPDATE (status, updated_at) ON {schema}.agent_approvals TO {role}"),
        format!("GRANT INSERT ON {schema}.agent_exposure TO {role}"),
        format!("GRANT UPDATE (level) ON {schema}.agent_exposure TO {role}"),
    ]
}

/// The tables of `schema` the gateway reads whole, as a grant lists them.
fn gateway_read_tables(schema: &str) -> String {
    GATEWAY_READS
        .iter()
        .map(|table| format!("{schema}.{table}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What the nameservers' role `role` may do in `schema`, and nothing more:
/// reach it, read every zone and its records, and read of each claim who
/// holds it and whether it was proved. Whatever it held before is taken
/// away first.
fn nameserver_grants(schema: &str, role: &str) -> [String; 7] {
    [
        format!("REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {role}"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!("GRANT SELECT ON {schema}.dns_zones, {schema}.dns_records TO {role}"),
        format!("GRANT SELECT ({CLAIM_STANDING_PARTS}) ON {schema}.domain_claims TO {role}"),
        format!(
            "GRANT SELECT (root, tenant_id, readable, nameservers, address, changed_at) ON {schema}.platform_certificates TO {role}"
        ),
        format!("GRANT SELECT ON {schema}.platform_dns_proofs TO {role}"),
        format!("GRANT SELECT (id, status, readable_address) ON {schema}.tenants TO {role}"),
    ]
}

/// What the gateway's role `role` reads of the tables only the platform's
/// database keeps.
fn gateway_platform_reads(role: &str) -> String {
    let reads = GATEWAY_PLATFORM_READS
        .iter()
        .map(|table| format!("{PLATFORM_SCHEMA}.{table}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "GRANT SELECT ON {reads} TO {role}; \
         GRANT SELECT ({MEMBER_REACH_PARTS}) ON {PLATFORM_SCHEMA}.org_users TO {role}"
    )
}

async fn run(owner: &PgPool, statement: &str) -> Result<(), DomainError> {
    sqlx::raw_sql(statement)
        .execute(owner)
        .await
        .map(|_| ())
        .map_err(DomainError::infra)
}

/// `name`, quoted as an identifier, when it is one the platform makes.
pub(crate) fn checked_name(name: &str) -> Result<String, DomainError> {
    let made_here = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !made_here {
        return Err(DomainError::infra_msg(
            "a role's name is not one the platform makes",
        ));
    }
    Ok(format!("\"{name}\""))
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::errors::causes;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    /// A database holding two tenants' records, two each.
    async fn two_trails() -> (TestDb, TenantId, TenantId) {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let acme = *saved_tenant_of(&db.databases, organization).await;
        let globex = *saved_tenant_of(&db.databases, organization).await;
        for tenant in [acme, globex] {
            recorded(
                &db.databases,
                vec![failed_sign_in(tenant, 1), failed_sign_in(tenant, 2)],
            )
            .await;
        }
        (db, acme, globex)
    }

    /// Runs `statement` as the role of `databases`, scoped to `scope`, and
    /// answers the rows it touched.
    async fn ran(
        databases: &Databases,
        scope: RowScope,
        statement: &str,
    ) -> Result<u64, DomainError> {
        scoped(databases, scope, async |connection| {
            sqlx::query(statement)
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
        })
        .await
    }

    /// How many of `tenant`'s records are left.
    async fn left(db: &TestDb, tenant: TenantId) -> i64 {
        scoped(
            &db.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_scalar("SELECT count(*) FROM audit_records")
                    .fetch_one(connection)
                    .await
            },
        )
        .await
        .unwrap()
    }

    /// Setting the purge flag does not let the app role delete audit
    /// records; the delete fails and both records remain.
    #[tokio::test]
    async fn the_apps_role_never_removes_a_record_whatever_it_sets() {
        let (db, acme, _) = two_trails().await;

        let removed = scoped(&db.databases, RowScope::Tenant(acme), async |connection| {
            sqlx::query("SELECT set_config('app.audit_purge', $1, false)")
                .bind(acme.as_uuid().to_string())
                .execute(&mut *connection)
                .await?;
            sqlx::query("DELETE FROM audit_records")
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
        })
        .await;

        assert!(removed.is_err());
        assert_eq!(left(&db, acme).await, 2);
    }

    /// Platform scope does not let the app role update audit records or
    /// delete chain anchors; both statements are refused.
    #[tokio::test]
    async fn the_apps_role_never_changes_a_record_or_removes_an_anchor() {
        let (db, _, _) = two_trails().await;

        let changed = ran(
            &db.databases,
            RowScope::Platform,
            "UPDATE audit_records SET event_type = 'nothing'",
        )
        .await;
        let unanchored = ran(
            &db.databases,
            RowScope::Platform,
            "DELETE FROM audit_chain_anchors",
        )
        .await;

        assert!(changed.is_err());
        assert!(unanchored.is_err());
    }

    /// The purge's role removes the records of the tenant its transaction
    /// is scoped to, and no other tenant's.
    #[tokio::test]
    async fn the_purge_role_removes_records_of_its_own_tenant_only() {
        let (db, acme, globex) = two_trails().await;

        let removed = ran(
            &db.audit_purge,
            RowScope::Tenant(acme),
            "DELETE FROM audit_records",
        )
        .await;

        assert_eq!(removed.unwrap(), 2);
        assert_eq!(left(&db, acme).await, 0);
        assert_eq!(left(&db, globex).await, 2);
    }

    /// A platform-scoped delete by the purge role removes nothing and
    /// leaves both tenants' audit records intact.
    #[tokio::test]
    async fn the_purge_role_removes_nothing_in_work_spanning_tenants() {
        let (db, acme, globex) = two_trails().await;

        let removed = ran(
            &db.audit_purge,
            RowScope::Platform,
            "DELETE FROM audit_records",
        )
        .await;

        assert_eq!(removed.unwrap(), 0);
        assert_eq!(left(&db, acme).await, 2);
        assert_eq!(left(&db, globex).await, 2);
    }

    /// The purge role cannot update audit records or read audit streams;
    /// the refused statements leave the tenant's records intact.
    #[tokio::test]
    async fn the_purge_role_reaches_nothing_but_the_purge() {
        let (db, acme, _) = two_trails().await;

        let changed = ran(
            &db.audit_purge,
            RowScope::Tenant(acme),
            "UPDATE audit_records SET event_type = 'nothing'",
        )
        .await;
        let read = ran(
            &db.audit_purge,
            RowScope::Tenant(acme),
            "SELECT id FROM audit_streams",
        )
        .await;

        assert!(changed.is_err());
        assert!(read.is_err());
        assert_eq!(left(&db, acme).await, 2);
    }

    /// The app's role reads as sealed from the audit trail; the purge's,
    /// which may remove records, does not, so a start-up wired to the wrong
    /// role is caught.
    #[tokio::test]
    async fn only_the_apps_role_reads_as_sealed_from_the_trail() {
        let db = TestDb::fresh().await;

        let app = audit_sealed_from(&db.databases).await.unwrap();
        let purge = audit_sealed_from(&db.audit_purge).await.unwrap();

        assert!(app);
        assert!(!purge);
    }

    /// Giving the app and purge the same role name is refused before a
    /// database connection is attempted.
    #[tokio::test]
    async fn one_role_for_both_is_refused() {
        let owner = PgPool::connect_lazy("postgres://nobody@127.0.0.1:1/nothing").unwrap();
        let roles = PlatformRoles {
            app: LoginRole {
                name: "ianua_app",
                password: "one",
            },
            audit_purge: LoginRole {
                name: "ianua_app",
                password: "two",
            },
            gateway: None,
            nameserver: None,
        };

        let made = ensure_roles(&owner, &roles).await;

        assert!(matches!(made, Err(DomainError::Infrastructure(_))));
    }

    /// A gateway configured with the app's role name is refused before a
    /// database connection is attempted.
    #[tokio::test]
    async fn the_gateway_as_another_role_is_refused() {
        let owner = PgPool::connect_lazy("postgres://nobody@127.0.0.1:1/nothing").unwrap();
        let roles = PlatformRoles {
            app: LoginRole {
                name: "ianua_app",
                password: "one",
            },
            audit_purge: LoginRole {
                name: "ianua_audit_purge",
                password: "two",
            },
            gateway: Some(LoginRole {
                name: "ianua_app",
                password: "three",
            }),
            nameserver: None,
        };

        let made = ensure_roles(&owner, &roles).await;

        assert!(matches!(made, Err(DomainError::Infrastructure(_))));
    }

    /// Whether `ran` was refused for want of a privilege, not for any other
    /// fault of the statement.
    fn denied(ran: Result<u64, DomainError>) -> bool {
        ran.is_err_and(|error| causes(&error).contains("permission denied"))
    }

    /// The gateway cannot insert audit records or outbox events, or delete
    /// chain heads; all three fail for missing privileges and the trail remains.
    #[tokio::test]
    async fn the_gateway_role_never_writes_the_trail_or_the_outbox() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let record = ran(
            &db.gateway,
            scope,
            "INSERT INTO audit_records (id, tenant_id) \
             VALUES (gen_random_uuid(), current_setting('app.current_tenant_id')::uuid)",
        )
        .await;
        let queued = ran(
            &db.gateway,
            scope,
            "INSERT INTO event_outbox (tenant_id, record_id, queued_at) \
             VALUES (current_setting('app.current_tenant_id')::uuid, gen_random_uuid(), now())",
        )
        .await;
        let head = ran(&db.gateway, scope, "DELETE FROM audit_chain_heads").await;

        assert!(denied(record));
        assert!(denied(queued));
        assert!(denied(head));
        assert_eq!(left(&db, acme).await, 2);
    }

    /// Gateway privileges refuse route updates and deletion, tenant status
    /// changes and session activation.
    #[tokio::test]
    async fn the_gateway_role_changes_no_configuration() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let rerouted = ran(&db.gateway, scope, "UPDATE routes SET name = 'mine'").await;
        let removed = ran(&db.gateway, scope, "DELETE FROM routes").await;
        let reopened = ran(&db.gateway, scope, "UPDATE tenants SET status = 'active'").await;
        let signed_in = ran(
            &db.gateway,
            scope,
            "UPDATE sessions SET refresh_token_hash = 'mine'",
        )
        .await;

        assert!(denied(rerouted));
        assert!(denied(removed));
        assert!(denied(reopened));
        assert!(denied(signed_in));
    }

    /// The gateway judges an agent acting for an organization member, so it
    /// reads who the member is, whose member, in what role and status, and
    /// their tenant grants; never their address or password hash.
    #[tokio::test]
    async fn the_gateway_role_reads_a_members_reach_and_never_their_secrets() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let reach = ran(
            &db.gateway,
            scope,
            "SELECT id, organization_id, role, status FROM org_users",
        )
        .await;
        let grants = ran(&db.gateway, scope, "SELECT role_id FROM org_tenant_grants").await;
        let password = ran(&db.gateway, scope, "SELECT password_hash FROM org_users").await;
        let address = ran(&db.gateway, scope, "SELECT email FROM org_users").await;

        assert!(reach.is_ok(), "{reach:?}");
        assert!(grants.is_ok(), "{grants:?}");
        assert!(denied(password));
        assert!(denied(address));
    }

    /// The gateway cannot read password rows, private signing keys, audit
    /// records, its event inbox or stream records. Public keys, routes and
    /// classification rules remain readable.
    #[tokio::test]
    async fn the_gateway_role_reads_nothing_it_was_not_granted() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let passwords = ran(&db.gateway, scope, "SELECT tenant_id FROM user_passwords").await;
        let private_keys = ran(
            &db.gateway,
            scope,
            "SELECT private_key_sealed FROM signing_keys",
        )
        .await;
        let trail = ran(&db.gateway, scope, "SELECT id FROM audit_records").await;
        let inbox = ran(&db.gateway, scope, "SELECT id FROM gateway_events").await;
        assert_gateway_configuration_readable(&db.gateway, scope).await;
        let stream_records = ran(&db.gateway, scope, "SELECT id FROM stream_records").await;

        assert!(denied(passwords));
        assert!(denied(private_keys));
        assert!(denied(trail));
        assert!(denied(inbox));
        assert!(denied(stream_records));
    }

    /// The gateway can still read public keys, routes and classification rules.
    async fn assert_gateway_configuration_readable(gateway: &Databases, scope: RowScope) {
        let public_keys = ran(gateway, scope, "SELECT kid, public_key FROM signing_keys").await;
        let routes = ran(gateway, scope, "SELECT id FROM routes").await;
        let rules = ran(gateway, scope, "SELECT rules FROM classification_rule_sets").await;
        assert!(public_keys.is_ok());
        assert!(routes.is_ok());
        assert!(rules.is_ok());
    }

    /// The gateway may read a stream route's workflow setting but is
    /// refused access to its stored login password.
    #[tokio::test]
    async fn the_gateway_role_reads_no_stream_route_login() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let logins = ran(
            &db.gateway,
            scope,
            "SELECT login_password FROM stream_route_logins",
        )
        .await;
        let workflow_use = ran(&db.gateway, scope, "SELECT workflow_use FROM stream_routes").await;

        assert!(denied(logins));
        assert!(workflow_use.is_ok());
    }

    /// The gateway can read device ownership and status, while reading
    /// secret digests or all device columns is denied.
    #[tokio::test]
    async fn the_gateway_role_reads_only_the_standing_of_trusted_devices() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let digests = ran(
            &db.gateway,
            scope,
            "SELECT secret_hash FROM trusted_devices",
        )
        .await;
        let everything = ran(&db.gateway, scope, "SELECT * FROM trusted_devices").await;
        let standing = ran(
            &db.gateway,
            scope,
            "SELECT id, user_id, status FROM trusted_devices",
        )
        .await;

        assert!(denied(digests));
        assert!(denied(everything));
        assert!(standing.is_ok());
    }

    /// The gateway cannot read enrollment digests or alter connector keys
    /// or status. Reading link identity and recording last-seen time succeed.
    #[tokio::test]
    async fn the_gateway_role_reads_only_what_a_connector_link_is_judged_by() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let codes = ran(&db.gateway, scope, "SELECT code_hash FROM connectors").await;
        let rekeyed = ran(&db.gateway, scope, "UPDATE connectors SET public_key = 'x'").await;
        let revoked = ran(
            &db.gateway,
            scope,
            "UPDATE connectors SET status = 'revoked'",
        )
        .await;
        let judged = ran(
            &db.gateway,
            scope,
            "SELECT id, scope, public_key, status FROM connectors",
        )
        .await;
        let seen = ran(
            &db.gateway,
            scope,
            "UPDATE connectors SET last_seen_at = now() WHERE enrolled_at <= now()",
        )
        .await;

        assert!(denied(codes));
        assert!(denied(rekeyed));
        assert!(denied(revoked));
        assert!(judged.is_ok());
        assert!(seen.is_ok());
    }

    /// The gateway can read assertion signing keys but cannot insert,
    /// revoke or delete them.
    #[tokio::test]
    async fn the_gateway_role_reads_assertion_keys_and_writes_none() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Tenant(acme);

        let read = ran(
            &db.gateway,
            scope,
            "SELECT kid, private_key_sealed FROM assertion_keys",
        )
        .await;
        let planted = ran(
            &db.gateway,
            scope,
            "INSERT INTO assertion_keys \
             (tenant_id, kid, algorithm, public_key, private_key_sealed, status, created_at) \
             VALUES (current_setting('app.current_tenant_id')::uuid, 'mine', 'ES256', 'x', 'x', \
                     'revoked', now())",
        )
        .await;
        let retired = ran(
            &db.gateway,
            scope,
            "UPDATE assertion_keys SET status = 'revoked'",
        )
        .await;
        let removed = ran(&db.gateway, scope, "DELETE FROM assertion_keys").await;

        assert!(read.is_ok());
        assert!(denied(planted));
        assert!(denied(retired));
        assert!(denied(removed));
    }

    /// The gateway's role reads as sealed from the trail, as the app's
    /// does.
    #[tokio::test]
    async fn the_gateway_role_reads_as_sealed_from_the_trail() {
        let db = TestDb::fresh().await;

        assert!(audit_sealed_from(&db.gateway).await.unwrap());
    }

    /// A nameserver configured with the gateway's role name is refused
    /// before a database connection is attempted.
    #[tokio::test]
    async fn the_nameserver_as_another_role_is_refused() {
        let owner = PgPool::connect_lazy("postgres://nobody@127.0.0.1:1/nothing").unwrap();
        let roles = PlatformRoles {
            app: LoginRole {
                name: "ianua_app",
                password: "one",
            },
            audit_purge: LoginRole {
                name: "ianua_audit_purge",
                password: "two",
            },
            gateway: Some(LoginRole {
                name: "ianua_gateway",
                password: "three",
            }),
            nameserver: Some(LoginRole {
                name: "ianua_gateway",
                password: "four",
            }),
        };

        let made = ensure_roles(&owner, &roles).await;

        assert!(matches!(made, Err(DomainError::Infrastructure(_))));
    }

    /// The nameservers' role reads every zone, its records, and whether
    /// each claim was proved.
    #[tokio::test]
    async fn the_nameserver_role_reads_the_zones() {
        let db = TestDb::fresh().await;
        let scope = RowScope::Platform;

        let zones = ran(&db.nameserver, scope, "SELECT hostname FROM dns_zones").await;
        let records = ran(&db.nameserver, scope, "SELECT name FROM dns_records").await;
        let claims = ran(
            &db.nameserver,
            scope,
            "SELECT tenant_id, hostname, verified FROM domain_claims",
        )
        .await;

        assert!(zones.is_ok());
        assert!(records.is_ok());
        assert!(claims.is_ok());
    }

    /// Nameservers can read platform DNS settings and proofs, but cannot
    /// read certificate material, change DNS settings or delete proofs.
    #[tokio::test]
    async fn the_nameserver_reads_platform_dns_but_no_certificate_material() {
        let db = TestDb::fresh().await;
        let scope = RowScope::Platform;
        assert!(ran(&db.nameserver, scope, "SELECT root, tenant_id, readable, nameservers, address, changed_at FROM platform_certificates").await.is_ok());
        assert!(
            ran(
                &db.nameserver,
                scope,
                "SELECT root, value, expires_at FROM platform_dns_proofs"
            )
            .await
            .is_ok()
        );
        for statement in [
            "SELECT private_key FROM platform_certificates",
            "SELECT certificate_pem FROM platform_certificates",
            "UPDATE platform_certificates SET readable = true",
            "DELETE FROM platform_dns_proofs",
        ] {
            assert!(
                denied(ran(&db.nameserver, scope, statement).await),
                "{statement}"
            );
        }
    }

    /// Nameserver privileges refuse user, signing-key, audit and domain
    /// registration reads, along with DNS record insertion and zone deletion.
    #[tokio::test]
    async fn the_nameserver_role_reads_nothing_else_and_writes_nothing() {
        let (db, acme, _) = two_trails().await;
        let scope = RowScope::Platform;

        let users = ran(&db.nameserver, scope, "SELECT 1 FROM users").await;
        let keys = ran(&db.nameserver, scope, "SELECT kid FROM signing_keys").await;
        let trail = ran(&db.nameserver, scope, "SELECT id FROM audit_records").await;
        let registration = ran(&db.nameserver, scope, "SELECT domain_id FROM domain_claims").await;
        let written = ran(
            &db.nameserver,
            RowScope::Tenant(acme),
            "INSERT INTO dns_records (tenant_id, hostname, name, kind, ttl, record_values) \
             VALUES (current_setting('app.current_tenant_id')::uuid, 'a.example', \
             'a.example', 'A', 300, '{203.0.113.66}')",
        )
        .await;
        let removed = ran(&db.nameserver, scope, "DELETE FROM dns_zones").await;

        assert!(denied(users));
        assert!(denied(keys));
        assert!(denied(trail));
        assert!(denied(registration));
        assert!(denied(written));
        assert!(denied(removed));
    }

    /// The nameservers' role reads as sealed from the trail.
    #[tokio::test]
    async fn the_nameserver_role_reads_as_sealed_from_the_trail() {
        let db = TestDb::fresh().await;

        assert!(audit_sealed_from(&db.nameserver).await.unwrap());
    }
}
