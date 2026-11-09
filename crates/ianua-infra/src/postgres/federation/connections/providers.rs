//! A tenant's connections to outside identity providers, each with the
//! rules of its group mapping.
//!
//! The rules live in `connection_group_rules`, beside the connection's row,
//! so the role or group a rule gives is a link the database keeps. Saving a
//! connection writes both in one transaction.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{ConnectionSortField, ConnectionStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, GroupId, RoleId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{ConnectionColumns, ConnectionRecord, connections_from};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of a tenant's federation connections.
pub struct PgConnectionStore {
    databases: Arc<Databases>,
}

impl PgConnectionStore {
    /// A store keeping connections in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgConnectionStore {}

/// The records of the connections of `tenant_id` that `ids` names, in no
/// order.
async fn records_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<ConnectionRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ConnectionRecord,
        "queries/federation_connections/by_ids.sql",
        tenant_id,
        ids
    )
    .fetch_all(connection)
    .await
}

/// Writes the connection `columns` describe, and puts exactly its rules
/// on it.
async fn write_connection(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &ConnectionColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/federation_connections/save.sql",
        columns.id,
        tenant_id,
        columns.provider_name,
        columns.status,
        columns.saml,
        columns.oidc,
        columns.jit_provisioning,
        columns.jit_default_role_id,
        columns.email_trust,
        columns.assurance_trust,
        columns.domain_hint,
        &columns.allowed_domains,
        &columns.mapped_claims,
        &columns.mapped_fields,
        columns.group_claim,
        columns.created_at,
        columns.keyed_at,
    )
    .execute(&mut *connection)
    .await?;
    replace_rules(connection, tenant_id, columns).await
}

/// Puts exactly the group mapping rules of `columns` on the connection.
async fn replace_rules(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &ConnectionColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/connection_group_rules/withdraw.sql",
        tenant_id,
        columns.id
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/connection_group_rules/give.sql",
        tenant_id,
        columns.id,
        &columns.rules.groups,
        &columns.rules.kinds,
        &columns.rules.grants,
    )
    .execute(connection)
    .await?;
    Ok(())
}

impl SortColumns for ConnectionSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::ProviderName => "provider_name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl ConnectionStore for PgConnectionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConnectionId,
    ) -> Result<Option<FederatedIdpConnection<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(connections_from(records)?.pop())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<ConnectionStatus>,
        sort: &SortOrder<ConnectionSortField>,
        page: &PageRequest,
    ) -> Result<Page<FederatedIdpConnection<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "federation_connections")
            .filter("tenant_id = ?", *tenant_id.as_uuid());
        let listed = match status {
            None => listed,
            Some(status) => listed.filter("status = ?", status.word()),
        };
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(connections_from(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ConnectionColumns::of(connection)?;
        scoped(&self.databases, RowScope::from(tenant_id), async |db| {
            write_connection(db, tenant_id.as_uuid(), &columns).await
        })
        .await
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConnectionId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/federation_connections/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn count_naming_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/federation_connections/naming_role.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn count_naming_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/connection_group_rules/naming_group.sql",
                    tenant_id.as_uuid(),
                    group_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::authorization::{GroupStore, RoleStore};
    use ianua_domain::domains::federation::connection::{
        ConnectionRow, EmailTrust, GroupMapping, GroupRule, GroupRules, JitProvisioning,
        MappedGrant, ProfileField, ProviderGroupName,
    };
    use ianua_domain::types::{DomainName, GroupId, Label, RoleId, Setting};

    use super::*;
    use crate::postgres::authorization::{PgGroupStore, PgRoleStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{group, role, tenant};
    use crate::test_support::rows::federation::{connection_row, oidc_config, saml_config};

    struct Fixture {
        db: TestDb,
        store: PgConnectionStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep
    /// connections in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgConnectionStore::new(Arc::clone(&db.databases)),
            tenant: tenant(),
            db,
        }
    }

    fn connection(row: ConnectionRow) -> FederatedIdpConnection<ResolvedTenant> {
        FederatedIdpConnection::reconstitute(row).unwrap()
    }

    impl Fixture {
        /// Counts connections naming this role within the selected tenant.
        async fn naming_role(&self, tenant: &ScopedTenant, role: &RoleId) -> u64 {
            self.store.count_naming_role(tenant, role).await.unwrap()
        }

        async fn save_all(&self, connections: &[&FederatedIdpConnection<ResolvedTenant>]) {
            for connection in connections {
                self.store.save(&self.tenant, connection).await.unwrap();
            }
        }

        async fn found(&self, id: &ConnectionId) -> FederatedIdpConnection<ResolvedTenant> {
            self.store
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .unwrap()
        }

        /// A role and a group of the tenant, kept through their stores.
        async fn a_role_and_a_group(&self) -> (RoleId, GroupId) {
            let reviewer = role("reviewer");
            let engineering = group("engineering", Vec::new());
            PgRoleStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &reviewer)
                .await
                .unwrap();
            PgGroupStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &engineering)
                .await
                .unwrap();
            (*reviewer.id(), *engineering.id())
        }

        async fn names(&self, sort: Sort<ConnectionSortField>, page: &PageRequest) -> Vec<String> {
            let page = self
                .store
                .list_all(&self.tenant, None, &SortOrder::single(sort), page)
                .await
                .unwrap();
            names(&page)
        }
    }

    fn names(page: &Page<FederatedIdpConnection<ResolvedTenant>>) -> Vec<String> {
        page.items
            .iter()
            .map(|connection| connection.provider_name().as_str().to_owned())
            .collect()
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn domain(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    fn label(text: &str) -> Label {
        Label::new("claim", text).unwrap()
    }

    /// Assigns each grant its own numbered provider group on the groups claim.
    fn numbered_group_rules(grants: Vec<MappedGrant>) -> GroupMapping {
        let named = grants
            .into_iter()
            .enumerate()
            .map(|(at, grant)| GroupRule {
                provider_group: ProviderGroupName::new(format!("okta-{at}")).unwrap(),
                grant,
            })
            .collect();
        GroupMapping::On(GroupRules::new(label("groups"), named).unwrap())
    }

    /// Maps Okta's reviewer and engineering groups to the saved tenant grants.
    fn okta_group_rules(reviewer: RoleId, engineering: GroupId) -> GroupRules {
        GroupRules::new(
            label("groups"),
            vec![
                GroupRule {
                    provider_group: ProviderGroupName::new("okta-reviewers").unwrap(),
                    grant: MappedGrant::Role(reviewer),
                },
                GroupRule {
                    provider_group: ProviderGroupName::new("okta-engineering").unwrap(),
                    grant: MappedGrant::Group(engineering),
                },
            ],
        )
        .unwrap()
    }

    /// Okta gives new accounts "reviewer" and maps a group to
    /// "engineering"; a second connection maps a group to "reviewer" too.
    /// Each role and group counts the connections that hand it out, once
    /// each, and another tenant counts none.
    #[tokio::test]
    async fn the_connections_naming_a_role_or_group_are_counted() {
        let fx = fixture().await;
        let (reviewer, engineering) = fx.a_role_and_a_group().await;
        let okta = connection(ConnectionRow {
            jit_provisioning: JitProvisioning::Enabled,
            jit_default_role_id: Setting::Set(reviewer),
            group_mapping: numbered_group_rules(vec![
                MappedGrant::Role(reviewer),
                MappedGrant::Group(engineering),
            ]),
            ..connection_row("Okta", saml_config())
        });
        let entra = connection(ConnectionRow {
            group_mapping: numbered_group_rules(vec![MappedGrant::Role(reviewer)]),
            ..connection_row("Entra", oidc_config())
        });
        fx.save_all(&[&okta, &entra]).await;

        let for_reviewer = fx.naming_role(&fx.tenant, &reviewer).await;
        let for_engineering = fx
            .store
            .count_naming_group(&fx.tenant, &engineering)
            .await
            .unwrap();
        let elsewhere = fx.naming_role(&tenant(), &reviewer).await;

        assert_eq!((for_reviewer, for_engineering, elsewhere), (2, 1, 0));
    }

    /// Okta over SAML, making accounts with a role, vouching for two
    /// domains, filling the display name from a claim and mapping two of
    /// its groups, is found by its id as it was saved.
    #[tokio::test]
    async fn a_saml_connection_is_found_as_it_was_saved() {
        let fx = fixture().await;
        let (reviewer, engineering) = fx.a_role_and_a_group().await;
        let rules = okta_group_rules(reviewer, engineering);
        let okta = connection(ConnectionRow {
            jit_provisioning: JitProvisioning::Enabled,
            jit_default_role_id: Setting::Set(reviewer),
            email_trust: EmailTrust::Authoritative,
            domain_hint: Setting::Set(domain("acme.example")),
            allowed_domains: vec![domain("acme.example"), domain("acme.io")],
            attribute_mapping: HashMap::from([(label("name"), ProfileField::DisplayName)]),
            group_mapping: GroupMapping::On(rules),
            keyed_at: at(5),
            ..connection_row("Okta", saml_config())
        });

        fx.save_all(&[&okta]).await;

        let found = fx.found(okta.id()).await;
        assert_eq!(found.provider_name(), okta.provider_name());
        assert_eq!(found.config(), okta.config());
        assert_eq!(found.jit_provisioning(), JitProvisioning::Enabled);
        assert_eq!(found.jit_default_role_id(), Some(&reviewer));
        assert_eq!(found.email_trust(), EmailTrust::Authoritative);
        assert_eq!(found.domain_hint(), okta.domain_hint());
        assert_eq!(found.allowed_domains(), okta.allowed_domains());
        assert_eq!(found.attribute_mapping(), okta.attribute_mapping());
        assert_eq!(found.group_mapping(), okta.group_mapping());
        assert_eq!(found.keyed_at(), at(5));
    }

    /// Google over OIDC reads back with its sealed client secret, and with
    /// no mapping at all.
    #[tokio::test]
    async fn an_oidc_connection_is_found_as_it_was_saved() {
        let fx = fixture().await;
        let google = connection(connection_row("Google", oidc_config()));

        fx.save_all(&[&google]).await;

        let found = fx.found(google.id()).await;
        assert_eq!(found.config(), google.config());
        assert_eq!(found.group_mapping(), &GroupMapping::Off);
        assert!(found.attribute_mapping().is_empty());
    }

    /// An id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_connection_is_not_found() {
        let fx = fixture().await;

        let found = fx.store.find_by_id(&fx.tenant, &ConnectionId::new()).await;

        assert!(found.unwrap().is_none());
    }

    /// Globex cannot find or list Acme's connection, and deleting its ID
    /// from Globex leaves it readable in Acme.
    #[tokio::test]
    async fn another_tenants_connection_is_out_of_reach() {
        let fx = fixture().await;
        let okta = connection(connection_row("Okta", saml_config()));
        fx.save_all(&[&okta]).await;
        let globex = tenant();

        let by_id = fx.store.find_by_id(&globex, okta.id()).await.unwrap();
        let listed = fx
            .store
            .list_all(&globex, None, &SortOrder::default(), &first(10))
            .await
            .unwrap();
        fx.store.delete(&globex, okta.id()).await.unwrap();

        assert!(by_id.is_none());
        assert!(listed.items.is_empty());
        assert_eq!(fx.found(okta.id()).await.id(), okta.id());
    }

    /// Acme's connections are read newest first page by page: each page
    /// follows the last, and the last says nothing follows.
    #[tokio::test]
    async fn a_list_is_read_page_by_page_newest_first() {
        let fx = fixture().await;
        let [okta, entra, google] =
            [("Okta", 0), ("Entra", 10), ("Google", 20)].map(|(name, created)| {
                connection(ConnectionRow {
                    created_at: at(created),
                    keyed_at: at(created),
                    ..connection_row(name, oidc_config())
                })
            });
        fx.save_all(&[&okta, &entra, &google]).await;
        let order = SortOrder::default();

        let page_one = fx
            .store
            .list_all(&fx.tenant, None, &order, &first(2))
            .await
            .unwrap();
        let page_two = fx
            .store
            .list_all(
                &fx.tenant,
                None,
                &order,
                &PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(names(&page_one), ["Google", "Entra"]);
        assert_eq!(names(&page_two), ["Okta"]);
        assert!(!page_two.has_next());
    }

    /// Sorted by name, and by status, the list follows the stored words.
    #[tokio::test]
    async fn a_list_is_sorted_by_name_and_by_status() {
        let fx = fixture().await;
        let okta = connection(connection_row("Okta", oidc_config()));
        let entra = connection(ConnectionRow {
            status: ConnectionStatus::Disabled,
            ..connection_row("Entra", oidc_config())
        });
        fx.save_all(&[&okta, &entra]).await;

        let by_name = fx
            .names(
                Sort::ascending(ConnectionSortField::ProviderName),
                &first(10),
            )
            .await;
        let by_status = fx
            .names(Sort::ascending(ConnectionSortField::Status), &first(10))
            .await;

        assert_eq!(by_name, ["Entra", "Okta"]);
        assert_eq!(by_status, ["Okta", "Entra"]);
    }

    /// A list kept to disabled connections shows only those.
    #[tokio::test]
    async fn a_list_narrows_by_status() {
        let fx = fixture().await;
        let okta = connection(connection_row("Okta", oidc_config()));
        let entra = connection(ConnectionRow {
            status: ConnectionStatus::Disabled,
            ..connection_row("Entra", oidc_config())
        });
        fx.save_all(&[&okta, &entra]).await;

        let disabled = fx
            .store
            .list_all(
                &fx.tenant,
                Some(ConnectionStatus::Disabled),
                &SortOrder::default(),
                &first(10),
            )
            .await
            .unwrap();

        assert_eq!(names(&disabled), ["Entra"]);
    }

    /// An admin renames Okta and stops mapping its groups: saving again
    /// keeps the new name, drops the rules, and keeps when it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let (reviewer, _) = fx.a_role_and_a_group().await;
        let rules = GroupRules::new(
            label("groups"),
            vec![GroupRule {
                provider_group: ProviderGroupName::new("okta-reviewers").unwrap(),
                grant: MappedGrant::Role(reviewer),
            }],
        )
        .unwrap();
        let okta = connection(ConnectionRow {
            group_mapping: GroupMapping::On(rules),
            ..connection_row("Okta", saml_config())
        });
        fx.save_all(&[&okta]).await;
        let renamed = connection(ConnectionRow {
            id: *okta.id(),
            provider_name: Label::new("provider_name", "Okta EU").unwrap(),
            ..connection_row("Okta", saml_config())
        });

        fx.save_all(&[&renamed]).await;

        let found = fx.found(okta.id()).await;
        assert_eq!(found.provider_name().as_str(), "Okta EU");
        assert_eq!(found.group_mapping(), &GroupMapping::Off);
        assert_eq!(found.created_at(), okta.created_at());
    }

    /// A removed connection is gone, and removing it again is no error.
    #[tokio::test]
    async fn a_deleted_connection_is_gone() {
        let fx = fixture().await;
        let okta = connection(connection_row("Okta", saml_config()));
        fx.save_all(&[&okta]).await;

        fx.store.delete(&fx.tenant, okta.id()).await.unwrap();
        fx.store.delete(&fx.tenant, okta.id()).await.unwrap();

        let found = fx.store.find_by_id(&fx.tenant, okta.id()).await.unwrap();
        assert!(found.is_none());
    }

    /// A connection with an empty stored provider name fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_connection_is_refused() {
        let fx = fixture().await;
        let okta = connection(connection_row("Okta", saml_config()));
        fx.save_all(&[&okta]).await;
        fx.db
            .tamper("UPDATE federation_connections SET provider_name = ''")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, okta.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A connection mapping a claim to the unsupported profile field
    /// `email` fails to load as corrupt storage.
    #[tokio::test]
    async fn an_unknown_profile_field_is_refused() {
        let fx = fixture().await;
        let okta = connection(ConnectionRow {
            attribute_mapping: HashMap::from([(label("name"), ProfileField::DisplayName)]),
            ..connection_row("Okta", saml_config())
        });
        fx.save_all(&[&okta]).await;
        fx.db
            .tamper("UPDATE federation_connections SET mapped_fields = ARRAY['email']")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, okta.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
