//! Who a tenant's mail is addressed under: the tenant's and its
//! organization's names, which every template may show.
//!
//! They are filled in here, once, so no use case can leave them out. A name
//! the use case gave already is kept: it may have chosen a better one.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use ianua_app::ports::organization::OrganizationStore;
use ianua_app::ports::tenant::TenantStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::email_template::TemplateVariable;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::errors::DomainError;

/// The names a tenant's mail is addressed under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AudienceNames {
    /// The tenant's display name.
    pub(crate) tenant: Option<String>,
    /// Its organization's display name.
    pub(crate) organization: Option<String>,
}

impl AudienceNames {
    /// `values` with the tenant's and the organization's names added where
    /// they were not given.
    pub(crate) fn fill(
        &self,
        mut values: HashMap<TemplateVariable, String>,
    ) -> HashMap<TemplateVariable, String> {
        for (variable, name) in [
            (TemplateVariable::TenantName, &self.tenant),
            (TemplateVariable::OrganizationName, &self.organization),
        ] {
            let Some(name) = name else {
                continue;
            };
            values.entry(variable).or_insert_with(|| name.clone());
        }
        values
    }
}

/// Reads the names a tenant's mail is addressed under.
pub struct MailAudience {
    tenants: Arc<dyn TenantStore>,
    organizations: Arc<dyn OrganizationStore>,
}

impl fmt::Debug for MailAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailAudience").finish_non_exhaustive()
    }
}

impl MailAudience {
    /// An audience reading tenants from `tenants` and their organizations
    /// from `organizations`.
    #[must_use]
    pub fn new(tenants: Arc<dyn TenantStore>, organizations: Arc<dyn OrganizationStore>) -> Self {
        Self {
            tenants,
            organizations,
        }
    }

    /// The names `tenant`'s mail is addressed under, or none when the
    /// tenant is gone: its mail is not sent any more.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenant or its
    /// organization cannot be read.
    pub(crate) async fn names_of(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Option<AudienceNames>, DomainError> {
        let Some(found) = self.tenants.find_by_id(tenant).await? else {
            return Ok(None);
        };
        let addressed = match found.status() {
            TenantStatus::Deleted => return Ok(None),
            TenantStatus::Provisioning
            | TenantStatus::Active
            | TenantStatus::Suspended
            | TenantStatus::Archived => found,
        };
        let organization = self
            .organizations
            .find_by_id(addressed.organization_id())
            .await?;
        Ok(Some(AudienceNames {
            tenant: Some(addressed.display_name().as_str().to_owned()),
            organization: organization.map(|found| found.display_name().as_str().to_owned()),
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! The audience over a test database, and its own tests.

    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::organization_row;
    use crate::test_support::rows::tenant::{deleted_tenant_row, tenant_row};

    /// The audience reading `db`'s tenants and organizations.
    pub(crate) fn audience_over(db: &TestDb) -> MailAudience {
        MailAudience::new(
            Arc::new(PgTenantStore::new(
                Arc::clone(&db.databases),
                DomainLimits::default(),
            )),
            Arc::new(PgOrganizationStore::new(
                Arc::clone(&db.databases),
                DomainLimits::default(),
            )),
        )
    }

    /// Acme, a tenant of the organization Acme Corp, kept in `db` as `row`
    /// makes it.
    pub(crate) async fn acme(
        db: &TestDb,
        row: fn(OrganizationId, &str) -> TenantRow,
    ) -> ScopedTenant {
        let organization =
            Organization::reconstitute(organization_row("acme-corp", "Acme Corp")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let tenant = Tenant::reconstitute(row(*organization.id(), "acme")).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        ScopedTenant::for_background(*tenant.id())
    }

    /// Acme's mail is addressed under its own name and its organization's.
    #[tokio::test]
    async fn a_tenants_mail_is_addressed_under_both_names() {
        let db = TestDb::fresh().await;
        let tenant = acme(&db, tenant_row).await;

        let names = audience_over(&db).names_of(&tenant).await.unwrap().unwrap();

        assert_eq!(names.tenant.as_deref(), Some("acme"));
        assert_eq!(names.organization.as_deref(), Some("Acme Corp"));
    }

    /// Deleted and absent tenants have no audience names for addressing mail.
    #[tokio::test]
    async fn a_tenant_that_is_gone_is_addressed_under_nothing() {
        let db = TestDb::fresh().await;
        let deleted = acme(&db, deleted_tenant_row).await;
        let never = ScopedTenant::for_background(TenantId::new());
        let audience = audience_over(&db);

        assert!(audience.names_of(&deleted).await.unwrap().is_none());
        assert!(audience.names_of(&never).await.unwrap().is_none());
    }

    /// A name the use case gave is kept; a missing one is filled in.
    #[test]
    fn a_given_name_is_kept_and_a_missing_one_filled_in() {
        let names = AudienceNames {
            tenant: Some("acme".to_owned()),
            organization: Some("Acme Corp".to_owned()),
        };
        let given = HashMap::from([(TemplateVariable::OrganizationName, "Acme Inc".to_owned())]);

        let filled = names.fill(given);

        assert_eq!(
            filled
                .get(&TemplateVariable::TenantName)
                .map(String::as_str),
            Some("acme")
        );
        assert_eq!(
            filled
                .get(&TemplateVariable::OrganizationName)
                .map(String::as_str),
            Some("Acme Inc")
        );
    }
}
