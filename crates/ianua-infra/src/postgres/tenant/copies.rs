//! Copies one part of a tenant's setup into another tenant of its
//! organization, as a step of a clone: the copier of `ports/tenant.rs`.
//!
//! Each part is read whole from the source through the stores of its own
//! context and written over the target through the same stores, so every
//! row passes the domain's checks on the way in and out, and each side runs
//! under its own tenant's row security in whichever database it lives in.
//! Users, sessions, signing keys and secrets are never read: roles come
//! without who holds them, groups without their members, and OAuth
//! applications without their secrets.
//!
//! A part copied again replaces what the first copy wrote. A record is
//! matched in the target by what names it there (a role, group, pipeline,
//! service or route by its name, an application by its public client id, a
//! template by its slot), so a worker that stopped half-way, or a second
//! clone into the same tenant, writes over the copy it made before instead
//! of adding another. Nothing is written until the whole part is read: a
//! source holding more of a part than one copy carries is refused before
//! the target is touched.

mod access;
mod applications;
mod branding;
mod routes;
mod rules;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Limit, Page, PageRequest};
use ianua_app::ports::oauth::ClientSecretGenerator;
use ianua_app::ports::tenant::ClonePartCopier;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::tenant::clone::{ClonePart, TenantClone};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::tenant::copies::access::AccessCopy;
use crate::postgres::tenant::copies::applications::ApplicationCopy;
use crate::postgres::tenant::copies::branding::BrandingCopy;
use crate::postgres::tenant::copies::routes::RouteCopy;

/// The most records of one kind a copy carries: past any plan's ceiling,
/// so a source at its limit is copied whole.
const COPIED_AT_MOST: u32 = 5_000;

/// The two tenants of a clone, each as the stores reach it.
pub(crate) struct Pair {
    /// The tenant copied from.
    pub(crate) source: ScopedTenant,
    /// The tenant filled.
    pub(crate) target: ScopedTenant,
}

impl Pair {
    /// The tenants `clone` copies between. The clone vouches for both: it
    /// was started by someone who may make tenants in their organization.
    fn of(clone: &TenantClone) -> Self {
        Self {
            source: ScopedTenant::for_background(*clone.source()),
            target: ScopedTenant::for_background(*clone.target()),
        }
    }
}

/// The one page every read of a part asks for.
pub(crate) fn whole_part() -> PageRequest {
    PageRequest::first(Limit::internal(COPIED_AT_MOST))
}

/// The records of `page`, refused when more follow, so a part is never
/// copied in half.
///
/// # Errors
///
/// Returns `DomainError::Conflict` when the tenant holds more `what` than
/// one copy carries.
pub(crate) fn all_of<T>(page: Page<T>, what: &str) -> Result<Vec<T>, DomainError> {
    if page.has_next() {
        return Err(DomainError::conflict(message!(
            "infra-the-source-tenant-holds-more-than",
            format!("the source tenant holds more {what} than one clone copies")
        )));
    }
    Ok(page.items)
}

/// The Postgres copier of the parts of a clone.
pub struct PgClonePartCopier {
    branding: BrandingCopy,
    access: AccessCopy,
    routes: RouteCopy,
    applications: ApplicationCopy,
}

impl PgClonePartCopier {
    /// A copier reading and writing the tenants of `databases`, giving each
    /// confidential OAuth application it copies a secret of its own from
    /// `client_secrets`.
    #[must_use]
    pub fn new(databases: &Arc<Databases>, client_secrets: Arc<dyn ClientSecretGenerator>) -> Self {
        Self {
            branding: BrandingCopy::new(databases),
            access: AccessCopy::new(databases),
            routes: RouteCopy::new(databases),
            applications: ApplicationCopy::new(databases, client_secrets),
        }
    }
}

#[async_trait]
impl ClonePartCopier for PgClonePartCopier {
    async fn copy(&self, clone: &TenantClone, part: ClonePart) -> Result<(), DomainError> {
        let pair = Pair::of(clone);
        match part {
            ClonePart::Settings => Err(DomainError::invalid(message!(
                "infra-a-tenant-s-settings-are-copied",
                "a tenant's settings are copied through the tenant itself"
            ))),
            ClonePart::Branding => self.branding.copy(&pair).await,
            ClonePart::RolesAndPolicies => self.access.copy(&pair).await,
            ClonePart::Routes => self.routes.copy(&pair).await,
            ClonePart::OAuthApplications => self.applications.copy(&pair).await,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_app::listing::{Cursor, SortOrder};
    use ianua_app::ports::authorization::{RoleSortField, RoleStore as _};
    use ianua_domain::domains::tenant::clone::{CloneState, TenantCloneRow};
    use ianua_domain::types::{OrganizationId, TenantCloneId, TenantId};

    use super::*;
    use crate::crypto::HmacClientSecretGenerator;
    use crate::crypto::keys::tests::test_root;
    use crate::postgres::authorization::PgRoleStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::role;

    /// A clone copying every part from one new tenant into another.
    pub(crate) fn clone_between(source: TenantId, target: TenantId) -> TenantClone {
        TenantClone::reconstitute(TenantCloneRow {
            id: TenantCloneId::new(),
            organization_id: OrganizationId::new(),
            source,
            target,
            parts: ClonePart::ALL.to_vec(),
            copied: Vec::new(),
            state: CloneState::Copying,
            started_at: at(0),
        })
        .unwrap()
    }

    /// A copier over `db`, with secrets from a fixed root.
    pub(crate) fn copier(db: &TestDb) -> PgClonePartCopier {
        PgClonePartCopier::new(
            &db.databases,
            Arc::new(HmacClientSecretGenerator::new(&test_root())),
        )
    }

    /// Asking the part copier to copy tenant settings returns a validation
    /// error because the tenant owns that step.
    #[tokio::test]
    async fn the_settings_are_refused() {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());

        let copied = copier(&db).copy(&clone, ClonePart::Settings).await;

        assert!(matches!(copied, Err(DomainError::Validation(_))));
    }

    /// A source page with a continuation cursor is rejected as an incomplete
    /// part with a conflict error.
    #[test]
    fn a_source_past_the_copy_ceiling_is_refused_whole() {
        let page: Page<u8> = Page {
            items: vec![1],
            next: Some(Cursor::at(
                &SortOrder::<RoleSortField>::default(),
                Vec::new(),
            )),
            limit: Limit::internal(1),
        };

        assert!(matches!(
            all_of(page, "roles"),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A part copied into a tenant leaves the source as it was.
    #[tokio::test]
    async fn copying_leaves_the_source_alone() {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        let source = ScopedTenant::for_background(*clone.source());
        let roles = PgRoleStore::new(Arc::clone(&db.databases));
        roles.save(&source, &role("auditor")).await.unwrap();

        copier(&db)
            .copy(&clone, ClonePart::RolesAndPolicies)
            .await
            .unwrap();

        let page = roles
            .list_all(&source, &SortOrder::default(), &whole_part())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
    }
}
