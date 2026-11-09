//! List tenants: the tenants a member or an operator may see, filtered,
//! ordered and paged.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::organization::members::permission::{OrgPermission, TenantAction};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::setup::SetupStanding;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::context::{OperatorCaller, OrgCaller};
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::tenant::{TenantSetupStore, TenantSortField, TenantStore};
use crate::use_case::Query;
use crate::use_cases::tenant::lifecycle::reading::get::TenantRead;

/// Who lists tenants, and so which ones they see.
pub enum TenantLister {
    /// A member: every tenant of their organization when they may view the
    /// organization's tenants, else the ones they were granted.
    Member(OrgCaller),
    /// An operator, across the platform.
    Platform {
        /// The operator asking.
        caller: OperatorCaller,
        /// Only this organization's tenants, or every tenant when `None`.
        organization: Option<OrganizationId>,
    },
}

/// Which tenants to list, in what order, and which page.
pub struct ListTenantsRequest {
    /// Only tenants in this status, or every status when `None`.
    pub status: Option<TenantStatus>,
    /// The field and direction to order by.
    pub sort: SortOrder<TenantSortField>,
    /// Which page of the ordered tenants to return.
    pub page: PageRequest,
}

/// The ports [`ListTenantsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListTenantsPorts {
    /// Reads the workspaces visible to the authorized lister.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Each tenant's setup, read for the ones still provisioning.
    pub setup_store: Arc<dyn TenantSetupStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Pages through visible workspaces with their provisioning progress.
pub struct ListTenantsUseCase {
    ports: ListTenantsPorts,
}

/// The tenants a lister sees.
enum Visible {
    /// Every tenant of this organization.
    Organization(OrganizationId),
    /// The tenants granted to this member.
    GrantedTo(OrgUserId),
    /// Every tenant.
    All,
}

impl ListTenantsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListTenantsPorts) -> Self {
        Self { ports }
    }

    /// Which tenants `lister` sees, as the stored records prove them.
    async fn visible_to(&self, lister: &TenantLister) -> Result<Visible, AppError> {
        match lister {
            TenantLister::Member(caller) => {
                let (organization, actor) = self.ports.org_actors.actor(caller).await?;
                let sees_all = actor
                    .control()?
                    .ensure_may(
                        organization.id(),
                        OrgPermission::Tenants(TenantAction::View),
                    )
                    .is_ok();
                Ok(if sees_all {
                    Visible::Organization(*organization.id())
                } else {
                    Visible::GrantedTo(*actor.member().id())
                })
            }
            TenantLister::Platform {
                caller,
                organization,
            } => {
                self.ports.operator_authorities.authority(caller).await?;
                Ok(organization.map_or(Visible::All, Visible::Organization))
            }
        }
    }

    /// One page of the tenants `visible` names, in the order `req` asks.
    async fn listed(
        &self,
        visible: Visible,
        req: &ListTenantsRequest,
    ) -> Result<Page<Tenant>, AppError> {
        let store = self.ports.tenant_store.as_ref();
        let page = &req.page;
        match visible {
            Visible::Organization(id) => {
                store
                    .list_by_organization(&id, req.status, &req.sort, page)
                    .await
            }
            Visible::GrantedTo(member) => {
                store
                    .list_granted_to_org_user(&member, req.status, &req.sort, page)
                    .await
            }
            Visible::All => store.list_all(req.status, &req.sort, page).await,
        }
        .map_err(AppError::from_domain)
    }

    /// `page` with how each tenant's setup stands.
    async fn read(&self, page: Page<Tenant>) -> Result<Page<TenantRead>, AppError> {
        let Page { items, next, limit } = page;
        let ids: Vec<_> = items
            .iter()
            .filter(|tenant| SetupStanding::needs_setup(tenant))
            .map(|tenant| *tenant.id())
            .collect();
        let setups = if ids.is_empty() {
            Vec::new()
        } else {
            self.ports.setup_store.find_many(&ids).await.or_internal()?
        };
        let setups: HashMap<_, _> = setups
            .iter()
            .map(|setup| (*setup.tenant_id(), setup))
            .collect();
        let read = items
            .into_iter()
            .map(|tenant| TenantRead {
                setup: SetupStanding::of(&tenant, setups.get(tenant.id()).copied()),
                tenant,
            })
            .collect();
        Ok(Page {
            items: read,
            next,
            limit,
        })
    }
}

impl Query for ListTenantsUseCase {
    type Caller = TenantLister;
    type Input = ListTenantsRequest;
    type Output = Result<Page<TenantRead>, AppError>;

    /// One page of the tenants `lister` sees, in the order asked, each with
    /// how its setup stands. Only a tenant still provisioning has its setup
    /// read.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member's session or key is someone
    ///   else's, or the operator is disabled.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        lister: &TenantLister,
        req: ListTenantsRequest,
    ) -> Result<Page<TenantRead>, AppError> {
        let visible = self.visible_to(lister).await?;
        let page = self.listed(visible, &req).await?;
        self.read(page).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::setup::{SetupStanding, SetupStep, TenantSetup};
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold};
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::tenant::{
        FakeTenantSetupStore, FakeTenantStore, tenant_for_ctx_standing, test_tenant,
        test_tenant_for_ctx, test_tenant_in,
    };
    use crate::test_support::{block_on, test_ctx, test_org_caller};

    fn request(status: Option<TenantStatus>, page: PageRequest) -> ListTenantsRequest {
        ListTenantsRequest {
            status,
            sort: SortOrder::default(),
            page,
        }
    }

    fn listing(store: FakeTenantStore, ports: ListTenantsPorts) -> ListTenantsUseCase {
        ListTenantsUseCase::new(ListTenantsPorts {
            tenant_store: Arc::new(store),
            ..ports
        })
    }

    fn platform(organization: Option<OrganizationId>) -> TenantLister {
        TenantLister::Platform {
            caller: test_operator_caller(),
            organization,
        }
    }

    /// Lists with the supplied caller's visibility and page request.
    fn list(
        uc: &ListTenantsUseCase,
        lister: &TenantLister,
        req: ListTenantsRequest,
    ) -> Result<Page<TenantRead>, AppError> {
        block_on(uc.execute(lister, req))
    }

    /// Keeps a setup whose signing key could not be provisioned.
    fn setups_with_failed_signing_key(tenant: &Tenant) -> Arc<FakeTenantSetupStore> {
        let mut setup = TenantSetup::begin(tenant).unwrap();
        setup
            .fail(SetupStep::SigningKey, UntrustedText::record("unavailable"))
            .unwrap();
        let setups = Arc::new(FakeTenantSetupStore::empty());
        block_on(setups.save(&setup)).unwrap();
        setups
    }

    /// A mixed page reads only its provisioning setups, together, retaining
    /// a failed setup, an absent setup and an active tenant in page order.
    #[test]
    fn provisioning_setups_share_one_page_read() {
        let failed = test_tenant("failed", "failed.com");
        let missing = test_tenant("missing", "missing.com");
        let active = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let setups = setups_with_failed_signing_key(&failed);
        let expected_ids = vec![*failed.id(), *missing.id()];
        let uc = ListTenantsUseCase::new(ListTenantsPorts {
            setup_store: setups.clone(),
            ..ListTenantsPorts::fakes()
        });

        let page = block_on(uc.read(Page {
            items: vec![failed, active, missing],
            next: None,
            limit: Limit::new(3).unwrap(),
        }))
        .unwrap();

        assert!(matches!(
            page.items[0].setup,
            SetupStanding::Failed(SetupStep::SigningKey)
        ));
        assert!(matches!(page.items[1].setup, SetupStanding::Over));
        assert!(matches!(page.items[2].setup, SetupStanding::Running));
        assert_eq!(setups.reads(), [expected_ids]);
    }

    /// The platform has five tenants. Bob asks for three; he gets three
    /// and is told there are more.
    #[test]
    fn list_with_pagination() {
        let tenants = (0..5).map(|i| test_tenant(&format!("tenant{i}"), &format!("t{i}.com")));
        let uc = listing(
            FakeTenantStore::holding_all(tenants),
            ListTenantsPorts::fakes(),
        );

        let page = list(
            &uc,
            &platform(None),
            request(None, PageRequest::first(Limit::new(3).unwrap())),
        )
        .unwrap();

        assert_eq!(page.items.len(), 3);
        assert!(page.has_next());
    }

    /// One tenant is active, one still being provisioned. Asking for
    /// active ones lists only the first.
    #[test]
    fn filter_by_status() {
        let active = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let store = FakeTenantStore::holding_all([active, test_tenant("new", "p.com")]);
        let uc = listing(store, ListTenantsPorts::fakes());

        let page = list(
            &uc,
            &platform(None),
            request(Some(TenantStatus::Active), PageRequest::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Bob lists one organization's tenants. Another organization's are
    /// left out.
    #[test]
    fn filter_by_organization() {
        let acme = test_tenant("acme", "acme.com");
        let acme_org = *acme.organization_id();
        let store = FakeTenantStore::holding_all([acme, test_tenant("other", "other.com")]);
        let uc = listing(store, ListTenantsPorts::fakes());

        let page = list(
            &uc,
            &platform(Some(acme_org)),
            request(None, PageRequest::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Ann, an owner of Acme, lists its tenants. She sees Acme's and not
    /// another organization's.
    #[test]
    fn an_owner_sees_every_tenant_of_their_organization() {
        let store = FakeTenantStore::holding_all([
            test_tenant_for_ctx(),
            test_tenant("other", "other.com"),
        ]);
        let uc = listing(store, ListTenantsPorts::fakes());

        let page = list(
            &uc,
            &TenantLister::Member(test_org_caller()),
            request(None, PageRequest::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(*page.items[0].tenant.id(), test_ctx().tenant_id());
    }

    /// Sam, a plain member of Acme, was granted one of its two tenants. A
    /// member may still view every tenant of the organization, so he sees
    /// both; what he may do inside each is his grants' business.
    #[test]
    fn a_plain_member_sees_every_tenant_of_their_organization() {
        let other = test_tenant_in(test_ctx().organization_id(), "beta", "beta.com");
        let store = FakeTenantStore::holding_all([test_tenant_for_ctx(), other]);
        store.grant(*test_org_caller().member(), test_ctx().tenant_id());
        let uc = listing(
            store,
            ListTenantsPorts {
                org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
                ..ListTenantsPorts::fakes()
            },
        );

        let page = list(
            &uc,
            &TenantLister::Member(test_org_caller()),
            request(None, PageRequest::default()),
        )
        .unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// A signed-out organization member cannot list tenants.
    #[test]
    fn a_signed_out_member_is_refused() {
        let uc = listing(
            FakeTenantStore::empty(),
            ListTenantsPorts {
                org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
                ..ListTenantsPorts::fakes()
            },
        );

        let result = list(
            &uc,
            &TenantLister::Member(test_org_caller()),
            request(None, PageRequest::default()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator denied platform authority cannot list tenants.
    #[test]
    fn a_disabled_operator_is_refused() {
        let uc = listing(
            FakeTenantStore::empty(),
            ListTenantsPorts {
                operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(
                    Refusal::Forbidden,
                )),
                ..ListTenantsPorts::fakes()
            },
        );

        let result = list(&uc, &platform(None), request(None, PageRequest::default()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
