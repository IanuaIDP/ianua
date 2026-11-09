//! What every seeding step works through: the use cases the API serves,
//! the stores they read, the organization being seeded, and its owner,
//! signed in once, the first time something is to be made, with the
//! authenticator app that sign-in set up.
//!
//! A step first looks for what it seeds and makes it only when it is not
//! there, so a run that finds everything never signs the owner in and
//! leaves no record at all. Whatever it makes, it makes as the owner, each
//! call kept in one unit with the records it raised, as the API keeps a
//! request. An organization session works in one tenant, so before acting
//! in another the owner's session moves there through the organization's
//! tenant switch, as the dashboard's does.

use std::future::Future;

use ianua_api::state::{ApiState, Deps};
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::{CallerContext, CallerIdentity, Credential, OrgCaller, OrgCredential};
use ianua_app::error::AppError;
use ianua_app::services::kept_together::kept_together;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::organization::sign_in::{SwitchOrgTenantPorts, SwitchOrgTenantUseCase};
use ianua_assembly::deps::{Adapters, Settings};
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::organization::access::session::SessionPlace;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{OrgUserId, OrganizationId, OtpauthUrl, TenantId, TenantSlug, UserAgent};
use tokio::sync::{Mutex, MutexGuard, OnceCell};

use crate::demo::owner::{self, Owner, OwnerSession};
use crate::demo::{DemoError, catalog};

/// The organization being seeded.
pub(super) struct DemoOrganization {
    /// The ownership boundary used when creating the demo's tenants and members.
    pub(super) id: OrganizationId,
    /// Its slug, which the owner's sign-in names.
    pub(super) slug: TenantSlug,
    /// Its plan's limits, as every tenant call carries them.
    pub(super) limits: PlanLimits,
}

/// A tenant of the organization.
pub(super) struct DemoTenant {
    /// The isolation boundary used for this tenant's seeded records.
    pub(super) id: TenantId,
    /// Its slug, which links into it name.
    pub(super) slug: TenantSlug,
}

impl DemoTenant {
    /// The tenant as its stores take it, for the seeder's lookups.
    pub(super) fn scoped(&self) -> ScopedTenant {
        ScopedTenant::for_background(self.id)
    }
}

/// The owner acting in one tenant, and what records it.
pub(super) struct InTenant {
    /// The owner, signed in, acting in the tenant.
    pub(super) caller: CallerContext,
    /// Records what they change there.
    pub(super) auditor: RequestAuditor,
}

/// The owner acting on the organization, and what records it.
pub(super) struct InOrganization {
    /// The owner, signed in.
    pub(super) caller: OrgCaller,
    /// Records what they change.
    pub(super) auditor: RequestAuditor,
}

/// Whether a step made what it seeds or found it there already.
pub(super) enum Seed<T> {
    /// Made just now.
    Made(T),
    /// There already.
    Found(T),
}

/// How many pieces a run made, and how many it found there already.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    /// Made by this run.
    pub made: u32,
    /// Found there already.
    pub found: u32,
}

impl Tally {
    /// Counts `seed`, and answers what it holds.
    pub(super) fn count<T>(&mut self, seed: Seed<T>) -> T {
        match seed {
            Seed::Made(value) => {
                self.made += 1;
                value
            }
            Seed::Found(value) => {
                self.found += 1;
                value
            }
        }
    }
}

/// Everything a seeding step works through.
pub(super) struct Seeder<'a> {
    /// The use cases, as the API serves them.
    pub(super) state: ApiState,
    /// The stores the steps look in before they make anything.
    pub(super) adapters: &'a Adapters,
    /// The deployment's settings.
    pub(super) settings: &'a Settings,
    /// The organization being seeded.
    pub(super) organization: DemoOrganization,
    /// What the seeder says it is, in every record it leaves.
    pub(super) user_agent: UserAgent,
    /// Moves the owner's session from tenant to tenant, as the dashboard's
    /// tenant switch does.
    switch: SwitchOrgTenantUseCase,
    owner: OnceCell<Mutex<Owner>>,
}

impl<'a> Seeder<'a> {
    /// A seeder of `organization` through the use cases `state` holds,
    /// which `deps` built.
    ///
    /// # Errors
    ///
    /// [`DemoError::Catalog`] when the seeder's own name does not read.
    pub(super) fn new(
        deps: &'a Deps,
        state: ApiState,
        organization: DemoOrganization,
    ) -> Result<Self, DemoError> {
        Ok(Self {
            state,
            adapters: &deps.adapters,
            settings: &deps.settings,
            organization,
            user_agent: UserAgent::new(catalog::USER_AGENT)?,
            switch: tenant_switch(&deps.adapters),
            owner: OnceCell::new(),
        })
    }

    /// The lengths and counts names are checked against.
    pub(super) fn limits(&self) -> &DomainLimits {
        &self.settings.domain_limits
    }

    /// Runs `work`, the making of `what`, as one unit with what it records.
    ///
    /// # Errors
    ///
    /// [`DemoError::Refused`] with what the use case answered.
    pub(super) async fn kept<T: Send>(
        &self,
        what: &'static str,
        work: impl Future<Output = Result<T, AppError>> + Send,
    ) -> Result<T, DemoError> {
        kept_together(self.adapters.unit_of_work.as_ref(), work)
            .await
            .map_err(|cause| DemoError::Refused { what, cause })
    }

    /// The owner acting on the organization.
    ///
    /// # Errors
    ///
    /// As [`owner::signed_in`], the first time.
    pub(super) async fn in_organization(&self) -> Result<InOrganization, DemoError> {
        let owner = self.owner().await?;
        Ok(self.on_organization(owner.member, owner.session))
    }

    /// The owner acting in `tenant`, their session moved into it first
    /// when it works elsewhere, as the dashboard moves it.
    ///
    /// # Errors
    ///
    /// As [`owner::signed_in`], the first time, and
    /// [`DemoError::Refused`] when the session cannot move into the tenant
    /// or does not fit a tenant call.
    pub(super) async fn in_tenant(&self, tenant: &DemoTenant) -> Result<InTenant, DemoError> {
        let mut owner = self.owner().await?;
        owner.session = self.moved_into(&owner, tenant).await?;
        let caller = CallerContext::new(
            CallerIdentity::OrgUser(owner.member),
            Credential::OrgSession(owner.session.id),
            self.organization.id,
            tenant.id,
            self.organization.limits.clone(),
        )
        .map_err(|cause| DemoError::Refused {
            what: "the owner's call into a tenant",
            cause,
        })?
        .with_request_metadata(None, Some(self.user_agent.clone()));
        Ok(InTenant {
            auditor: self.auditor(caller.audit_context()),
            caller,
        })
    }

    /// `member` acting on the organization through `session`.
    fn on_organization(&self, member: OrgUserId, session: OwnerSession) -> InOrganization {
        let credential = OrgCredential::Session(session.id);
        let caller = OrgCaller::new(member, credential, self.organization.id)
            .with_request_metadata(None, Some(self.user_agent.clone()));
        InOrganization {
            auditor: self.auditor(caller.audit_context()),
            caller,
        }
    }

    /// The session `owner` acts through in `tenant`: theirs when it works
    /// there already, else the one the organization's tenant switch moves
    /// it to, which ends the old one.
    async fn moved_into(
        &self,
        owner: &Owner,
        tenant: &DemoTenant,
    ) -> Result<OwnerSession, DemoError> {
        if owner.session.place == SessionPlace::Tenant(tenant.id) {
            return Ok(owner.session);
        }
        let acting = self.on_organization(owner.member, owner.session);
        let moved = self
            .kept(
                "the owner's move into a tenant",
                self.switch
                    .execute(&acting.caller, &acting.auditor, tenant.id),
            )
            .await?;
        Ok(OwnerSession {
            id: moved.session_id,
            place: SessionPlace::Tenant(moved.tenant_id),
        })
    }

    /// The owner, signed in the first time anything is to be made, locked
    /// while their session is read or moved.
    async fn owner(&self) -> Result<MutexGuard<'_, Owner>, DemoError> {
        let owner = self
            .owner
            .get_or_try_init(|| async { owner::signed_in(self).await.map(Mutex::new) })
            .await?;
        Ok(owner.lock().await)
    }

    /// The link of the authenticator app the owner set up as this run
    /// signed them in, or none when nobody signed in or none was owed.
    pub(super) fn into_authenticator(self) -> Option<OtpauthUrl> {
        self.owner.into_inner()?.into_inner().authenticator
    }

    /// Records under `context` through the platform's dispatcher.
    fn auditor(&self, context: AuditContext) -> RequestAuditor {
        RequestAuditor::new(self.adapters.event_dispatcher.clone(), context)
    }
}

/// The organization's tenant switch, moving a member's session through the
/// same ports the API's moves it through.
fn tenant_switch(a: &Adapters) -> SwitchOrgTenantUseCase {
    SwitchOrgTenantUseCase::new(SwitchOrgTenantPorts {
        sessions: a.org_session_store.clone(),
        grants: a.org_tenant_grant_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        org_actors: a.org_actors.clone(),
    })
}
