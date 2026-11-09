//! Founding: the one way an organization, its first tenant and its owner
//! come into existence together.
//!
//! Shared by public signup and by an installation creating its own
//! organization. They differ only in the charter the organization is made
//! under; the checks, the order things are saved in and the events are the
//! same, and keeping them in one place is what stops the two from drifting.
//!
//! The platform makes the first tenant, since nobody can act in an
//! organization that does not exist yet. The owner is made from the
//! [`Founding`] the organization's creation gave, so only a fresh
//! organization gets a first owner. Their address starts unverified, as
//! every new account's does: nobody creating it can vouch for a mailbox.

use std::sync::Arc;

use ianua_domain::message;

mod defaults;
mod names;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::verified_email::VerifiedEmail;
use ianua_domain::domains::identity::tokens::installation_setup::InstallationSetup;
use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::domains::organization::access::token::{
    NewOrgToken, OrgInstallationToken, OrgToken,
};
use ianua_domain::domains::organization::billing::payment::BillingCycle;
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::domains::organization::lifecycle::{
    CreateOrganizationParams, Founding, InstallationParams, Organization,
};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::{
    AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
};
use ianua_domain::domains::organization::slugs::ensure_organization_label;
use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
use ianua_domain::domains::tenant::hosts::PlatformLabel;
use ianua_domain::domains::tenant::lifecycle::{ProvisionTenantParams, Tenant};
use ianua_domain::domains::tenant::provisioning::infrastructure::TenantResidency;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::Validator;
use ianua_domain::types::{
    ActedBy, ActorRef, DisplayName, DomainName, Email, Label, Lifetime, Locale, OrgUserId,
    OrganizationId, PasswordHash, TenantId, TenantSlug, Timezone,
};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::authentication::CredentialBreachChecker;
use crate::ports::organization::{
    OrgSubscriptionStore, OrgTokenStore, OrgUserStore, OrganizationStore,
};
use crate::ports::runtime::SecureRandom;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::use_cases::onboarding::founding::defaults::invalid;
pub(super) use crate::use_cases::onboarding::founding::defaults::{
    locale_or_default, timezone_or_utc,
};
use crate::use_cases::onboarding::founding::names::slugify;
use crate::use_cases::organization::password_breach::ensure_password_unbreached;

/// How long an installation's setup token works: a day, the longest the
/// domain lets one live.
const SETUP_TOKEN_SECONDS: i64 = 86_400;

/// What a founder is told when another organization already holds the slug
/// their company name makes.
const COMPANY_NAME_TAKEN: &str = "company name already taken";

/// What a founder is told when the store refuses the first tenant's slug.
/// Tenant slugs are unique only within an organization, and a new one has
/// no tenant yet, so only a broken founding meets it.
const TENANT_NAME_TAKEN: &str = "tenant name already taken";

/// The tier every organization founded by its own founder lands on: by the
/// public sign-up, or by a member founding another.
///
/// Not a request field. It was, and since signup is unauthenticated and
/// takes no payment, anyone could ask for the top tier and be provisioned its
/// limits for free. Moving to another plan is a billing decision, made after
/// the organization exists.
pub(super) const SELF_SERVICE_PLAN: OrganizationPlan = OrganizationPlan::Free;

/// What an organization is founded as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charter {
    /// A customer of the hosted service, on this plan.
    Hosted(OrganizationPlan),
    /// The one organization of an installation its owner runs themselves.
    Installation,
}

/// The founder's address, and whether a link has proven it yet.
pub(crate) enum FounderAddress {
    /// Not proven yet: an installation's owner confirms it with the setup
    /// token.
    Unproven(Email),
    /// Proven by the sign-up link that came back to it.
    Proven(VerifiedEmail),
}

impl FounderAddress {
    /// The address itself.
    #[must_use]
    pub(crate) fn email(&self) -> &Email {
        match self {
            Self::Unproven(email) => email,
            Self::Proven(proof) => proof.as_email(),
        }
    }
}

/// Everything an organization is founded from.
pub(crate) struct FoundingRequest {
    /// Company name (used to derive org slug and display name).
    pub company_name: String,
    /// Tenant name (used to derive tenant slug and display name).
    pub tenant_name: String,
    /// Owner's email address, and whether it is proven yet.
    pub admin_address: FounderAddress,
    /// Owner's full name, shown in the dashboard.
    pub admin_display_name: DisplayName,
    /// The hash of the owner's password, checked by
    /// [`Founder::checked_password`].
    pub admin_password: PasswordHash,
    /// Timezone for the tenant (defaults to UTC).
    pub timezone: Option<Timezone>,
    /// Locale for the tenant (defaults to en-US).
    pub locale: Option<Locale>,
    /// What the organization is founded as.
    pub charter: Charter,
}

/// The setup token an installation's first owner confirms their address
/// with. It holds a secret, so it has no `Debug`.
pub enum SetupToken {
    /// Issued for an installation: the raw token, to show once to whoever
    /// ran the install.
    Issued(Secret),
    /// None for a hosted organization, whose owner confirms their address by
    /// mail.
    NotIssued,
}

/// What founding created.
pub struct Founded {
    /// The setup token for the first owner, when founding an installation.
    pub setup_token: SetupToken,
    /// The created organization's slug.
    pub org_slug: String,
    /// The created tenant's slug.
    pub tenant_slug: String,
    /// The owner's org user ID.
    pub admin_user_id: OrgUserId,
    /// The newly founded owner of the first tenant.
    pub organization_id: OrganizationId,
    /// The newly provisioned workspace under that organization.
    pub tenant_id: TenantId,
}

/// Ports founding writes through.
#[derive(ianua_macros::Fakes)]
pub struct FoundingPorts {
    /// Supplies independent randomness for the first tenant's address.
    pub random: Arc<dyn SecureRandom>,
    /// Organizations.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Their subscriptions, started with them.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Saves the initial workspace created during founding.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Organization members.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// The setup token an installation issues its first owner.
    pub setup_token_store: Arc<dyn OrgTokenStore<InstallationSetup>>,
    /// Makes the setup token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Looks the owner's password up in known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
}

/// The setup token a founding issued, before it is saved.
enum IssuedSetup {
    /// For an installation: the raw token and the token to store.
    Token {
        raw: Secret,
        token: OrgInstallationToken,
    },
    /// None for a hosted organization.
    Nothing,
}

/// Creates an organization, its first tenant and its owner.
pub struct Founder {
    hashing: PasswordHashing,
    limits: DomainLimits,
    compliance: ComplianceLimits,
    ports: FoundingPorts,
    platform_hosts: Vec<DomainName>,
}

/// The slugs and display names a founding request derives.
struct Names {
    org_slug: TenantSlug,
    tenant_slug: TenantSlug,
    org_label: Label,
    org_display_name: DisplayName,
    tenant_display_name: DisplayName,
}

/// Everything one founding makes, before it is saved.
struct Made {
    organization: Organization,
    subscription: OrgSubscription,
    tenant: Tenant,
    owner: OrgUser,
}

impl Founder {
    /// A founder hashing passwords through `hashing`, under `limits` and
    /// `compliance`, writing through `ports`.
    #[must_use]
    pub fn new(
        hashing: PasswordHashing,
        limits: DomainLimits,
        compliance: ComplianceLimits,
        ports: FoundingPorts,
    ) -> Self {
        Self {
            hashing,
            limits,
            compliance,
            ports,
            platform_hosts: Vec::new(),
        }
    }

    /// Reserves the deployment's own host labels when deriving organization
    /// slugs, in addition to the labels every deployment reserves.
    #[must_use]
    pub fn with_platform_hosts(mut self, hosts: Vec<DomainName>) -> Self {
        self.platform_hosts = hosts;
        self
    }

    /// The organization store, for callers that must look before founding.
    pub(super) fn org_store(&self) -> &Arc<dyn OrganizationStore> {
        &self.ports.org_store
    }

    /// Founds the organization `req` describes.
    ///
    /// The tenant starts in `Provisioning`; the `tenant.provisioned` event
    /// emitted here is what starts the workflow that activates it.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if another organization holds the company
    ///   name's slug, even one founded meanwhile, or the store refuses the
    ///   first tenant's slug. Another organization's tenant under the same
    ///   slug is no conflict: tenant slugs are unique only within an
    ///   organization.
    /// - `AppError::Domain` if a name or the password breaks the rules.
    /// - `AppError::Internal` on persistence, hashing or audit failure.
    pub(super) async fn found(
        &self,
        auditor: &RequestAuditor,
        req: &FoundingRequest,
    ) -> Result<Founded, AppError> {
        let names = self.names(req)?;
        self.ensure_unclaimed(&names.org_slug).await?;
        let (mut made, setup) = self.make(req, &names)?;
        self.save(&made).await?;
        let setup_token = self.saved_setup_token(setup).await?;
        let owner = ActorRef::OrgUser(*made.owner.id());
        auditor
            .dispatch_by(&owner, raised_in_order(&mut made))
            .await
            .or_internal()?;
        Ok(founded(&made, &names, setup_token))
    }

    /// Saves the organization, its subscription, its first tenant and its
    /// owner. A name the store refuses as taken, such as a company name
    /// another founding claimed meanwhile, is a conflict.
    async fn save(&self, made: &Made) -> Result<(), AppError> {
        self.ports
            .org_store
            .save(&made.organization)
            .await
            .or_conflict(message!(
                "onboarding-company-name-already-taken",
                COMPANY_NAME_TAKEN
            ))?;
        self.ports
            .subscriptions
            .save(&made.subscription)
            .await
            .or_internal()?;
        self.ports
            .tenant_store
            .save(&made.tenant)
            .await
            .or_conflict(message!(
                "onboarding-tenant-name-already-taken",
                TENANT_NAME_TAKEN
            ))?;
        self.ports
            .org_user_store
            .save(&made.owner)
            .await
            .or_internal()
    }

    /// Saves the setup token `setup` issued, handing back what the install
    /// shows.
    async fn saved_setup_token(&self, setup: IssuedSetup) -> Result<SetupToken, AppError> {
        match setup {
            IssuedSetup::Token { raw, token } => {
                self.ports
                    .setup_token_store
                    .save(&token)
                    .await
                    .or_internal()?;
                Ok(SetupToken::Issued(raw))
            }
            IssuedSetup::Nothing => Ok(SetupToken::NotIssued),
        }
    }

    /// The organization, its subscription, its first tenant and its owner,
    /// as the domain makes them, with the setup token an installation's
    /// owner gets. The subscription starts monthly; a plan with a trial
    /// starts trialing.
    ///
    /// The subscription is started and the token issued while the founding
    /// is still held: making the owner uses it up.
    fn make(&self, req: &FoundingRequest, names: &Names) -> Result<(Made, IssuedSetup), AppError> {
        let (mut organization, founding) = self.organization(req, names)?;
        let tenant = self.first_tenant(req, names, *organization.id())?;
        organization
            .add_tenant(&tenant, ActedBy::Platform)
            .map_err(AppError::from_domain)?;
        let subscription = OrgSubscription::start(&founding, &organization, BillingCycle::Monthly)
            .map_err(AppError::from_domain)?;
        let owner_id = OrgUserId::new();
        let setup = self.setup_token(req, &founding, owner_id)?;
        let owner = self.owner(req, &organization, founding, owner_id)?;
        let made = Made {
            organization,
            subscription,
            tenant,
            owner,
        };
        Ok((made, setup))
    }

    /// The setup token for the owner `owner_id`, when `req` founds an
    /// installation.
    fn setup_token(
        &self,
        req: &FoundingRequest,
        founding: &Founding,
        owner_id: OrgUserId,
    ) -> Result<IssuedSetup, AppError> {
        match req.charter {
            Charter::Hosted(_) => Ok(IssuedSetup::Nothing),
            Charter::Installation => self.installer_token(req, founding, owner_id),
        }
    }

    /// A fresh setup token for the installation's first owner, good for a
    /// day.
    fn installer_token(
        &self,
        req: &FoundingRequest,
        founding: &Founding,
        owner_id: OrgUserId,
    ) -> Result<IssuedSetup, AppError> {
        let generator = self.ports.token_generator.as_ref();
        let (raw, token_hash) = generator.generate().or_internal()?.into_parts();
        let new = NewOrgToken {
            token_hash,
            org_user_id: owner_id,
            sent_to: req.admin_address.email().clone(),
            lifetime: Lifetime::seconds(SETUP_TOKEN_SECONDS).map_err(invalid)?,
        };
        let token = OrgToken::for_installer(founding, new).map_err(AppError::from_domain)?;
        Ok(IssuedSetup::Token { raw, token })
    }

    /// The slugs and display names `req` derives.
    fn names(&self, req: &FoundingRequest) -> Result<Names, AppError> {
        self.names_of(&req.company_name, &req.tenant_name)
    }

    /// The slugs and display names a company and a tenant name derive.
    fn names_of(&self, company_name: &str, tenant_name: &str) -> Result<Names, AppError> {
        Ok(Names {
            org_slug: TenantSlug::new(slugify(company_name), &self.limits.slug).map_err(invalid)?,
            tenant_slug: TenantSlug::new(slugify(tenant_name), &self.limits.slug)
                .map_err(invalid)?,
            org_label: Label::new("name", company_name).map_err(invalid)?,
            org_display_name: DisplayName::new(company_name, &self.limits.display_name)
                .map_err(invalid)?,
            tenant_display_name: DisplayName::new(tenant_name, &self.limits.display_name)
                .map_err(invalid)?,
        })
    }

    /// Refuses names that make no slug, or a company name another
    /// organization already holds.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if a name makes no valid slug or name.
    /// - `AppError::Conflict` if the company name is taken.
    /// - `AppError::Internal` on lookup failure.
    pub(super) async fn ensure_names_free(
        &self,
        company_name: &str,
        tenant_name: &str,
    ) -> Result<(), AppError> {
        let names = self.names_of(company_name, tenant_name)?;
        self.ensure_unclaimed(&names.org_slug).await
    }

    /// Refuses a slug another organization holds.
    ///
    /// The owner's address is never refused: an address is unique within
    /// an organization, and a new one has no members yet, so a person who
    /// holds an account elsewhere founds another under the same address.
    async fn ensure_unclaimed(&self, slug: &TenantSlug) -> Result<(), AppError> {
        ensure_organization_label(slug, &self.platform_hosts).map_err(AppError::from_domain)?;
        let slug_taken = self.ports.org_store.slug_exists(slug).await.or_internal()?;
        if slug_taken {
            return Err(AppError::Conflict(COMPANY_NAME_TAKEN.to_owned().into()));
        }
        Ok(())
    }

    /// The new organization under `req`'s charter, with its founding.
    fn organization(
        &self,
        req: &FoundingRequest,
        names: &Names,
    ) -> Result<(Organization, Founding), AppError> {
        let params = InstallationParams {
            id: OrganizationId::new(),
            slug: names.org_slug.clone(),
            name: names.org_label.clone(),
            contact_email: req.admin_address.email().clone(),
            display_name: names.org_display_name.clone(),
        };
        match req.charter {
            Charter::Installation => {
                Organization::create_installation(params).map_err(AppError::from_domain)
            }
            Charter::Hosted(plan) => Organization::create(CreateOrganizationParams {
                id: params.id,
                slug: params.slug,
                name: params.name,
                contact_email: params.contact_email,
                display_name: params.display_name,
                plan,
            })
            .map_err(AppError::from_domain),
        }
    }

    /// The first tenant, made by the platform.
    ///
    /// Founding never asks where the data should live: somebody evaluating
    /// the product in five minutes should not be handed an infrastructure
    /// question. The tenant lands on the operator's default region and can
    /// move later.
    fn first_tenant(
        &self,
        req: &FoundingRequest,
        names: &Names,
        organization_id: OrganizationId,
    ) -> Result<Tenant, AppError> {
        let params = ProvisionTenantParams {
            id: TenantId::new(),
            platform_label: PlatformLabel::generate(&mut self.ports.random.as_ref())
                .map_err(AppError::from_domain)?,
            organization_id,
            slug: names.tenant_slug.clone(),
            display_name: names.tenant_display_name.clone(),
            contact_email: req.admin_address.email().clone(),
            timezone: timezone_or_utc(req.timezone.as_ref())?,
            locale: locale_or_default(req.locale.as_ref())?,
            residency: TenantResidency::shared_on_platform(self.compliance.default_region()),
        };
        Tenant::provision(params, &self.compliance, ActedBy::Platform)
            .map_err(AppError::from_domain)
    }

    /// The first owner, with their address confirmed when a link proved
    /// it.
    fn owner(
        &self,
        req: &FoundingRequest,
        organization: &Organization,
        founding: Founding,
        owner_id: OrgUserId,
    ) -> Result<OrgUser, AppError> {
        let params = CreateOrgUserParams {
            id: owner_id,
            organization_id: *organization.id(),
            email: req.admin_address.email().clone(),
            display_name: req.admin_display_name.clone(),
            password_hash: OrgPassword::Set(req.admin_password.clone()),
            role: OrgRole::Owner,
        };
        let mut owner =
            OrgUser::create(params, AddedBy::Founding(founding)).map_err(AppError::from_domain)?;
        if let FounderAddress::Proven(proof) = &req.admin_address {
            owner.verify_email(proof).or_internal()?;
        }
        Ok(owner)
    }

    /// The hash of `password`, once it keeps the password rules every new
    /// organization starts with and is not found in known breaches.
    ///
    /// A new organization blocks breached passwords, so the owner's, the
    /// most powerful account in it, is looked up like any password a member
    /// sets. A breach service that cannot be reached refuses it with a "try
    /// again", as it does for every password set under a block.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the password breaks the rules, appears in
    ///   known breaches, or could not be looked up.
    /// - `AppError::Busy` if no hash could start on this node in time.
    /// - `AppError::Internal` if it cannot be hashed.
    pub(super) async fn checked_password(&self, password: &str) -> Result<PasswordHash, AppError> {
        let rules = OrganizationAuthConfig::default();
        Validator::new("password", password)
            .password(&rules.settings().password_policy)
            .validate_first()
            .map_err(invalid)?;
        let checker = self.ports.breach_checker.as_ref();
        let secret = Secret::new(password.to_owned());
        ensure_password_unbreached(checker, rules.breached_passwords(), &secret).await?;
        let hasher = self.hashing.permitted().await?;
        hasher.hash(password).or_internal()
    }
}

/// What founding hands back once `made` is saved, with the setup token it
/// issued.
fn founded(made: &Made, names: &Names, setup_token: SetupToken) -> Founded {
    Founded {
        setup_token,
        org_slug: names.org_slug.as_str().to_owned(),
        tenant_slug: names.tenant_slug.as_str().to_owned(),
        admin_user_id: *made.owner.id(),
        organization_id: *made.organization.id(),
        tenant_id: *made.tenant.id(),
    }
}

/// What a founding raised, in the order it happened: the organization's
/// creation, its first tenant's provisioning, the organization taking the
/// tenant in, its subscription starting, and the owner's account.
///
/// The organization raised its creation and the tenant it took in, so the
/// tenant's provisioning goes between the two.
fn raised_in_order(made: &mut Made) -> Vec<DomainEvent> {
    let mut events = made.organization.take_events();
    let provisioned = made.tenant.take_events();
    let after_creation = events.len().min(1);
    events.splice(after_creation..after_creation, provisioned);
    events.extend(made.subscription.take_events());
    events.extend(made.owner.take_events());
    events
}
