//! The demonstration organization and its owner: founded through the
//! install use case with its first tenant, the owner's address confirmed
//! with the setup token the founding issued, and the owner signed in with
//! their password the first time anything else is to be made, setting up
//! the authenticator app that sign-in owes.

use ianua_api::state::{ApiState, Deps};
use ianua_app::auditor::RequestAuditor;
use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::services::kept_together::kept_together;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::authentication::mfa::SetupProof;
use ianua_app::use_cases::onboarding::founding::SetupToken;
use ianua_app::use_cases::onboarding::{InstallRequest, Installation};
use ianua_app::use_cases::organization::mfa::OrgConfirmRequest;
use ianua_app::use_cases::organization::mfa::setter::{MemberFactorSetter, PendingMemberSession};
use ianua_app::use_cases::organization::sign_in::{
    LandedTenant, OrgLoginOutcome, OrgLoginSuccess, OrgPasswordLoginRequest, OrganizationChoice,
};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::organization::access::session::SessionPlace;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DisplayName, Email, Fact, OrgUserId, OrganizationId, OtpauthUrl, SessionId, TenantSlug,
};
use ianua_infra::crypto::TotpMfaVerifier;

use crate::demo::seeder::{DemoOrganization, Seed, Seeder};
use crate::demo::{DemoError, catalog};
use crate::install::install_use_case;

/// The owner, signed in.
#[derive(Debug)]
pub(super) struct Owner {
    /// Their account.
    pub(super) member: OrgUserId,
    /// The session they act through now.
    pub(super) session: OwnerSession,
    /// The link of the authenticator app set up as they signed in, to show
    /// once, or none when the sign-in owed none.
    pub(super) authenticator: Option<OtpauthUrl>,
}

/// The session the owner acts through, and where it works. Moving into
/// another tenant swaps it for a new one.
#[derive(Debug, Clone, Copy)]
pub(super) struct OwnerSession {
    /// The session.
    pub(super) id: SessionId,
    /// Where it works.
    pub(super) place: SessionPlace,
}

/// The demonstration organization: found by its slug, or founded with its
/// first tenant and owner, and the owner confirmed, all in one unit.
///
/// # Errors
///
/// - [`DemoError::Occupied`] when the platform holds another organization,
///   which the install use case founds next to nothing.
/// - [`DemoError::Refused`] when the founding or the confirmation fails.
pub(super) async fn organization(
    deps: &Deps,
    state: &ApiState,
) -> Result<Seed<DemoOrganization>, DemoError> {
    let limits = &deps.settings.domain_limits;
    let slug = TenantSlug::new(catalog::ORGANIZATION_SLUG, &limits.slug)?;
    if let Some(found) = deps.adapters.organization_store.find_by_slug(&slug).await? {
        return Ok(Seed::Found(demo_organization(&found)));
    }
    let id = founded(deps, state, request(limits)?).await?;
    let made = deps
        .adapters
        .organization_store
        .find_by_id(&id)
        .await?
        .ok_or(DemoError::Vanished("the organization just founded"))?;
    Ok(Seed::Made(demo_organization(&made)))
}

/// Founds the organization `request` describes and confirms its owner with
/// the setup token it issued, in one unit, so a run that stops part way
/// leaves no owner nobody can confirm.
async fn founded(
    deps: &Deps,
    state: &ApiState,
    request: InstallRequest,
) -> Result<OrganizationId, DemoError> {
    let install = install_use_case(&deps.adapters, &deps.settings);
    let confirm = state.organization.invitations.confirm_installer.as_ref();
    let auditor = RequestAuditor::system(deps.adapters.event_dispatcher.clone());
    let unit = deps.adapters.unit_of_work.as_ref();
    let founded = kept_together(unit, async {
        let Installation::Created(founded) = install.execute(&(), &auditor, request).await? else {
            return Ok(None);
        };
        if let SetupToken::Issued(token) = &founded.setup_token {
            confirm
                .execute(&(), &auditor, token.expose().to_owned())
                .await?;
        }
        Ok(Some(founded.organization_id))
    })
    .await
    .map_err(|cause| DemoError::Refused {
        what: "the demonstration organization",
        cause,
    })?;
    founded.ok_or(DemoError::Occupied)
}

/// What the install use case is asked to found.
fn request(limits: &DomainLimits) -> Result<InstallRequest, DemoError> {
    Ok(InstallRequest {
        organization_name: catalog::ORGANIZATION.to_owned(),
        tenant_name: catalog::TENANTS[0].name.to_owned(),
        owner_email: Email::new(catalog::OWNER_EMAIL)?,
        owner_display_name: DisplayName::new(catalog::OWNER_NAME, &limits.display_name)?,
        owner_password: catalog::PASSWORD.to_owned(),
    })
}

/// The seeder's view of `organization`.
fn demo_organization(organization: &Organization) -> DemoOrganization {
    DemoOrganization {
        id: *organization.id(),
        slug: organization.slug().clone(),
        limits: organization.limits(),
    }
}

/// The owner signed in with their password, as the dashboard signs them
/// in, through the sign-in use case: the sign-in is recorded like any
/// other.
///
/// The seeder reads no mailbox. The setup token vouches for the owner's
/// first sign-in, so on a deployment with no mail server it owes an
/// authenticator app set up there and then, and where mail reaches it owes
/// nothing more. The owner sets one up through the enrolment use cases,
/// and the code that confirms it lets the sign-in in.
///
/// # Errors
///
/// - [`DemoError::Refused`] when the sign-in or the setup is refused.
/// - [`DemoError::SignIn`] when it opened no session that may act: it owes
///   a factor the seeder cannot give, or offers a choice of organizations.
/// - [`DemoError::Authenticator`] when no code can be read from the app
///   just set up.
pub(super) async fn signed_in(seeder: &Seeder<'_>) -> Result<Owner, DemoError> {
    let success = password_sign_in(seeder).await?;
    let owner = Owner {
        member: success.org_user_id,
        session: OwnerSession {
            id: success.session_id,
            place: place_of(&success.tenant),
        },
        authenticator: None,
    };
    match success.second_factor {
        SecondFactor::NotOwed => Ok(owner),
        SecondFactor::Enrol => with_authenticator(seeder, owner).await,
        SecondFactor::Verify | SecondFactor::ConfirmByEmail | SecondFactor::ConfirmThenEnrol => {
            Err(DemoError::SignIn(
                "asks for a second factor the seeder cannot give",
            ))
        }
    }
}

/// The owner's sign-in through the password use case, which opened a
/// session in the demonstration organization.
async fn password_sign_in(seeder: &Seeder<'_>) -> Result<Box<OrgLoginSuccess>, DemoError> {
    let request = OrgPasswordLoginRequest {
        email: Email::new(catalog::OWNER_EMAIL)?,
        password: Secret::new(catalog::PASSWORD),
        organization: OrganizationChoice::Named(seeder.organization.slug.clone()),
        tenant_slug: None,
        device_secret: None,
        challenge: None,
        origin: ClientOrigin {
            ip_address: Fact::Unknown,
            user_agent: Some(seeder.user_agent.clone()),
        },
    };
    let auditor = RequestAuditor::system(seeder.adapters.event_dispatcher.clone());
    let login = seeder.state.organization.sign_in.password_login.as_ref();
    let outcome = seeder
        .kept("the owner's sign-in", login.execute(&(), &auditor, request))
        .await?;
    let OrgLoginOutcome::SignedIn(success) = outcome else {
        return Err(DemoError::SignIn("offered a choice of organizations"));
    };
    Ok(success)
}

/// `owner`, whose sign-in waits for an authenticator app, once one is set
/// up and confirmed with the code it shows now, which lets the sign-in in.
async fn with_authenticator(seeder: &Seeder<'_>, owner: Owner) -> Result<Owner, DemoError> {
    let mfa = &seeder.state.organization.mfa;
    let auditor = RequestAuditor::system(seeder.adapters.event_dispatcher.clone());
    let started = seeder
        .kept(
            "the owner's authenticator app",
            mfa.begin
                .execute(&waiting(&owner), &auditor, SetupProof::OwedBySignIn),
        )
        .await?;
    let code = TotpMfaVerifier
        .shown_code(&started.otpauth_uri, clock::now())
        .map_err(DemoError::Authenticator)?;
    let request = OrgConfirmRequest {
        code: code.expose().to_owned(),
    };
    seeder
        .kept(
            "the owner's authenticator app",
            mfa.confirm.execute(&waiting(&owner), &auditor, request),
        )
        .await?;
    Ok(Owner {
        authenticator: Some(started.otpauth_uri),
        ..owner
    })
}

/// Where the session a sign-in that landed at `landed` opened works.
fn place_of(landed: &LandedTenant) -> SessionPlace {
    match landed {
        LandedTenant::Tenant { id, .. } => SessionPlace::Tenant(*id),
        LandedTenant::NoTenantAccess => SessionPlace::Organization,
    }
}

/// The owner's sign-in, waiting for the factor it owes.
fn waiting(owner: &Owner) -> MemberFactorSetter {
    MemberFactorSetter::SigningIn(PendingMemberSession {
        session_id: owner.session.id,
        member: owner.member,
    })
}
