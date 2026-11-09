//! Onboarding handlers: whether this deployment takes signups, asking for
//! an organization, confirming it from the link, and a member founding
//! another.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::onboarding::OnboardingState;
use ianua_domain::shared::config::DomainLimits;

use crate::dto::onboarding::{
    AnotherOrganizationBody, ConfirmSignupBody, SignupAcceptedResponse, SignupBody,
    SignupOpenResponse, SignupResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::Visitor;
use crate::extractors::json::Json;
use crate::extractors::organization::HomeMember;
use crate::response::{Accepted, Created};

#[utoipa::path(
    get,
    path = "/api/v1/signup",
    tag = "Onboarding",
    responses(
        (status = 200, description = "Whether signups are taken", body = SignupOpenResponse),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Whether signups are open
///
/// Public. `open` is `false` on a self-hosted installation, which refuses
/// every signup, so a sign-in page can leave out its "Sign up" button.
pub(crate) async fn signup_open(
    State(onboarding): State<OnboardingState>,
) -> Json<SignupOpenResponse> {
    let open = onboarding.signup_open.execute(&(), ()).await;
    Json(SignupOpenResponse { open })
}

#[utoipa::path(
    post,
    path = "/api/v1/signup",
    tag = "Onboarding",
    request_body = SignupBody,
    responses(
        (status = 202, description = "A link, or a notice, went to the address", body = SignupAcceptedResponse),
        (status = 403, description = "This installation does not accept signups", body = ErrorBody),
        (status = 409, description = "The company name is taken", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sign up: ask for an organization
///
/// Public. Mails `admin_email` a link; `POST /api/v1/signup/confirm` creates the
/// organization, first tenant and owner. Names become `org_slug`/`tenant_slug`;
/// the owner receives `admin_display_name` and hashed `admin_password`.
///
/// Always answers `202` with `status: "check_inbox"`, whether or not the
/// address has an account, in the same time either way. An address with an
/// account is mailed a notice to sign in instead. Returns `403` on a
/// self-hosted installation; `409` if the derived organization slug is taken
/// (organization names are public, as every sign-in address shows them);
/// `422` for an invalid email or display name, a weak password, or an
/// unslugifiable name. Rate-limited per address (`429`), and at most one
/// mail a minute goes to an address. Records nothing: nothing exists yet.
pub(crate) async fn signup(
    State(onboarding): State<OnboardingState>,
    State(limits): State<DomainLimits>,
    visitor: Visitor,
    Json(body): Json<SignupBody>,
) -> Result<Accepted<SignupAcceptedResponse>, ApiError> {
    onboarding
        .signup
        .execute(&(), &visitor.auditor, body.request(&limits)?)
        .await?;
    Ok(Accepted(SignupAcceptedResponse::check_inbox()))
}

#[utoipa::path(
    post,
    path = "/api/v1/signup/confirm",
    tag = "Onboarding",
    request_body = ConfirmSignupBody,
    responses(
        (status = 201, description = "Created", body = SignupResponse),
        (status = 404, description = "The link is not valid, or was used already", body = ErrorBody),
        (status = 409, description = "The company name or the address was taken meanwhile", body = ErrorBody),
        (status = 410, description = "The link has run out", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sign up: confirm and create the organization
///
/// Public. Takes the `token` from the link a sign-up mailed, once, within
/// the day it works. Creates the organization, its first tenant and the
/// owner, whose address the link proved, so they can sign in at once. The
/// tenant starts in `Provisioning` and moves to `Active` once its setup,
/// started by the `tenant.provisioned` event, completes.
///
/// Returns the `org_slug`, `tenant_slug`, `admin_user_id`, and
/// `status: "provisioning"`. Returns `404` for a link that is not valid or
/// was used, `410` once it has run out, and `409` if the company name or
/// the address was taken since the sign-up. Rate-limited per address
/// (`429`). Records `organization.created`, `tenant.provisioned`,
/// `organization.tenant_created` and `organization.org_user_created`.
pub(crate) async fn confirm_signup(
    State(onboarding): State<OnboardingState>,
    visitor: Visitor,
    Json(body): Json<ConfirmSignupBody>,
) -> Result<Created<SignupResponse>, ApiError> {
    let founded = onboarding
        .confirm_signup
        .execute(&(), &visitor.auditor, body.into())
        .await?;
    Ok(Created(SignupResponse::from(&founded)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations",
    tag = "Onboarding",
    request_body = AnotherOrganizationBody,
    responses(
        (status = 201, description = "Created", body = SignupResponse),
        (status = 401, description = "Unauthenticated, or a key rather than a session", body = ErrorBody),
        (status = 403, description = "This installation takes no new organizations, or the caller's address was never verified", body = ErrorBody),
        (status = 409, description = "The company name is taken", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Found another organization
///
/// A signed-in member founds another organization and first tenant, becoming owner under the same
/// address, already verified. The new account has its own `password`: an
/// address holds one account per organization. Their current account and
/// organization stay as they are; sign in to the new one with the new
/// password. The organization starts on the plan a sign-up gets.
///
/// Returns the new `org_slug`, `tenant_slug`, `admin_user_id` and
/// `status: "provisioning"`, as a sign-up does. Requires the member's own
/// session. Records `organization.created`, `tenant.provisioned`,
/// `organization.tenant_created`, `organization.subscription_started`,
/// `organization.org_user_created` and
/// `organization.org_user_email_verified`.
pub(crate) async fn found_another_organization(
    State(onboarding): State<OnboardingState>,
    member: HomeMember,
    Json(body): Json<AnotherOrganizationBody>,
) -> Result<Created<SignupResponse>, ApiError> {
    let founded = onboarding
        .another_organization
        .execute(&member.caller, &member.auditor, body.try_into()?)
        .await?;
    Ok(Created(SignupResponse::from(&founded)))
}
