//! The organization use cases the API serves: the organization itself, its
//! plan and bill, its members and invitations, how members sign in and
//! prove who they are, its identity provider, its members' privacy, its
//! branding, its API keys and its cloud accounts.

use std::sync::Arc;

use ianua_app::email::{InvitationMailing, InvitationPolicy};
use ianua_app::services::authorization::grant_revocation::{GrantRevocation, OrgGrantRevocation};
use ianua_app::use_cases::authentication::password::ConfirmationLinkPolicy;
use ianua_app::use_cases::authentication::sessions::device_trust::Policy;
use ianua_app::use_cases::identity::email::VerificationPolicy;
use ianua_app::use_cases::identity::users::PasswordMaker;
use ianua_app::use_cases::organization::{
    api_keys, billing, branding, cloud_accounts, identity_providers, invitations, lifecycle,
    members, mfa, passkeys, password_reset, privacy, sign_in,
};
use ianua_domain::types::HttpsUrl;

use crate::authentication::{flood_gate, password_hashing, sign_in_counts};
use crate::deps::{Adapters, Settings};

/// The organization use cases.
#[derive(Clone)]
pub struct OrganizationState {
    pub lifecycle: LifecycleState,
    pub billing: BillingState,
    pub members: MemberState,
    /// Bringing people in, and confirming an installation's first owner.
    pub invitations: InvitationState,
    pub api_keys: ApiKeyState,
    pub cloud_accounts: CloudAccountState,
    /// How members sign in.
    pub sign_in: SignInState,
    /// Members' second factors.
    pub mfa: MfaState,
    pub passkeys: PasskeyState,
    pub password_reset: PasswordResetState,
    pub identity_provider: IdentityProviderState,
    pub privacy: PrivacyState,
    pub branding: BrandingState,
}

/// The organization itself: reading it, changing it and its status.
#[derive(Clone)]
pub struct LifecycleState {
    pub get: Arc<lifecycle::GetOrganizationUseCase>,
    pub list: Arc<lifecycle::ListOrganizationsUseCase>,
    pub update: Arc<lifecycle::UpdateOrganizationUseCase>,
    pub update_auth_config: Arc<lifecycle::UpdateOrganizationAuthConfigUseCase>,
    pub change_status: Arc<lifecycle::ChangeOrganizationStatusUseCase>,
    pub metrics: Arc<lifecycle::GetOrgMetricsUseCase>,
}

/// What the organization pays for: the plans on sale, its subscription and
/// usage, the checkout, the payment provider's notices, and the plans an
/// operator arranges.
#[derive(Clone)]
pub struct BillingState {
    pub plans: Arc<billing::ListPlansUseCase>,
    pub subscription: Arc<billing::GetSubscriptionUseCase>,
    pub choose_plan: Arc<billing::ChoosePlanUseCase>,
    pub usage: Arc<billing::GetPlanUsageUseCase>,
    pub checkout: Arc<billing::StartCheckoutUseCase>,
    pub payment_notice: Arc<billing::ReceivePaymentNoticeUseCase>,
    pub arrange_plan: Arc<billing::ArrangePlanUseCase>,
}

/// The organization's members: their accounts, roles, tenant access and
/// linked identities.
#[derive(Clone)]
pub struct MemberState {
    pub list: Arc<members::ListOrgUsersUseCase>,
    pub me: Arc<members::GetOrgMeUseCase>,
    pub create: Arc<members::CreateOrgUserUseCase>,
    pub delete: Arc<members::DeleteOrgUserUseCase>,
    pub update_status: Arc<members::UpdateOrgUserStatusUseCase>,
    pub change_role: Arc<members::ChangeOrgUserRoleUseCase>,
    pub transfer_ownership: Arc<members::TransferOwnershipUseCase>,
    pub change_email: Arc<members::ChangeOrgUserEmailUseCase>,
    pub change_display_name: Arc<members::ChangeOrgUserDisplayNameUseCase>,
    pub change_password: Arc<members::ChangeOrgUserPasswordUseCase>,
    pub update_preferences: Arc<members::UpdateOrgUserPreferencesUseCase>,
    pub reset_password: Arc<members::ResetOrgUserPasswordUseCase>,
    pub reset_mfa: Arc<members::ResetMfaUseCase>,
    pub access: Arc<members::GetOrgUserAccessUseCase>,
    pub set_tenant_access: Arc<members::SetOrgUserTenantAccessUseCase>,
    pub grantable_roles: Arc<members::ListGrantableRolesUseCase>,
    pub link_identity: Arc<members::LinkIdentityUseCase>,
    pub unlink_identity: Arc<members::UnlinkIdentityUseCase>,
}

/// Bringing people in: invitations, welcome mail and address confirmation.
#[derive(Clone)]
pub struct InvitationState {
    pub invite: Arc<invitations::InviteOrgUserUseCase>,
    pub resend: Arc<invitations::ResendOrgUseCase>,
    pub renew: Arc<invitations::RenewOrgUseCase>,
    pub revoke: Arc<invitations::RevokeOrgUseCase>,
    pub accept: Arc<invitations::AcceptOrgUseCase>,
    pub decline: Arc<invitations::DeclineOrgUseCase>,
    pub status: Arc<invitations::OrgStatusUseCase>,
    pub send_welcome: Arc<invitations::SendOrgWelcomeUseCase>,
    pub send_activation_welcome: Arc<invitations::SendOrgActivationWelcomeUseCase>,
    pub confirm_verification: Arc<invitations::ConfirmOrgVerificationUseCase>,
    pub verification_status: Arc<invitations::OrgVerificationStatusUseCase>,
    pub resend_verification: Arc<invitations::ResendOrgVerificationUseCase>,
    pub resend_verification_by_email: Arc<invitations::ResendOrgVerificationByEmailUseCase>,
    pub resend_verification_from_link: Arc<invitations::ResendOrgVerificationFromLinkUseCase>,
    /// Confirms an installation's first owner with the setup token the
    /// install printed.
    pub confirm_installer: Arc<invitations::ConfirmInstallerUseCase>,
}

/// API keys that act for the organization.
#[derive(Clone)]
pub struct ApiKeyState {
    pub create: Arc<api_keys::CreateOrgUseCase>,
    pub list: Arc<api_keys::ListOrgUseCase>,
    pub revoke: Arc<api_keys::RevokeOrgUseCase>,
}

/// The organization's own cloud accounts.
#[derive(Clone)]
pub struct CloudAccountState {
    pub begin: Arc<cloud_accounts::BeginCloudConnectionUseCase>,
    pub attach: Arc<cloud_accounts::AttachCloudCredentialUseCase>,
    pub verify: Arc<cloud_accounts::VerifyUseCase>,
    pub list: Arc<cloud_accounts::ListUseCase>,
    pub external_id: Arc<cloud_accounts::GetCloudExternalIdUseCase>,
    pub networks: Arc<cloud_accounts::ListCloudNetworksUseCase>,
    pub disconnect: Arc<cloud_accounts::DisconnectUseCase>,
    /// The console link template shown when a connection begins, with
    /// `{external_id}` and `{provider}` to fill in.
    pub console_template: Option<Arc<str>>,
}

/// How members sign in and stay signed in: password, single sign-on,
/// mailed links, emailed confirmation, sessions, devices and tenants.
#[derive(Clone)]
pub struct SignInState {
    /// Signs a member in with their address and password.
    pub password_login: Arc<sign_in::OrgPasswordLoginUseCase>,
    pub sso_start: Arc<sign_in::OrgSsoStartUseCase>,
    pub sso_callback: Arc<sign_in::OrgSsoCallbackUseCase>,
    pub magic_link_request: Arc<sign_in::RequestOrgMagicLinkUseCase>,
    pub magic_link: Arc<sign_in::OrgMagicLinkUseCase>,
    pub confirm_by_email: Arc<sign_in::OrgConfirmUseCase>,
    pub logout: Arc<sign_in::OrgLogoutUseCase>,
    pub active_sessions: Arc<sign_in::ListActiveSessionsUseCase>,
    pub revoke_session: Arc<sign_in::RevokeMemberSessionUseCase>,
    pub list_devices: Arc<sign_in::ListOrgDevicesUseCase>,
    pub trust_device: Arc<sign_in::TrustOrgDeviceUseCase>,
    pub revoke_device: Arc<sign_in::RevokeOrgDeviceUseCase>,
    pub switch_tenant: Arc<sign_in::SwitchOrgTenantUseCase>,
    pub linked_switch: Arc<sign_in::LinkedTenantSwitchUseCase>,
    pub mark_credential_used: Arc<sign_in::MarkCredentialUsedUseCase>,
    /// The deployment's public address, which the organization's identity
    /// provider sends members back to.
    pub app_base_url: HttpsUrl,
}

/// Members' second factors and recovery codes.
#[derive(Clone)]
pub struct MfaState {
    pub status: Arc<mfa::GetOrgStatusUseCase>,
    /// Starts setting up a member's authenticator app.
    pub begin: Arc<mfa::OrgBeginUseCase>,
    /// Confirms it with a code from the app, letting in a sign-in that
    /// waited for it.
    pub confirm: Arc<mfa::OrgConfirmUseCase>,
    pub abandon: Arc<mfa::OrgAbandonUseCase>,
    pub disable: Arc<mfa::OrgDisableUseCase>,
    pub verify: Arc<mfa::OrgVerifyUseCase>,
    pub recovery_sign_in: Arc<mfa::OrgRecoveryCodeSignInUseCase>,
    pub regenerate_codes: Arc<mfa::RegenerateOrgRecoveryCodesUseCase>,
}

/// Members' passkeys: registering, managing and signing in with them.
#[derive(Clone)]
pub struct PasskeyState {
    pub register_begin: Arc<passkeys::OrgRegisterBeginUseCase>,
    pub register_confirm: Arc<passkeys::OrgRegisterConfirmUseCase>,
    pub list: Arc<passkeys::OrgListUseCase>,
    pub rename: Arc<passkeys::OrgRenameUseCase>,
    pub delete: Arc<passkeys::OrgDeleteUseCase>,
    pub login_begin: Arc<passkeys::OrgLoginBeginUseCase>,
    pub login_discover: Arc<passkeys::OrgDiscoverBeginUseCase>,
    pub login_confirm: Arc<passkeys::OrgLoginConfirmUseCase>,
}

/// Members who forgot their password setting a new one.
#[derive(Clone)]
pub struct PasswordResetState {
    pub request: Arc<password_reset::RequestOrgResetUseCase>,
    pub resend: Arc<password_reset::ResendOrgResetUseCase>,
    pub status: Arc<password_reset::OrgResetStatusUseCase>,
    pub confirm: Arc<password_reset::ConfirmOrgResetUseCase>,
}

/// The organization's own identity provider, which signs its members in
/// to the dashboard.
#[derive(Clone)]
pub struct IdentityProviderState {
    pub get: Arc<identity_providers::GetOrgUseCase>,
    pub add: Arc<identity_providers::AddOrgUseCase>,
    pub change: Arc<identity_providers::ChangeOrgUseCase>,
    pub switch: Arc<identity_providers::SwitchOrgUseCase>,
    pub remove: Arc<identity_providers::RemoveOrgUseCase>,
}

/// Members' consent decisions and erasure requests.
#[derive(Clone)]
pub struct PrivacyState {
    pub grant_consent: Arc<privacy::GrantOrgConsentUseCase>,
    pub revoke_consent: Arc<privacy::RevokeOrgConsentUseCase>,
    pub list_consents: Arc<privacy::ListOrgConsentsUseCase>,
    pub request_erasure: Arc<privacy::RequestOrgErasureUseCase>,
    pub cancel_erasure: Arc<privacy::CancelOrgErasureUseCase>,
    pub cancel_erasure_by_link: Arc<privacy::CancelOrgErasureByLinkUseCase>,
    pub hold_erasure: Arc<privacy::HoldOrgErasureUseCase>,
    pub release_erasure: Arc<privacy::ReleaseOrgErasureUseCase>,
}

/// How the organization's own dashboard and mail look.
#[derive(Clone)]
pub struct BrandingState {
    pub get: Arc<branding::GetOrgUseCase>,
    pub change: Arc<branding::ChangeOrgUseCase>,
    pub reset: Arc<branding::ResetOrgUseCase>,
}

/// Builds the organization use cases over `a`, tuned by `s`.
pub fn build(a: &Adapters, s: &Settings) -> OrganizationState {
    OrganizationState {
        lifecycle: lifecycle(a),
        billing: billing(a),
        members: members(a, s),
        invitations: invitations(a, s),
        api_keys: api_keys(a),
        cloud_accounts: cloud_accounts(a, s),
        sign_in: sign_in(a, s),
        mfa: mfa(a, s),
        passkeys: passkeys(a, s),
        password_reset: password_reset(a, s),
        identity_provider: identity_provider(a),
        privacy: privacy(a, s),
        branding: branding(a),
    }
}

/// The use cases that read, change and suspend an organization.
fn lifecycle(a: &Adapters) -> LifecycleState {
    LifecycleState {
        get: Arc::new(get_organization(a)),
        list: Arc::new(list_organizations(a)),
        update: Arc::new(update_organization(a)),
        update_auth_config: Arc::new(update_auth_config(a)),
        change_status: Arc::new(change_organization_status(a)),
        metrics: Arc::new(organization_metrics(a)),
    }
}

/// Reads the caller's organization through its authority resolver.
fn get_organization(a: &Adapters) -> lifecycle::GetOrganizationUseCase {
    lifecycle::GetOrganizationUseCase::new(lifecycle::GetOrganizationPorts {
        org_actors: a.org_actors.clone(),
    })
}

/// Lists organizations through the operator's authority.
fn list_organizations(a: &Adapters) -> lifecycle::ListOrganizationsUseCase {
    lifecycle::ListOrganizationsUseCase::new(lifecycle::ListOrganizationsPorts {
        organizations: a.organization_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Changes organization details through the stored organization and caller authority.
fn update_organization(a: &Adapters) -> lifecycle::UpdateOrganizationUseCase {
    lifecycle::UpdateOrganizationUseCase::new(lifecycle::UpdateOrganizationPorts {
        organizations: a.organization_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Changes sign-in rules using fresh proofs and the deployment's mail and text capabilities.
fn update_auth_config(a: &Adapters) -> lifecycle::UpdateOrganizationAuthConfigUseCase {
    lifecycle::UpdateOrganizationAuthConfigUseCase::new(
        lifecycle::UpdateOrganizationAuthConfigPorts {
            organizations: a.organization_store.clone(),
            org_actors: a.org_actors.clone(),
            fresh_proofs: a.fresh_proofs.clone(),
            text_messaging: a.text_messaging.clone(),
            mail: a.mail_setup.clone(),
        },
    )
}

/// Changes organization status with its sessions, tenants and both authority resolvers.
fn change_organization_status(a: &Adapters) -> lifecycle::ChangeOrganizationStatusUseCase {
    lifecycle::ChangeOrganizationStatusUseCase::new(lifecycle::ChangeOrganizationStatusPorts {
        organizations: a.organization_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
        org_sessions: a.org_session_store.clone(),
        tenants: a.tenant_store.clone(),
    })
}

/// Reads organization metrics under the caller's authority.
fn organization_metrics(a: &Adapters) -> lifecycle::GetOrgMetricsUseCase {
    lifecycle::GetOrgMetricsUseCase::new(lifecycle::GetOrgMetricsPorts {
        reader: a.organization_metrics_reader.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// The use cases that sell, read and change what the organization pays
/// for.
fn billing(a: &Adapters) -> BillingState {
    BillingState {
        plans: Arc::new(billing::ListPlansUseCase::new()),
        subscription: Arc::new(subscription(a)),
        choose_plan: Arc::new(choose_plan(a)),
        usage: Arc::new(plan_usage(a)),
        checkout: Arc::new(start_checkout(a)),
        payment_notice: Arc::new(receive_payment_notice(a)),
        arrange_plan: Arc::new(arrange_plan(a)),
    }
}

/// Reads subscriptions under organization authority.
fn subscription(a: &Adapters) -> billing::GetSubscriptionUseCase {
    billing::GetSubscriptionUseCase::new(billing::GetSubscriptionPorts {
        subscriptions: a.org_subscription_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Changes plans against stored subscriptions and measured usage.
fn choose_plan(a: &Adapters) -> billing::ChoosePlanUseCase {
    billing::ChoosePlanUseCase::new(billing::ChoosePlanPorts {
        organizations: a.organization_store.clone(),
        subscriptions: a.org_subscription_store.clone(),
        usage: a.plan_usage_counter.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Reads plan usage under organization authority.
fn plan_usage(a: &Adapters) -> billing::GetPlanUsageUseCase {
    billing::GetPlanUsageUseCase::new(billing::GetPlanUsagePorts {
        usage: a.plan_usage_counter.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Starts checkout through the payment provider and organization authority.
fn start_checkout(a: &Adapters) -> billing::StartCheckoutUseCase {
    billing::StartCheckoutUseCase::new(billing::StartCheckoutPorts {
        payment_provider: a.payment_provider.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Applies payment notices through the ledger, subscription and organization stores.
fn receive_payment_notice(a: &Adapters) -> billing::ReceivePaymentNoticeUseCase {
    billing::ReceivePaymentNoticeUseCase::new(billing::ReceivePaymentNoticePorts {
        payment_provider: a.payment_provider.clone(),
        subscriptions: a.org_subscription_store.clone(),
        organizations: a.organization_store.clone(),
        payment_events: a.payment_event_ledger.clone(),
    })
}

/// Lets an operator arrange plans against current subscription usage.
fn arrange_plan(a: &Adapters) -> billing::ArrangePlanUseCase {
    billing::ArrangePlanUseCase::new(billing::ArrangePlanPorts {
        organizations: a.organization_store.clone(),
        subscriptions: a.org_subscription_store.clone(),
        usage: a.plan_usage_counter.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// The use cases that add, change and remove members, and set what they may
/// reach in each tenant.
fn members(a: &Adapters, s: &Settings) -> MemberState {
    MemberState {
        list: Arc::new(list_members(a)),
        me: Arc::new(current_member(a)),
        create: Arc::new(create_member(a, s)),
        delete: Arc::new(delete_member(a)),
        update_status: Arc::new(update_member_status(a)),
        change_role: Arc::new(change_member_role(a)),
        transfer_ownership: Arc::new(transfer_ownership(a)),
        change_email: Arc::new(change_member_email(a, s)),
        change_display_name: Arc::new(change_member_name(a)),
        change_password: Arc::new(change_member_password(a)),
        update_preferences: Arc::new(update_member_preferences(a)),
        reset_password: Arc::new(reset_member_password(a)),
        reset_mfa: Arc::new(reset_member_factor(a)),
        access: Arc::new(member_access(a)),
        set_tenant_access: Arc::new(set_member_access(a)),
        grantable_roles: Arc::new(grantable_roles(a)),
        link_identity: Arc::new(link_identity(a)),
        unlink_identity: Arc::new(unlink_identity(a)),
    }
}

/// Lists members with their pending invitations under organization authority.
fn list_members(a: &Adapters) -> members::ListOrgUsersUseCase {
    members::ListOrgUsersUseCase::new(members::ListOrgUsersPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        org_invitations: a.org_invitation_store.clone(),
    })
}

/// Reads the current member with their tenant grants and roles.
fn current_member(a: &Adapters) -> members::GetOrgMeUseCase {
    members::GetOrgMeUseCase::new(members::GetOrgMePorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        tenants: a.tenant_store.clone(),
        roles: a.role_store.clone(),
        grants: a.org_tenant_grant_store.clone(),
    })
}

/// Creates members using generated passwords and throttled verification mail.
fn create_member(a: &Adapters, s: &Settings) -> members::CreateOrgUserUseCase {
    members::CreateOrgUserUseCase::new(members::CreateOrgUserPorts {
        mail_throttle: a.mail_throttle.clone(),
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        passwords: password_maker(a),
        verification: verification_mail(a, s),
    })
}

/// Deletes members and revokes their sessions and grants.
fn delete_member(a: &Adapters) -> members::DeleteOrgUserUseCase {
    members::DeleteOrgUserUseCase::new(members::DeleteOrgUserPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        org_sessions: a.org_session_store.clone(),
        grant_revocation: grant_revocation(a),
    })
}

/// Changes member status with the session and grant revocation ports.
fn update_member_status(a: &Adapters) -> members::UpdateOrgUserStatusUseCase {
    members::UpdateOrgUserStatusUseCase::new(members::UpdateOrgUserStatusPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        org_sessions: a.org_session_store.clone(),
        grant_revocation: grant_revocation(a),
    })
}

/// Changes a member's role with the stored accounts and sessions.
fn change_member_role(a: &Adapters) -> members::ChangeOrgUserRoleUseCase {
    members::ChangeOrgUserRoleUseCase::new(members::ChangeOrgUserRolePorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        org_sessions: a.org_session_store.clone(),
    })
}

/// Transfers ownership through organization authority and member sessions.
fn transfer_ownership(a: &Adapters) -> members::TransferOwnershipUseCase {
    members::TransferOwnershipUseCase::new(members::TransferOwnershipPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        org_sessions: a.org_session_store.clone(),
    })
}

/// Changes a member's address with throttled verification mail.
fn change_member_email(a: &Adapters, s: &Settings) -> members::ChangeOrgUserEmailUseCase {
    members::ChangeOrgUserEmailUseCase::new(members::ChangeOrgUserEmailPorts {
        mail_throttle: a.mail_throttle.clone(),
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        verification: verification_mail(a, s),
    })
}

/// Changes a member's display name through organization authority.
fn change_member_name(a: &Adapters) -> members::ChangeOrgUserDisplayNameUseCase {
    members::ChangeOrgUserDisplayNameUseCase::new(members::ChangeOrgUserDisplayNamePorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
    })
}

/// Changes a member's password with hashing, breach checks and session storage.
fn change_member_password(a: &Adapters) -> members::ChangeOrgUserPasswordUseCase {
    members::ChangeOrgUserPasswordUseCase::new(members::ChangeOrgUserPasswordPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        hashing: password_hashing(a),
        org_sessions: a.org_session_store.clone(),
        breach_checker: a.credential_breach_checker.clone(),
    })
}

/// Changes stored member preferences under organization authority.
fn update_member_preferences(a: &Adapters) -> members::UpdateOrgUserPreferencesUseCase {
    members::UpdateOrgUserPreferencesUseCase::new(members::UpdateOrgUserPreferencesPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
    })
}

/// Resets a member's password with generated credentials and session storage.
fn reset_member_password(a: &Adapters) -> members::ResetOrgUserPasswordUseCase {
    members::ResetOrgUserPasswordUseCase::new(members::ResetOrgUserPasswordPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        passwords: password_maker(a),
        org_sessions: a.org_session_store.clone(),
        breach_checker: a.credential_breach_checker.clone(),
    })
}

/// Resets a member's authenticator with its sessions and notification mail.
fn reset_member_factor(a: &Adapters) -> members::ResetMfaUseCase {
    members::ResetMfaUseCase::new(members::ResetMfaPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        enrollments: a.org_mfa_enrollment_store.clone(),
        org_sessions: a.org_session_store.clone(),
        organizations: a.organization_store.clone(),
        mailer: a.mailer.clone(),
    })
}

/// Reads a member's tenant grants and the roles they name.
fn member_access(a: &Adapters) -> members::GetOrgUserAccessUseCase {
    members::GetOrgUserAccessUseCase::new(members::GetOrgUserAccessPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        tenants: a.tenant_store.clone(),
        roles: a.role_store.clone(),
        grants: a.org_tenant_grant_store.clone(),
    })
}

/// Replaces tenant grants against the organization's member and role stores.
fn set_member_access(a: &Adapters) -> members::SetOrgUserTenantAccessUseCase {
    members::SetOrgUserTenantAccessUseCase::new(members::SetOrgUserTenantAccessPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        tenants: a.tenant_store.clone(),
        roles: a.role_store.clone(),
        grants: a.org_tenant_grant_store.clone(),
    })
}

/// Reads a tenant's role names under the organization's tenant-access right.
fn grantable_roles(a: &Adapters) -> members::ListGrantableRolesUseCase {
    members::ListGrantableRolesUseCase::new(members::ListGrantableRolesPorts {
        org_actors: a.org_actors.clone(),
        tenants: a.tenant_store.clone(),
        roles: a.role_store.clone(),
    })
}

/// Links tenant identities through tenant authority and organization ownership.
fn link_identity(a: &Adapters) -> members::LinkIdentityUseCase {
    members::LinkIdentityUseCase::new(members::LinkIdentityPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        organizations: a.organization_store.clone(),
        identities: a.linked_identity_store.clone(),
        tenants: a.tenant_store.clone(),
    })
}

/// Unlinks tenant identities through tenant and organization authority.
fn unlink_identity(a: &Adapters) -> members::UnlinkIdentityUseCase {
    members::UnlinkIdentityUseCase::new(members::UnlinkIdentityPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        org_actors: a.org_actors.clone(),
        identities: a.linked_identity_store.clone(),
        tenants: a.tenant_store.clone(),
    })
}

/// The use cases that invite members, answer invitations, and confirm a new
/// member's address.
fn invitations(a: &Adapters, s: &Settings) -> InvitationState {
    InvitationState {
        invite: Arc::new(invite_member(a, s)),
        resend: Arc::new(resend_invitation(a, s)),
        renew: Arc::new(renew_invitation(a, s)),
        revoke: Arc::new(revoke_invitation(a)),
        accept: Arc::new(accept_invitation(a)),
        decline: Arc::new(decline_invitation(a)),
        status: Arc::new(invitation_status(a)),
        send_welcome: Arc::new(send_welcome(a, s)),
        send_activation_welcome: Arc::new(send_activation_welcome(a, s)),
        confirm_verification: Arc::new(confirm_member_address(a)),
        verification_status: Arc::new(verification_status(a)),
        resend_verification: Arc::new(resend_verification(a, s)),
        resend_verification_by_email: Arc::new(resend_verification_by_email(a, s)),
        resend_verification_from_link: Arc::new(resend_verification_from_link(a, s)),
        confirm_installer: Arc::new(confirm_installer(a)),
    }
}

/// Issues invitations with the member's existing grants and factors and throttled mail.
fn invite_member(a: &Adapters, s: &Settings) -> invitations::InviteOrgUserUseCase {
    invitations::InviteOrgUserUseCase::new(invitations::InviteOrgUserPorts {
        mail_throttle: a.mail_throttle.clone(),
        org_user_store: a.org_user_store.clone(),
        tenant_grants: a.org_tenant_grant_store.clone(),
        enrollments: a.org_mfa_enrollment_store.clone(),
        passkeys: a.org_passkey_store.clone(),
        org_invitation_store: a.org_invitation_store.clone(),
        org_actors: a.org_actors.clone(),
        mailing: invitation_mailing(a, s),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Resends invitations through the same token generator and invitation mailing policy.
fn resend_invitation(a: &Adapters, s: &Settings) -> invitations::ResendOrgUseCase {
    invitations::ResendOrgUseCase::new(invitations::ResendOrgPorts {
        mail_throttle: a.mail_throttle.clone(),
        org_user_store: a.org_user_store.clone(),
        org_invitation_store: a.org_invitation_store.clone(),
        org_actors: a.org_actors.clone(),
        mailing: invitation_mailing(a, s),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Renews invitations against their organization with throttled mail.
fn renew_invitation(a: &Adapters, s: &Settings) -> invitations::RenewOrgUseCase {
    invitations::RenewOrgUseCase::new(invitations::RenewOrgPorts {
        org_user_store: a.org_user_store.clone(),
        org_invitation_store: a.org_invitation_store.clone(),
        organization_store: a.organization_store.clone(),
        mailing: invitation_mailing(a, s),
        mail_throttle: a.mail_throttle.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Revokes invitations under organization or operator authority.
fn revoke_invitation(a: &Adapters) -> invitations::RevokeOrgUseCase {
    invitations::RevokeOrgUseCase::new(invitations::RevokeOrgPorts {
        org_invitation_store: a.org_invitation_store.clone(),
        org_user_store: a.org_user_store.clone(),
        organization_store: a.organization_store.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Accepts invitations using password hashing, breach checks and mail availability.
fn accept_invitation(a: &Adapters) -> invitations::AcceptOrgUseCase {
    invitations::AcceptOrgUseCase::new(invitations::AcceptOrgPorts {
        org_user_store: a.org_user_store.clone(),
        org_invitation_store: a.org_invitation_store.clone(),
        organization_store: a.organization_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        hashing: password_hashing(a),
        breach_checker: a.credential_breach_checker.clone(),
        mail: a.mail_setup.clone(),
    })
}

/// Declines invitations against the stored token and member.
fn decline_invitation(a: &Adapters) -> invitations::DeclineOrgUseCase {
    invitations::DeclineOrgUseCase::new(invitations::DeclineOrgPorts {
        org_user_store: a.org_user_store.clone(),
        org_invitation_store: a.org_invitation_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Reads invitation status with its organization and token generator.
fn invitation_status(a: &Adapters) -> invitations::OrgStatusUseCase {
    invitations::OrgStatusUseCase::new(invitations::OrgStatusPorts {
        org_invitation_store: a.org_invitation_store.clone(),
        organization_store: a.organization_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Sends welcome mail under organization authority.
fn send_welcome(a: &Adapters, s: &Settings) -> invitations::SendOrgWelcomeUseCase {
    invitations::SendOrgWelcomeUseCase::new(invitations::SendOrgWelcomePorts {
        welcome: welcome_mail(a, s),
        org_actors: a.org_actors.clone(),
    })
}

/// Sends activation welcome mail through the organization's mailing ports.
fn send_activation_welcome(
    a: &Adapters,
    s: &Settings,
) -> invitations::SendOrgActivationWelcomeUseCase {
    invitations::SendOrgActivationWelcomeUseCase::new(welcome_mail(a, s))
}

/// Confirms a member's address against the verification token store.
fn confirm_member_address(a: &Adapters) -> invitations::ConfirmOrgVerificationUseCase {
    invitations::ConfirmOrgVerificationUseCase::new(invitations::ConfirmOrgVerificationPorts {
        org_user_store: a.org_user_store.clone(),
        token_store: a.org_token_store_email_verification.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Reads address verification status through the member and token stores.
fn verification_status(a: &Adapters) -> invitations::OrgVerificationStatusUseCase {
    invitations::OrgVerificationStatusUseCase::new(invitations::OrgVerificationStatusPorts {
        org_user_store: a.org_user_store.clone(),
        token_store: a.org_token_store_email_verification.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Resends address verification through the organization's mailing policy.
fn resend_verification(a: &Adapters, s: &Settings) -> invitations::ResendOrgVerificationUseCase {
    invitations::ResendOrgVerificationUseCase::new(verification_mail(a, s))
}

/// Resends address verification for a member located by email.
fn resend_verification_by_email(
    a: &Adapters,
    s: &Settings,
) -> invitations::ResendOrgVerificationByEmailUseCase {
    invitations::ResendOrgVerificationByEmailUseCase::new(verification_mail(a, s))
}

/// Resends address verification from an existing link.
fn resend_verification_from_link(
    a: &Adapters,
    s: &Settings,
) -> invitations::ResendOrgVerificationFromLinkUseCase {
    invitations::ResendOrgVerificationFromLinkUseCase::new(verification_mail(a, s))
}

/// Confirms the installation's first owner through its setup token store.
fn confirm_installer(a: &Adapters) -> invitations::ConfirmInstallerUseCase {
    invitations::ConfirmInstallerUseCase::new(invitations::ConfirmInstallerPorts {
        org_user_store: a.org_user_store.clone(),
        setup_token_store: a.org_token_store_installation_setup.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// The use cases that create, list and revoke organization API keys.
fn api_keys(a: &Adapters) -> ApiKeyState {
    ApiKeyState {
        create: Arc::new(api_keys::CreateOrgUseCase::new(api_keys::CreateOrgPorts {
            key_store: a.org_api_key_store.clone(),
            key_generator: a.api_key_generator.clone(),
            org_actors: a.org_actors.clone(),
        })),
        list: Arc::new(api_keys::ListOrgUseCase::new(api_keys::ListOrgPorts {
            key_store: a.org_api_key_store.clone(),
            org_actors: a.org_actors.clone(),
        })),
        revoke: Arc::new(api_keys::RevokeOrgUseCase::new(api_keys::RevokeOrgPorts {
            key_store: a.org_api_key_store.clone(),
            organizations: a.organization_store.clone(),
            org_actors: a.org_actors.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
    }
}

/// The use cases that connect, check, list and disconnect cloud accounts.
fn cloud_accounts(a: &Adapters, s: &Settings) -> CloudAccountState {
    CloudAccountState {
        begin: Arc::new(begin_cloud_connection(a)),
        attach: Arc::new(attach_cloud_credential(a)),
        verify: Arc::new(verify_cloud_account(a)),
        list: Arc::new(list_cloud_accounts(a)),
        external_id: Arc::new(cloud_external_id(a)),
        networks: Arc::new(list_cloud_networks(a)),
        disconnect: Arc::new(disconnect_cloud_account(a)),
        console_template: s.cloud_console_template.as_deref().map(Arc::from),
    }
}

/// Starts cloud connection through the registry and external ID generator.
fn begin_cloud_connection(a: &Adapters) -> cloud_accounts::BeginCloudConnectionUseCase {
    cloud_accounts::BeginCloudConnectionUseCase::new(cloud_accounts::BeginCloudConnectionPorts {
        store: a.cloud_account_store.clone(),
        registry: a.cloud_provider_registry.clone(),
        external_ids: a.external_id_generator.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Attaches cloud credentials under organization authority.
fn attach_cloud_credential(a: &Adapters) -> cloud_accounts::AttachCloudCredentialUseCase {
    cloud_accounts::AttachCloudCredentialUseCase::new(cloud_accounts::AttachCloudCredentialPorts {
        store: a.cloud_account_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Verifies a stored cloud account through the provider registry.
fn verify_cloud_account(a: &Adapters) -> cloud_accounts::VerifyUseCase {
    cloud_accounts::VerifyUseCase::new(cloud_accounts::VerifyPorts {
        store: a.cloud_account_store.clone(),
        registry: a.cloud_provider_registry.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Lists cloud accounts under organization authority.
fn list_cloud_accounts(a: &Adapters) -> cloud_accounts::ListUseCase {
    cloud_accounts::ListUseCase::new(cloud_accounts::ListPorts {
        store: a.cloud_account_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Reads a cloud account's external ID under organization authority.
fn cloud_external_id(a: &Adapters) -> cloud_accounts::GetCloudExternalIdUseCase {
    cloud_accounts::GetCloudExternalIdUseCase::new(cloud_accounts::GetCloudExternalIdPorts {
        store: a.cloud_account_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Lists the connected cloud account's networks through its provider.
fn list_cloud_networks(a: &Adapters) -> cloud_accounts::ListCloudNetworksUseCase {
    cloud_accounts::ListCloudNetworksUseCase::new(cloud_accounts::ListCloudNetworksPorts {
        store: a.cloud_account_store.clone(),
        registry: a.cloud_provider_registry.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Disconnects cloud accounts after checking their tenant dependencies.
fn disconnect_cloud_account(a: &Adapters) -> cloud_accounts::DisconnectUseCase {
    cloud_accounts::DisconnectUseCase::new(cloud_accounts::DisconnectPorts {
        store: a.cloud_account_store.clone(),
        tenants: a.tenant_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// The use cases that sign members in and out, and look after their
/// sessions, trusted devices and current tenant.
fn sign_in(a: &Adapters, s: &Settings) -> SignInState {
    SignInState {
        password_login: Arc::new(password_login(a, s)),
        sso_start: Arc::new(sign_in::OrgSsoStartUseCase::new(sso_start_ports(a))),
        sso_callback: Arc::new(sign_in::OrgSsoCallbackUseCase::new(sso_callback_ports(a))),
        magic_link_request: Arc::new(request_magic_link(a, s)),
        magic_link: Arc::new(follow_magic_link(a)),
        confirm_by_email: Arc::new(confirm_sign_in(a)),
        logout: Arc::new(logout(a)),
        active_sessions: Arc::new(active_sessions(a)),
        revoke_session: Arc::new(revoke_member_session(a)),
        list_devices: Arc::new(list_devices(a)),
        trust_device: Arc::new(trust_device(a, s)),
        revoke_device: Arc::new(revoke_device(a)),
        switch_tenant: Arc::new(switch_tenant(a)),
        linked_switch: Arc::new(linked_switch(a)),
        mark_credential_used: Arc::new(mark_credential_used(a)),
        app_base_url: s.app_base_url.clone(),
    }
}

/// Signs members in under the configured device trust and confirmation policies.
fn password_login(a: &Adapters, s: &Settings) -> sign_in::OrgPasswordLoginUseCase {
    sign_in::OrgPasswordLoginUseCase::new(
        password_login_ports(a),
        sign_in::OrgLoginSettings {
            device_trust: s.tunables.device_trust,
            confirmation: ConfirmationLinkPolicy {
                lifetime: s.tunables.sign_in_confirmation_ttl,
                base_url: s.app_base_url.clone(),
            },
            unnamed_threshold: s.tunables.unnamed_org_challenge_threshold,
        },
    )
}

/// Issues mailed sign-in links under the configured lifetime and throttle.
fn request_magic_link(a: &Adapters, s: &Settings) -> sign_in::RequestOrgMagicLinkUseCase {
    sign_in::RequestOrgMagicLinkUseCase::new(
        sign_in::OrgMagicLinkPolicy {
            lifetime: s.tunables.magic_link_ttl,
            base_url: s.app_base_url.clone(),
        },
        sign_in::RequestOrgMagicLinkPorts {
            members: a.org_user_store.clone(),
            organizations: a.organization_store.clone(),
            links: a.org_token_store_magic_link.clone(),
            mailer: a.mailer.clone(),
            mail_throttle: a.mail_throttle.clone(),
            token_generator: a.refresh_token_generator.clone(),
            mail: a.mail_setup.clone(),
        },
    )
}

/// Follows mailed sign-in links through the shared sign-in finishing ports.
fn follow_magic_link(a: &Adapters) -> sign_in::OrgMagicLinkUseCase {
    sign_in::OrgMagicLinkUseCase::new(sign_in::OrgMagicLinkPorts {
        links: a.org_token_store_magic_link.clone(),
        link_hasher: a.refresh_token_generator.clone(),
        members: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
        finish: finishing(a),
    })
}

/// Confirms member sign-ins against their stored sessions and emailed links.
fn confirm_sign_in(a: &Adapters) -> sign_in::OrgConfirmUseCase {
    sign_in::OrgConfirmUseCase::new(sign_in::OrgConfirmPorts {
        sessions: a.org_session_store.clone(),
        organizations: a.organization_store.clone(),
        members: a.org_user_store.clone(),
        links: a.org_token_store_sign_in_confirmation.clone(),
        token_hasher: a.refresh_token_generator.clone(),
    })
}

/// Signs members out through organization authority and session storage.
fn logout(a: &Adapters) -> sign_in::OrgLogoutUseCase {
    sign_in::OrgLogoutUseCase::new(sign_in::OrgLogoutPorts {
        sessions: a.org_session_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Lists a member's sessions with geolocation under organization authority.
fn active_sessions(a: &Adapters) -> sign_in::ListActiveSessionsUseCase {
    sign_in::ListActiveSessionsUseCase::new(sign_in::ListActiveSessionsPorts {
        sessions: a.org_session_store.clone(),
        geolocator: a.geolocator.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Revokes member sessions under organization or operator authority.
fn revoke_member_session(a: &Adapters) -> sign_in::RevokeMemberSessionUseCase {
    sign_in::RevokeMemberSessionUseCase::new(sign_in::RevokeMemberSessionPorts {
        sessions: a.org_session_store.clone(),
        organizations: a.organization_store.clone(),
        org_actors: a.org_actors.clone(),
        operators: a.operator_authorities.clone(),
    })
}

/// Lists a member's remembered devices under organization authority.
fn list_devices(a: &Adapters) -> sign_in::ListOrgDevicesUseCase {
    sign_in::ListOrgDevicesUseCase::new(sign_in::ListOrgDevicesPorts {
        devices: a.org_trusted_device_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Remembers member devices under the configured device limit.
fn trust_device(a: &Adapters, s: &Settings) -> sign_in::TrustOrgDeviceUseCase {
    sign_in::TrustOrgDeviceUseCase::new(
        Policy {
            max_devices_per_user: s.tunables.max_trusted_devices_per_user,
        },
        sign_in::TrustOrgDevicePorts {
            devices: a.org_trusted_device_store.clone(),
            device_secret_hasher: a.code_hasher.clone(),
            org_actors: a.org_actors.clone(),
        },
    )
}

/// Revokes member device trust through the stored devices and caller authority.
fn revoke_device(a: &Adapters) -> sign_in::RevokeOrgDeviceUseCase {
    sign_in::RevokeOrgDeviceUseCase::new(sign_in::RevokeOrgDevicePorts {
        devices: a.org_trusted_device_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Moves member sessions using tenant grants and newly generated refresh tokens.
fn switch_tenant(a: &Adapters) -> sign_in::SwitchOrgTenantUseCase {
    sign_in::SwitchOrgTenantUseCase::new(sign_in::SwitchOrgTenantPorts {
        sessions: a.org_session_store.clone(),
        grants: a.org_tenant_grant_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Switches linked tenant accounts through tenant authority and their stored factors.
fn linked_switch(a: &Adapters) -> sign_in::LinkedTenantSwitchUseCase {
    sign_in::LinkedTenantSwitchUseCase::new(sign_in::LinkedTenantSwitchPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        organizations: a.organization_store.clone(),
        tenants: a.tenant_store.clone(),
        users: a.user_store.clone(),
        identities: a.linked_identity_lookup.clone(),
        enrollments: a.mfa_enrollment_store.clone(),
        passkeys: a.passkey_store.clone(),
        sessions: a.session_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Records credential use through both session and API key storage.
fn mark_credential_used(a: &Adapters) -> sign_in::MarkCredentialUsedUseCase {
    sign_in::MarkCredentialUsedUseCase::new(sign_in::MarkCredentialUsedPorts {
        sessions: a.org_session_store.clone(),
        api_keys: a.org_api_key_store.clone(),
        org_actors: a.org_actors.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// What a password sign-in reads and writes.
fn password_login_ports(a: &Adapters) -> sign_in::OrgPasswordLoginPorts {
    sign_in::OrgPasswordLoginPorts {
        members: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
        tenants: a.tenant_store.clone(),
        confirmation: sign_in::OrgConfirmationMailPorts {
            links: a.org_token_store_sign_in_confirmation.clone(),
            link_tokens: a.refresh_token_generator.clone(),
            mailer: a.mailer.clone(),
            mail: a.mail_setup.clone(),
        },
        password: sign_in::OrgPasswordCheckPorts {
            hashing: password_hashing(a),
            flood: flood_gate(a),
            attempts: sign_in_counts(a),
        },
        factors: sign_in::OrgLoginFactorPorts {
            enrollments: a.org_mfa_enrollment_store.clone(),
            passkeys: a.org_passkey_store.clone(),
            devices: a.org_trusted_device_store.clone(),
            device_secret_hasher: a.code_hasher.clone(),
        },
        session: sign_in::OrgSessionOpeningPorts {
            sessions: a.org_session_store.clone(),
            grants: a.org_tenant_grant_store.clone(),
            token_generator: a.refresh_token_generator.clone(),
            roles: a.role_store.clone(),
        },
    }
}

/// What sends a member to their organization's identity provider.
fn sso_start_ports(a: &Adapters) -> sign_in::OrgSsoStartPorts {
    sign_in::OrgSsoStartPorts {
        organizations: a.organization_store.clone(),
        providers: a.org_identity_provider_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        oidc_validator: a.oidc_validator.clone(),
        saml_messages: a.saml_service_provider_messages.clone(),
        requests: a.org_sso_request_store.clone(),
        code_hasher: a.code_hasher.clone(),
    }
}

/// What checks the identity provider's answer and signs the member in.
fn sso_callback_ports(a: &Adapters) -> sign_in::OrgSsoCallbackPorts {
    sign_in::OrgSsoCallbackPorts {
        requests: a.org_sso_request_store.clone(),
        organizations: a.organization_store.clone(),
        providers: a.org_identity_provider_store.clone(),
        members: a.org_user_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        oidc_validator: a.oidc_validator.clone(),
        saml_validator: a.saml_validator.clone(),
        assertion_ledger: a.org_saml_assertion_ledger.clone(),
        code_hasher: a.code_hasher.clone(),
        finish: finishing(a),
    }
}

/// What finishes a sign-in another way began: the factor it owes, where it
/// lands, and the session it opens.
fn finishing(a: &Adapters) -> sign_in::FinishingPorts {
    sign_in::FinishingPorts {
        members: a.org_user_store.clone(),
        enrollments: a.org_mfa_enrollment_store.clone(),
        passkeys: a.org_passkey_store.clone(),
        tenants: a.tenant_store.clone(),
        sessions: a.org_session_store.clone(),
        grants: a.org_tenant_grant_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        roles: a.role_store.clone(),
    }
}

/// The use cases that set up, check and switch off a member's second
/// factor, and answer a sign-in or renew the codes with recovery codes.
fn mfa(a: &Adapters, s: &Settings) -> MfaState {
    MfaState {
        status: Arc::new(factor_status(a)),
        begin: Arc::new(begin_factor(a, s)),
        confirm: Arc::new(confirm_factor(a, s)),
        abandon: Arc::new(abandon_factor(a)),
        disable: Arc::new(disable_factor(a, s)),
        verify: Arc::new(verify_factor(a, s)),
        recovery_sign_in: Arc::new(recovery_sign_in(a, s)),
        regenerate_codes: Arc::new(regenerate_recovery_codes(a)),
    }
}

/// Reads member enrollment status under organization authority.
fn factor_status(a: &Adapters) -> mfa::GetOrgStatusUseCase {
    mfa::GetOrgStatusUseCase::new(mfa::GetOrgStatusPorts {
        enrollment_store: a.org_mfa_enrollment_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Starts an authenticator enrollment with the configured issuer and member proof ports.
fn begin_factor(a: &Adapters, s: &Settings) -> mfa::OrgBeginUseCase {
    mfa::OrgBeginUseCase::new(
        s.tunables.mfa_issuer.clone(),
        mfa::OrgBeginPorts {
            enrollment_store: a.org_mfa_enrollment_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            setters: member_setters(a),
        },
    )
}

/// Confirms an enrollment and issues recovery codes under the configured lockout.
fn confirm_factor(a: &Adapters, s: &Settings) -> mfa::OrgConfirmUseCase {
    mfa::OrgConfirmUseCase::new(
        s.tunables.mfa_lockout,
        mfa::OrgConfirmPorts {
            codes: member_codes(a),
            recovery_generator: a.recovery_code_generator.clone(),
            recovery_store: a.org_recovery_code_store.clone(),
            setters: member_setters(a),
        },
    )
}

/// Abandons a pending enrollment through member proof ports.
fn abandon_factor(a: &Adapters) -> mfa::OrgAbandonUseCase {
    mfa::OrgAbandonUseCase::new(mfa::OrgAbandonPorts {
        enrollment_store: a.org_mfa_enrollment_store.clone(),
        setters: member_setters(a),
    })
}

/// Disables a member's authenticator after code verification.
fn disable_factor(a: &Adapters, s: &Settings) -> mfa::OrgDisableUseCase {
    mfa::OrgDisableUseCase::new(
        s.tunables.mfa_lockout,
        mfa::OrgDisablePorts {
            codes: member_codes(a),
            members: a.org_user_store.clone(),
            org_actors: a.org_actors.clone(),
        },
    )
}

/// Verifies a sign-in's second factor against its session and organization.
fn verify_factor(a: &Adapters, s: &Settings) -> mfa::OrgVerifyUseCase {
    mfa::OrgVerifyUseCase::new(
        s.tunables.mfa_lockout,
        mfa::OrgVerifyPorts {
            sessions: a.org_session_store.clone(),
            organizations: a.organization_store.clone(),
            members: a.org_user_store.clone(),
            codes: member_codes(a),
        },
    )
}

/// Answers a member sign-in with a stored recovery code under the configured lockout.
fn recovery_sign_in(a: &Adapters, s: &Settings) -> mfa::OrgRecoveryCodeSignInUseCase {
    mfa::OrgRecoveryCodeSignInUseCase::new(
        s.tunables.mfa_lockout,
        mfa::OrgRecoveryCodeSignInPorts {
            sessions: a.org_session_store.clone(),
            organizations: a.organization_store.clone(),
            members: a.org_user_store.clone(),
            enrollment_store: a.org_mfa_enrollment_store.clone(),
            recovery_store: a.org_recovery_code_store.clone(),
            recovery_generator: a.recovery_code_generator.clone(),
        },
    )
}

/// Replaces a member's recovery codes through their enrollment and proof ports.
fn regenerate_recovery_codes(a: &Adapters) -> mfa::RegenerateOrgRecoveryCodesUseCase {
    mfa::RegenerateOrgRecoveryCodesUseCase::new(mfa::RegenerateOrgRecoveryCodesPorts {
        enrollment_store: a.org_mfa_enrollment_store.clone(),
        recovery_store: a.org_recovery_code_store.clone(),
        recovery_generator: a.recovery_code_generator.clone(),
        setters: member_setters(a),
    })
}

/// The use cases that add, list, rename and remove a member's passkeys, and
/// sign in with one.
fn passkeys(a: &Adapters, s: &Settings) -> PasskeyState {
    PasskeyState {
        register_begin: Arc::new(begin_passkey_registration(a, s)),
        register_confirm: Arc::new(confirm_passkey_registration(a, s)),
        list: Arc::new(list_passkeys(a)),
        rename: Arc::new(rename_passkey(a)),
        delete: Arc::new(delete_passkey(a)),
        login_begin: Arc::new(begin_passkey_sign_in(a, s)),
        login_discover: Arc::new(discover_passkey(a, s)),
        login_confirm: Arc::new(confirm_passkey_sign_in(a)),
    }
}

/// Starts member passkey registration with the configured ceremony lifetime.
fn begin_passkey_registration(a: &Adapters, s: &Settings) -> passkeys::OrgRegisterBeginUseCase {
    let ceremony = s.tunables.passkey_ceremony_ttl;
    passkeys::OrgRegisterBeginUseCase::new(
        ceremony,
        passkeys::OrgRegisterBeginPorts {
            registrant: member_registrants(a),
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.org_passkey_ceremony_store.clone(),
        },
    )
}

/// Confirms member passkeys under the configured limit with fresh proofs.
fn confirm_passkey_registration(a: &Adapters, s: &Settings) -> passkeys::OrgRegisterConfirmUseCase {
    passkeys::OrgRegisterConfirmUseCase::new(
        passkeys::OrgPolicy {
            max_passkeys_per_user: s.tunables.max_passkeys_per_user,
        },
        passkeys::OrgRegisterConfirmPorts {
            registrant: member_registrants(a),
            fresh_proofs: a.fresh_proofs.clone(),
            passkey_store: a.org_passkey_store.clone(),
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.org_passkey_ceremony_store.clone(),
        },
    )
}

/// Lists member passkeys under organization authority.
fn list_passkeys(a: &Adapters) -> passkeys::OrgListUseCase {
    passkeys::OrgListUseCase::new(passkeys::OrgListPorts {
        passkey_store: a.org_passkey_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Renames member passkeys under organization authority.
fn rename_passkey(a: &Adapters) -> passkeys::OrgRenameUseCase {
    passkeys::OrgRenameUseCase::new(passkeys::OrgRenamePorts {
        passkey_store: a.org_passkey_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Deletes member passkeys with the member and session stores.
fn delete_passkey(a: &Adapters) -> passkeys::OrgDeleteUseCase {
    passkeys::OrgDeleteUseCase::new(passkeys::OrgDeletePorts {
        passkey_store: a.org_passkey_store.clone(),
        members: a.org_user_store.clone(),
        sessions: a.org_session_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Starts a member's passkey sign-in with its stored ceremony.
fn begin_passkey_sign_in(a: &Adapters, s: &Settings) -> passkeys::OrgLoginBeginUseCase {
    let ceremony = s.tunables.passkey_ceremony_ttl;
    passkeys::OrgLoginBeginUseCase::new(
        ceremony,
        passkeys::OrgLoginBeginPorts {
            org_user_store: a.org_user_store.clone(),
            passkey_store: a.org_passkey_store.clone(),
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.org_passkey_ceremony_store.clone(),
        },
    )
}

/// Starts a discoverable member passkey ceremony.
fn discover_passkey(a: &Adapters, s: &Settings) -> passkeys::OrgDiscoverBeginUseCase {
    let ceremony = s.tunables.passkey_ceremony_ttl;
    passkeys::OrgDiscoverBeginUseCase::new(
        ceremony,
        passkeys::OrgDiscoverBeginPorts {
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.org_passkey_ceremony_store.clone(),
        },
    )
}

/// Confirms passkey sign-in through member, tenant, grant and session storage.
fn confirm_passkey_sign_in(a: &Adapters) -> passkeys::OrgLoginConfirmUseCase {
    passkeys::OrgLoginConfirmUseCase::new(passkeys::OrgLoginConfirmPorts {
        passkey_store: a.org_passkey_store.clone(),
        verifier: a.passkey_verifier.clone(),
        ceremony_store: a.org_passkey_ceremony_store.clone(),
        org_user_store: a.org_user_store.clone(),
        org_store: a.organization_store.clone(),
        tenant_store: a.tenant_store.clone(),
        grant_store: a.org_tenant_grant_store.clone(),
        role_store: a.role_store.clone(),
        org_session_store: a.org_session_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// The use cases that let a member who forgot their password set a new one.
fn password_reset(a: &Adapters, s: &Settings) -> PasswordResetState {
    let request = Arc::new(password_reset::RequestOrgResetUseCase::new(
        password_reset::OrgResetPolicy {
            lifetime: s.tunables.password_reset_ttl,
            base_url: s.app_base_url.clone(),
        },
        password_reset::RequestOrgResetPorts {
            org_user_store: a.org_user_store.clone(),
            org_store: a.organization_store.clone(),
            token_store: a.org_token_store_password_reset.clone(),
            mailer: a.mailer.clone(),
            mail_throttle: a.mail_throttle.clone(),
            token_generator: a.refresh_token_generator.clone(),
            mail: a.mail_setup.clone(),
        },
    ));
    PasswordResetState {
        resend: Arc::new(password_reset::ResendOrgResetUseCase::new(
            request.clone(),
            s.tunables.resend_cooldown,
            password_reset::ResendOrgResetPorts {
                token_store: a.org_token_store_password_reset.clone(),
                token_generator: a.refresh_token_generator.clone(),
            },
        )),
        request,
        status: Arc::new(password_reset_status(a)),
        confirm: Arc::new(confirm_password_reset(a, s)),
    }
}

/// Reads reset-link status with the member's organization.
fn password_reset_status(a: &Adapters) -> password_reset::OrgResetStatusUseCase {
    password_reset::OrgResetStatusUseCase::new(password_reset::OrgResetStatusPorts {
        org_user_store: a.org_user_store.clone(),
        token_store: a.org_token_store_password_reset.clone(),
        org_store: a.organization_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Confirms a password reset using factor verification, hashing and breach checks.
fn confirm_password_reset(a: &Adapters, s: &Settings) -> password_reset::ConfirmOrgResetUseCase {
    password_reset::ConfirmOrgResetUseCase::new(
        s.tunables.mfa_lockout,
        password_reset::ConfirmOrgResetPorts {
            org_user_store: a.org_user_store.clone(),
            token_store: a.org_token_store_password_reset.clone(),
            org_session_store: a.org_session_store.clone(),
            org_store: a.organization_store.clone(),
            mfa_store: a.org_mfa_enrollment_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            hashing: password_hashing(a),
            token_generator: a.refresh_token_generator.clone(),
            breach_checker: a.credential_breach_checker.clone(),
        },
    )
}

/// The use cases that read, add, change, switch and remove the
/// organization's identity provider.
fn identity_provider(a: &Adapters) -> IdentityProviderState {
    IdentityProviderState {
        get: Arc::new(get_identity_provider(a)),
        add: Arc::new(add_identity_provider(a)),
        change: Arc::new(change_identity_provider(a)),
        switch: Arc::new(switch_identity_provider(a)),
        remove: Arc::new(remove_identity_provider(a)),
    }
}

/// Reads the organization's identity provider under caller authority.
fn get_identity_provider(a: &Adapters) -> identity_providers::GetOrgUseCase {
    identity_providers::GetOrgUseCase::new(identity_providers::GetOrgPorts {
        providers: a.org_identity_provider_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Adds a provider with encrypted secrets and OIDC validation.
fn add_identity_provider(a: &Adapters) -> identity_providers::AddOrgUseCase {
    identity_providers::AddOrgUseCase::new(identity_providers::AddOrgPorts {
        providers: a.org_identity_provider_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        oidc_validator: a.oidc_validator.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Changes provider settings using fresh proofs and OIDC validation.
fn change_identity_provider(a: &Adapters) -> identity_providers::ChangeOrgUseCase {
    identity_providers::ChangeOrgUseCase::new(identity_providers::ChangeOrgPorts {
        providers: a.org_identity_provider_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        oidc_validator: a.oidc_validator.clone(),
        org_actors: a.org_actors.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
    })
}

/// Switches a provider's status using fresh organization proofs.
fn switch_identity_provider(a: &Adapters) -> identity_providers::SwitchOrgUseCase {
    identity_providers::SwitchOrgUseCase::new(identity_providers::SwitchOrgPorts {
        providers: a.org_identity_provider_store.clone(),
        org_actors: a.org_actors.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
    })
}

/// Removes the organization's identity provider under caller authority.
fn remove_identity_provider(a: &Adapters) -> identity_providers::RemoveOrgUseCase {
    identity_providers::RemoveOrgUseCase::new(identity_providers::RemoveOrgPorts {
        providers: a.org_identity_provider_store.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// The use cases that record members' consent and erase their data.
fn privacy(a: &Adapters, s: &Settings) -> PrivacyState {
    PrivacyState {
        grant_consent: Arc::new(grant_consent(a)),
        revoke_consent: Arc::new(revoke_consent(a)),
        list_consents: Arc::new(list_consents(a)),
        request_erasure: Arc::new(request_erasure(a, s)),
        cancel_erasure: Arc::new(cancel_erasure(a)),
        cancel_erasure_by_link: Arc::new(cancel_erasure_by_link(a)),
        hold_erasure: Arc::new(hold_erasure(a)),
        release_erasure: Arc::new(release_erasure(a)),
    }
}

/// Records member consent through organization authority.
fn grant_consent(a: &Adapters) -> privacy::GrantOrgConsentUseCase {
    privacy::GrantOrgConsentUseCase::new(privacy::GrantOrgConsentPorts {
        org_actors: a.org_actors.clone(),
        consents: a.org_consent_store.clone(),
    })
}

/// Revokes member consent against the member and consent stores.
fn revoke_consent(a: &Adapters) -> privacy::RevokeOrgConsentUseCase {
    privacy::RevokeOrgConsentUseCase::new(privacy::RevokeOrgConsentPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        consents: a.org_consent_store.clone(),
    })
}

/// Lists member consent through organization authority.
fn list_consents(a: &Adapters) -> privacy::ListOrgConsentsUseCase {
    privacy::ListOrgConsentsUseCase::new(privacy::ListOrgConsentsPorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        consents: a.org_consent_store.clone(),
    })
}

/// Requests erasure with session and grant revocation and a mailed cancellation link.
fn request_erasure(a: &Adapters, s: &Settings) -> privacy::RequestOrgErasureUseCase {
    privacy::RequestOrgErasureUseCase::new(privacy::RequestOrgErasurePorts {
        org_actors: a.org_actors.clone(),
        org_users: a.org_user_store.clone(),
        erasures: a.org_erasure_request_store.clone(),
        org_sessions: a.org_session_store.clone(),
        grant_revocation: grant_revocation(a),
        mailer: a.mailer.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: privacy::OrgErasurePolicy {
            grace_period: s.tunables.erasure_grace,
            base_url: s.app_base_url.clone(),
        },
    })
}

/// Cancels erasure through organization authority and stored member state.
fn cancel_erasure(a: &Adapters) -> privacy::CancelOrgErasureUseCase {
    privacy::CancelOrgErasureUseCase::new(privacy::CancelOrgErasurePorts {
        org_actors: a.org_actors.clone(),
        erasures: a.org_erasure_request_store.clone(),
        org_users: a.org_user_store.clone(),
    })
}

/// Cancels erasure using the token in a mailed link.
fn cancel_erasure_by_link(a: &Adapters) -> privacy::CancelOrgErasureByLinkUseCase {
    privacy::CancelOrgErasureByLinkUseCase::new(privacy::CancelOrgErasureByLinkPorts {
        erasures: a.org_erasure_request_store.clone(),
        org_users: a.org_user_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Places member erasure on hold under organization authority.
fn hold_erasure(a: &Adapters) -> privacy::HoldOrgErasureUseCase {
    privacy::HoldOrgErasureUseCase::new(privacy::HoldOrgErasurePorts {
        org_actors: a.org_actors.clone(),
        erasures: a.org_erasure_request_store.clone(),
        org_users: a.org_user_store.clone(),
    })
}

/// Releases a member's erasure hold under organization authority.
fn release_erasure(a: &Adapters) -> privacy::ReleaseOrgErasureUseCase {
    privacy::ReleaseOrgErasureUseCase::new(privacy::ReleaseOrgErasurePorts {
        org_actors: a.org_actors.clone(),
        erasures: a.org_erasure_request_store.clone(),
        org_users: a.org_user_store.clone(),
    })
}

/// The use cases that read, change and reset the organization's branding.
fn branding(a: &Adapters) -> BrandingState {
    BrandingState {
        get: Arc::new(branding::GetOrgUseCase::new(branding::GetOrgPorts {
            org_actors: a.org_actors.clone(),
            branding: a.org_branding_store.clone(),
        })),
        change: Arc::new(branding::ChangeOrgUseCase::new(branding::ChangeOrgPorts {
            org_actors: a.org_actors.clone(),
            branding: a.org_branding_store.clone(),
        })),
        reset: Arc::new(branding::ResetOrgUseCase::new(branding::ResetOrgPorts {
            org_actors: a.org_actors.clone(),
            branding: a.org_branding_store.clone(),
        })),
    }
}

/// Makes and hashes the passwords an owner hands a member.
fn password_maker(a: &Adapters) -> Arc<PasswordMaker> {
    Arc::new(PasswordMaker::new(
        password_hashing(a),
        a.secure_random.clone(),
    ))
}

/// Withdraws what a member granted when they leave or are switched off.
fn grant_revocation(a: &Adapters) -> OrgGrantRevocation {
    OrgGrantRevocation::new(
        a.tenant_store.clone(),
        GrantRevocation::new(a.delegation_store.clone()),
    )
}

/// How organization invitations are sent: through the mailer, as far as
/// this deployment mails, lasting as long as an organization invitation
/// does, with where its link lands and how soon another may be sent.
fn invitation_mailing(a: &Adapters, s: &Settings) -> InvitationMailing {
    InvitationMailing {
        mailer: a.mailer.clone(),
        mail: a.mail_setup.clone(),
        policy: InvitationPolicy {
            lifetime: s.tunables.org_invitation_lifetime,
            base_url: s.app_base_url.clone(),
            resend_cooldown: s.tunables.resend_cooldown,
        },
    }
}

/// What mails a member the link that confirms their address.
fn verification_mail(a: &Adapters, s: &Settings) -> invitations::OrgVerificationMail {
    invitations::OrgVerificationMail {
        org_user_store: a.org_user_store.clone(),
        organization_store: a.organization_store.clone(),
        token_store: a.org_token_store_email_verification.clone(),
        mailer: a.mailer.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: VerificationPolicy {
            lifetime: s.tunables.org_verification_lifetime,
            base_url: s.app_base_url.clone(),
            resend_cooldown: s.tunables.resend_cooldown,
        },
        mail: a.mail_setup.clone(),
    }
}

/// What mails a member that their account is ready.
fn welcome_mail(a: &Adapters, s: &Settings) -> invitations::OrgWelcomePorts {
    invitations::OrgWelcomePorts {
        org_user_store: a.org_user_store.clone(),
        organization_store: a.organization_store.clone(),
        mailer: a.mailer.clone(),
        base_url: s.app_base_url.clone(),
    }
}

/// What works out who sets up a member's second factor.
fn member_setters(a: &Adapters) -> mfa::setter::MemberSetterPorts {
    mfa::setter::MemberSetterPorts {
        org_actors: a.org_actors.clone(),
        members: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
        sessions: a.org_session_store.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
    }
}

/// What checks a code against a member's second factor.
fn member_codes(a: &Adapters) -> mfa::codes::MemberCodePorts {
    mfa::codes::MemberCodePorts {
        enrollment_store: a.org_mfa_enrollment_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        verifier: a.mfa_verifier.clone(),
    }
}

/// What works out who adds a member's passkey.
fn member_registrants(a: &Adapters) -> passkeys::registrant::MemberRegistrantPorts {
    passkeys::registrant::MemberRegistrantPorts {
        org_actors: a.org_actors.clone(),
        sessions: a.org_session_store.clone(),
        members: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
        token_hasher: a.refresh_token_generator.clone(),
    }
}
