//! The identity use cases the API serves: a tenant's users, their sessions,
//! invitations, addresses, custom attributes, privacy requests and support
//! impersonations, and an organization member's own address.

use std::sync::Arc;

use ianua_app::email::{InvitationMailing, InvitationPolicy};
use ianua_app::services::authorization::grant_revocation::GrantRevocation;
use ianua_app::use_cases::identity::invitations::inviter::InviterPorts;
use ianua_app::use_cases::identity::{
    attributes, email, impersonation, imports, invitations, privacy, users,
};

use crate::authentication::{new_password, password_hashing, reset_mail, reset_policy};
use crate::deps::{Adapters, Settings};

/// The identity use cases, grouped as the app groups them.
#[derive(Clone)]
pub struct IdentityState {
    /// A tenant's users.
    pub users: UserUseCases,
    pub sessions: UserSessionUseCases,
    pub invitations: InvitationUseCases,
    pub email: EmailUseCases,
    pub attributes: AttributeUseCases,
    pub privacy: PrivacyUseCases,
    pub impersonation: ImpersonationUseCases,
}

/// Creating, reading, changing and removing a tenant's users, a person's
/// own account, sign-up and preferences.
#[derive(Clone)]
pub struct UserUseCases {
    /// An admin adding an account to the tenant.
    pub register: Arc<users::RegisterUseCase>,
    pub import: Arc<imports::StartUseCase>,
    pub get_import: Arc<imports::GetUseCase>,
    pub list: Arc<users::ListUseCase>,
    pub get: Arc<users::GetUseCase>,
    pub get_me: Arc<users::GetMeUseCase>,
    pub rename: Arc<users::RenameUseCase>,
    pub update_details: Arc<users::UpdateDetailsUseCase>,
    pub update_records: Arc<users::UpdateRecordsUseCase>,
    pub update_status: Arc<users::UpdateStatusUseCase>,
    pub deactivate: Arc<users::DeactivateUseCase>,
    pub delete: Arc<users::DeleteUseCase>,
    pub reset_password: Arc<users::ResetPasswordUseCase>,
    pub send_reset_link: Arc<users::SendResetLinkUseCase>,
    pub reset_factors: Arc<users::ResetFactorsUseCase>,
    pub update_preferences: Arc<users::UpdatePreferencesUseCase>,
    pub sign_up: Arc<users::SignUpUseCase>,
    pub sign_up_rules: Arc<users::SignUpRulesUseCase>,
}

/// A user's sessions and sign-in history, read and ended by themselves or
/// by an admin.
#[derive(Clone)]
pub struct UserSessionUseCases {
    pub list: Arc<users::ListSessionsUseCase>,
    pub revoke: Arc<users::RevokeSessionUseCase>,
    pub sign_out_others: Arc<users::SignOutOtherSessionsUseCase>,
    pub sign_ins: Arc<users::ListSignInsUseCase>,
}

/// Inviting people into a tenant, their answers, and welcoming them.
#[derive(Clone)]
pub struct InvitationUseCases {
    pub invite: Arc<invitations::InviteUserUseCase>,
    pub accept: Arc<invitations::AcceptUseCase>,
    pub decline: Arc<invitations::DeclineUseCase>,
    pub status: Arc<invitations::StatusUseCase>,
    pub renew: Arc<invitations::RenewUseCase>,
    pub resend: Arc<invitations::ResendUseCase>,
    pub revoke: Arc<invitations::RevokeUseCase>,
    pub send_welcome: Arc<invitations::SendWelcomeUseCase>,
    pub send_activation_welcome: Arc<invitations::SendActivationWelcomeUseCase>,
}

/// Confirming addresses and moving accounts onto new ones, on the tenant
/// plane and the organization plane.
#[derive(Clone)]
pub struct EmailUseCases {
    pub change: Arc<email::ChangeUseCase>,
    pub request_change: Arc<email::RequestChangeUseCase>,
    pub confirm_change: Arc<email::ConfirmChangeUseCase>,
    pub cancel_change: Arc<email::CancelChangeUseCase>,
    pub change_status: Arc<email::ChangeStatusUseCase>,
    pub resend_change: Arc<email::ResendChangeUseCase>,
    pub send_verification: Arc<email::SendVerificationUseCase>,
    pub verify: Arc<email::VerifyUseCase>,
    pub verification_status: Arc<email::VerificationStatusUseCase>,
    pub resend_verification: Arc<email::ResendVerificationUseCase>,
    pub request_org_change: Arc<email::RequestOrgChangeUseCase>,
    pub confirm_org_change: Arc<email::ConfirmOrgChangeUseCase>,
    pub cancel_org_change: Arc<email::CancelOrgChangeUseCase>,
    pub org_change_status: Arc<email::OrgChangeStatusUseCase>,
    pub resend_org_change: Arc<email::ResendOrgChangeUseCase>,
}

/// A tenant's custom user attributes: their declarations and the values
/// people hold.
#[derive(Clone)]
pub struct AttributeUseCases {
    pub declare: Arc<attributes::DeclareUseCase>,
    pub list: Arc<attributes::ListUseCase>,
    pub schema: Arc<attributes::GetSchemaUseCase>,
    pub update: Arc<attributes::UpdateUseCase>,
    pub set_status: Arc<attributes::SetStatusUseCase>,
    pub delete: Arc<attributes::DeleteUseCase>,
    pub values: Arc<attributes::GetMetadataUseCase>,
    pub page_values: Arc<attributes::GetUsersMetadataUseCase>,
    pub set_value: Arc<attributes::SetValueUseCase>,
    pub delete_values: Arc<attributes::DeleteUserMetadataUseCase>,
}

/// Consent records, data exports and data erasure.
#[derive(Clone)]
pub struct PrivacyUseCases {
    pub grant_consent: Arc<privacy::GrantConsentUseCase>,
    pub revoke_consent: Arc<privacy::RevokeConsentUseCase>,
    pub consent_history: Arc<privacy::ConsentHistoryUseCase>,
    pub request_export: Arc<privacy::RequestExportUseCase>,
    pub list_exports: Arc<privacy::ListExportsUseCase>,
    pub download_export: Arc<privacy::DownloadExportUseCase>,
    pub request_erasure: Arc<privacy::RequestErasureUseCase>,
    pub cancel_erasure: Arc<privacy::CancelErasureUseCase>,
    pub cancel_erasure_by_link: Arc<privacy::CancelErasureByLinkUseCase>,
    pub hold_erasure: Arc<privacy::HoldErasureUseCase>,
    pub release_erasure: Arc<privacy::ReleaseErasureUseCase>,
}

/// A tenant admin acting as a user for support: asking, the person's
/// answer, ending it, and the caller the admin acts through.
#[derive(Clone)]
pub struct ImpersonationUseCases {
    pub request: Arc<impersonation::RequestUseCase>,
    pub approve: Arc<impersonation::ApproveUseCase>,
    pub decline: Arc<impersonation::DeclineUseCase>,
    pub end: Arc<impersonation::EndUseCase>,
    pub list: Arc<impersonation::ListImpersonationsUseCase>,
    pub act_as: Arc<impersonation::ActAsUseCase>,
}

/// Builds the identity use cases over `a`, tuned by `s`.
pub fn build(a: &Adapters, s: &Settings) -> IdentityState {
    let links = verification_links(a, s);
    IdentityState {
        users: users(a, s, &links),
        sessions: user_sessions(a),
        invitations: invitations(a, s),
        email: email(a, s, &links),
        attributes: attributes(a),
        privacy: privacy(a, s),
        impersonation: impersonations(a),
    }
}

/// The user use cases, mailing confirmation links through `links`.
fn users(a: &Adapters, s: &Settings, links: &Arc<email::VerificationLinks>) -> UserUseCases {
    UserUseCases {
        register: Arc::new(register(a, links)),
        import: Arc::new(import(a)),
        get_import: Arc::new(get_import(a)),
        list: Arc::new(list_users(a)),
        get: Arc::new(users::GetUseCase::new(users::GetPorts {
            user_store: a.user_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get_me: Arc::new(users::GetMeUseCase::new(users::GetMePorts {
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        rename: Arc::new(rename(a)),
        update_details: Arc::new(update_details(a)),
        update_records: Arc::new(update_records(a)),
        update_status: Arc::new(update_status(a)),
        deactivate: Arc::new(deactivate(a)),
        delete: Arc::new(delete_user(a)),
        reset_password: Arc::new(reset_password(a)),
        send_reset_link: Arc::new(send_reset_link(a, s)),
        reset_factors: Arc::new(reset_factors(a)),
        update_preferences: Arc::new(update_preferences(a)),
        sign_up: Arc::new(sign_up(a, links)),
        sign_up_rules: Arc::new(users::SignUpRulesUseCase::new(users::SignUpRulesPorts {
            tenant_store: a.tenant_store.clone(),
        })),
    }
}

/// Reads queued user imports under tenant authority.
fn get_import(a: &Adapters) -> imports::GetUseCase {
    imports::GetUseCase::new(imports::GetPorts {
        import_store: a.user_import_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Lists users with their invitations, roles and declared attributes.
fn list_users(a: &Adapters) -> users::ListUseCase {
    users::ListUseCase::new(users::ListPorts {
        user_store: a.user_store.clone(),
        invitation_store: a.invitation_store.clone(),
        role_store: a.role_store.clone(),
        attribute_store: a.user_attribute_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Renames users together with their effective access records.
fn rename(a: &Adapters) -> users::RenameUseCase {
    users::RenameUseCase::new(users::RenamePorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes account preferences under tenant authority.
fn update_preferences(a: &Adapters) -> users::UpdatePreferencesUseCase {
    users::UpdatePreferencesUseCase::new(users::UpdatePreferencesPorts {
        user_store: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// An admin registering a user, confirmed through `links`.
fn register(a: &Adapters, links: &Arc<email::VerificationLinks>) -> users::RegisterUseCase {
    users::RegisterUseCase::new(users::RegisterPorts {
        user_store: a.user_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        credential_store: a.credential_store.clone(),
        tenant_store: a.tenant_store.clone(),
        role_store: a.role_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        verification_links: links.clone(),
        passwords: passwords(a),
        new_password: new_password(a),
        guard: crate::workflows::change_guard(a),
    })
}

/// An admin bringing accounts over from another system: kept and queued
/// here, opened and mailed by the worker.
fn import(a: &Adapters) -> imports::StartUseCase {
    imports::StartUseCase::new(imports::StartPorts {
        import_store: a.user_import_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        job_queue: a.job_queue.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changing a user's personal details.
fn update_details(a: &Adapters) -> users::UpdateDetailsUseCase {
    users::UpdateDetailsUseCase::new(users::UpdateDetailsPorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changing what the company's directory records about a user.
fn update_records(a: &Adapters) -> users::UpdateRecordsUseCase {
    users::UpdateRecordsUseCase::new(users::UpdateRecordsPorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Letting a user in or shutting them out.
fn update_status(a: &Adapters) -> users::UpdateStatusUseCase {
    users::UpdateStatusUseCase::new(users::UpdateStatusPorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        removal: removal(a),
    })
}

/// Switching a user off.
fn deactivate(a: &Adapters) -> users::DeactivateUseCase {
    users::DeactivateUseCase::new(users::DeactivatePorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        removal: removal(a),
    })
}

/// Removing a user for good, with the agents they own.
fn delete_user(a: &Adapters) -> users::DeleteUseCase {
    users::DeleteUseCase::new(users::DeletePorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        agent_store: a.agent_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        removal: removal(a),
    })
}

/// An admin setting a user's password.
fn reset_password(a: &Adapters) -> users::ResetPasswordUseCase {
    users::ResetPasswordUseCase::new(users::ResetPasswordPorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        credential_store: a.credential_store.clone(),
        tenant_store: a.tenant_store.clone(),
        session_store: a.session_store.clone(),
        passwords: passwords(a),
        hashing: password_hashing(a),
        new_password: new_password(a),
    })
}

/// An admin mailing a user a reset link instead of choosing the password.
fn send_reset_link(a: &Adapters, s: &Settings) -> users::SendResetLinkUseCase {
    users::SendResetLinkUseCase::new(
        reset_policy(s),
        users::SendResetLinkPorts {
            user_store: a.user_store.clone(),
            access_records: a.access_record_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            mail: reset_mail(a),
        },
    )
}

/// An admin clearing a user's second factor and passkeys.
fn reset_factors(a: &Adapters) -> users::ResetFactorsUseCase {
    users::ResetFactorsUseCase::new(users::ResetFactorsPorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        enrollment_store: a.mfa_enrollment_store.clone(),
        passkey_store: a.passkey_store.clone(),
    })
}

/// A person signing themselves up, confirmed through `links`.
fn sign_up(a: &Adapters, links: &Arc<email::VerificationLinks>) -> users::SignUpUseCase {
    users::SignUpUseCase::new(users::SignUpPorts {
        tenant_store: a.tenant_store.clone(),
        user_store: a.user_store.clone(),
        credential_store: a.credential_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        role_store: a.role_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        verification_links: links.clone(),
        hashing: password_hashing(a),
        new_password: new_password(a),
    })
}

/// A user's sessions and sign-in history.
fn user_sessions(a: &Adapters) -> UserSessionUseCases {
    UserSessionUseCases {
        list: Arc::new(users::ListSessionsUseCase::new(users::ListSessionsPorts {
            session_store: a.session_store.clone(),
            user_store: a.user_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        revoke: Arc::new(users::RevokeSessionUseCase::new(
            users::RevokeSessionPorts {
                session_store: a.session_store.clone(),
                access_records: a.access_record_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        sign_out_others: Arc::new(users::SignOutOtherSessionsUseCase::new(
            users::SignOutOtherSessionsPorts {
                session_store: a.session_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        sign_ins: Arc::new(users::ListSignInsUseCase::new(users::ListSignInsPorts {
            audit_log: a.tenant_audit_log_store.clone(),
            user_store: a.user_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The invitation use cases.
fn invitations(a: &Adapters, s: &Settings) -> InvitationUseCases {
    InvitationUseCases {
        invite: Arc::new(invite(a, s)),
        accept: Arc::new(accept(a)),
        decline: Arc::new(decline_invitation(a)),
        status: Arc::new(invitations::StatusUseCase::new(invitations::StatusPorts {
            invitation_store: a.invitation_store.clone(),
            tenant_store: a.tenant_store.clone(),
            token_generator: a.refresh_token_generator.clone(),
        })),
        renew: Arc::new(renew_invitation(a, s)),
        resend: Arc::new(resend_invitation(a, s)),
        revoke: Arc::new(invitations::RevokeUseCase::new(invitations::RevokePorts {
            user_store: a.user_store.clone(),
            invitation_store: a.invitation_store.clone(),
            access_records: a.access_record_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        send_welcome: Arc::new(invitations::SendWelcomeUseCase::new(
            invitations::SendWelcomePorts {
                welcome: welcome(a, s),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        send_activation_welcome: Arc::new(invitations::SendActivationWelcomeUseCase::new(welcome(
            a, s,
        ))),
    }
}

/// Declines invitations through the token generator and associated account records.
fn decline_invitation(a: &Adapters) -> invitations::DeclineUseCase {
    invitations::DeclineUseCase::new(invitations::DeclinePorts {
        user_store: a.user_store.clone(),
        invitation_store: a.invitation_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Renews invitations using the deployment's mailing policy and token generator.
fn renew_invitation(a: &Adapters, s: &Settings) -> invitations::RenewUseCase {
    invitations::RenewUseCase::new(invitations::RenewPorts {
        user_store: a.user_store.clone(),
        invitation_store: a.invitation_store.clone(),
        mailing: invitation_mailing(a, s),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Inviting someone into the tenant.
fn invite(a: &Adapters, s: &Settings) -> invitations::InviteUserUseCase {
    invitations::InviteUserUseCase::new(invitations::InviteUserPorts {
        user_store: a.user_store.clone(),
        invitation_store: a.invitation_store.clone(),
        role_store: a.role_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        mailing: invitation_mailing(a, s),
        mail_throttle: a.mail_throttle.clone(),
        token_generator: a.refresh_token_generator.clone(),
        guard: crate::workflows::change_guard(a),
    })
}

/// An invitee accepting from their link.
fn accept(a: &Adapters) -> invitations::AcceptUseCase {
    invitations::AcceptUseCase::new(invitations::AcceptPorts {
        invitation_store: a.invitation_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        inviter: inviter(a),
        mail: a.mail_setup.clone(),
        account: invitations::AcceptedAccountPorts {
            user_store: a.user_store.clone(),
            credential_store: a.credential_store.clone(),
            tenant_store: a.tenant_store.clone(),
            token_generator: a.refresh_token_generator.clone(),
            hashing: password_hashing(a),
            new_password: new_password(a),
        },
        roles: invitations::AcceptedRolePorts {
            role_store: a.role_store.clone(),
            assignment_store: a.role_assignment_store.clone(),
            separation_rules: a.separation_rule_store.clone(),
        },
    })
}

/// An admin sending a waiting invitation again.
fn resend_invitation(a: &Adapters, s: &Settings) -> invitations::ResendUseCase {
    invitations::ResendUseCase::new(invitations::ResendPorts {
        user_store: a.user_store.clone(),
        invitation_store: a.invitation_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        mailing: invitation_mailing(a, s),
        mail_throttle: a.mail_throttle.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// The address use cases of both planes, mailing confirmation links
/// through `links`.
fn email(a: &Adapters, s: &Settings, links: &Arc<email::VerificationLinks>) -> EmailUseCases {
    EmailUseCases {
        change: Arc::new(change_email(a, links)),
        request_change: Arc::new(request_change(a, s)),
        confirm_change: Arc::new(confirm_change(a)),
        cancel_change: Arc::new(cancel_change(a)),
        change_status: Arc::new(email::ChangeStatusUseCase::new(email::ChangeStatusPorts {
            change_store: a.tenant_email_change_store.clone(),
            user_store: a.user_store.clone(),
            token_generator: a.refresh_token_generator.clone(),
        })),
        resend_change: Arc::new(resend_change(a, s)),
        send_verification: Arc::new(send_verification(a, links)),
        verify: Arc::new(verify_email(a)),
        verification_status: Arc::new(verification_status(a)),
        resend_verification: Arc::new(resend_verification(a, links)),
        request_org_change: Arc::new(request_org_change(a, s)),
        confirm_org_change: Arc::new(confirm_org_change(a)),
        cancel_org_change: Arc::new(email::CancelOrgChangeUseCase::new(
            email::CancelOrgChangePorts {
                stores: org_change(a),
            },
        )),
        org_change_status: Arc::new(email::OrgChangeStatusUseCase::new(org_change(a))),
        resend_org_change: Arc::new(resend_org_change(a, s)),
    }
}

/// Changes tenant email with reset-token cleanup and throttled verification links.
fn change_email(a: &Adapters, links: &Arc<email::VerificationLinks>) -> email::ChangeUseCase {
    email::ChangeUseCase::new(email::ChangePorts {
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        reset_requests: a.reset_request_store.clone(),
        verification_links: links.clone(),
        mail_throttle: a.mail_throttle.clone(),
    })
}

/// Confirms address changes with token validation, reset cleanup and notification mail.
fn confirm_change(a: &Adapters) -> email::ConfirmChangeUseCase {
    email::ConfirmChangeUseCase::new(email::ConfirmChangePorts {
        change_store: a.tenant_email_change_store.clone(),
        user_store: a.user_store.clone(),
        token_store: a.verification_token_store.clone(),
        reset_requests: a.reset_request_store.clone(),
        mailer: a.mailer.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Cancels tenant email changes through their generated tokens.
fn cancel_change(a: &Adapters) -> email::CancelChangeUseCase {
    email::CancelChangeUseCase::new(email::CancelChangePorts {
        change_store: a.tenant_email_change_store.clone(),
        user_store: a.user_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Resends tenant address-change mail under the configured lifetime and cooldown.
fn resend_change(a: &Adapters, s: &Settings) -> email::ResendChangeUseCase {
    email::ResendChangeUseCase::new(email::ResendChangePorts {
        change_store: a.tenant_email_change_store.clone(),
        user_store: a.user_store.clone(),
        mailer: a.mailer.clone(),
        mail: a.mail_setup.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: email_change_policy(s),
    })
}

/// Sends address-verification links under tenant authority.
fn send_verification(
    a: &Adapters,
    links: &Arc<email::VerificationLinks>,
) -> email::SendVerificationUseCase {
    email::SendVerificationUseCase::new(email::SendVerificationPorts {
        user_store: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        verification_links: links.clone(),
    })
}

/// Verifies mailbox tokens against the associated account and token records.
fn verify_email(a: &Adapters) -> email::VerifyUseCase {
    email::VerifyUseCase::new(email::VerifyPorts {
        user_store: a.user_store.clone(),
        token_store: a.verification_token_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Reads verification status through the same account and token records.
fn verification_status(a: &Adapters) -> email::VerificationStatusUseCase {
    email::VerificationStatusUseCase::new(email::VerificationStatusPorts {
        user_store: a.user_store.clone(),
        token_store: a.verification_token_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Resends verification links using the existing account and token records.
fn resend_verification(
    a: &Adapters,
    links: &Arc<email::VerificationLinks>,
) -> email::ResendVerificationUseCase {
    email::ResendVerificationUseCase::new(email::ResendVerificationPorts {
        user_store: a.user_store.clone(),
        token_store: a.verification_token_store.clone(),
        verification_links: links.clone(),
    })
}

/// Confirms control-plane address changes and sends their notification mail.
fn confirm_org_change(a: &Adapters) -> email::ConfirmOrgChangeUseCase {
    email::ConfirmOrgChangeUseCase::new(email::ConfirmOrgChangePorts {
        stores: org_change(a),
        mailer: a.mailer.clone(),
    })
}

/// Resends control-plane address changes under the configured mailing policy.
fn resend_org_change(a: &Adapters, s: &Settings) -> email::ResendOrgChangeUseCase {
    email::ResendOrgChangeUseCase::new(email::ResendOrgChangePorts {
        stores: org_change(a),
        mailer: a.mailer.clone(),
        mail: a.mail_setup.clone(),
        policy: email_change_policy(s),
    })
}

/// A tenant user asking to move their own address.
fn request_change(a: &Adapters, s: &Settings) -> email::RequestChangeUseCase {
    email::RequestChangeUseCase::new(email::RequestChangePorts {
        change_store: a.tenant_email_change_store.clone(),
        user_store: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        mailer: a.mailer.clone(),
        mail: a.mail_setup.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: email_change_policy(s),
    })
}

/// An organization member asking to move their own address.
fn request_org_change(a: &Adapters, s: &Settings) -> email::RequestOrgChangeUseCase {
    email::RequestOrgChangeUseCase::new(email::RequestOrgChangePorts {
        change_store: a.org_email_change_store.clone(),
        org_user_store: a.org_user_store.clone(),
        org_actors: a.org_actors.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        mailer: a.mailer.clone(),
        mail: a.mail_setup.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: email_change_policy(s),
    })
}

/// The custom attribute use cases.
fn attributes(a: &Adapters) -> AttributeUseCases {
    AttributeUseCases {
        declare: Arc::new(declare_attribute(a)),
        list: Arc::new(attributes::ListUseCase::new(attributes::ListPorts {
            attribute_store: a.user_attribute_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        schema: Arc::new(attributes::GetSchemaUseCase::new(
            attributes::GetSchemaPorts {
                attribute_store: a.user_attribute_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        update: Arc::new(update_attribute(a)),
        set_status: Arc::new(attributes::SetStatusUseCase::new(
            attributes::SetStatusPorts {
                attribute_store: a.user_attribute_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        delete: Arc::new(attributes::DeleteUseCase::new(attributes::DeletePorts {
            attribute_store: a.user_attribute_store.clone(),
            metadata_store: a.metadata_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        values: Arc::new(attribute_values(a)),
        page_values: Arc::new(page_attribute_values(a)),
        set_value: Arc::new(set_attribute_value(a)),
        delete_values: Arc::new(delete_attribute_values(a)),
    }
}

/// Declares tenant attributes with plan enforcement.
fn declare_attribute(a: &Adapters) -> attributes::DeclareUseCase {
    attributes::DeclareUseCase::new(attributes::DeclarePorts {
        attribute_store: a.user_attribute_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes attribute declarations against existing user metadata.
fn update_attribute(a: &Adapters) -> attributes::UpdateUseCase {
    attributes::UpdateUseCase::new(attributes::UpdatePorts {
        attribute_store: a.user_attribute_store.clone(),
        metadata_store: a.metadata_store.clone(),
        user_store: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Reading one user's custom values.
fn attribute_values(a: &Adapters) -> attributes::GetMetadataUseCase {
    attributes::GetMetadataUseCase::new(attributes::GetMetadataPorts {
        metadata_store: a.metadata_store.clone(),
        attribute_store: a.user_attribute_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Reading a listing page's custom values.
fn page_attribute_values(a: &Adapters) -> attributes::GetUsersMetadataUseCase {
    attributes::GetUsersMetadataUseCase::new(attributes::GetUsersMetadataPorts {
        metadata_store: a.metadata_store.clone(),
        attribute_store: a.user_attribute_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Setting one user's value for one attribute.
fn set_attribute_value(a: &Adapters) -> attributes::SetValueUseCase {
    attributes::SetValueUseCase::new(attributes::SetValuePorts {
        metadata_store: a.metadata_store.clone(),
        attribute_store: a.user_attribute_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Clearing every custom value a user holds.
fn delete_attribute_values(a: &Adapters) -> attributes::DeleteUserMetadataUseCase {
    attributes::DeleteUserMetadataUseCase::new(attributes::DeleteUserMetadataPorts {
        metadata_store: a.metadata_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The consent, export and erasure use cases.
fn privacy(a: &Adapters, s: &Settings) -> PrivacyUseCases {
    PrivacyUseCases {
        grant_consent: Arc::new(privacy::GrantConsentUseCase::new(
            privacy::GrantConsentPorts {
                consent_store: a.consent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        revoke_consent: Arc::new(revoke_consent(a)),
        consent_history: Arc::new(privacy::ConsentHistoryUseCase::new(
            privacy::ConsentHistoryPorts {
                consent_store: a.consent_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        request_export: Arc::new(request_export(a)),
        list_exports: Arc::new(list_exports(a)),
        download_export: Arc::new(download_export(a)),
        request_erasure: Arc::new(request_erasure(a, s)),
        cancel_erasure: Arc::new(cancel_erasure(a)),
        cancel_erasure_by_link: Arc::new(cancel_erasure_by_link(a)),
        hold_erasure: Arc::new(hold_erasure(a)),
        release_erasure: Arc::new(privacy::ReleaseErasureUseCase::new(
            privacy::ReleaseErasurePorts {
                erasure_store: a.erasure_request_store.clone(),
                access_records: a.access_record_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Revokes consent with access-record and account updates.
fn revoke_consent(a: &Adapters) -> privacy::RevokeConsentUseCase {
    privacy::RevokeConsentUseCase::new(privacy::RevokeConsentPorts {
        consent_store: a.consent_store.clone(),
        access_records: a.access_record_store.clone(),
        users: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Lists data exports with the caller's effective access records.
fn list_exports(a: &Adapters) -> privacy::ListExportsUseCase {
    privacy::ListExportsUseCase::new(privacy::ListExportsPorts {
        export_store: a.data_export_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Downloads stored export files under tenant authority.
fn download_export(a: &Adapters) -> privacy::DownloadExportUseCase {
    privacy::DownloadExportUseCase::new(privacy::DownloadExportPorts {
        export_store: a.data_export_store.clone(),
        files: a.data_export_files.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Cancels erasure requests with the user's account and effective access records.
fn cancel_erasure(a: &Adapters) -> privacy::CancelErasureUseCase {
    privacy::CancelErasureUseCase::new(privacy::CancelErasurePorts {
        erasure_store: a.erasure_request_store.clone(),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Places erasure requests on hold under tenant authority.
fn hold_erasure(a: &Adapters) -> privacy::HoldErasureUseCase {
    privacy::HoldErasureUseCase::new(privacy::HoldErasurePorts {
        erasure_store: a.erasure_request_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// A person, or an admin for them, asking for a copy of their data.
fn request_export(a: &Adapters) -> privacy::RequestExportUseCase {
    privacy::RequestExportUseCase::new(privacy::RequestExportPorts {
        export_store: a.data_export_store.clone(),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Asking for a person's data to be erased, after a grace period.
fn request_erasure(a: &Adapters, s: &Settings) -> privacy::RequestErasureUseCase {
    privacy::RequestErasureUseCase::new(privacy::RequestErasurePorts {
        erasure_store: a.erasure_request_store.clone(),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        removal: removal(a),
        mailer: a.mailer.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: privacy::ErasurePolicy {
            grace_period: s.tunables.erasure_grace,
            base_url: s.app_base_url.clone(),
        },
    })
}

/// A person calling off their erasure from the link mailed to them.
fn cancel_erasure_by_link(a: &Adapters) -> privacy::CancelErasureByLinkUseCase {
    privacy::CancelErasureByLinkUseCase::new(privacy::CancelErasureByLinkPorts {
        erasure_store: a.erasure_request_store.clone(),
        user_store: a.user_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// The support impersonation use cases.
fn impersonations(a: &Adapters) -> ImpersonationUseCases {
    ImpersonationUseCases {
        request: Arc::new(request_impersonation(a)),
        approve: Arc::new(impersonation::ApproveUseCase::new(
            impersonation::ApprovePorts {
                impersonation_store: a.support_impersonation_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        decline: Arc::new(impersonation::DeclineUseCase::new(
            impersonation::DeclinePorts {
                impersonation_store: a.support_impersonation_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        end: Arc::new(impersonation::EndUseCase::new(impersonation::EndPorts {
            impersonation_store: a.support_impersonation_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(impersonation::ListImpersonationsUseCase::new(
            impersonation::ListImpersonationsPorts {
                impersonation_store: a.support_impersonation_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        act_as: Arc::new(act_as(a)),
    }
}

/// Requests support impersonation with account checks and notification mail.
fn request_impersonation(a: &Adapters) -> impersonation::RequestUseCase {
    impersonation::RequestUseCase::new(impersonation::RequestPorts {
        impersonation_store: a.support_impersonation_store.clone(),
        user_store: a.user_store.clone(),
        tenant_store: a.tenant_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        mailer: a.mailer.clone(),
    })
}

/// Resolves an impersonated caller through the approved support grant.
fn act_as(a: &Adapters) -> impersonation::ActAsUseCase {
    impersonation::ActAsUseCase::new(impersonation::ActAsPorts {
        impersonation_store: a.support_impersonation_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// What mails the links that confirm a tenant user's address.
fn verification_links(a: &Adapters, s: &Settings) -> Arc<email::VerificationLinks> {
    Arc::new(email::VerificationLinks::new(
        a.refresh_token_generator.clone(),
        email::VerificationPolicy {
            lifetime: s.tunables.verification_lifetime,
            base_url: s.app_base_url.clone(),
            resend_cooldown: s.tunables.resend_cooldown,
        },
        email::VerificationLinkStores {
            tokens: a.verification_token_store.clone(),
            mailer: a.mailer.clone(),
            mail: a.mail_setup.clone(),
        },
    ))
}

/// How email change links are made, on either plane.
fn email_change_policy(s: &Settings) -> email::EmailChangePolicy {
    email::EmailChangePolicy {
        lifetime: s.tunables.email_change_lifetime,
        base_url: s.app_base_url.clone(),
        resend_cooldown: s.tunables.resend_cooldown,
    }
}

/// How tenant invitations are sent: through the mailer, as far as this
/// deployment mails, under the tenant invitation policy.
fn invitation_mailing(a: &Adapters, s: &Settings) -> InvitationMailing {
    InvitationMailing {
        mailer: a.mailer.clone(),
        mail: a.mail_setup.clone(),
        policy: InvitationPolicy {
            lifetime: s.tunables.invitation_lifetime,
            base_url: s.app_base_url.clone(),
            resend_cooldown: s.tunables.resend_cooldown,
        },
    }
}

/// The control-plane stores an organization member's or operator's
/// address change reads and writes.
fn org_change(a: &Adapters) -> email::OrgChangePorts {
    email::OrgChangePorts {
        change_store: a.org_email_change_store.clone(),
        org_user_store: a.org_user_store.clone(),
        operator_store: a.operator_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    }
}

/// Where what the sender of an invitation holds now is read from.
fn inviter(a: &Adapters) -> InviterPorts {
    InviterPorts {
        access_records: a.access_record_store.clone(),
        user_store: a.user_store.clone(),
        tenant_store: a.tenant_store.clone(),
        organization_store: a.organization_store.clone(),
        org_user_store: a.org_user_store.clone(),
        org_grant_store: a.org_tenant_grant_store.clone(),
    }
}

/// How a welcome mail reads its user and tenant, and goes out.
fn welcome(a: &Adapters, s: &Settings) -> invitations::WelcomePorts {
    invitations::WelcomePorts {
        user_store: a.user_store.clone(),
        tenant_store: a.tenant_store.clone(),
        mailer: a.mailer.clone(),
        base_url: s.app_base_url.clone(),
    }
}

/// What ends a shut-out user's sessions and the delegations they granted.
fn removal(a: &Adapters) -> users::StandingRemoval {
    users::StandingRemoval {
        session_store: a.session_store.clone(),
        grant_revocation: GrantRevocation::new(a.delegation_store.clone()),
        exports: a.data_export_store.clone(),
        export_files: a.data_export_files.clone(),
    }
}

/// What checks or draws the passwords an admin hands out.
fn passwords(a: &Adapters) -> Arc<users::PasswordMaker> {
    Arc::new(users::PasswordMaker::new(
        password_hashing(a),
        a.secure_random.clone(),
    ))
}
