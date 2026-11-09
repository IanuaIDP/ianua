//! The words an email template's type is stored as: the type's own name,
//! which is also the word a list sorts by.

use ianua_domain::domains::branding::email_template::EmailTemplateType;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    EmailTemplateType as "email template type" {
        Verification => "Verification",
        PasswordReset => "PasswordReset",
        MagicLink => "MagicLink",
        Invitation => "Invitation",
        AccountLocked => "AccountLocked",
        MfaEnrolled => "MfaEnrolled",
        RecoveryCodes => "RecoveryCodes",
        DeviceTrusted => "DeviceTrusted",
        SessionSuspended => "SessionSuspended",
        BreachedPassword => "BreachedPassword",
        ErasureConfirmation => "ErasureConfirmation",
        ErasureCompleted => "ErasureCompleted",
        Welcome => "Welcome",
        EmailChangeVerification => "EmailChangeVerification",
        EmailChanged => "EmailChanged",
        EmailChangeRequested => "EmailChangeRequested",
        AccountLinked => "AccountLinked",
        SignInCode => "SignInCode",
        ExportReady => "ExportReady",
        ImpersonationRequested => "ImpersonationRequested",
        OrgVerification => "OrgVerification",
        OrgInvitation => "OrgInvitation",
        OrgWelcome => "OrgWelcome",
        OrgMfaReset => "OrgMfaReset",
        OrgEmailChangeRequested => "OrgEmailChangeRequested",
        SignupVerification => "SignupVerification",
        SignupWelcome => "SignupWelcome",
        SignupAccountExists => "SignupAccountExists",
        ActivationWelcome => "ActivationWelcome",
        ActivityNotice => "ActivityNotice",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every persisted template kind, including platform and organization mail.
    const TEMPLATE_TYPES: &[EmailTemplateType] = &[
        EmailTemplateType::Verification,
        EmailTemplateType::PasswordReset,
        EmailTemplateType::MagicLink,
        EmailTemplateType::Invitation,
        EmailTemplateType::AccountLocked,
        EmailTemplateType::MfaEnrolled,
        EmailTemplateType::RecoveryCodes,
        EmailTemplateType::DeviceTrusted,
        EmailTemplateType::SessionSuspended,
        EmailTemplateType::BreachedPassword,
        EmailTemplateType::ErasureConfirmation,
        EmailTemplateType::ErasureCompleted,
        EmailTemplateType::Welcome,
        EmailTemplateType::EmailChangeVerification,
        EmailTemplateType::EmailChanged,
        EmailTemplateType::EmailChangeRequested,
        EmailTemplateType::AccountLinked,
        EmailTemplateType::SignInCode,
        EmailTemplateType::ExportReady,
        EmailTemplateType::ImpersonationRequested,
        EmailTemplateType::OrgVerification,
        EmailTemplateType::OrgInvitation,
        EmailTemplateType::OrgWelcome,
        EmailTemplateType::OrgMfaReset,
        EmailTemplateType::OrgEmailChangeRequested,
        EmailTemplateType::SignupVerification,
        EmailTemplateType::SignupWelcome,
        EmailTemplateType::SignupAccountExists,
        EmailTemplateType::ActivationWelcome,
        EmailTemplateType::ActivityNotice,
    ];

    /// A list sorted by type seeks past the cursor's word in the column,
    /// which is the type's name, so every type is stored as its name.
    #[test]
    fn every_type_is_stored_as_its_name() {
        for &template_type in TEMPLATE_TYPES {
            assert_eq!(template_type.word(), template_type.name());
            assert_eq!(
                EmailTemplateType::from_word(template_type.word()),
                Some(template_type)
            );
        }
    }
}
