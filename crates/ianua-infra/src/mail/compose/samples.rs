//! The values a preview is filled with: obvious samples, and a link to a
//! host that never resolves, so a preview never carries a link that works.

use std::collections::HashMap;

use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::shared::clock;

use crate::mail::audience::AudienceNames;

/// The link every preview carries. `.invalid` never resolves (RFC 2606).
const SAMPLE_LINK: &str = "https://preview.example.invalid/sample-link";

/// A sample for every value `template_type` takes, the tenant's and the
/// organization's names taken from `names` where they are known.
pub(crate) fn sample_values(
    template_type: EmailTemplateType,
    names: &AudienceNames,
) -> HashMap<TemplateVariable, String> {
    template_type
        .available_variables()
        .iter()
        .map(|variable| (*variable, sample_of(*variable, names)))
        .collect()
}

/// The sample `variable` is filled with.
fn sample_of(variable: TemplateVariable, names: &AudienceNames) -> String {
    let known =
        |name: Option<&String>, sample: &str| name.map_or_else(|| sample.to_owned(), Clone::clone);
    match variable {
        TemplateVariable::UserName => "Alex Sample".to_owned(),
        TemplateVariable::UserEmail => "alex@example.invalid".to_owned(),
        TemplateVariable::TenantName => known(names.tenant.as_ref(), "Sample tenant"),
        TemplateVariable::OrganizationName => {
            known(names.organization.as_ref(), "Sample organization")
        }
        TemplateVariable::ActionUrl | TemplateVariable::ActionLink => SAMPLE_LINK.to_owned(),
        TemplateVariable::ExpiresAt => "24 hours".to_owned(),
        TemplateVariable::DeviceName => "Sample laptop".to_owned(),
        TemplateVariable::IpAddress => "203.0.113.7".to_owned(),
        TemplateVariable::RemainingCodes => "8".to_owned(),
        TemplateVariable::ErasureDate => "1 January 2030".to_owned(),
        TemplateVariable::RoleName => "Member".to_owned(),
        TemplateVariable::ProviderName => "Sample provider".to_owned(),
        TemplateVariable::OneTimeCode => "123456".to_owned(),
        TemplateVariable::RequesterName => "Sam Admin".to_owned(),
        TemplateVariable::Reason => "To help with a sign-in problem".to_owned(),
        TemplateVariable::NoticeTitle => "A sample notice".to_owned(),
        TemplateVariable::NoticeBody => "This is what a notice says.".to_owned(),
        TemplateVariable::Year => clock::now().year().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password-reset preview uses an action URL whose host ends in `.invalid`.
    #[test]
    fn a_preview_never_carries_a_working_link() {
        let values = sample_values(EmailTemplateType::PasswordReset, &AudienceNames::default());

        let link = values.get(&TemplateVariable::ActionUrl).unwrap();

        assert!(
            url::Url::parse(link)
                .unwrap()
                .host_str()
                .unwrap()
                .ends_with(".invalid")
        );
    }

    /// A preview names the tenant it is for, when its name is known.
    #[test]
    fn a_preview_names_its_tenant() {
        let names = AudienceNames {
            tenant: Some("Acme".to_owned()),
            organization: None,
        };

        let values = sample_values(EmailTemplateType::Welcome, &names);

        assert_eq!(
            values
                .get(&TemplateVariable::TenantName)
                .map(String::as_str),
            Some("Acme")
        );
    }
}
