//! The files the platform publishes, compiled into the build.
//!
//! The mail logo sits with the mail templates, in
//! `templates/mail/assets/email-logo.png`. The CloudFormation template sits
//! with the AWS adapter that assumes the role it makes, in
//! `src/cloud/aws/ianua-connect.yaml`, so a change to how the role is
//! assumed and a change to the role it grants are made side by side. Each
//! file is the one copy; the deployment serving it is the only place a
//! customer fetches it from.

use std::borrow::Cow;

use ianua_app::ports::files::{PublishedCaching, PublishedContent, PublishedFile, PublishedFiles};

/// The logo at the top of the platform's mail.
const EMAIL_LOGO: &[u8] = include_bytes!("../../templates/mail/assets/email-logo.png");

/// The template a customer runs to make the role the platform assumes.
const AWS_TRUST_TEMPLATE: &[u8] = include_bytes!("../cloud/aws/ianua-connect.yaml");

/// The published files bundled with the build.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundledPublishedFiles;

impl PublishedFiles for BundledPublishedFiles {
    fn content(&self, file: PublishedFile) -> PublishedContent {
        match file {
            PublishedFile::EmailLogo => PublishedContent {
                content_type: "image/png",
                caching: PublishedCaching::WeekUnchanged,
                download_name: None,
                bytes: Cow::Borrowed(EMAIL_LOGO),
            },
            PublishedFile::AwsTrustTemplate => PublishedContent {
                content_type: "application/x-yaml; charset=utf-8",
                caching: PublishedCaching::Hour,
                download_name: Some("ianua-connect.yaml"),
                bytes: Cow::Borrowed(AWS_TRUST_TEMPLATE),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PNG signature every PNG starts with.
    const PNG_SIGNATURE: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    /// The mail logo is a PNG, served as one, kept for a week and never
    /// offered for saving.
    #[test]
    fn the_email_logo_is_a_png_kept_for_a_week() {
        let logo = BundledPublishedFiles.content(PublishedFile::EmailLogo);

        assert_eq!(logo.content_type, "image/png");
        assert!(logo.bytes.starts_with(PNG_SIGNATURE));
        assert_eq!(logo.caching, PublishedCaching::WeekUnchanged);
        assert_eq!(logo.download_name, None);
    }

    /// The AWS template is a CloudFormation template, served as YAML under
    /// its own name and kept for an hour.
    #[test]
    fn the_aws_template_is_yaml_under_its_name() {
        let template = BundledPublishedFiles.content(PublishedFile::AwsTrustTemplate);

        assert_eq!(template.content_type, "application/x-yaml; charset=utf-8");
        assert!(template.bytes.starts_with(b"AWSTemplateFormatVersion"));
        assert_eq!(template.caching, PublishedCaching::Hour);
        assert_eq!(template.download_name, Some("ianua-connect.yaml"));
    }

    /// The published trust template contains both the named AWS account and
    /// the external-id condition.
    #[test]
    fn the_aws_template_trusts_only_with_the_external_id() {
        let template = BundledPublishedFiles.content(PublishedFile::AwsTrustTemplate);
        let text = std::str::from_utf8(&template.bytes).unwrap();

        assert!(text.contains("sts:ExternalId: !Ref ExternalId"));
        assert!(text.contains("iam::${IanuaAccountId}:root"));
    }
}
