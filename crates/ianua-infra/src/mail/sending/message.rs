//! Who a mail is from and to, and the message an SMTP server is handed.
//!
//! The tenant's own name is shown only beside the tenant's own address: a
//! tenant may call itself anything, and under the platform's address a
//! name such as "Your bank" would borrow the platform's standing.

use ianua_app::ports::branding::AddressedMail;
use ianua_domain::domains::branding::config::MailSender;
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, Label};
use lettre::Message;
use lettre::message::{Mailbox, MultiPart, SinglePart};

use crate::mail::sending::accounts::PlatformMail;

/// The addresses of one mail: whose it is sent from, under which name,
/// and who it goes to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Envelope<'a> {
    /// The address it is sent from.
    pub(crate) from: &'a Email,
    /// The name it is sent under.
    pub(crate) name: Option<&'a str>,
    /// The address it goes to.
    pub(crate) to: &'a Email,
}

impl<'a> Envelope<'a> {
    /// The envelope of `mail`: from the tenant's address under its name when
    /// the sender is the tenant, otherwise from the platform's.
    pub(crate) fn of(mail: &AddressedMail<'a>, platform: &'a PlatformMail) -> Self {
        match mail.sender {
            MailSender::Tenant(address) => Self {
                from: address,
                name: mail.sender_name.map(Label::as_str),
                to: mail.to,
            },
            MailSender::Platform => Self::platform(platform, mail.to),
        }
    }

    /// The envelope of the platform's own mail to `to`.
    pub(crate) fn platform(platform: &'a PlatformMail, to: &'a Email) -> Self {
        Self {
            from: &platform.from,
            name: platform.from_name.as_ref().map(Label::as_str),
            to,
        }
    }

    /// The `From` as a header reads it: `Name <address>`, or the bare
    /// address. Quotes and line breaks in the name are dropped, so a name
    /// cannot start a header of its own.
    pub(crate) fn sender_header(&self) -> String {
        let Some(name) = self.name.map(header_safe).filter(|name| !name.is_empty()) else {
            return self.from.as_str().to_owned();
        };
        format!("\"{name}\" <{}>", self.from.as_str())
    }

    /// The domain of the address it is sent from, which an SMTP server is
    /// greeted with.
    pub(crate) fn sending_domain(&self) -> &'a str {
        self.from.domain()
    }
}

/// `text` as one header line: every control character, quote and
/// backslash taken out.
fn header_safe(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The message an SMTP server is handed: plain text alone, or plain text
/// and HTML as alternatives of each other.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when an address is not one a mail
/// header can carry.
pub(crate) fn message_of(
    envelope: &Envelope<'_>,
    rendered: &RenderedEmail,
) -> Result<Message, DomainError> {
    let from = Mailbox::new(
        envelope
            .name
            .map(header_safe)
            .filter(|name| !name.is_empty()),
        envelope.from.as_str().parse().map_err(DomainError::infra)?,
    );
    let to = Mailbox::new(
        None,
        envelope.to.as_str().parse().map_err(DomainError::infra)?,
    );
    let builder = Message::builder()
        .from(from)
        .to(to)
        .subject(rendered.subject());
    let text = rendered.text().to_owned();
    let built = match rendered.html() {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(text, html.to_owned())),
        None => builder.singlepart(SinglePart::plain(text)),
    };
    built.map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::sending::accounts::{MailAccount, SmtpAccount, SmtpTls};

    fn email(address: &str) -> Email {
        Email::new(address).unwrap()
    }

    fn platform() -> PlatformMail {
        PlatformMail {
            account: Some(MailAccount::Smtp(SmtpAccount {
                host: "localhost".to_owned(),
                port: 1025,
                tls: SmtpTls::Unencrypted,
                login: None,
            })),
            from: email("noreply@ianua.test"),
            from_name: Some(Label::new("name", "Ianua").unwrap()),
        }
    }

    fn formatted(envelope: &Envelope<'_>, rendered: &RenderedEmail) -> String {
        String::from_utf8(message_of(envelope, rendered).unwrap().formatted()).unwrap()
    }

    /// A mail with both bodies goes out as plain text and HTML, the two as
    /// alternatives of each other, from and to the envelope's addresses.
    #[test]
    fn a_mail_with_both_bodies_is_sent_as_alternatives() {
        let platform = platform();
        let to = email("ann@acme.test");
        let rendered = RenderedEmail::multipart("Welcome", "<p>Hello Ann</p>", "Hello Ann");

        let message = formatted(&Envelope::platform(&platform, &to), &rendered);

        assert!(message.contains("multipart/alternative"));
        assert!(message.contains("<noreply@ianua.test>"));
        assert!(message.contains("To: ann@acme.test"));
        assert!(message.contains("Subject: Welcome"));
        assert!(message.contains("<p>Hello Ann</p>"));
    }

    /// A plain-text mail goes out as one plain part, with no HTML half.
    #[test]
    fn a_text_mail_is_one_plain_part() {
        let platform = platform();
        let to = email("ann@acme.test");

        let message = formatted(
            &Envelope::platform(&platform, &to),
            &RenderedEmail::text_only("Hi", "Hello"),
        );

        assert!(!message.contains("multipart"));
        assert!(message.contains("text/plain"));
    }

    /// A sender name containing a newline and Bcc text creates no Bcc header,
    /// and its sender header contains no newline.
    #[test]
    fn a_sender_name_cannot_start_a_header_of_its_own() {
        let to = email("ann@acme.test");
        let from = email("hello@acme.test");
        let name = "Acme\r\nBcc: eve@evil.test";
        let envelope = Envelope {
            from: &from,
            name: Some(name),
            to: &to,
        };

        let message = formatted(&envelope, &RenderedEmail::text_only("Hi", "Hello"));

        assert!(!message.contains("\r\nBcc:"));
        assert!(!envelope.sender_header().contains('\n'));
    }

    /// The platform sender keeps the platform's name, while the tenant sender
    /// uses the tenant's chosen name and address.
    #[test]
    fn the_tenants_name_is_shown_only_beside_its_own_address() {
        let platform = platform();
        let to = email("ann@acme.test");
        let acme = email("hello@acme.test");
        let named = Label::new("name", "Your bank").unwrap();
        let rendered = RenderedEmail::text_only("Hi", "Hello");
        let from_platform = AddressedMail {
            to: &to,
            sender: MailSender::Platform,
            sender_name: Some(&named),
            rendered: &rendered,
        };
        let from_acme = AddressedMail {
            sender: MailSender::Tenant(&acme),
            ..from_platform
        };

        let platforms = Envelope::of(&from_platform, &platform);
        let tenants = Envelope::of(&from_acme, &platform);

        assert_eq!(platforms.sender_header(), "\"Ianua\" <noreply@ianua.test>");
        assert_eq!(tenants.sender_header(), "\"Your bank\" <hello@acme.test>");
    }
}
