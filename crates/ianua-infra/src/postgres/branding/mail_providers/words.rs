//! The words a mail provider's choices are stored as.

use ianua_domain::domains::branding::mail_provider::{
    MailProviderKind, MailgunRegion, SmtpSecurity,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    MailProviderKind as "mail provider kind" {
        Platform => "platform",
        Smtp => "smtp",
        SendGrid => "sendgrid",
        Ses => "ses",
        Postmark => "postmark",
        Mailgun => "mailgun",
    }
}

stored_words! {
    SmtpSecurity as "SMTP encryption" {
        StartTls => "start_tls",
        ImplicitTls => "implicit_tls",
    }
}

stored_words! {
    MailgunRegion as "Mailgun region" {
        Us => "us",
        Eu => "eu",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A kind is stored as the name records use for it, so the two never
    /// disagree.
    #[test]
    fn every_kind_is_stored_as_the_name_records_use() {
        for kind in [
            MailProviderKind::Platform,
            MailProviderKind::Smtp,
            MailProviderKind::SendGrid,
            MailProviderKind::Ses,
            MailProviderKind::Postmark,
            MailProviderKind::Mailgun,
        ] {
            assert_eq!(kind.word(), kind.as_str());
        }
    }
}
