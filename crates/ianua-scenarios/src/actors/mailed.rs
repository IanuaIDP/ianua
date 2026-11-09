//! Reading one's own mail the way a person does: past the welcome and the
//! notices, to the one mail with the link they wait for.

use crate::mail::{Mail, Mailbox};

/// The most mails passed over before the one awaited, so a missing link
/// fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// The next mail to `address` with a link to `path_prefix`, passing over
/// any other mail that came first, such as a welcome.
///
/// # Panics
///
/// When no such mail comes, or more than ten others came before it.
pub(crate) async fn mail_linking(mailbox: &Mailbox, address: &str, path_prefix: &str) -> Mail {
    for _ in 0..=PASSED_OVER {
        let mail = mailbox.next_for(address).await;
        let links = mail.links();
        if links
            .iter()
            .any(|link| link.path().starts_with(path_prefix))
        {
            return mail;
        }
    }
    panic!("{address} got {PASSED_OVER} mails before one linking to {path_prefix}");
}
