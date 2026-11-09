//! The mailbox in a sign-in. A sign-in from a device Ann never remembered
//! waits for the link mailed to her, which finishes that one sign-in and
//! nothing else, and only while it is fresh. A mailed link alone, with no
//! password, signs her in once, still owes her authenticator's code when
//! she has one, and obeys the ways of signing in her company allows now.
//!
//! - `confirmations`: a waiting sign-in is finished only by its own link,
//!   once; a link mailed for one waiting sign-in finishes no other and is
//!   not spent by the attempt; a link followed too late leaves the sign-in
//!   waiting, and a fresh sign-in still gets in.
//! - `links`: a mailed link signs in with no password, once, and ends the
//!   session held before; with an authenticator set up it still owes the
//!   code; a link mailed before the method was turned off is refused and
//!   not spent, and works once the method is back; one link opened in two
//!   browsers at once opens one session; an expired link opens none.

mod confirmations;
mod links;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, organizations};
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::MemberProof;

/// Ann adds mailed links to the ways her company's members sign in,
/// proving who she is with her password.
async fn allow_mailed_links(ann: &Founder, org: &OrgPath) {
    let mut settings = organizations::sign_in_settings(org)
        .send(ann.client())
        .await
        .ok();
    settings.enabled_methods.push("MagicLink".to_owned());
    let replace = ReplaceOrgSignInSettings {
        settings,
        proof: MemberProof {
            password: FOUNDER_PASSWORD.to_owned(),
            code: None,
        },
    };
    organizations::replace_sign_in_settings(org, &replace)
        .send(ann.client())
        .await
        .ok();
}
