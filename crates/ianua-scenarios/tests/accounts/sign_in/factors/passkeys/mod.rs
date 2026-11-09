//! Ann signs in to the dashboard with a passkey, a software key signing
//! real WebAuthn challenges: by her address or by the key alone, with no
//! password and no mailbox step, each answer good once. Mallory's relayed
//! and copied answers, Bob's key at Ann's address, an answer moved to
//! another challenge and a key added without the password are refused;
//! a challenge obeys the policy and the lifetime in force when it is
//! answered; and a passkey meets a two-factor baseline a password alone
//! does not.
//!
//! - `sign_in`: a passkey signs in by address, by the key alone, and
//!   beside an authenticator app, once; two answers at once open one
//!   session.
//! - `attacks`: a relayed, copied, removed, borrowed or moved answer, and
//!   a key added without the right password.
//! - `policy`: a challenge issued before passkeys were switched off or
//!   before it expired, and a passkey meeting a two-factor baseline.

mod attacks;
mod policy;
mod sign_in;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, member_factors, organizations};
use ianua_scenarios::authenticators::SoftPasskey;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::factors::{PasskeyAnswerBody, PasskeyChallenge, PasskeySignInFor};
use ianua_scenarios::wire::organization::{OrgSignInSettings, ReplaceOrgSignInSettings};
use ianua_scenarios::wire::sign_in::{ConfirmMemberPasskey, MemberProof, Session, SignedIn};

/// Ann, signed in on her own client, her organization, and the passkey
/// she added to her account.
struct PasskeyHolder {
    ann: Founder,
    org: OrgPath,
    key: SoftPasskey,
}

/// Ann founded Acme, signed in, and added a passkey from that session
/// with her password typed again, as the account page does.
async fn enrolled(stack: &Stack) -> PasskeyHolder {
    let mut ann = Founder::named(stack, "Ann");
    let founded = ann.founded(stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let session = ann.signed_in(stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let key = registered_key(stack, &ann, &org, None).await;
    PasskeyHolder { ann, org, key }
}

/// Ann founded Acme, signed in, set up an authenticator app, and added a
/// passkey with her password and the app's code typed again.
async fn enrolled_with_authenticator(stack: &Stack) -> PasskeyHolder {
    let mut ann = Founder::named(stack, "Ann");
    let founded = ann.founded(stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let session = ann.signed_in(stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let mut phone = ann.set_up_authenticator(org.slug(), &session).await;
    let code = phone.code().await;
    let key = registered_key(stack, &ann, &org, Some(code)).await;
    PasskeyHolder { ann, org, key }
}

/// A new passkey Ann adds from her client, proving herself with her
/// password and `code` from her authenticator when she has one.
async fn registered_key(
    stack: &Stack,
    ann: &Founder,
    org: &OrgPath,
    code: Option<String>,
) -> SoftPasskey {
    let key = SoftPasskey::new(&stack.app_url());
    let begun = member_factors::begin_passkey(org)
        .send(ann.client())
        .await
        .ok();
    let registration = key.register(&begun.challenge);
    let confirm = ConfirmMemberPasskey {
        ceremony_id: begun.ceremony_id,
        response: registration.response,
        passkey_name: "Ann's laptop".to_owned(),
        proof: Some(MemberProof {
            password: FOUNDER_PASSWORD.to_owned(),
            code,
        }),
    };
    member_factors::confirm_passkey(org, &confirm)
        .send(ann.client())
        .await
        .ok();
    key
}

/// The sign-in challenge for the passkeys of `email`, asked for by
/// `client` before it is signed in.
async fn challenge(client: &Client, email: &str) -> PasskeyChallenge {
    let whose = PasskeySignInFor {
        email: email.to_owned(),
    };
    member_factors::begin_passkey_sign_in(&whose)
        .send(client)
        .await
        .ok()
}

/// `key`'s signed answer to `challenge`, its sign count one higher, with
/// the ceremony it answers, as the browser sends it.
fn answer(key: &mut SoftPasskey, challenge: PasskeyChallenge) -> PasskeyAnswerBody {
    let signed = key.sign_in(&challenge.challenge);
    PasskeyAnswerBody {
        ceremony_id: challenge.ceremony_id,
        response: signed.response,
        credential_id: signed.credential_id,
    }
}

/// The session `answer` opens through `client`.
///
/// # Panics
///
/// When the answer is refused or offers a choice, which a passkey naming
/// one account never does.
async fn signed_in(client: &Client, answer: &PasskeyAnswerBody) -> Session {
    let opened = member_factors::confirm_passkey_sign_in(answer)
        .send(client)
        .await
        .ok();
    let SignedIn::Authenticated(session) = opened else {
        panic!("a registered passkey names one account, so no choice is offered");
    };
    session
}

/// Ann replaces Acme's sign-in settings with `settings`, her password
/// typed again.
async fn replace_settings(ann: &Founder, org: &OrgPath, settings: OrgSignInSettings) {
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
