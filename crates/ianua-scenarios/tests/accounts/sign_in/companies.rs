//! One address with an account in two companies: when the password opens
//! both, Ann is asked which, and naming one signs her in there; a company
//! she is not in is told apart from nothing; a wrong guess is counted in
//! both; a different password in each company opens only its own; and a
//! reset link names the company whose password it changes.

use std::collections::HashMap;

use ianua_scenarios::api::{OrgPath, members, sessions};
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{AcceptMemberInvitation, InviteMember, OrgRole};
use ianua_scenarios::wire::sign_in::{
    ConfirmMemberPasswordReset, MemberPasswordResetFor, PasswordSignIn, ResetLinkToken, Session,
    SignedIn,
};
use ianua_scenarios::world::World;

use crate::support::{WRONG_GUESS, mail_linking_to, settled_sign_in};

/// The password Ann chooses at Globex when she wants one of its own: a
/// sentence, so no scanner takes it for a key.
const GLOBEX_PASSWORD: &str = "Scenario separate orchard lantern 6729";

/// The password Ann sets at Acme from the reset link naming Acme.
const RESET_PASSWORD: &str = "Independent mountain orchard meadow 8274!";

/// Separate mailed reset proofs for the two accounts sharing Ann's mailbox.
struct CompanyProofs {
    /// The proof whose reset must change Acme alone.
    acme: String,
    /// The proof that must remain usable at Globex.
    globex: String,
}

/// Sam invites Ann, who owns Acme, into Globex; Ann accepts with the
/// password she uses at Acme and signs in there. Somebody asks for a
/// password reset at Ann's address, and two links come, each naming one
/// company. Ann follows the one naming Acme: her Acme session is ended
/// while her Globex session still reads, the link naming Globex is still
/// worth something, the new password signs her in at Acme and is refused
/// at Globex, and one change is recorded at Acme and none at Globex.
#[tokio::test]
async fn a_shared_mailbox_reset_changes_only_the_company_named_by_its_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner();
    let sam = world.stranger();
    let mut at_globex = accepted_into_globex(&world, "Ann, at Globex", ann.password()).await;
    let there = settled_sign_in(
        &stack,
        &at_globex,
        &naming(sam.org(), &PasswordSignIn::of(ann.email(), ann.password())),
    )
    .await;
    at_globex.authorize(&there.refresh_token);

    let proofs = request_company_proofs(&world).await;
    reset_acme_only(&world, &at_globex, proofs).await;
    let at_acme = assert_reset_password(&world).await;
    assert_reset_audits(&world, &at_acme).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A reset request to Ann's shared mailbox yields one proof naming each company.
async fn request_company_proofs(world: &World<'_>) -> CompanyProofs {
    let ann = world.owner();
    let sam = world.stranger();
    sessions::request_member_password_reset(&MemberPasswordResetFor {
        email: ann.email().to_owned(),
    })
    .send(world.anonymous().client())
    .await
    .ok();
    let mut proofs = reset_proofs_by_company(world.stack(), ann.email()).await;
    let Some(acme_proof) = proofs.remove(ann.org().slug()) else {
        panic!("one of the two reset links names Acme");
    };
    let Some(globex_proof) = proofs.remove(sam.org().slug()) else {
        panic!("one of the two reset links names Globex");
    };
    CompanyProofs {
        acme: acme_proof,
        globex: globex_proof,
    }
}

/// Acme's proof ends its old session while Globex's session and reset proof remain usable.
async fn reset_acme_only(world: &World<'_>, at_globex: &Client, proofs: CompanyProofs) {
    let ann = world.owner();
    let sam = world.stranger();
    sessions::confirm_member_password_reset(&ConfirmMemberPasswordReset {
        token: proofs.acme,
        password: RESET_PASSWORD.to_owned(),
        mfa_code: None,
    })
    .send(world.anonymous().client())
    .await
    .ok();
    members::me(ann.org())
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(sam.org()).send(at_globex).await.ok();
    let untouched = sessions::member_reset_link_status(&ResetLinkToken {
        token: proofs.globex,
    })
    .send(world.anonymous().client())
    .await
    .ok();
    assert_eq!(
        untouched.status, "Valid",
        "the link naming Globex is still worth something"
    );
}

/// Ann's replacement password opens Acme under her account and is refused at Globex.
async fn assert_reset_password(world: &World<'_>) -> Client {
    let ann = world.owner();
    let sam = world.stranger();
    let mut at_acme = Client::new(world.stack(), "Ann, with her reset password").expect("a client");
    let fresh = settled_sign_in(
        world.stack(),
        &at_acme,
        &naming(ann.org(), &PasswordSignIn::of(ann.email(), RESET_PASSWORD)),
    )
    .await;
    at_acme.authorize(&fresh.refresh_token);
    assert_eq!(
        members::me(ann.org()).send(&at_acme).await.ok().id,
        ann.id(),
        "the reset password signs Ann in at Acme"
    );
    sessions::member_sign_in(&naming(
        sam.org(),
        &PasswordSignIn::of(ann.email(), RESET_PASSWORD),
    ))
    .send(world.anonymous().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    at_acme
}

/// Only Acme records a password change after the shared-mailbox reset.
async fn assert_reset_audits(world: &World<'_>, at_acme: &Client) {
    let ann = world.owner();
    let sam = world.stranger();
    assert_eq!(
        Trail::of_organization(at_acme, ann.org().slug())
            .count("organization.org_user_password_changed")
            .await,
        1,
        "one password change is recorded at Acme"
    );
    assert_eq!(
        Trail::of_organization(sam.client(), sam.org().slug())
            .count("organization.org_user_password_changed")
            .await,
        0,
        "no password change is recorded at Globex"
    );
}

/// Sam invites Ann, who owns Acme, into Globex as a member, and Ann
/// accepts with the password she uses at Acme. Signing in without naming
/// a company, she is offered both and nothing is opened; naming Acme
/// opens Acme, naming Globex opens Globex; naming a company she is not
/// in is answered as a wrong password is. Mallory's wrong guess at Ann's
/// address is refused and recorded in both companies' trails.
#[tokio::test]
async fn one_address_in_two_companies_chooses_by_naming_one() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner();
    let sam = world.stranger();
    let mut browser = accepted_into_globex(&world, "Ann, at the dashboard", ann.password()).await;

    let unnamed = PasswordSignIn::of(ann.email(), ann.password());
    assert_company_choice(&world, &browser, &unnamed).await;
    let at_acme = assert_named_sign_ins(&world, &browser, &unnamed).await;

    let mallory = Client::new(&stack, "Mallory, guessing at Ann").expect("a client");
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), WRONG_GUESS))
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    browser.authorize(&at_acme.refresh_token);
    Trail::of_organization(&browser, ann.org().slug())
        .recorded("organization.org_login_failed")
        .await;
    Trail::of_organization(sam.client(), sam.org().slug())
        .recorded("organization.org_login_failed")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unnamed sign-in with a shared password offers exactly Ann's two companies.
async fn assert_company_choice(world: &World<'_>, browser: &Client, unnamed: &PasswordSignIn) {
    let ann = world.owner();
    let sam = world.stranger();
    let answer = sessions::member_sign_in(unnamed).send(browser).await.ok();
    let SignedIn::ChooseOrganization { organizations } = answer else {
        panic!("the password opens both companies, so Ann is asked which");
    };
    let mut offered: Vec<&str> = organizations.iter().map(|org| org.slug.as_str()).collect();
    offered.sort_unstable();
    let mut both = [ann.org().slug(), sam.org().slug()];
    both.sort_unstable();
    assert_eq!(offered, both, "both companies are offered, and no other");
}

/// Naming each known company opens it, while an unknown company remains indistinguishable from a bad password.
async fn assert_named_sign_ins(
    world: &World<'_>,
    browser: &Client,
    unnamed: &PasswordSignIn,
) -> Session {
    let ann = world.owner();
    let sam = world.stranger();
    let at_acme = settled_sign_in(world.stack(), browser, &naming(ann.org(), unnamed)).await;
    assert_eq!(
        at_acme.org_slug,
        ann.org().slug(),
        "naming Acme signs Ann in at Acme"
    );
    let at_globex = settled_sign_in(world.stack(), browser, &naming(sam.org(), unnamed)).await;
    assert_eq!(
        at_globex.org_slug,
        sam.org().slug(),
        "naming Globex signs Ann in at Globex"
    );
    let nowhere = PasswordSignIn {
        organization: Some("nowhere".to_owned()),
        ..unnamed.clone()
    };
    sessions::member_sign_in(&nowhere)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    at_acme
}

/// Sam invites Ann into Globex and she accepts with a password of
/// Globex's own, different from Acme's. Each password is refused when she
/// names the company that does not know it, and without naming any it
/// lands her in the company that does, where she reads her own record and
/// is refused the other's. The two sessions stay open side by side.
#[tokio::test]
async fn different_passwords_at_one_address_open_only_their_own_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner();
    let sam = world.stranger();
    let mut browser =
        accepted_into_globex(&world, "Ann, choosing by password", GLOBEX_PASSWORD).await;

    let with_acmes = opened_only_at(
        &world,
        &mut browser,
        Choice {
            password: ann.password(),
            own: ann.org(),
            other: sam.org(),
        },
    )
    .await;
    let with_globexs = opened_only_at(
        &world,
        &mut browser,
        Choice {
            password: GLOBEX_PASSWORD,
            own: sam.org(),
            other: ann.org(),
        },
    )
    .await;

    assert_both_sessions(&world, &mut browser, &with_acmes, &with_globexs).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Switching the browser's credential shows that both company sessions remain usable.
async fn assert_both_sessions(
    world: &World<'_>,
    browser: &mut Client,
    acme: &Session,
    globex: &Session,
) {
    browser.authorize(&acme.refresh_token);
    members::me(world.owner().org()).send(browser).await.ok();
    browser.authorize(&globex.refresh_token);
    members::me(world.stranger().org()).send(browser).await.ok();
}

/// A password Ann holds, the company that knows it and the one that does
/// not.
struct Choice<'a> {
    /// The password.
    password: &'a str,
    /// The company it opens.
    own: &'a OrgPath,
    /// The company it does not.
    other: &'a OrgPath,
}

/// Ann's browser, once Sam invited her into Globex as a member and she
/// accepted from the mailed link with `password`. Not yet signed in.
async fn accepted_into_globex(world: &World<'_>, browser_name: &str, password: &str) -> Client {
    let ann = world.owner();
    let sam = world.stranger();
    let invitation = InviteMember {
        email: ann.email().to_owned(),
        display_name: "Ann Consulting".to_owned(),
        role: OrgRole::Member,
    };
    members::invite(sam.org(), &invitation)
        .send(sam.client())
        .await
        .ok();
    let mail = mail_linking_to(world.stack(), ann.email(), "/accept-invite").await;
    let accept = AcceptMemberInvitation {
        token: mail.token_in("/accept-invite"),
        password: password.to_owned(),
    };
    let browser = Client::new(world.stack(), browser_name).expect("a client");
    members::accept_invitation(sam.org(), &accept)
        .send(&browser)
        .await
        .ok();
    browser
}

/// The session `choice.password` opens for Ann through `browser`: refused
/// when she names the company that does not know it; settled naming none,
/// it lands in the company that does, where she reads her own record and
/// is refused the other's.
async fn opened_only_at(world: &World<'_>, browser: &mut Client, choice: Choice<'_>) -> Session {
    let credentials = PasswordSignIn::of(world.owner().email(), choice.password);
    sessions::member_sign_in(&naming(choice.other, &credentials))
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let session = settled_sign_in(world.stack(), browser, &credentials).await;
    assert_eq!(
        session.org_slug,
        choice.own.slug(),
        "the password lands Ann in the company that knows it"
    );
    browser.authorize(&session.refresh_token);
    members::me(choice.own).send(browser).await.ok();
    members::me(choice.other)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    session
}

/// The reset links mailed to `email`, held in two companies: each link's
/// token under the slug of the company it names.
async fn reset_proofs_by_company(stack: &Stack, email: &str) -> HashMap<String, String> {
    let mut proofs = HashMap::new();
    for _ in 0..2 {
        let mail = mail_linking_to(stack, email, "/reset-password").await;
        let named = mail
            .link_to("/reset-password")
            .query_pairs()
            .find(|(key, _)| key == "org")
            .map(|(_, slug)| slug.into_owned());
        let Some(named) = named else {
            panic!("a reset link to an address held in two companies names which");
        };
        proofs.insert(named, mail.token_in("/reset-password"));
    }
    proofs
}

/// `sign_in` again, naming `org`.
fn naming(org: &OrgPath, sign_in: &PasswordSignIn) -> PasswordSignIn {
    PasswordSignIn {
        organization: Some(org.slug().to_owned()),
        ..sign_in.clone()
    }
}
