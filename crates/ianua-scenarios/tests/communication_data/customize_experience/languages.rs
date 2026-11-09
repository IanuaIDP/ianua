//! The mail a person gets, in the language they chose for themselves.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::account::{self, Plane};
use ianua_scenarios::api::people;
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::account::Preferences;
use ianua_scenarios::world::World;

use crate::support::person;

/// How a welcome reads in English.
const ENGLISH_SUBJECT: &str = "Welcome to";

/// How a welcome reads in German.
const GERMAN_SUBJECT: &str = "Willkommen bei";

/// How many earlier mails are passed over on the way to the welcome.
const EARLIER_MAILS: usize = 4;

/// Pat chooses German for herself; Uma chooses nothing. Tess sends each a
/// welcome. Pat's arrives in German and Uma's in English, the same
/// platform email in the language each of them reads.
#[tokio::test]
async fn pat_s_mail_comes_in_the_language_she_chose() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let german = Preferences {
        locale: Some("de-DE".to_owned()),
        ..Preferences::default()
    };
    account::preferences(Plane::Tenant(world.tenant()), &german)
        .send(pat.client())
        .await
        .ok();

    let pats = welcomed(&world, &pat, GERMAN_SUBJECT).await;
    let umas = welcomed(&world, &uma, ENGLISH_SUBJECT).await;

    assert!(
        pats.text().is_some_and(|text| text.contains("Hallo")),
        "Pat's welcome reads German through and through"
    );
    assert!(umas.text().is_some_and(|text| text.contains("Hi ")));

    stack.stop().await.expect("the stack stops cleanly");
}

/// `who`'s welcome from Tess, whose subject starts with `subject`, passing
/// over any mail that came before it.
async fn welcomed(world: &World<'_>, who: &Person, subject: &str) -> Mail {
    people::send_welcome(world.tenant(), who.id())
        .send(world.admin().client())
        .await
        .ok();
    for _ in 0..EARLIER_MAILS {
        let mail = world.stack().mailbox().next_for(who.email()).await;
        if mail.subject().starts_with(subject) {
            return mail;
        }
    }
    panic!("{} got no mail starting {subject:?}", who.email());
}
