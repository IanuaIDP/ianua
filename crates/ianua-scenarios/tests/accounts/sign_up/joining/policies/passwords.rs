//! The password rules of the public form: each class a policy may
//! require, the shortest and longest password the form advertises, and
//! the hygiene switches against personal data, common passwords and
//! breached ones. Pat's form is taken exactly when the password keeps the
//! rules, and Pat then proves the mailbox and signs in; a refused form
//! leaves no account.

use std::ops::Range;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, registration, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{BREACHED_PASSWORDS, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenants::MfaPolicy;
use ianua_scenarios::world::World;
use serde_json::json;

use super::super::support::{Enrollment, enrollment, form, mailed_proof, tenant_records};
use super::support::{saved, signed_in_under};

/// The classes a policy may require, in the order of their bits in a
/// mask.
const CLASSES: [&str; 4] = ["uppercase", "lowercase", "digit", "special"];

/// A password holding every class.
const COMPLETE: &str = "VioletOrchardLantern7942!";

/// The same password missing one class each, in the order of `CLASSES`.
const MISSING_ONE: [&str; 4] = [
    "violetorchardlantern7942!",
    "VIOLETORCHARDLANTERN7942!",
    "VioletOrchardLantern!",
    "VioletOrchardLantern7942",
];

/// The longest password the platform takes, which no policy raises.
const LONGEST: usize = 128;

/// The shortest lengths a policy may ask for in the length scenario: the
/// platform's own floor, a raised one, and the ceiling itself.
const MINIMA: [usize; 3] = [8, 20, 128];

/// A password holding Pat's own name, which the personal-data rule
/// refuses.
const PERSONAL: &str = "PatOrchardLantern7942!";

/// A password on the common list, which reads clean from the breach
/// service, so it tells the list's rule from the breach rule.
const COMMON: &str = "password";

/// Whether a proposed password is taken under the rules of the moment.
enum Verdict {
    /// Taken: Pat proves the mailbox and signs in.
    Taken,
    /// Refused, with no account made.
    Refused,
}

/// How breached passwords are treated.
#[derive(Clone, Copy, Debug)]
enum Breach {
    /// Not looked up.
    Off,
    /// Looked up and warned about, but taken.
    Warn,
    /// Looked up and refused.
    Block,
}

impl Breach {
    /// The setting as the API spells it.
    fn wire(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Warn => "Warn",
            Self::Block => "Block",
        }
    }

    /// What a breached password gets under this setting.
    fn verdict(self) -> Verdict {
        match self {
            Self::Off | Self::Warn => Verdict::Taken,
            Self::Block => Verdict::Refused,
        }
    }
}

/// For each `mask` of required classes, Ann saves the rules and Pat
/// registers with the complete password, then with each password missing
/// one class: the missing class refuses the form exactly when required.
/// Each taken form ends in a proved, signed-in account, and the accounts
/// registered are counted.
async fn case_rules(masks: Range<u8>) {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;

    let mut taken = 0;
    for mask in masks {
        taken += exercise_class_rules(&world, mask).await;
    }

    assert_registration_count(&world, taken).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// One set of required classes admits the complete password and only the permitted omissions.
async fn exercise_class_rules(world: &World<'_>, mask: u8) -> usize {
    let mut taken = 0;
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    for (bit, class) in CLASSES.iter().enumerate() {
        settings.rest["password_policy"]["require"][class] = json!(mask & (1 << bit) != 0);
    }
    saved(world, settings).await;
    let complete = pat_choosing(world, &format!("complete-{mask}"), COMPLETE);
    screened(world, complete, Verdict::Taken).await;
    taken += 1;
    for (bit, password) in MISSING_ONE.iter().enumerate() {
        let verdict = if mask & (1 << bit) != 0 {
            Verdict::Refused
        } else {
            Verdict::Taken
        };
        if matches!(verdict, Verdict::Taken) {
            taken += 1;
        }
        let pat = pat_choosing(world, &format!("missing-{mask}-{bit}"), password);
        screened(world, pat, verdict).await;
    }
    taken
}

/// The audit trail counts every admitted password once across the matrix.
async fn assert_registration_count(world: &World<'_>, taken: usize) {
    assert_eq!(
        tenant_records(world, "identity.user_registered", &[]).await,
        taken,
        "one registration for each password taken"
    );
}

/// Across all uppercase and lowercase requirements, with digits and special
/// characters optional, passwords missing a required class are refused without
/// an account. Accepted forms reach verified sign-in and are counted in the
/// registration audit trail.
#[tokio::test]
async fn case_rules_alone_refuse_only_the_missing_class() {
    case_rules(0..4).await;
}

/// Rules four to seven: a digit required, each choice of upper and lower
/// case. A password keeping the rules proves the mailbox and signs in.
#[tokio::test]
async fn case_rules_with_a_digit_refuse_only_the_missing_class() {
    case_rules(4..8).await;
}

/// With special characters required and digits optional, every uppercase and
/// lowercase combination refuses missing required classes without an account.
/// Accepted forms reach verified sign-in and are counted in the registration
/// audit trail.
#[tokio::test]
async fn case_rules_with_a_special_refuse_only_the_missing_class() {
    case_rules(8..12).await;
}

/// Rules twelve to fifteen: a digit and a special character required,
/// each choice of upper and lower case; a class not required stays
/// optional and the taken forms reach a signed-in account.
#[tokio::test]
async fn case_rules_with_a_digit_and_a_special_refuse_only_the_missing_class() {
    case_rules(12..16).await;
}

/// Ann raises the shortest password to each of three lengths; the form
/// advertises each. Pat registers with a password one short of it, one
/// exactly as long, one as long as the platform's longest, and one
/// longer: taken exactly within the bounds, and refused outside them
/// with no account made.
#[tokio::test]
async fn a_password_is_taken_exactly_within_the_advertised_lengths() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;

    let mut taken = 0;
    for minimum in MINIMA {
        advertise_minimum(&world, minimum).await;
        taken += exercise_lengths(&world, minimum).await;
    }

    assert_registration_count(&world, taken).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann saves a minimum length and the public form advertises that exact boundary.
async fn advertise_minimum(world: &World<'_>, minimum: usize) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.rest["password_policy"]["min_length"] = json!(minimum);
    saved(world, settings).await;
    let rules = registration::rules(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    let Some(policy) = rules.password_policy else {
        panic!("the open form shows its password rules");
    };
    assert_eq!(
        policy["min_length"], minimum,
        "the form advertises the shortest password"
    );
}

/// Distinct boundary lengths are admitted exactly inside the configured and platform bounds.
async fn exercise_lengths(world: &World<'_>, minimum: usize) -> usize {
    let mut taken = 0;
    let mut lengths = vec![minimum - 1, minimum, LONGEST, LONGEST + 1];
    lengths.sort_unstable();
    lengths.dedup();
    for length in lengths {
        let password = format!("Z7!{}", "v".repeat(length - 3));
        let verdict = if length < minimum || length > LONGEST {
            Verdict::Refused
        } else {
            Verdict::Taken
        };
        if matches!(verdict, Verdict::Taken) {
            taken += 1;
        }
        let pat = pat_choosing(world, &format!("length-{minimum}-{length}"), &password);
        screened(world, pat, verdict).await;
    }
    taken
}

/// With breached passwords treated as `breach`, Ann saves each choice of
/// the personal-data and common-list rules, and Pat registers with a
/// password holding their name, one from the common list, and one from a
/// breach: each refused exactly when its rule is on. The accounts
/// registered are counted.
async fn hygiene_switches_under(breach: Breach) {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    enrollment(&world, Enrollment::Open).await;

    let mut taken = 0;
    for mask in 0..4 {
        save_hygiene_rules(&world, breach, mask).await;
        taken += exercise_hygiene(&world, breach, mask).await;
    }

    assert_registration_count(&world, taken).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann configures independent hygiene switches with character and length rules held permissive.
async fn save_hygiene_rules(world: &World<'_>, breach: Breach, mask: u8) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings
        .rest
        .insert("breached_passwords".to_owned(), json!(breach.wire()));
    settings.rest["password_policy"]["hygiene"]["personal_data"] = json!(mask & 1 != 0);
    settings.rest["password_policy"]["hygiene"]["common_passwords"] = json!(mask & 2 != 0);
    settings.rest["password_policy"]["require"]["digit"] = json!(false);
    settings.rest["password_policy"]["require"]["uppercase"] = json!(false);
    settings.rest["password_policy"]["min_length"] = json!(8);
    saved(world, settings).await;
}

/// Personal, common and breached passwords follow their respective switches independently.
async fn exercise_hygiene(world: &World<'_>, breach: Breach, mask: u8) -> usize {
    let mut taken = 0;
    let personal = if mask & 1 != 0 {
        Verdict::Refused
    } else {
        Verdict::Taken
    };
    let common = if mask & 2 != 0 {
        Verdict::Refused
    } else {
        Verdict::Taken
    };
    for (kind, password, verdict) in [
        ("personal", PERSONAL, personal),
        ("common", COMMON, common),
        ("breached", BREACHED_PASSWORDS[0], breach.verdict()),
    ] {
        if matches!(verdict, Verdict::Taken) {
            taken += 1;
        }
        let name = format!("{kind}-{}-{mask}", breach.wire());
        let pat = pat_choosing(world, &name.to_lowercase(), password);
        screened(world, pat, verdict).await;
    }
    taken
}

/// With breached passwords not looked up, the personal-data and
/// common-list rules each refuse on their own, and the breached password
/// is taken.
#[tokio::test]
async fn with_breach_screening_off_only_the_switched_on_hygiene_rules_refuse() {
    hygiene_switches_under(Breach::Off).await;
}

/// With breached passwords warned about, the breached password is still
/// taken, and the personal-data and common-list rules still refuse on
/// their own.
#[tokio::test]
async fn with_breach_warnings_a_breached_password_is_still_taken() {
    hygiene_switches_under(Breach::Warn).await;
}

/// With breached passwords blocked, the breached password is refused
/// under every choice of the other rules, and the passwords those rules
/// allow still reach a signed-in account.
#[tokio::test]
async fn with_breach_blocking_a_breached_password_is_refused_whatever_the_hygiene() {
    hygiene_switches_under(Breach::Block).await;
}

/// Pat at an address of their own for `name`, who chose `password` for
/// the form.
fn pat_choosing(world: &World<'_>, name: &str, password: &str) -> Person {
    let pat = world.newcomer(name, "Pat Newcomer");
    Person::new(
        Client::new(world.stack(), name).expect("a client"),
        pat.account().clone(),
        password,
    )
}

/// `person`'s form under the rules of the moment: with `Verdict::Taken`,
/// the proof is mailed, the mailbox proved, the registration recorded,
/// and they sign in; with `Verdict::Refused`, the form is refused for the
/// password and no account is made.
///
/// # Panics
///
/// When the form is answered otherwise than `verdict` says.
async fn screened(world: &World<'_>, mut person: Person, verdict: Verdict) {
    match verdict {
        Verdict::Taken => {
            let proof = mailed_proof(world, &mut person).await;
            registration::verify(world.tenant(), &proof)
                .send(person.client())
                .await
                .ok();
            signed_in_under(world, &person, MfaPolicy::Optional).await;
            let secrets = [person.password(), proof.token.as_str()];
            assert!(
                tenant_records(world, "identity.user_registered", &secrets).await > 0,
                "{} was registered",
                person.email()
            );
        }
        Verdict::Refused => {
            assert_password_refusal(world, &person).await;
        }
    }
}

/// A password rejected by the current policy leaves no account for its address.
async fn assert_password_refusal(world: &World<'_>, person: &Person) {
    registration::sign_up(world.tenant(), &form(person))
        .send(person.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let listed = people::list(world.tenant(), Some(person.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        listed.items.is_empty(),
        "{}: a refused form makes no account",
        person.email()
    );
}
