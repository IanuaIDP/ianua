//! The tenant's own fields on its people: Tess declares a shirt size Pat
//! keeps herself and a badge number only staff keep; a salary shows only
//! to those cleared for it. A field everyone must hold cannot be emptied,
//! nor required while someone lacks it, and withdrawing a field keeps its
//! values until Tess discards them. Uma changes none of it, and nobody
//! signed in reads any of it.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::attributes::{self, HeldValue};
use ianua_scenarios::api::roles;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::attributes::{
    AttributeStatus, AttributeValue, ChangeAttribute, DeclareAttribute,
};
use ianua_scenarios::wire::roles::AssignRole;
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{person, reader};

/// The namespace a field in which the person keeps the value.
const USER: &str = "user";

/// The namespace of a field only staff keep.
const APP: &str = "app";

/// The field a person keeps herself.
const SHIRT_SIZE: &str = "shirt_size";

/// The field only staff keep.
const BADGE_NUMBER: &str = "badge_number";

/// The field only the cleared see.
const SALARY: &str = "salary";

/// The record a declared field leaves.
const DECLARED: &str = "identity.attribute_declared";

/// The record a value change leaves.
const VALUE_CHANGED: &str = "identity.metadata_updated";

/// The record a withdrawn field leaves.
const WITHDRAWN: &str = "identity.attribute_archived";

/// The record a discarded field leaves.
const DISCARDED: &str = "identity.attribute_deleted";

/// The record every cleared value of a person leaves.
const VALUES_CLEARED: &str = "identity.metadata_deleted";

/// A value Pat chooses from the field's options.
const MEDIUM: &str = "medium";

/// `value` as the body of a write.
fn valued(value: Value) -> AttributeValue {
    AttributeValue { value }
}

/// A field `key` in `namespace` of `kind`, the other choices left at the
/// defaults.
fn field(namespace: &str, key: &str, kind: &str) -> DeclareAttribute {
    DeclareAttribute {
        namespace: namespace.to_owned(),
        kind: kind.to_owned(),
        display_name: key.replace('_', " "),
        key: Some(key.to_owned()),
        ..DeclareAttribute::default()
    }
}

/// The shirt-size field Pat keeps herself, chosen from a list.
fn shirt_size() -> DeclareAttribute {
    DeclareAttribute {
        options: vec!["small".to_owned(), MEDIUM.to_owned(), "large".to_owned()],
        ..field(USER, SHIRT_SIZE, "single_choice")
    }
}

/// `whose` value under `namespace` and `key`.
fn value_of<'a>(whose: &'a Person, namespace: &'a str, key: &'a str) -> HeldValue<'a> {
    HeldValue {
        user: whose.id(),
        namespace,
        key,
    }
}

/// Tess reads the catalogue of kinds and declares a shirt size chosen
/// from a list: it lists at once and the declaration is on record. Pat
/// sets her own from her session and reads it back, as Tess does, and the
/// value leaves the record clean. A value off the list is refused and
/// leaves hers unchanged. Uma, an ordinary user, cannot declare a field or
/// write Pat's value, and nobody signed in can read Pat's.
#[tokio::test]
async fn tess_declares_a_shirt_size_and_pat_keeps_her_own() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;

    let kinds = attributes::kinds(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let choice = kinds.iter().find(|kind| kind.kind == "single_choice");
    assert!(
        choice.is_some_and(|kind| kind.requires_options),
        "the catalogue says a choice needs a list of options"
    );
    let declared = attributes::declare(world.tenant(), &shirt_size())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(declared.namespace, USER);
    assert_eq!(declared.key, SHIRT_SIZE);
    assert_eq!(declared.options.len(), 3, "the options were kept");
    assert!(!declared.archived, "a new field is in use");
    world.trail().recorded_after(&seen, DECLARED).await;

    pat_keeps_her_own_size(&world, &pat, &uma).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat sets her own value, reads it, and Tess reads it; a value off the
/// list changes nothing; Uma writes nothing of Pat's and nobody signed in
/// reads it.
async fn pat_keeps_her_own_size(world: &World<'_>, pat: &Person, uma: &Person) {
    let seen = world.trail().ids().await;
    let held = value_of(pat, USER, SHIRT_SIZE);
    attributes::set_value(world.tenant(), held, &valued(json!(MEDIUM)))
        .send(pat.client())
        .await
        .ok();
    let own = attributes::values(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(own.values["user.shirt_size"], json!(MEDIUM));
    let by_tess = attributes::values(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(by_tess.values["user.shirt_size"], json!(MEDIUM));
    let recorded = world.trail().recorded_after(&seen, VALUE_CHANGED).await;
    no_secret_leaked(&recorded.details.to_string(), &[MEDIUM]);

    attributes::set_value(world.tenant(), held, &valued(json!("gigantic")))
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    attributes::set_value(world.tenant(), held, &valued(json!("large")))
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    attributes::values(world.tenant(), pat.id())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    attributes::values(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    attributes::declare(world.tenant(), &field(USER, "favourite_colour", "text"))
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let after = attributes::values(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        after.values["user.shirt_size"],
        json!(MEDIUM),
        "the refused writes changed nothing"
    );
}

/// Tess declares a badge number only staff keep, every user to hold one.
/// Pat cannot write it; Tess writes it for her and Pat reads it. It cannot
/// be emptied. A value of the wrong type and a field nobody declared are
/// each refused.
#[tokio::test]
async fn staff_keep_a_required_badge_number_that_cannot_be_emptied() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let badge = DeclareAttribute {
        required: true,
        ..field(APP, BADGE_NUMBER, "whole_number")
    };
    attributes::declare(world.tenant(), &badge)
        .send(world.admin().client())
        .await
        .ok();
    let held = value_of(&pat, APP, BADGE_NUMBER);

    attributes::set_value(world.tenant(), held, &valued(json!(7)))
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    attributes::set_value(world.tenant(), held, &valued(json!(1042)))
        .send(world.admin().client())
        .await
        .ok();
    let own = attributes::values(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        own.values["app.badge_number"],
        json!(1042),
        "Pat reads what staff keep about her"
    );

    attributes::set_value(world.tenant(), held, &valued(Value::Null))
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    attributes::set_value(world.tenant(), held, &valued(json!("not a number")))
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let undeclared = value_of(&pat, APP, "never_declared");
    attributes::set_value(world.tenant(), undeclared, &valued(json!(1)))
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess declares a sensitive salary and sets Pat's. Uma, given only the
/// right to read users, sees no such field listed and no such value on
/// Pat, while Tess, holding every right, sees both.
#[tokio::test]
async fn a_sensitive_salary_shows_only_to_those_cleared() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let role = reader(&world).await;
    roles::assign(
        world.tenant(),
        &role,
        &AssignRole {
            user_id: uma.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let salary = DeclareAttribute {
        sensitive: true,
        ..field(APP, SALARY, "whole_number")
    };
    attributes::declare(world.tenant(), &salary)
        .send(world.admin().client())
        .await
        .ok();
    attributes::set_value(
        world.tenant(),
        value_of(&pat, APP, SALARY),
        &valued(json!(50_000)),
    )
    .send(world.admin().client())
    .await
    .ok();

    let cleared = attributes::values(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(cleared.values["app.salary"], json!(50_000));
    let not_cleared = attributes::values(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .ok();
    assert!(
        !not_cleared.values.contains_key("app.salary"),
        "the value is left out for someone not cleared"
    );
    let uma_sees = attributes::list(world.tenant(), "false")
        .send(uma.client())
        .await
        .ok();
    assert!(
        uma_sees.iter().all(|declared| declared.key != SALARY),
        "the field itself is left out too"
    );
    let tess_sees = attributes::list(world.tenant(), "false")
        .send(world.admin().client())
        .await
        .ok();
    assert!(tess_sees.iter().any(|declared| declared.key == SALARY));

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess makes a field required that not everyone holds: refused, naming
/// how many lack it. She sets it for Pat and Uma and the change goes
/// through. She renames the field, withdraws it from use, where a listing
/// no longer shows it, and it reappears when asked for; a field in use
/// cannot be discarded. Withdrawn, its values stay until she discards it,
/// which takes them with it and is on record.
#[tokio::test]
async fn a_field_is_required_only_when_everyone_holds_it_and_discarded_only_when_withdrawn() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    attributes::declare(world.tenant(), &field(APP, BADGE_NUMBER, "whole_number"))
        .send(world.admin().client())
        .await
        .ok();

    require_badge_once_everyone_holds_one(&world, &pat, &uma).await;
    withdraw_and_discard(&world, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Requiring the field fails while Pat and Uma lack it, then passes once
/// both hold a value.
async fn require_badge_once_everyone_holds_one(world: &World<'_>, pat: &Person, uma: &Person) {
    let change = ChangeAttribute {
        required: Some(true),
        ..ChangeAttribute::default()
    };
    let problem = attributes::change(world.tenant(), APP, BADGE_NUMBER, &change)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    assert!(
        problem.message().contains('2'),
        "the refusal names how many people lack it"
    );
    for (holder, number) in [(pat, 1), (uma, 2)] {
        attributes::set_value(
            world.tenant(),
            value_of(holder, APP, BADGE_NUMBER),
            &valued(json!(number)),
        )
        .send(world.admin().client())
        .await
        .ok();
    }
    let required = attributes::change(world.tenant(), APP, BADGE_NUMBER, &change)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        required.required,
        "with everyone holding it, it is required"
    );
}

/// A field in use cannot be discarded. Withdrawn it leaves listings until
/// asked for, keeps its values, and is then discarded with them.
async fn withdraw_and_discard(world: &World<'_>, pat: &Person) {
    let renamed = ChangeAttribute {
        display_name: Some("Badge".to_owned()),
        ..ChangeAttribute::default()
    };
    let changed = attributes::change(world.tenant(), APP, BADGE_NUMBER, &renamed)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(changed.display_name, "Badge");
    attributes::remove(world.tenant(), APP, BADGE_NUMBER)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    let withdrawn = attributes::set_status(
        world.tenant(),
        APP,
        BADGE_NUMBER,
        &AttributeStatus { archived: true },
    )
    .send(world.admin().client())
    .await
    .ok();
    assert!(withdrawn.archived, "the field is withdrawn");
    world.trail().recorded(WITHDRAWN).await;
    let in_use = attributes::list(world.tenant(), "false")
        .send(world.admin().client())
        .await
        .ok();
    assert!(in_use.iter().all(|declared| declared.key != BADGE_NUMBER));
    let all = attributes::list(world.tenant(), "true")
        .send(world.admin().client())
        .await
        .ok();
    assert!(all.iter().any(|declared| declared.key == BADGE_NUMBER));

    let discarded = attributes::remove(world.tenant(), APP, BADGE_NUMBER)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(discarded.values_discarded, 2, "both values went with it");
    world.trail().recorded(DISCARDED).await;
    let after = attributes::values(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert!(after.values.is_empty(), "Pat holds nothing of it now");
}

/// Tess clears every value Pat holds, in both namespaces at once, and it
/// is on record; Uma cannot and nobody signed in cannot try.
#[tokio::test]
async fn tess_clears_every_value_pat_holds_and_nobody_else_can() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    attributes::declare(world.tenant(), &shirt_size())
        .send(world.admin().client())
        .await
        .ok();
    attributes::declare(world.tenant(), &field(APP, BADGE_NUMBER, "whole_number"))
        .send(world.admin().client())
        .await
        .ok();
    attributes::set_value(
        world.tenant(),
        value_of(&pat, USER, SHIRT_SIZE),
        &valued(json!(MEDIUM)),
    )
    .send(pat.client())
    .await
    .ok();
    attributes::set_value(
        world.tenant(),
        value_of(&pat, APP, BADGE_NUMBER),
        &valued(json!(9)),
    )
    .send(world.admin().client())
    .await
    .ok();

    attributes::clear_values(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    attributes::clear_values(world.tenant(), pat.id())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let kept = attributes::values(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(kept.values.len(), 2, "the refused clears changed nothing");

    attributes::clear_values(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    let emptied = attributes::values(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert!(emptied.values.is_empty(), "Pat holds no values now");
    assert_eq!(
        world.trail().count(VALUES_CLEARED).await,
        1,
        "the clear is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
