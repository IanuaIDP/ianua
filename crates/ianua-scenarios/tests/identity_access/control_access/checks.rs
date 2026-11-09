//! Asking whether someone may do something, the way a tenant's app asks:
//! anything the records do not show is refused, with the reason, and
//! every answer is recorded. A role's app permission or a relationship on
//! the object changes the answer for as long as it stands.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{control_access, policies};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{
    AccessCheck, AccessCheckBatch, AccessQuestion, AppObject, AppPermission, NewAction, NewAppRole,
    NewRelationship, NewResourceType, Principal, RelationLink, RelationSubject,
};
use ianua_scenarios::world::World;

use crate::support::{USER, add_to_group, bind_role, group, person};

/// A subject the tenant has never heard of.
const NOBODY: &str = "00000000-0000-4000-8000-000000000000";

/// The app's resource type.
const DOCUMENT: &str = "document";

/// `person` as a principal.
fn principal(person: &Person) -> Principal {
    Principal {
        kind: USER.to_owned(),
        id: person.id().to_owned(),
    }
}

/// The question whether a subject may do `action` on documents, or on
/// the one keyed `key`.
fn asking(action: &str, key: Option<&str>) -> AccessQuestion {
    AccessQuestion {
        action: action.to_owned(),
        resource_type: DOCUMENT.to_owned(),
        object_key: key.map(str::to_owned),
    }
}

/// One check of `action` on documents by `subject`.
fn check_of(subject: Principal, question: AccessQuestion) -> AccessCheck {
    AccessCheck { subject, question }
}

/// Tess declares documents, whose `editor` action brings `viewer`.
async fn declare_documents(world: &World<'_>) {
    let action = |key: &str, implies: &[&str]| NewAction {
        key: key.to_owned(),
        display_name: key.to_owned(),
        implies: implies.iter().map(|action| (*action).to_owned()).collect(),
    };
    let declared = NewResourceType {
        key: DOCUMENT.to_owned(),
        display_name: "Documents".to_owned(),
        actions: vec![action("viewer", &[]), action("editor", &["viewer"])],
        data_class: "Internal".to_owned(),
    };
    control_access::declare_resource_type(world.tenant(), &declared)
        .send(world.admin().client())
        .await
        .ok();
}

/// The answer to whether `subject` may `action`, read as Tess, its
/// reason when refused.
async fn answer(world: &World<'_>, subject: &Principal, question: AccessQuestion) -> String {
    let answer = control_access::check(world.tenant(), &check_of(subject.clone(), question))
        .send(world.admin().client())
        .await
        .ok();
    answer.reason.unwrap_or(answer.decision)
}

/// `person` holding `relation` on the document keyed `key`.
fn holds(person: &Person, key: &str, relation: &str) -> NewRelationship {
    NewRelationship {
        object: AppObject {
            resource_type: DOCUMENT.to_owned(),
            key: key.to_owned(),
        },
        link: RelationLink::Holds {
            relation: relation.to_owned(),
            subject: RelationSubject {
                kind: USER.to_owned(),
                id: person.id().to_owned(),
            },
        },
    }
}

/// Nothing is declared yet: asking about documents is refused because
/// the app's resource type is unknown. Declared, an action no document
/// accepts is refused as undeclared, and Pat, who holds nothing, is
/// refused as not holding it; so is someone the tenant has never heard
/// of. Asked in one batch the answers come in order, and an empty batch
/// is refused. Max, Sam and nobody signed in may not ask at all. Every
/// answer is recorded and found by subject and verdict; Max may not read
/// the records.
#[tokio::test]
async fn anything_the_records_do_not_show_is_refused_and_every_answer_recorded() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let pat_subject = principal(&pat);

    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", None)).await,
        "unknown_resource_type"
    );
    declare_documents(&world).await;
    assert_eq!(
        answer(&world, &pat_subject, asking("shred", None)).await,
        "undeclared_action"
    );
    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", None)).await,
        "not_held"
    );
    let nobody = Principal {
        kind: USER.to_owned(),
        id: NOBODY.to_owned(),
    };
    assert_eq!(
        answer(&world, &nobody, asking("viewer", Some("42"))).await,
        "not_held",
        "a principal the tenant does not know holds nothing"
    );

    let batch = AccessCheckBatch {
        subject: pat_subject.clone(),
        checks: vec![asking("shred", None), asking("viewer", Some("42"))],
    };
    let batched = control_access::check_batch(world.tenant(), &batch)
        .send(world.admin().client())
        .await
        .ok();
    let reasons: Vec<_> = batched
        .decisions
        .iter()
        .map(|decision| decision.reason.as_deref())
        .collect();
    assert_eq!(
        reasons,
        [Some("undeclared_action"), Some("not_held")],
        "answers come in the order asked"
    );
    let empty = AccessCheckBatch {
        subject: pat_subject.clone(),
        checks: vec![],
    };
    control_access::check_batch(world.tenant(), &empty)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    Matrix::new(
        "asking the access check",
        control_access::check(
            world.tenant(),
            &check_of(pat_subject.clone(), asking("viewer", None)),
        )
        .call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    let refused = control_access::decisions(
        world.tenant(),
        &[
            ("subject_kind", USER),
            ("subject_id", pat.id()),
            ("verdict", "denied"),
        ],
    )
    .send(world.admin().client())
    .await
    .ok();
    assert_eq!(
        refused.items.len(),
        5,
        "each of Pat's refused answers is on the record"
    );
    assert_eq!(refused.items[0].subject, pat_subject);
    assert_eq!(refused.items[0].verdict, "denied");
    assert_eq!(refused.items[0].basis["kind"], "app_check");
    control_access::decisions(world.tenant(), &[])
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess makes a role carrying `document:editor`, binds it to a group, and
/// puts Pat in the group: checks say Pat may edit, and read through the
/// action's ladder, on any document. Taken out of the group, Pat is
/// refused again.
#[tokio::test]
async fn a_role_with_an_app_permission_answers_yes_until_it_goes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let pat_subject = principal(&pat);
    declare_documents(&world).await;

    let role = control_access::create_app_role(
        world.tenant(),
        &NewAppRole {
            name: "Document editors".to_owned(),
            custom_permissions: vec![AppPermission {
                resource: DOCUMENT.to_owned(),
                action: "editor".to_owned(),
            }],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id;
    let editors = group(&world, "Editors").await;
    bind_role(&world, &editors, &role).await;
    add_to_group(&world, &editors, &pat).await;

    assert_eq!(
        answer(&world, &pat_subject, asking("editor", None)).await,
        "allowed"
    );
    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", Some("42"))).await,
        "allowed",
        "editing brings viewing, on one object or any"
    );

    policies::remove_member(world.tenant(), &editors, USER, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        answer(&world, &pat_subject, asking("editor", None)).await,
        "not_held",
        "taken out of the group, Pat holds nothing"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess writes that Pat may view document 42: checks say so for that
/// document only, and not for another or for any at all. A folder
/// document 43 sits under brings Pat's reach there too; Uma, in a group
/// holding a relation on 7, reaches it through the group. Writing the same
/// fact twice answers the same record with no second record. Tess may not
/// write a relation the type does not declare, nor put a document under
/// itself. Listed by object or by subject, the facts read back. Tess
/// removes Pat's fact: checks stop saying yes at once, and removal of an
/// unknown fact is refused.
#[tokio::test]
async fn a_relationship_lets_pat_view_one_document_until_tess_removes_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let pat_subject = principal(&pat);
    declare_documents(&world).await;
    let tess = world.admin().client();

    let written = control_access::write_relationship(world.tenant(), &holds(&pat, "42", "viewer"))
        .send(tess)
        .await
        .ok();
    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", Some("42"))).await,
        "allowed"
    );
    assert_eq!(
        answer(&world, &pat_subject, asking("editor", Some("42"))).await,
        "not_held",
        "a relation brings only what it says"
    );
    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", Some("43"))).await,
        "not_held",
        "another document stays closed"
    );
    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", None)).await,
        "not_held",
        "a relation on one object is no permission on all of them"
    );

    let again = control_access::write_relationship(world.tenant(), &holds(&pat, "42", "viewer"))
        .send(tess)
        .await
        .ok();
    assert_eq!(again.id, written.id, "the same fact answers as it was");
    assert_eq!(
        world
            .trail()
            .count("authorization.relationship_added")
            .await,
        1,
        "writing the same fact records nothing new"
    );

    write_group_and_folder(&world, &pat, &uma).await;
    refuse_bad_writes(&world, &pat).await;
    list_by_object_and_subject(&world, &pat).await;

    control_access::remove_relationship(world.tenant(), &written.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(
        answer(&world, &pat_subject, asking("viewer", Some("42"))).await,
        "not_held",
        "once removed, the check stops saying yes"
    );
    control_access::remove_relationship(world.tenant(), &written.id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    world
        .trail()
        .recorded("authorization.relationship_removed")
        .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess gives a group a relation Uma reaches through, and puts document
/// 43 under the folder 99 Pat holds a relation on.
async fn write_group_and_folder(world: &World<'_>, pat: &Person, uma: &Person) {
    let tess = world.admin().client();
    let viewers = group(world, "Document viewers").await;
    add_to_group(world, &viewers, uma).await;
    let for_group = NewRelationship {
        object: AppObject {
            resource_type: DOCUMENT.to_owned(),
            key: "7".to_owned(),
        },
        link: RelationLink::Holds {
            relation: "viewer".to_owned(),
            subject: RelationSubject {
                kind: "group".to_owned(),
                id: viewers,
            },
        },
    };
    control_access::write_relationship(world.tenant(), &for_group)
        .send(tess)
        .await
        .ok();
    assert_eq!(
        answer(world, &principal(uma), asking("viewer", Some("7"))).await,
        "allowed",
        "Uma reaches the document through her group"
    );

    let folder_relation = holds(pat, "99", "viewer");
    control_access::write_relationship(world.tenant(), &folder_relation)
        .send(tess)
        .await
        .ok();
    let under_folder = NewRelationship {
        object: AppObject {
            resource_type: DOCUMENT.to_owned(),
            key: "43".to_owned(),
        },
        link: RelationLink::Under(AppObject {
            resource_type: DOCUMENT.to_owned(),
            key: "99".to_owned(),
        }),
    };
    control_access::write_relationship(world.tenant(), &under_folder)
        .send(tess)
        .await
        .ok();
    assert_eq!(
        answer(world, &principal(pat), asking("viewer", Some("43"))).await,
        "allowed",
        "a relation on the folder reaches the document under it"
    );
}

/// A relation the type does not declare, and a document under itself, are
/// refused.
async fn refuse_bad_writes(world: &World<'_>, pat: &Person) {
    let tess = world.admin().client();
    control_access::write_relationship(world.tenant(), &holds(pat, "42", "owner"))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let under_itself = NewRelationship {
        object: AppObject {
            resource_type: DOCUMENT.to_owned(),
            key: "42".to_owned(),
        },
        link: RelationLink::Under(AppObject {
            resource_type: DOCUMENT.to_owned(),
            key: "42".to_owned(),
        }),
    };
    control_access::write_relationship(world.tenant(), &under_itself)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// The facts read back one object at a time and one subject at a time.
async fn list_by_object_and_subject(world: &World<'_>, pat: &Person) {
    let tess = world.admin().client();
    let on_document = control_access::relationships(
        world.tenant(),
        &[("object_type", DOCUMENT), ("object_key", "42")],
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(on_document.items.len(), 1, "one fact about document 42");
    let held_by_pat = control_access::relationships(
        world.tenant(),
        &[("subject_kind", USER), ("subject_id", pat.id())],
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(held_by_pat.items.len(), 2, "Pat holds two relations");
}

/// Max, Sam and nobody signed in neither write, list nor remove a
/// relationship; Tess's fact stays.
#[tokio::test]
async fn nobody_without_the_right_writes_or_reads_relationships() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    declare_documents(&world).await;
    let written = control_access::write_relationship(world.tenant(), &holds(&pat, "42", "viewer"))
        .send(world.admin().client())
        .await
        .ok();

    for (what, call) in [
        (
            "writing a relationship",
            control_access::write_relationship(world.tenant(), &holds(&pat, "9", "viewer")).call(),
        ),
        (
            "listing relationships",
            control_access::relationships(world.tenant(), &[]).call(),
        ),
        (
            "removing a relationship",
            control_access::remove_relationship(world.tenant(), &written.id).call(),
        ),
    ] {
        Matrix::new(what, call)
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }
    assert_eq!(
        control_access::relationships(world.tenant(), &[])
            .send(world.admin().client())
            .await
            .ok()
            .items
            .len(),
        1,
        "Tess's fact stays"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
