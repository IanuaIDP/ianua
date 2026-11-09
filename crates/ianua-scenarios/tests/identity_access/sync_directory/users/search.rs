//! How a directory finds the people it keeps: filters on each attribute
//! the endpoint keeps, joined and grouped, with letter case as each
//! attribute compares it; attributes it does not keep matching nobody; and
//! pages in either order.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::directory;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{
    DirectoryEnterprise, DirectoryName, DirectoryRecord, DirectorySearch,
};
use ianua_scenarios::world::World;

use super::ENTERPRISE;
use crate::support::{OnRemove, linked_directory};

/// Someone the directory keeps, with what it may be asked about them.
struct Hire {
    /// Their given name, which also names their address and display name.
    given: &'static str,
    /// Their family name.
    family: &'static str,
    /// Their department.
    department: &'static str,
    /// Their employee number.
    number: &'static str,
}

/// `hire` made through `linked`, their display name their two names and
/// the directory's id for them `EXT-` and their given name.
async fn kept(world: &World<'_>, linked: &Client, hire: &Hire) -> Person {
    let shown = format!("{} {}", hire.given, hire.family);
    let person = world.newcomer(&hire.given.to_ascii_lowercase(), &shown);
    let record = DirectoryRecord {
        user_name: person.email().to_owned(),
        display_name: Some(shown),
        name: Some(DirectoryName {
            formatted: None,
            given_name: Some(hire.given.to_owned()),
            family_name: Some(hire.family.to_owned()),
        }),
        external_id: Some(format!("EXT-{}", hire.given)),
        enterprise: Some(DirectoryEnterprise {
            department: Some(hire.department.to_owned()),
            employee_number: Some(hire.number.to_owned()),
            manager: None,
        }),
        ..DirectoryRecord::default()
    };
    directory::create_record(world.tenant(), &record)
        .send(linked)
        .await
        .ok();
    person
}

/// The display names `filter` finds, in alphabetical order, checked
/// against the total the endpoint reports.
async fn found(world: &World<'_>, linked: &Client, filter: &str) -> Vec<String> {
    let listing = directory::find_users(world.tenant(), filter)
        .send(linked)
        .await
        .ok();
    assert_eq!(
        listing.total_results as usize,
        listing.resources.len(),
        "the page holds every match of {filter}"
    );
    let mut names: Vec<String> = listing
        .resources
        .into_iter()
        .map(|person| person.display_name)
        .collect();
    names.sort();
    names
}

/// The directory keeps Pat and Uma in Finance and Quinn in Research; Pat
/// and Quinn share a family name. It finds people by the start or a
/// fragment of a name, by family name in any letter case, by department
/// through the enterprise extension's full path, and by comparisons joined
/// with `and` and `or` and grouped in parentheses. Its own id and the
/// employee number compare exactly, in their letter case; an address does
/// not, and is found by `emails.value` too. A comparison on an attribute
/// the endpoint does not keep finds nobody, unless `or` offers another
/// side. A filter it cannot read at all is refused as `invalidFilter`.
#[tokio::test]
async fn the_directory_finds_people_by_every_attribute_it_keeps() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = kept(
        &world,
        &linked,
        &Hire {
            given: "Pat",
            family: "Holder",
            department: "Finance",
            number: "E-100",
        },
    )
    .await;
    kept(
        &world,
        &linked,
        &Hire {
            given: "Uma",
            family: "Stone",
            department: "Finance",
            number: "E-200",
        },
    )
    .await;
    kept(
        &world,
        &linked,
        &Hire {
            given: "Quinn",
            family: "Holder",
            department: "Research",
            number: "E-300",
        },
    )
    .await;
    let holders = ["Pat Holder".to_owned(), "Quinn Holder".to_owned()];

    assert_eq!(
        found(&world, &linked, "displayName sw \"Pat\"").await,
        ["Pat Holder"]
    );
    assert_eq!(
        found(&world, &linked, "name.givenName co \"uin\"").await,
        ["Quinn Holder"]
    );
    assert_eq!(
        found(&world, &linked, "name.familyName eq \"holder\"").await,
        holders,
        "a family name compares without its letter case"
    );
    assert_eq!(
        found(
            &world,
            &linked,
            &format!("{ENTERPRISE}:department eq \"Finance\" and displayName sw \"Uma\""),
        )
        .await,
        ["Uma Stone"]
    );
    assert_eq!(
        found(
            &world,
            &linked,
            "department eq \"Research\" or employeeNumber eq \"E-100\"",
        )
        .await,
        holders
    );
    assert_eq!(
        found(
            &world,
            &linked,
            "(department eq \"Finance\" or department eq \"Research\") and name.familyName eq \"Holder\"",
        )
        .await,
        holders,
        "parentheses group the `or` before the `and`"
    );

    assert_eq!(
        found(&world, &linked, "externalId eq \"EXT-Pat\"").await,
        ["Pat Holder"]
    );
    assert!(
        found(&world, &linked, "externalId eq \"ext-pat\"")
            .await
            .is_empty(),
        "the directory's own id compares with its letter case"
    );
    assert!(
        found(&world, &linked, "employeeNumber eq \"e-100\"")
            .await
            .is_empty(),
        "an employee number compares with its letter case"
    );
    assert_eq!(
        found(
            &world,
            &linked,
            &format!("userName eq \"{}\"", pat.email().to_ascii_uppercase()),
        )
        .await,
        ["Pat Holder"],
        "an address compares without its letter case"
    );
    assert_eq!(
        found(
            &world,
            &linked,
            &format!("emails.value eq \"{}\"", pat.email()),
        )
        .await,
        ["Pat Holder"]
    );

    assert!(
        found(&world, &linked, "phoneNumbers eq \"5550100\"")
            .await
            .is_empty(),
        "an attribute not kept finds nobody"
    );
    assert_eq!(
        found(
            &world,
            &linked,
            "phoneNumbers eq \"5550100\" or displayName sw \"Pat\"",
        )
        .await,
        ["Pat Holder"],
        "`or` with an attribute not kept is the other side alone"
    );

    for unreadable in [
        "displayName gt \"A\"",
        "displayName eq",
        "(displayName eq \"A\"",
    ] {
        directory::find_users(world.tenant(), unreadable)
            .send(&linked)
            .await
            .refused(Status::BAD_REQUEST, "invalidFilter");
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// The directory keeps five people in one department. Asking by display
/// name two at a time from the start, the third and the fifth gives each
/// page in turn, the total always five and the first index echoed; past
/// the end there is nobody, the total still five. Descending it starts
/// from the other end. An order by an attribute the endpoint does not keep
/// or in a direction it does not know is refused as `invalidValue`.
#[tokio::test]
async fn the_directory_pages_its_people_in_either_order() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    for given in ["Ava", "Bea", "Cal", "Dan", "Eve"] {
        kept(
            &world,
            &linked,
            &Hire {
                given,
                family: "Paged",
                department: "Paging",
                number: "E-500",
            },
        )
        .await;
    }
    let page = |start_index: u64, sort_order: &str| DirectorySearch {
        filter: Some("department eq \"Paging\"".to_owned()),
        start_index: Some(start_index),
        count: Some(2),
        sort_by: Some("displayName".to_owned()),
        sort_order: Some(sort_order.to_owned()),
    };

    for (start_index, sort_order, expected) in [
        (1, "ascending", vec!["Ava Paged", "Bea Paged"]),
        (3, "ascending", vec!["Cal Paged", "Dan Paged"]),
        (5, "ascending", vec!["Eve Paged"]),
        (6, "ascending", vec![]),
        (1, "descending", vec!["Eve Paged", "Dan Paged"]),
    ] {
        let listing = directory::search_users(world.tenant(), &page(start_index, sort_order))
            .send(&linked)
            .await
            .ok();
        assert_eq!(listing.total_results, 5, "the total counts every match");
        assert_eq!(listing.start_index, start_index, "the index is echoed");
        assert_eq!(listing.items_per_page as usize, expected.len());
        let names: Vec<&str> = listing
            .resources
            .iter()
            .map(|person| person.display_name.as_str())
            .collect();
        assert_eq!(names, expected, "from {start_index}, {sort_order}");
    }

    let unknown_sort = DirectorySearch {
        sort_by: Some("favouriteColour".to_owned()),
        ..DirectorySearch::default()
    };
    directory::search_users(world.tenant(), &unknown_sort)
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "invalidValue");
    let unknown_order = DirectorySearch {
        sort_by: Some("displayName".to_owned()),
        sort_order: Some("sideways".to_owned()),
        ..DirectorySearch::default()
    };
    directory::search_users(world.tenant(), &unknown_order)
        .send(&linked)
        .await
        .refused(Status::BAD_REQUEST, "invalidValue");

    stack.stop().await.expect("the stack stops cleanly");
}
