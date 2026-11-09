//! The log and everything cut from it hold what happened, never what would
//! let a reader do it again: no password, no token, no key and no factor's
//! secret, however it was handed over that day.

use ianua_scenarios::api::{Request, Text, api_keys, audit, sessions};
use ianua_scenarios::expect::{eventually, no_secret_leaked};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::api_keys::NewApiKey;
use ianua_scenarios::wire::audit::{AuditExport, ExportAsked};
use ianua_scenarios::wire::tenant_sign_in::ChangePassword;
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::invited;

/// What Pat changes her password to: a sentence, so no scanner takes it
/// for a key.
const CHANGED_PASSWORD: &str = "Scenario orchard copper lantern 4821";

/// What she resets it to from the mailed link.
const RESET_PASSWORD: &str = "Scenario harbour meadow ribbon 9036";

/// The most pages of a log read, far more than a new company fills.
const MOST_PAGES: usize = 64;

/// Every record the day's secrets should have left behind.
const RECORDED: [&str; 4] = [
    "oauth.api_key_created",
    "authentication.password_changed",
    "authentication.password_reset_completed",
    "authentication.mfa_enrolled",
];

/// Pat joins from her invitation, changes her password, resets it from a
/// mailed link and sets up an authenticator app, and Tess makes an API key,
/// shown to her that once. All four are on record. Read record by record,
/// the whole tenant's log, the whole company's log and a JSON export of
/// them hold none of Pat's passwords, her reset link's token, her session
/// tokens, her authenticator's secret or recovery codes, nor Tess's key,
/// and none of the cast's passwords or tokens.
#[tokio::test]
async fn no_record_or_export_holds_a_secret_handed_over_that_day() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, "pat").await;
    pat.accept_invitation(&stack).await;
    pat.sign_in(&stack).await;
    let change = ChangePassword {
        old_password: pat.password().to_owned(),
        new_password: CHANGED_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::change_password(world.tenant(), &change)
        .send(pat.client())
        .await
        .ok();
    let token = pat.reset_link(&stack).await;
    pat.confirm_reset(&token, RESET_PASSWORD).await.ok();
    pat.sign_in(&stack).await;
    pat.set_up_authenticator().await;
    let key = NewApiKey {
        name: "deploy".to_owned(),
        scopes: vec!["idp:users:view".to_owned()],
    };
    let made = api_keys::create(world.tenant(), &key)
        .send(world.admin().client())
        .await
        .ok();
    for event in RECORDED {
        world.trail().recorded(event).await;
    }

    let mut secrets = pat.secrets();
    secrets.extend(world.cast_secrets());
    secrets.push(CHANGED_PASSWORD.to_owned());
    secrets.push(made.raw_key.clone());
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();

    let tess = world.admin().client();
    let tenant_log = every_page(tess, |cursor| {
        audit::tenant_log_where(world.tenant(), &page_filters(cursor)).call()
    })
    .await;
    let ann = world.owner().client();
    let company_log = every_page(ann, |cursor| {
        audit::organization_log_where(world.org(), &page_filters(cursor)).call()
    })
    .await;
    assert!(
        tenant_log.contains(RECORDED[0]),
        "the sweep read the record of the key"
    );
    no_secret_leaked(&tenant_log, &secrets);
    no_secret_leaked(&company_log, &secrets);
    no_secret_leaked(&exported_as_json(&world).await, &secrets);

    stack.stop().await.expect("the stack stops cleanly");
}

/// The filters reading one page of a log after `cursor`.
fn page_filters(cursor: Option<&str>) -> Vec<(&str, &str)> {
    let mut filters = vec![("limit", "100")];
    if let Some(after) = cursor {
        filters.push(("after", after));
    }
    filters
}

/// Every page `page_after` asks for, read as `reader` and joined as they
/// came, so a field no wire type names is read too.
async fn every_page(reader: &Client, page_after: impl Fn(Option<&str>) -> Call) -> String {
    let mut pages = String::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MOST_PAGES {
        let text = Request::<Text>::text(page_after(cursor.as_deref()))
            .send_text(reader)
            .await
            .ok();
        let page: Value = serde_json::from_str(&text).expect("a page of the log is JSON");
        pages.push_str(&text);
        let Some(next) = page["next_cursor"].as_str() else {
            return pages;
        };
        cursor = Some(next.to_owned());
    }
    panic!("the log never ended");
}

/// The whole tenant's log, as a JSON export Tess asks for and downloads.
async fn exported_as_json(world: &World<'_>) -> String {
    let asked = ExportAsked {
        format: "json".to_owned(),
        event_type: None,
    };
    let export = audit::request_tenant_export(world.tenant(), &asked)
        .send(world.admin().client())
        .await
        .ok();
    let ready: AuditExport = eventually("the worker to write the export", || async {
        let standing = audit::tenant_export(world.tenant(), &export.id)
            .send(world.admin().client())
            .await
            .ok();
        (standing.status == "ready").then_some(standing)
    })
    .await;
    let link = ready.download_url.expect("a ready export hands out a link");
    Request::<Text>::text(Call::get(&link))
        .send_text(world.admin().client())
        .await
        .ok()
}
