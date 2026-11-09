//! A company signing up as a customer does it: the form, the mail, the
//! link, and a company founded with its first tenant and its owner, all of
//! it in the audit trail with no secret in it.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};

/// Ann signs her company up and founds it from the mailed link: the
/// company has her slug, its first tenant is "production", and she is its
/// owner, able to sign in. The founding of the company and of her account
/// are in the audit trail, with no password or token in it.
#[tokio::test]
async fn a_company_signs_up_and_is_founded_from_the_mail() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");

    let founded = ann.founded(&stack, "Acme").await;
    assert!(
        founded.org_slug.starts_with("acme"),
        "the company is named after itself: {}",
        founded.org_slug
    );
    assert_eq!(founded.tenant_slug, "production", "its first tenant");

    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let trail = Trail::of_organization(ann.client(), &founded.org_slug);
    for event in ["organization.created", "organization.org_user_created"] {
        let record = trail.recorded(event).await;
        no_secret_leaked(
            &record.details.to_string(),
            &[FOUNDER_PASSWORD, &session.refresh_token],
        );
    }

    stack.stop().await.expect("the stack stops cleanly");
}
