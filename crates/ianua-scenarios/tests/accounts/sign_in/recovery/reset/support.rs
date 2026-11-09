//! What the password-reset scenarios share: the link mailed to Max when
//! anyone asks for his reset, what everyone reads after a reset, the one
//! password change a reset records, and the reset request a link and a
//! password make.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{
    ConfirmMemberPasswordReset, MemberPasswordResetFor, ResetLinkToken,
};
use ianua_scenarios::world::World;

use crate::support::mail_linking_to;

/// The record a password change leaves, and a refused reset must not.
pub(super) const CHANGED: &str = "organization.org_user_password_changed";

/// The token of the link mailed to Max when nobody signed in asks for his
/// reset: the link reaches his address and reads as valid, and asking
/// for it ended no session of his.
///
/// # Panics
///
/// When the request is refused, no link comes, the link does not read as
/// valid, or Max's session no longer reads his account.
pub(super) async fn reset_link(world: &World<'_>) -> String {
    let for_max = MemberPasswordResetFor {
        email: world.member().email().to_owned(),
    };
    sessions::request_member_password_reset(&for_max)
        .send(world.anonymous().client())
        .await
        .ok();
    let mail = mail_linking_to(world.stack(), world.member().email(), "/reset-password").await;
    assert_eq!(
        mail.recipient(),
        world.member().email(),
        "the link reaches Max's address alone"
    );
    let token = mail.token_in("/reset-password");
    let asked = ResetLinkToken {
        token: token.clone(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "a fresh link reads as valid");
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    token
}

/// After Max's password was reset: the session he held reads nothing,
/// Ann and Tess read their accounts, Sam reads nothing in Acme and
/// everything in Globex, and nobody signed in reads nothing.
///
/// # Panics
///
/// When any of them is answered otherwise.
pub(super) async fn access_after_reset(world: &World<'_>) {
    Matrix::new(
        "reading one's own account after Max's reset",
        members::me(world.org()).call(),
    )
    .allowed(world.owner().client())
    .allowed(world.admin().client())
    .refused(
        world.member().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// The id of the one password change the trail holds, made by Max,
/// showing none of `secrets`.
///
/// # Panics
///
/// When the trail holds no change or more than one, the change is not
/// Max's, or a secret shows in it.
pub(super) async fn single_change(world: &World<'_>, secrets: &[String]) -> String {
    let trail = world.trail();
    trail.recorded(CHANGED).await;
    let entries = trail.entries(CHANGED).await;
    let [changed] = entries.as_slice() else {
        panic!(
            "one reset records one password change, not {}",
            entries.len()
        );
    };
    assert!(
        changed.actor.contains(world.member().email()),
        "the password change names Max"
    );
    let borrowed: Vec<&str> = secrets.iter().map(String::as_str).collect();
    no_secret_leaked(&format!("{changed:?}"), &borrowed);
    changed.id.clone()
}

/// The reset the link `token` and `password` make, from a member with
/// no second factor.
pub(super) fn reset(token: &str, password: &str) -> ConfirmMemberPasswordReset {
    ConfirmMemberPasswordReset {
        token: token.to_owned(),
        password: password.to_owned(),
        mfa_code: None,
    }
}
