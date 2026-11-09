//! What the recovery-code scenarios share: the sign-in a recovery code
//! finishes, how many factor answers the trail holds and that none of
//! them shows a secret, the refused sign-in that still reads nothing, and
//! the secrets Max's factor puts in play.

use ianua_scenarios::api::{OrgPath, member_factors, members};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::MemberRecoveryCode;
use ianua_scenarios::world::World;

use crate::factors::member::{Enrolled, others_keep_access};

/// The record a factor answer leaves, and a refused or duplicate one must
/// not.
pub(super) const VERIFIED: &str = "organization.org_mfa_verified";

/// Successful answers and sensitive values captured before a recovery attempt.
pub(super) struct FactorTrail {
    /// Accepted answers recorded before the attempt.
    pub(super) before: usize,
    /// Values that must not appear in its subsequent records.
    pub(super) secrets: Vec<String>,
}

impl FactorTrail {
    /// Captures the enrolled factor's secrets before counting its accepted answers.
    pub(super) async fn capture(world: &World<'_>, factor: &Enrolled) -> Self {
        let secrets = factor_secrets(world, factor);
        let before = world.trail().count(VERIFIED).await;
        Self { before, secrets }
    }
}

/// `code` finishes the waiting sign-in `client` carries, which then reads
/// its member's account; under the default policy no new factor is owed.
///
/// # Panics
///
/// When the code is refused, a new factor is owed, or the account read is
/// refused.
pub(super) async fn recovered_session(client: &Client, org: &OrgPath, code: &MemberRecoveryCode) {
    let accepted = member_factors::redeem_recovery_code(org, code)
        .send(client)
        .await
        .ok();
    assert!(
        !accepted.mfa_enrollment_required,
        "under the default policy a recovery code leaves no new factor owed"
    );
    members::me(org).send(client).await.ok();
}

/// The sign-in `browser` carries still reads nothing after a refused
/// step, the trail holds `expected` factor answers with no secret in
/// them, and the others keep their access.
pub(super) async fn denied(
    world: &World<'_>,
    browser: &Client,
    expected: usize,
    secrets: &[String],
) {
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    verified(world, expected, secrets).await;
    others_keep_access(world).await;
}

/// The trail holds exactly `expected` factor answers, none of which shows
/// one of `secrets`.
pub(super) async fn verified(world: &World<'_>, expected: usize, secrets: &[String]) {
    let trail = world.trail();
    assert_eq!(
        trail.count(VERIFIED).await,
        expected,
        "the trail holds the accepted factor answers and no other"
    );
    let records = trail.entries(VERIFIED).await;
    let borrowed: Vec<&str> = secrets.iter().map(String::as_str).collect();
    no_secret_leaked(&format!("{records:?}"), &borrowed);
}

/// The secrets Max's `factor` puts in play, with the cast's own: the
/// phone's secret and every code on the printout.
pub(super) fn factor_secrets(world: &World<'_>, factor: &Enrolled) -> Vec<String> {
    let mut secrets = world.cast_secrets();
    secrets.push(factor.phone.secret().to_owned());
    secrets.extend(factor.codes.all().iter().cloned());
    secrets
}
