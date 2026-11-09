//! Pat's whole life in a tenant: invited by Tess, joining from the mail,
//! signing in, setting up an authenticator app and a passkey, losing the
//! phone, having a session ended by Tess, and resetting a forgotten
//! password by mail.
//!
//! At every step the whole cast tries the step's protected reads, the
//! audit trail is read for what the step recorded, and every exchange is
//! searched for the secrets in play: none may appear outside the field
//! made to carry it.
//!
//! - `cast`: Pat's record and Pat's sessions, read by everyone.
//! - `witness`: the records each step raised, and the secrets in play.

mod cast;
mod witness;

use ianua_scenarios::actors::{Person, SignedInWith};
use ianua_scenarios::api::{factors, people, sessions};
use ianua_scenarios::authenticators::{RecoveryCodes, TotpApp};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{BREACHED_PASSWORDS, Profile, Stack};
use ianua_scenarios::wire::factors::SessionCode;
use ianua_scenarios::wire::tenant_sign_in::{
    ConfirmPasswordReset, TenantPasswordSignIn, TenantSignedIn,
};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use self::cast::{PatsClient, own_sessions_by_the_cast, record_read_by_the_cast};
use self::witness::{Witness, nothing_leaked, secrets_in_play};
use crate::support::{as_tess, invitation_of};

/// The password Pat chooses after forgetting the first: a sentence, so no
/// scanner takes it for a key.
const NEW_PASSWORD: &str = "Scenario willow saffron granite 6150";

/// Pat is invited by Tess, joins from the mail, signs in, sets up an
/// authenticator app and then a passkey, signs in with the passkey, loses
/// the phone and gets in with a recovery code, has that session ended by
/// Tess, and resets the forgotten password by mail once the phone turns up
/// again. Each step's refusals, records and secrets are checked as it
/// goes. The application clock advances between fresh authenticator codes;
/// the real factor and replay checks still run at each step.
#[tokio::test]
async fn a_person_lives_through_every_way_in_and_out() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut witness = Witness::of(&world).await;
    let mut pat = world.newcomer("pat", "Pat Person");

    invited(&world, &mut pat, &mut witness).await;

    joined(&world, &mut pat, &mut witness).await;

    let ended = signed_in(&world, &mut pat, &mut witness).await;
    let ended: Vec<&Client> = ended.iter().collect();

    with_authenticator(&world, &mut pat, &mut witness, &ended).await;

    with_passkey(&world, &mut pat, &mut witness, &ended).await;

    by_passkey(&world, &mut pat, &mut witness, &ended).await;

    let phone = by_recovery_code(&world, &mut pat, &mut witness, &ended).await;

    session_ended_by_tess(&world, &mut pat, &mut witness, &ended).await;

    pat.find_phone(phone);
    password_reset_by_mail(&world, &mut pat, &mut witness, &ended).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess invites Pat with the tenant's `Member` role.
async fn invited(world: &World<'_>, pat: &mut Person, witness: &mut Witness<'_>) {
    let mut exchanges = Vec::new();
    let made = invitation_of(world, pat, &mut exchanges).await;
    assert!(
        made.accept_link.is_none(),
        "a deployment with mail mails the link"
    );

    let record = witness.recorded("identity.user_invited").await;
    exchanges.extend(record_read_by_the_cast(world, pat, PatsClient::SignedOut, &[]).await);
    nothing_leaked(&exchanges, &[&record], &secrets_in_play(world, pat));
}

/// Pat follows the mailed link: a breached password is refused, then a
/// good one accepted. Pat is active with the invited role.
async fn joined(world: &World<'_>, pat: &mut Person, witness: &mut Witness<'_>) {
    let token = pat.invitation_token(world.stack()).await;
    pat.accept_with(&token, BREACHED_PASSWORDS[0])
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    witness.nothing_new("identity.invitation_accepted").await;
    let password = pat.password().to_owned();
    pat.accept_with(&token, &password).await.ok();

    let accepted = witness.recorded("identity.invitation_accepted").await;
    let assigned = witness.recorded("authorization.role_assigned").await;
    let record = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(record.status, "Active", "accepting activates the account");
    assert!(record.email_verified, "the mailed link proved the address");

    let mut exchanges = pat.take_exchanges();
    exchanges.extend(record_read_by_the_cast(world, pat, PatsClient::SignedOut, &[]).await);
    nothing_leaked(
        &exchanges,
        &[&accepted, &assigned],
        &secrets_in_play(world, pat),
    );
}

/// Pat signs in with the password alone, then makes two more sessions
/// that end: one Pat signs out of, one Tess ends. Answers the clients of
/// those ended sessions, which every later step tries again.
async fn signed_in(world: &World<'_>, pat: &mut Person, witness: &mut Witness<'_>) -> [Client; 2] {
    let stack = world.stack();
    assert_eq!(
        pat.sign_in(stack).await,
        SignedInWith::Password,
        "Pat, with no factor yet, signs in with the password alone"
    );
    let first = witness.recorded("authentication.login_succeeded").await;

    let signed_out = pat.signed_out(stack).await;
    let logged_out = witness.recorded("authentication.session_revoked").await;
    let (revoked, session_id) = pat.on_another_device(stack, "ended by Tess").await;
    let mut exchanges = pat.take_exchanges();
    let ending = sessions::end_user_session(world.tenant(), pat.id(), &session_id);
    as_tess(world, ending, &mut exchanges).await.ok();
    let ended_by_tess = witness.recorded("authentication.session_revoked").await;

    let spoiled = [&signed_out, &revoked];
    exchanges.extend(record_read_by_the_cast(world, pat, PatsClient::SignedIn, &spoiled).await);
    exchanges.extend(own_sessions_by_the_cast(world, pat.client(), &spoiled).await);
    let records = [&first, &logged_out, &ended_by_tess];
    nothing_leaked(&exchanges, &records, &secrets_in_play(world, pat));
    [signed_out, revoked]
}

/// Pat sets up an authenticator app, proving who they are with the
/// password, and is shown recovery codes. A sign-in now owes its code.
async fn with_authenticator(
    world: &World<'_>,
    pat: &mut Person,
    witness: &mut Witness<'_>,
    ended: &[&Client],
) {
    pat.set_up_authenticator().await;
    let enrolled = witness.recorded("authentication.mfa_enrolled").await;
    let codes = witness
        .recorded("authentication.recovery_codes_generated")
        .await;
    let status = pat.send(factors::status(world.tenant())).await.ok();
    assert!(
        status.enabled,
        "the authenticator is in force once confirmed"
    );

    let mut exchanges = pat.take_exchanges();
    exchanges.extend(own_sessions_by_the_cast(world, pat.client(), ended).await);
    exchanges.extend(record_read_by_the_cast(world, pat, PatsClient::SignedIn, ended).await);
    nothing_leaked(
        &exchanges,
        &[&enrolled, &codes],
        &secrets_in_play(world, pat),
    );
}

/// Pat adds a passkey, proving who they are with the password and a code
/// from the phone. It is listed as a passkey of this device.
async fn with_passkey(
    world: &World<'_>,
    pat: &mut Person,
    witness: &mut Witness<'_>,
    ended: &[&Client],
) {
    pat.add_passkey(world.stack(), "Pat's laptop").await;
    let registered = witness.recorded("authentication.passkey_registered").await;
    let listed = pat.send(factors::passkeys(world.tenant())).await.ok();
    assert_eq!(listed.passkeys.len(), 1, "Pat holds the one passkey added");
    assert_eq!(
        listed.passkeys[0].authenticator_type, "platform",
        "the passkey is listed as one of this device"
    );

    let mut exchanges = pat.take_exchanges();
    exchanges.extend(own_sessions_by_the_cast(world, pat.client(), ended).await);
    nothing_leaked(&exchanges, &[&registered], &secrets_in_play(world, pat));
}

/// Pat signs in with the passkey alone; the session owes nothing more.
async fn by_passkey(
    world: &World<'_>,
    pat: &mut Person,
    witness: &mut Witness<'_>,
    ended: &[&Client],
) {
    assert_eq!(
        pat.sign_in_with_passkey().await,
        SignedInWith::Passkey,
        "Pat's passkey signs in on its own"
    );
    let signed_in = witness.recorded("authentication.login_succeeded").await;
    let own = pat.send(sessions::my_sessions(world.tenant())).await.ok();
    let current = own.iter().find(|session| session.current);
    assert_eq!(
        current.map(|session| session.auth_method.as_str()),
        Some("passkey"),
        "the session asking is the passkey's"
    );

    let mut exchanges = pat.take_exchanges();
    exchanges.extend(own_sessions_by_the_cast(world, pat.client(), ended).await);
    nothing_leaked(&exchanges, &[&signed_in], &secrets_in_play(world, pat));
}

/// Pat loses the phone and answers a password sign-in with a recovery
/// code; the same code typed again on another sign-in is refused. Answers
/// the phone, for when it turns up.
async fn by_recovery_code(
    world: &World<'_>,
    pat: &mut Person,
    witness: &mut Witness<'_>,
    ended: &[&Client],
) -> TotpApp {
    let phone = pat.lose_phone();
    let stack = world.stack();
    assert_eq!(
        pat.sign_in_with_recovery_code(stack).await,
        SignedInWith::PasswordAndRecoveryCode,
        "without the phone, Pat gets in with the password and a recovery code"
    );
    let used = witness.recorded("authentication.recovery_code_used").await;

    let spent = spent_recovery_code_again(stack, pat).await;
    spent.refused(Status::FORBIDDEN, "forbidden");
    witness
        .nothing_new("authentication.recovery_code_used")
        .await;

    let mut exchanges = pat.take_exchanges();
    exchanges.extend(own_sessions_by_the_cast(world, pat.client(), ended).await);
    nothing_leaked(&exchanges, &[&used], &secrets_in_play(world, pat));
    phone
}

/// A sign-in with Pat's password on another device, answered with the
/// recovery code already used.
async fn spent_recovery_code_again(stack: &Stack, pat: &Person) -> Answer<()> {
    let mut device = Client::new(stack, "Pat, typing a used code").expect("a client");
    let sign_in = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(pat.tenant(), &sign_in)
        .send(&device)
        .await
        .ok();
    let TenantSignedIn::Session(waiting) = answer else {
        panic!("Pat's own password owes no change, so a session waits for the code");
    };
    device.authorize(&waiting.refresh_token);
    let Some(used) = pat.recovery_codes().map(RecoveryCodes::used_one) else {
        panic!("Pat was shown recovery codes and spent one");
    };
    let code = SessionCode {
        session_id: waiting.session_id,
        code: used,
    };
    factors::redeem_recovery_code(pat.tenant(), &code)
        .send(&device)
        .await
}

/// Tess ends the session Pat opened with the recovery code; Pat's client
/// is signed out from then on.
async fn session_ended_by_tess(
    world: &World<'_>,
    pat: &mut Person,
    witness: &mut Witness<'_>,
    ended: &[&Client],
) {
    let mut exchanges = Vec::new();
    let listing = sessions::user_sessions(world.tenant(), pat.id());
    let listed = as_tess(world, listing, &mut exchanges).await.ok();
    assert!(
        listed.iter().any(|session| session.id == pat.session_id()),
        "Tess sees the session she ends"
    );
    let ending = sessions::end_user_session(world.tenant(), pat.id(), pat.session_id());
    as_tess(world, ending, &mut exchanges).await.ok();
    let revoked = witness.recorded("authentication.session_revoked").await;

    exchanges.extend(record_read_by_the_cast(world, pat, PatsClient::SignedOut, ended).await);
    let mut all_ended = ended.to_vec();
    all_ended.push(pat.client());
    let call = sessions::my_sessions(world.tenant()).call();
    let matrix = all_ended.iter().fold(
        Matrix::new("listing Pat's sessions that ended", call),
        |matrix, client| matrix.refused(client, Status::UNAUTHORIZED, "unauthenticated"),
    );
    exchanges.extend(matrix.run().await);
    nothing_leaked(&exchanges, &[&revoked], &secrets_in_play(world, pat));
}

/// Pat, phone found, resets the forgotten password by mail: without a code
/// from the phone the reset is refused, a breached password is refused,
/// and a good one is set. The old password no longer signs in; the new
/// one does, with a code.
async fn password_reset_by_mail(
    world: &World<'_>,
    pat: &mut Person,
    witness: &mut Witness<'_>,
    ended: &[&Client],
) {
    let stack = world.stack();
    let old_password = pat.password().to_owned();
    let token = pat.reset_link(stack).await;
    let requested = witness
        .recorded("authentication.password_reset_requested")
        .await;
    refuse_invalid_resets(pat, witness, &token).await;
    pat.confirm_reset(&token, NEW_PASSWORD).await.ok();
    let completed = witness
        .recorded("authentication.password_reset_completed")
        .await;
    assert_replacement_password(world, pat, old_password).await;
    let mut exchanges = pat.take_exchanges();
    exchanges.extend(own_sessions_by_the_cast(world, pat.client(), ended).await);
    exchanges.extend(record_read_by_the_cast(world, pat, PatsClient::SignedIn, ended).await);
    nothing_leaked(
        &exchanges,
        &[&requested, &completed],
        &secrets_in_play(world, pat),
    );
}

/// The reset invalidates the old password while the new password still requires MFA.
async fn assert_replacement_password(world: &World<'_>, pat: &mut Person, old_password: String) {
    let old = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: old_password,
        fingerprint_hash: None,
    };
    pat.send(sessions::sign_in(pat.tenant(), &old))
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        pat.sign_in(world.stack()).await,
        SignedInWith::PasswordAndCode,
        "the new password signs in, with a code from the phone"
    );
}

/// Missing factor proof and a breached password leave the mailed reset unfinished.
async fn refuse_invalid_resets(pat: &mut Person, witness: &Witness<'_>, token: &str) {
    let without_code = ConfirmPasswordReset {
        token: token.to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    pat.send(sessions::confirm_password_reset(
        pat.tenant(),
        &without_code,
    ))
    .await
    .refused(Status::FORBIDDEN, "step_up_required");
    pat.confirm_reset(token, BREACHED_PASSWORDS[1])
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    witness
        .nothing_new("authentication.password_reset_completed")
        .await;
}
