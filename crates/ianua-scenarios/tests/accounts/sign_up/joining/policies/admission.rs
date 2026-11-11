//! The admission matrix behind the public form: every nonempty subset of
//! the five ways in, open and closed to the public, under each
//! second-factor policy, with a mail server and without. With mail, Pat's
//! form is taken exactly when the tenant is open and a password is a way
//! in, and Pat then proves the mailbox and signs in as the policy asks.
//! Without mail, no point of the matrix takes a public form, and the
//! mailed link cannot even be offered.

use std::ops::Range;
use std::time::Duration;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Person};
use ianua_scenarios::api::{audit, people, registration, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::registration::TenantSignup;
use ianua_scenarios::wire::tenants::{
    MfaPolicy, PasswordAgain, ReplaceSignInSettings, SignInSettings,
};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use super::super::offline::{Offline, installed_without_mail};
use super::super::support::{form, mailed_proof, tenant_records};
use super::support::{Admission, as_json, saved, signed_in_under};
use crate::support::{QUIET, past_lifetime};

/// How many points of a slice of eight subsets admit a public form: the
/// four odd masks offer a password, and only those, when open, take one.
const ADMITTED_IN_A_SLICE: usize = 4;

/// How long each refused address's mailbox is looked at, once the quiet
/// time has passed for all of them at once.
const A_MOMENT: Duration = Duration::from_millis(1);

/// The password Pat types into the public form without mail: a sentence,
/// so no scanner takes it for a key.
const PATS_PASSWORD: &str = "Quiet orchard lantern meadow 8492";

/// Evidence collected across the mailed admission cases for the final audit and mailbox checks.
#[derive(Default)]
struct MailCases {
    /// Addresses whose refused forms must receive no mail.
    refused: Vec<String>,
    /// Passwords and verification tokens that audit records must not reveal.
    secrets: Vec<String>,
}

/// With mail and `mfa`, each subset in `masks`, closed and open to the
/// public, is saved in turn, and Pat registers at each point under an
/// address of its own. The form says whether it is open; where it is, Pat
/// proves the mailbox and signs in as the policy asks; where not, the
/// form is refused and no account is made. Four accounts are registered
/// and proved, with no secret recorded, and no refused address is mailed.
async fn with_mail(mfa: MfaPolicy, masks: Range<u8>) {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let original = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();

    let mut outcomes = MailCases::default();
    for case in Admission::cases(mfa)
        .into_iter()
        .filter(|case| masks.contains(&case.mask))
    {
        exercise_mail_case(&world, &case, &original, &mut outcomes).await;
    }
    assert_admitted_records(&world, &outcomes.secrets).await;
    past_lifetime(QUIET).await;
    for address in outcomes.refused {
        stack.mailbox().nothing_for(&address, A_MOMENT).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// One mailed policy case either admits and verifies Pat or leaves no account behind.
async fn exercise_mail_case(
    world: &World<'_>,
    case: &Admission,
    original: &SignInSettings,
    outcomes: &mut MailCases,
) {
    saved(world, case.settings(original.clone())).await;
    let mut pat = world.newcomer(&case.name(), "Pat Newcomer");
    outcomes.secrets.push(pat.password().to_owned());
    assert_advertised_rules(world, &pat, case).await;
    if case.advertised() {
        let proof = mailed_proof(world, &mut pat).await;
        outcomes.secrets.push(proof.token.clone());
        registration::verify(world.tenant(), &proof)
            .send(pat.client())
            .await
            .ok();
        signed_in_under(world, &pat, case.mfa).await;
        return;
    }
    assert_refused_signup(world, &pat, case).await;
    outcomes.refused.push(pat.email().to_owned());
}

/// The public rules advertise password registration exactly when the saved policy admits it.
async fn assert_advertised_rules(world: &World<'_>, pat: &Person, case: &Admission) {
    let rules = registration::rules(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        rules.open,
        case.advertised(),
        "{}: the form says whether it is open",
        case.name()
    );
    assert_eq!(
        rules.password_policy.is_some(),
        case.advertised(),
        "{}: the form shows its password rules only when open",
        case.name()
    );
}

/// A closed policy refuses Pat's form and leaves the administrative listing empty.
async fn assert_refused_signup(world: &World<'_>, pat: &Person, case: &Admission) {
    registration::sign_up(world.tenant(), &form(pat))
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let listed = people::list(world.tenant(), Some(pat.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        listed.items.is_empty(),
        "{}: a refused form makes no account",
        case.name()
    );
}

/// Each admitted case contributes one registration and one verification without exposing secrets.
async fn assert_admitted_records(world: &World<'_>, secrets: &[String]) {
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    assert_eq!(
        tenant_records(world, "identity.user_registered", &secrets).await,
        ADMITTED_IN_A_SLICE,
        "one registration for each point that admits one"
    );
    assert_eq!(
        tenant_records(world, "identity.email_verified", &secrets).await,
        ADMITTED_IN_A_SLICE,
        "one mailbox proof for each"
    );
}

/// Without mail and with `mfa`, Ann saves each point whose subset is in
/// `masks`, closed and open to the public, in turn, with her
/// authenticator: a subset offering the mailed link is refused
/// for want of a mail server and leaves the settings as they were. At
/// every point Pat's form is refused, since no mailbox can be proved, and
/// no account is made; no registration is recorded and no address is
/// mailed.
async fn without_mail(mfa: MfaPolicy, masks: Range<u8>) {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let mut offline = installed_without_mail(&stack).await;
    let original = tenants::sign_in_settings(&offline.tenant)
        .send(offline.owner.client())
        .await
        .ok();

    let mut addresses = Vec::new();
    for case in Admission::cases(mfa)
        .into_iter()
        .filter(|case| masks.contains(&case.mask))
    {
        save_offline_case(&mut offline, &case, &original).await;
        addresses.push(assert_offline_signup(&stack, &offline, &case).await);
    }

    let registered = audit::tenant_log(&offline.tenant, "identity.user_registered")
        .send(offline.owner.client())
        .await
        .ok();
    assert!(
        registered.items.is_empty(),
        "no registration was recorded at any point"
    );
    past_lifetime(QUIET).await;
    for address in addresses {
        stack.mailbox().nothing_for(&address, A_MOMENT).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann can save only offline policies whose offered methods do not need mail.
async fn save_offline_case(offline: &mut Offline, case: &Admission, original: &SignInSettings) {
    let before = tenants::sign_in_settings(&offline.tenant)
        .send(offline.owner.client())
        .await
        .ok();
    let answer = tenants::replace_sign_in_settings(
        &offline.tenant,
        &ReplaceSignInSettings {
            settings: case.settings(original.clone()),
            proof: PasswordAgain {
                password: FOUNDER_PASSWORD.to_owned(),
                code: Some(offline.phone.code().await),
            },
        },
    )
    .send(offline.owner.client())
    .await;
    saved_unless_undeliverable(offline, case, answer, &before).await;
}

/// No offline policy creates Pat from the public form, even when registration is enabled.
async fn assert_offline_signup(stack: &Stack, offline: &Offline, case: &Admission) -> String {
    let pat = Client::new(stack, &case.name()).expect("a client");
    let form = TenantSignup {
        email: format!("{}@{}", case.name(), stack.base_domain()),
        display_name: "Pat Newcomer".to_owned(),
        password: PATS_PASSWORD.to_owned(),
    };
    registration::sign_up(&offline.tenant, &form)
        .send(&pat)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let listed = people::list(&offline.tenant, Some(&form.email))
        .send(offline.owner.client())
        .await
        .ok();
    assert!(
        listed.items.is_empty(),
        "{}: a refused form makes no account",
        case.name()
    );
    form.email
}

/// What the no-mail deployment `answer`ed Ann saving `case`'s settings: a
/// subset offering the mailed link is refused, naming the missing mail
/// server, and the settings stay as `before`; any other is saved.
async fn saved_unless_undeliverable(
    offline: &Offline,
    case: &Admission,
    answer: Answer<()>,
    before: &SignInSettings,
) {
    if !case.offers_magic_link() {
        answer.ok();
        return;
    }
    let problem = answer.refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert!(
        problem.message().contains("no mail server"),
        "{}: the mailed link cannot be offered without a mail server: {}",
        case.name(),
        problem.message()
    );
    let after = tenants::sign_in_settings(&offline.tenant)
        .send(offline.owner.client())
        .await
        .ok();
    assert_eq!(
        as_json(before),
        as_json(&after),
        "{}: a refused change leaves the settings as they were",
        case.name()
    );
}

/// With mail and no second factor, subsets one to seven: Pat is in at
/// each open point with a password, and refused at every other.
#[tokio::test]
async fn mfa_off_with_mail_admits_subsets_one_to_seven_as_the_policy_says() {
    with_mail(MfaPolicy::Disabled, 1..8).await;
}

/// With mail and an optional second factor, subsets one to seven: Pat,
/// who set none up, owes none.
#[tokio::test]
async fn mfa_optional_with_mail_admits_subsets_one_to_seven_as_the_policy_says() {
    with_mail(MfaPolicy::Optional, 1..8).await;
}

/// With mail and a required second factor, subsets one to seven: Pat
/// reads nothing until the authenticator is set up.
#[tokio::test]
async fn mfa_required_with_mail_admits_subsets_one_to_seven_as_the_policy_says() {
    with_mail(MfaPolicy::Required, 1..8).await;
}

/// With mail and no second factor, subsets eight to fifteen, which hold
/// SAML and not OIDC: Pat is in at each open point with a password.
#[tokio::test]
async fn mfa_off_with_mail_admits_subsets_eight_to_fifteen_as_the_policy_says() {
    with_mail(MfaPolicy::Disabled, 8..16).await;
}

/// With mail and an optional second factor, subsets eight to fifteen:
/// Pat, who set none up, owes none.
#[tokio::test]
async fn mfa_optional_with_mail_admits_subsets_eight_to_fifteen_as_the_policy_says() {
    with_mail(MfaPolicy::Optional, 8..16).await;
}

/// With mail and a required second factor, subsets eight to fifteen: Pat
/// reads nothing until the authenticator is set up.
#[tokio::test]
async fn mfa_required_with_mail_admits_subsets_eight_to_fifteen_as_the_policy_says() {
    with_mail(MfaPolicy::Required, 8..16).await;
}

/// With mail and no second factor, subsets sixteen to twenty-three, which
/// hold OIDC and not SAML: Pat is in at each open point with a password.
#[tokio::test]
async fn mfa_off_with_mail_admits_subsets_sixteen_to_twenty_three_as_the_policy_says() {
    with_mail(MfaPolicy::Disabled, 16..24).await;
}

/// With mail and an optional second factor, subsets sixteen to
/// twenty-three: Pat, who set none up, owes none.
#[tokio::test]
async fn mfa_optional_with_mail_admits_subsets_sixteen_to_twenty_three_as_the_policy_says() {
    with_mail(MfaPolicy::Optional, 16..24).await;
}

/// With mail and a required second factor, subsets sixteen to
/// twenty-three: Pat reads nothing until the authenticator is set up.
#[tokio::test]
async fn mfa_required_with_mail_admits_subsets_sixteen_to_twenty_three_as_the_policy_says() {
    with_mail(MfaPolicy::Required, 16..24).await;
}

/// With mail and no second factor, subsets twenty-four to thirty-one,
/// which hold both SAML and OIDC: Pat is in at each open point with a
/// password.
#[tokio::test]
async fn mfa_off_with_mail_admits_subsets_twenty_four_to_thirty_one_as_the_policy_says() {
    with_mail(MfaPolicy::Disabled, 24..32).await;
}

/// With mail and an optional second factor, subsets twenty-four to
/// thirty-one: Pat, who set none up, owes none.
#[tokio::test]
async fn mfa_optional_with_mail_admits_subsets_twenty_four_to_thirty_one_as_the_policy_says() {
    with_mail(MfaPolicy::Optional, 24..32).await;
}

/// With mail and a required second factor, subsets twenty-four to
/// thirty-one: Pat reads nothing until the authenticator is set up.
#[tokio::test]
async fn mfa_required_with_mail_admits_subsets_twenty_four_to_thirty_one_as_the_policy_says() {
    with_mail(MfaPolicy::Required, 24..32).await;
}

/// Without mail and with MFA disabled, subsets one to seven: no point
/// takes a public registration or leaves an account or record.
#[tokio::test]
async fn without_mail_no_point_with_mfa_off_takes_a_public_form_subsets_one_to_seven() {
    without_mail(MfaPolicy::Disabled, 1..8).await;
}

/// Without mail and with MFA disabled, subsets eight to fifteen.
#[tokio::test]
async fn without_mail_no_point_with_mfa_off_takes_a_public_form_subsets_eight_to_fifteen() {
    without_mail(MfaPolicy::Disabled, 8..16).await;
}

/// Without mail and with MFA disabled, subsets sixteen to twenty-three.
#[tokio::test]
async fn without_mail_no_point_with_mfa_off_takes_a_public_form_subsets_sixteen_to_twenty_three() {
    without_mail(MfaPolicy::Disabled, 16..24).await;
}

/// Without mail and with MFA disabled, subsets twenty-four to thirty-one.
#[tokio::test]
async fn without_mail_no_point_with_mfa_off_takes_a_public_form_subsets_twenty_four_to_thirty_one()
{
    without_mail(MfaPolicy::Disabled, 24..32).await;
}

/// Optional MFA cannot replace mailbox proof on a deployment without mail,
/// subsets one to seven: no point takes a registration or leaves a record.
#[tokio::test]
async fn without_mail_no_point_with_mfa_optional_takes_a_public_form_subsets_one_to_seven() {
    without_mail(MfaPolicy::Optional, 1..8).await;
}

/// Optional MFA without mail, subsets eight to fifteen.
#[tokio::test]
async fn without_mail_no_point_with_mfa_optional_takes_a_public_form_subsets_eight_to_fifteen() {
    without_mail(MfaPolicy::Optional, 8..16).await;
}

/// Optional MFA without mail, subsets sixteen to twenty-three.
#[tokio::test]
async fn without_mail_no_point_with_mfa_optional_takes_a_public_form_subsets_sixteen_to_twenty_three()
 {
    without_mail(MfaPolicy::Optional, 16..24).await;
}

/// Optional MFA without mail, subsets twenty-four to thirty-one.
#[tokio::test]
async fn without_mail_no_point_with_mfa_optional_takes_a_public_form_subsets_twenty_four_to_thirty_one()
 {
    without_mail(MfaPolicy::Optional, 24..32).await;
}

/// Required MFA cannot replace mailbox proof on a deployment without mail,
/// subsets one to seven: no point leaves a pending account.
#[tokio::test]
async fn without_mail_no_point_with_mfa_required_takes_a_public_form_subsets_one_to_seven() {
    without_mail(MfaPolicy::Required, 1..8).await;
}

/// Required MFA without mail, subsets eight to fifteen.
#[tokio::test]
async fn without_mail_no_point_with_mfa_required_takes_a_public_form_subsets_eight_to_fifteen() {
    without_mail(MfaPolicy::Required, 8..16).await;
}

/// Required MFA without mail, subsets sixteen to twenty-three.
#[tokio::test]
async fn without_mail_no_point_with_mfa_required_takes_a_public_form_subsets_sixteen_to_twenty_three()
 {
    without_mail(MfaPolicy::Required, 16..24).await;
}

/// Required MFA without mail, subsets twenty-four to thirty-one.
#[tokio::test]
async fn without_mail_no_point_with_mfa_required_takes_a_public_form_subsets_twenty_four_to_thirty_one()
 {
    without_mail(MfaPolicy::Required, 24..32).await;
}
