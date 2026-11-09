//! The stronger assurances a tenant may require, two factors or a
//! hardware-backed key, against every nonempty subset of the ways in and
//! each second-factor policy: Ann's settings are saved only where some way
//! in can reach the assurance, and a refused save leaves the settings as
//! they were. An empty set of ways in, and an empty or doubled factor
//! offer, are refused under every policy.

use ianua_scenarios::api::tenants;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::tenants::{
    MfaPolicy, PasswordAgain, ReplaceSignInSettings, SignInSettings,
};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde_json::json;

use super::support::{Admission, Registration, SUBSETS, as_json};

/// Every second-factor policy.
const MFA_POLICIES: [MfaPolicy; 3] = [
    MfaPolicy::Disabled,
    MfaPolicy::Optional,
    MfaPolicy::Required,
];

/// Every assurance a tenant may require, as the API spells it.
const ASSURANCES: [&str; 3] = ["Aal1", "Aal2", "Aal3"];

/// The assurances stronger than the ordinary one.
#[derive(Clone, Copy, Debug)]
enum Baseline {
    /// Two factors.
    TwoFactors,
    /// A hardware-backed key.
    Hardware,
}

impl Baseline {
    /// The assurance as the API spells it.
    fn wire(self) -> &'static str {
        match self {
            Self::TwoFactors => "Aal2",
            Self::Hardware => "Aal3",
        }
    }

    /// Whether some way in `case` offers reaches this assurance: a second
    /// factor makes two, when the policy allows one; a passkey, SAML or
    /// OIDC reaches either on its own.
    fn reachable(self, case: &Admission) -> bool {
        match self {
            Self::TwoFactors => case.mfa != MfaPolicy::Disabled || case.offers_a_strong_method(),
            Self::Hardware => case.offers_a_strong_method(),
        }
    }
}

/// Ann saves each of the 31 subsets of the ways in at `baseline`, with
/// `mfa`: where some way in reaches the assurance the settings are saved
/// as sent, and where none does the save is refused, naming the
/// assurance, and the settings stay as they were.
async fn every_subset_at(mfa: MfaPolicy, baseline: Baseline) {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let original = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();

    for mask in SUBSETS {
        let case = Admission {
            mask,
            registration: Registration::Open,
            mfa,
        };
        assert_assurance_case(&world, &original, &case, baseline).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// One method subset either reaches the requested assurance or leaves its saved policy intact.
async fn assert_assurance_case(
    world: &World<'_>,
    original: &SignInSettings,
    case: &Admission,
    baseline: Baseline,
) {
    let before = read_saved_settings(world).await;
    let mut settings = case.settings(original.clone());
    settings.rest["step_up"]["baseline_aal"] = json!(baseline.wire());
    settings.rest["step_up"]["sensitive_aal"] = json!(baseline.wire());
    let answer = attempt_save(world, settings.clone()).await;
    let expected = if baseline.reachable(case) {
        answer.ok();
        settings
    } else {
        let problem = answer.refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
        assert!(
            problem.message().contains("assurance"),
            "{} at {baseline:?}: the refusal names the assurance: {}",
            case.name(),
            problem.message()
        );
        before
    };
    let after = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        as_json(&after),
        as_json(&expected),
        "{} at {baseline:?}: the settings are as sent when reachable, else as before",
        case.name()
    );
}

/// Ann reads the complete stored policy so refused changes can be compared without omitting fields.
async fn read_saved_settings(world: &World<'_>) -> SignInSettings {
    tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok()
}

/// Ann submits the candidate policy with her password proof, leaving the caller to check its result.
async fn attempt_save(world: &World<'_>, settings: SignInSettings) -> Answer<()> {
    tenants::replace_sign_in_settings(
        world.tenant(),
        &ReplaceSignInSettings {
            settings,
            proof: PasswordAgain {
                password: world.owner().password().to_owned(),
                code: None,
            },
        },
    )
    .send(world.owner().client())
    .await
}

/// With MFA disabled, two-factor assurance is refused unless an offered
/// method reaches it. Every refused subset leaves the
/// settings as they were.
#[tokio::test]
async fn two_factor_assurance_with_mfa_off_is_saved_only_where_a_method_reaches_it() {
    every_subset_at(MfaPolicy::Disabled, Baseline::TwoFactors).await;
}

/// With an optional second factor every subset reaches two factors, a
/// password's sign-in owing one, so every subset is saved.
#[tokio::test]
async fn two_factor_assurance_with_mfa_optional_is_saved_for_every_subset() {
    every_subset_at(MfaPolicy::Optional, Baseline::TwoFactors).await;
}

/// With a required second factor every subset reaches two factors, so
/// every subset is saved and Ann reads it back as sent.
#[tokio::test]
async fn two_factor_assurance_with_mfa_required_is_saved_for_every_subset() {
    every_subset_at(MfaPolicy::Required, Baseline::TwoFactors).await;
}

/// With MFA disabled, hardware assurance requires a passkey, SAML or OIDC
/// among the offered methods. Other subsets leave the settings unchanged.
#[tokio::test]
async fn hardware_assurance_with_mfa_off_needs_a_passkey_or_federated_method() {
    every_subset_at(MfaPolicy::Disabled, Baseline::Hardware).await;
}

/// Optional MFA does not make password or mailed-link methods satisfy
/// hardware assurance. Only subsets with a passkey, SAML or OIDC are saved.
#[tokio::test]
async fn hardware_assurance_with_mfa_optional_needs_a_passkey_or_federated_method() {
    every_subset_at(MfaPolicy::Optional, Baseline::Hardware).await;
}

/// Required MFA does not make password or mailed-link methods satisfy
/// hardware assurance. Refused subsets leave the settings unchanged.
#[tokio::test]
async fn hardware_assurance_with_mfa_required_needs_a_passkey_or_federated_method() {
    every_subset_at(MfaPolicy::Required, Baseline::Hardware).await;
}

/// An empty method set is refused under all nine combinations of MFA
/// policy and assurance, leaving the stored settings unchanged.
#[tokio::test]
async fn no_mfa_or_assurance_policy_can_save_an_empty_method_set() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let original = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();

    for mfa in MFA_POLICIES {
        for assurance in ASSURANCES {
            let mut settings = original.clone();
            settings.enabled_methods.clear();
            settings.mfa_policy = mfa;
            settings.rest["step_up"]["baseline_aal"] = json!(assurance);
            settings.rest["step_up"]["sensitive_aal"] = json!(assurance);
            attempt_save(&world, settings)
                .await
                .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
            let after = tenants::sign_in_settings(world.tenant())
                .send(world.owner().client())
                .await
                .ok();
            assert_eq!(
                as_json(&after),
                as_json(&original),
                "{mfa:?} at {assurance}: no way in at all leaves the settings as they were"
            );
        }
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Empty or duplicate factor offers are refused under every MFA policy.
/// Each of the six refusals leaves the stored settings unchanged.
#[tokio::test]
async fn every_mfa_policy_refuses_empty_or_duplicate_factor_offers() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let original = read_saved_settings(&world).await;

    for mfa in MFA_POLICIES {
        for (what, factors) in [
            ("no factor to offer", json!([])),
            ("the same factor twice", json!(["Totp", "Totp"])),
        ] {
            let mut settings = original.clone();
            settings.mfa_policy = mfa;
            settings.rest.insert("second_factors".to_owned(), factors);
            attempt_save(&world, settings)
                .await
                .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
            let after = tenants::sign_in_settings(world.tenant())
                .send(world.owner().client())
                .await
                .ok();
            assert_eq!(
                as_json(&after),
                as_json(&original),
                "{mfa:?} with {what}: the settings are left as they were"
            );
        }
    }

    stack.stop().await.expect("the stack stops cleanly");
}
