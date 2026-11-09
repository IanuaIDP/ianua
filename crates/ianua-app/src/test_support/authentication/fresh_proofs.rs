//! A fake for proving who you are again: the account's password is the one
//! a test types, and the domain checks it as it does for the real step.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificate;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{
    FreshSignIn, PasswordCheck, WithFactor,
};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::fakes::FakeHasher;
use ianua_domain::types::{CertificateFingerprint, PrincipalId};

use crate::context::DirectoryBound;
use crate::error::AppError;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::{CertificateStanding, ldap_certificate_with_id};

/// The password every account a [`FakeFreshProofs`] checks holds.
pub const REENTERED_PASSWORD: &str = "correct horse battery staple";

/// Proves the holder of any account, tenant user or organization member,
/// that types [`REENTERED_PASSWORD`] again, through the domain's own
/// password check. A tenant user may also type it over a directory bind,
/// which the domain checks as it does for the real step: the bind must be
/// theirs and still fresh, over the certificate it was made with, here
/// taken to be in force. A member is never proved over a bind. Any other
/// password, or another kind of proof, is refused.
pub struct FakeFreshProofs;

#[async_trait]
impl FreshProofs for FakeFreshProofs {
    async fn prove(
        &self,
        _: &ScopedTenant,
        account: &User<ResolvedTenant>,
        proof: ReenteredProof,
        _from: AttemptOrigin,
    ) -> Result<FreshSignIn, AppError> {
        match proof {
            ReenteredProof::Password { password, .. } => typed_again(&password, |check| {
                FreshSignIn::by_password(
                    PrincipalId::from(*account.id()),
                    check,
                    WithFactor::NoneOnFile,
                )
            }),
            ReenteredProof::OverDirectoryBind { password, bound } => {
                let certificate = in_force_for(&bound);
                typed_again(&password, |check| {
                    bound.bind().fresh_sign_in(account, &certificate, check)
                })
            }
            ReenteredProof::Mailbox { .. } | ReenteredProof::Passkey(_) => Err(password_only()),
        }
    }

    async fn prove_member(
        &self,
        member: &OrgUser,
        _: &Organization,
        proof: ReenteredProof,
        _from: AttemptOrigin,
    ) -> Result<FreshSignIn, AppError> {
        let ReenteredProof::Password { password, .. } = proof else {
            return Err(password_only());
        };
        typed_again(&password, |check| {
            FreshSignIn::by_password(
                PrincipalId::from(*member.id()),
                check,
                WithFactor::NoneOnFile,
            )
        })
    }
}

fn password_only() -> AppError {
    AppError::Forbidden("the test proves people by password only".to_owned().into())
}

/// The record of the certificate `bound` was made over, in force for the
/// person who bound.
fn in_force_for(bound: &DirectoryBound) -> LdapClientCertificate<ResolvedTenant> {
    ldap_certificate_with_id(
        *bound.certificate(),
        *bound.bind().account(),
        CertificateFingerprint::from_digest([7; 32]),
        CertificateStanding::InForce,
    )
}

/// The fresh proof `prove` makes of `password` typed again, checked against
/// [`REENTERED_PASSWORD`].
fn typed_again(
    password: &Secret,
    prove: impl FnOnce(PasswordCheck<'_, FakeHasher>) -> Result<FreshSignIn, DomainError>,
) -> Result<FreshSignIn, AppError> {
    let stored = FakeHasher
        .hash(REENTERED_PASSWORD)
        .map_err(AppError::from_domain)?;
    let mut tracker = LoginAttemptTracker::new();
    let check = PasswordCheck {
        raw: password.expose(),
        stored: &stored,
        hasher: &FakeHasher,
        tracker: &mut tracker,
    };
    prove(check).map_err(AppError::from_domain)
}

impl Fake for Arc<dyn FreshProofs> {
    fn fake() -> Self {
        Arc::new(FakeFreshProofs)
    }
}

/// The right password typed again, which [`FakeFreshProofs`] accepts.
#[must_use]
pub fn right_password() -> ReenteredProof {
    typed(REENTERED_PASSWORD)
}

/// A wrong password typed again, which [`FakeFreshProofs`] refuses.
#[must_use]
pub fn wrong_password() -> ReenteredProof {
    typed("not the password")
}

fn typed(password: &str) -> ReenteredProof {
    ReenteredProof::Password {
        password: Secret::new(password),
        code: None,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OrganizationId, UserId};

    use super::*;
    use crate::test_support::authentication::directory_bound;
    use crate::test_support::identity::stored_user;
    use crate::test_support::organization::{test_org, test_org_user};
    use crate::test_support::{block_on, test_ctx};

    fn person(address: &str) -> User<ResolvedTenant> {
        stored_user(UserId::new(), address, UserStatus::Active)
    }

    fn unobserved() -> AttemptOrigin {
        AttemptOrigin::of(ianua_domain::types::Fact::Unknown)
    }

    fn over(bound: DirectoryBound) -> ReenteredProof {
        ReenteredProof::OverDirectoryBind {
            password: Secret::new(REENTERED_PASSWORD),
            bound,
        }
    }

    /// Ann types her password again over the connection she bound. She is
    /// proved fresh.
    #[test]
    fn the_bound_person_is_proved_over_their_own_bind() {
        let ann = person("ann@acme.test");
        let proof = over(directory_bound(&ann));

        let fresh =
            block_on(FakeFreshProofs.prove(&test_ctx().tenant(), &ann, proof, unobserved()))
                .unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(*ann.id()));
    }

    /// Ann's directory bind is refused as fresh proof of Bob's account.
    #[test]
    fn a_bind_proves_nobody_but_the_person_who_bound() {
        let ann = person("ann@acme.test");
        let bob = person("bob@acme.test");
        let proof = over(directory_bound(&ann));

        let result =
            block_on(FakeFreshProofs.prove(&test_ctx().tenant(), &bob, proof, unobserved()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A tenant directory bind is refused as fresh proof of an organization member.
    #[test]
    fn a_member_is_never_proved_over_a_bind() {
        let organization = test_org(OrganizationId::new(), "acme-corp");
        let member = test_org_user(*organization.id(), "sam@acme.com", OrgRole::Owner);
        let proof = over(directory_bound(&person("ann@acme.test")));

        let result =
            block_on(FakeFreshProofs.prove_member(&member, &organization, proof, unobserved()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
