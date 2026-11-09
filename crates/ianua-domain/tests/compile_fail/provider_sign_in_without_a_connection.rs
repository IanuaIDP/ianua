//! A provider's second factor counts only after the connection's trust
//! setting has weighed it.

use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::sign_in_progress::{
    FederatedMethod, ProviderSignIn,
};

fn main() {
    let _vouched = ProviderSignIn::new(FederatedMethod::Oidc, FactorProved::NoneYet);
}
