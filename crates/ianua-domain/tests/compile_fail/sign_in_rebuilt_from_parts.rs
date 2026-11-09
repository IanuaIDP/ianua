//! A finished sign-in is reached by proving factors, never written down by a
//! caller: progress is rebuilt only by the session that stored it.

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::authentication::sessions::sign_in_progress::{
    SignInProgress, SignInProgressRow,
};

fn main() {
    let _forged = SignInProgress::reconstitute(SignInProgressRow {
        method: AuthMethod::Password,
        factor: FactorProved::Proved(MfaFactor::HardwareKey),
        owed: SecondFactor::NotOwed,
    });
}
