//! Only the step-up policy says a sign-in reached its tenant's baseline.

use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authentication::risk_engine::step_up::BaselineMet;

fn main() {
    let _met = BaselineMet {
        level: AssuranceLevel::Aal2,
    };
}
