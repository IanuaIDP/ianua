/// Login risk scoring from geolocation and impossible travel, with a risk
/// level and an action.
pub mod assessment;
/// NIST 800-63 assurance levels and the strongest factor a session used.
pub mod assurance;
/// Whether an account is under attack from many networks, and what a
/// password sign-in to it must prove while it is.
pub mod attack;
/// What a password sign-in must show while sign-in is under high pressure.
pub mod challenge;
pub mod history;
/// Where a sign-in attempt came from, as its failures are counted.
pub mod origin;
/// How long a sign-in to an account waits, from its failures across every
/// origin.
pub mod pace;
/// How hard a tenant's or organization's password sign-in is being pushed.
pub mod pressure;
pub mod rate_limit;
/// Step-up policies. They decide when a sign-in or action must ask for a
/// second factor.
pub mod step_up;
