/// What a test says someone holds.
pub mod authority;
/// Small value builders shared by tests.
pub mod builders;
/// Sample events for adapters' tests, and the events an aggregate raised.
pub mod events;
/// Test doubles for domain ports.
///
/// Available in unit tests and under the `test-support` feature. Other
/// crates, such as `ianua-app` and the integration tests, turn it on with:
///
/// ```toml
/// [dev-dependencies]
/// ianua-domain = { path = "../ianua-domain", features = ["test-support"] }
/// ```
pub mod fakes;
