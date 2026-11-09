//! Misuse the domain's types make impossible, shown by code that must not
//! compile.
//!
//! Each file under `compile_fail/` tries one thing a caller outside the
//! domain must never be able to do, such as making a proof without the check
//! behind it or printing a secret. The expected compiler error sits next to
//! it in a `.stderr` file. If a change makes one of them compile, the rule it
//! guarded has a way around it, and this test fails.
//!
//! After an intended change to an error message, regenerate the expected
//! output with `TRYBUILD=overwrite` and read every changed `.stderr` before
//! keeping it.

#[test]
fn misuse_does_not_compile() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/*.rs");
}
