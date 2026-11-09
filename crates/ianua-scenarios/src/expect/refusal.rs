//! What an attacker's request must get back when its exact refusal is the
//! platform's own business: a refusal, said properly.

use crate::wire::Answer;

/// Asserts `answer` is a refusal of the caller's request: a 4xx status
/// with the platform's problem body, never a success, never a 5xx, never
/// a bare text page. `what` names the attempt in the failure.
///
/// # Panics
///
/// When `answer` is anything else, with its summary.
pub fn assert_clean_refusal<T>(what: &str, answer: &Answer<T>) {
    let status = answer.status();
    assert!(
        status.is_client_error(),
        "{what}: expected a refusal, got {}",
        answer.summary()
    );
    assert!(
        answer.problem().is_some(),
        "{what}: the refusal has no problem body: {}",
        answer.summary()
    );
}
