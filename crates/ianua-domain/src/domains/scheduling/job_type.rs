//! The name that tells a worker which handler runs a job.

use crate::message;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// The kind of a job, which picks the handler that runs it.
    ///
    /// Two or more names joined by dots, such as `domain.verify_retry`.
    /// Names use lowercase letters, digits and underscores. The whole is at
    /// most 128 characters.
    pub struct JobType;
}

impl TextValue for JobType {
    const FIELD: &'static str = "job_type";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .identifier(
                1..=128,
                Charset::LOWERCASE | Charset::DIGIT | Charset::UNDERSCORE | Charset::DOT,
            )
            .rule(&DotSeparated)
    }
}

/// Two or more names joined by dots, such as `domain.verify_retry`.
struct DotSeparated;

impl Rule for DotSeparated {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let parts = value.split('.');
        if value.contains('.') && parts.clone().all(|part| !part.is_empty()) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_job_type".to_owned(),
            message: message!(
                "scheduling-job-type-must-be-dot-separated",
                "job type must be dot-separated (e.g. domain.verify_retry)"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `domain.verify_retry` is accepted and kept exactly as written.
    #[test]
    fn valid_dot_separated_job_type() {
        let jt = JobType::new("domain.verify_retry").unwrap();
        assert_eq!(jt.as_str(), "domain.verify_retry");
    }

    /// A name with three parts, `email.verification.send`, is accepted too.
    #[test]
    fn multi_segment_job_type() {
        let jt = JobType::new("email.verification.send").unwrap();
        assert_eq!(jt.as_str(), "email.verification.send");
    }

    /// An empty job type is refused, since it would pick no handler.
    #[test]
    fn rejects_empty_string() {
        let result = JobType::new("");
        assert!(result.is_err());
    }

    /// A single name with no dot, `nodots`, is refused. A job type needs at
    /// least two parts.
    #[test]
    fn rejects_no_dot_separator() {
        let result = JobType::new("nodots");
        assert!(result.is_err());
    }

    /// A job of type `domain.verify_retry` prints as that same name. The
    /// queue row and the log line an operator reads on failure both show it.
    #[test]
    fn a_job_type_displays_as_the_name_it_holds() {
        let job_type = JobType::new("domain.verify_retry").unwrap();

        assert_eq!(job_type.to_string(), "domain.verify_retry");
        assert_eq!(job_type.to_string(), job_type.as_str());
    }
}
