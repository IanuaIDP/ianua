use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    redacted
    /// The short code a person types on a second screen to approve a device
    /// sign-in, such as `ABCD-1234`. RFC 8628 calls it the `user_code`.
    ///
    /// While the sign-in waits, whoever holds the code can approve it with
    /// their own account. So it never prints in a log, an error or a debug
    /// dump. The page that shows it reads it with `as_str`.
    pub struct DeviceUserCode;
}

impl TextValue for DeviceUserCode {
    const FIELD: &'static str = "user_code";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.device_user_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A code in the generated shape, `ABCD-1234`, is accepted as written.
    #[test]
    fn accepts_the_generated_shape() {
        assert_eq!(
            DeviceUserCode::new("ABCD-1234").unwrap().as_str(),
            "ABCD-1234"
        );
    }

    /// `abcd-1234` in lower case and `ABCD 1234` with a space are both
    /// refused.
    #[test]
    fn rejects_lowercase_and_spaces() {
        assert!(DeviceUserCode::new("abcd-1234").is_err());
        assert!(DeviceUserCode::new("ABCD 1234").is_err());
    }

    /// Debug formatting omits the device code's identifying text so diagnostic
    /// output does not disclose the approval credential.
    #[test]
    fn a_device_code_never_prints() {
        let code = DeviceUserCode::new("ABCD-1234").unwrap();

        assert!(!format!("{code:?}").contains("ABCD"));
    }

    /// An empty code and a 21-character code are both refused.
    #[test]
    fn rejects_empty_and_overlong_codes() {
        assert!(DeviceUserCode::new("").is_err());
        assert!(DeviceUserCode::new("A".repeat(21)).is_err());
    }
}
