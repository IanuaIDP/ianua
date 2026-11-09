use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// A permission written out as a token carries it.
    ///
    /// `idp:users:view` is a platform permission, and `invoices:approve` is
    /// one a tenant made.
    pub struct PermissionName;
}

impl TextValue for PermissionName {
    const FIELD: &'static str = "permission";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=200,
            Charset::LOWERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::COLON
                | Charset::ASTERISK,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `idp:users:view` and `invoices:approve` are both accepted.
    #[test]
    fn a_well_formed_permission_name_is_accepted() {
        for value in ["idp:users:view", "invoices:approve"] {
            assert!(PermissionName::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty name, `Idp:users` with a capital, and `idp users` with a
    /// space are all refused.
    #[test]
    fn a_malformed_permission_name_is_refused() {
        for value in ["", "Idp:users", "idp users"] {
            assert!(
                PermissionName::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }
}
