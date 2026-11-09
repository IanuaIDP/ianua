use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The public identifier of an OAuth client, as it appears in an
    /// authorization request and the `aud` of an ID token.
    pub struct ClientId;
}

impl TextValue for ClientId {
    const FIELD: &'static str = "client_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=255)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A short name like `client_1` and a UUID-style id are both accepted.
    #[test]
    fn a_well_formed_client_id_is_accepted() {
        for value in ["client_1", "3fa85f64-5717-4562-b3fc-2c963f66afa6"] {
            assert!(ClientId::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty id, one with a space and one ending in a line break are all
    /// refused.
    #[test]
    fn a_malformed_client_id_is_refused() {
        for value in ["", "client 1", "client\r\n"] {
            assert!(ClientId::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
