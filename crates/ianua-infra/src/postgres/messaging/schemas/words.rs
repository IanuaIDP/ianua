//! The words an event schema's choices are stored as.

use ianua_domain::domains::messaging::schema::{CompatibilityMode, SchemaFormat};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    SchemaFormat as "schema format" {
        JsonSchema => "json_schema",
        Avro => "avro",
        Protobuf => "protobuf",
    }
}

stored_words! {
    CompatibilityMode as "compatibility mode" {
        None => "none",
        Backward => "backward",
        Forward => "forward",
        Full => "full",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every format reads back from the word it is written as, so a schema
    /// is never parsed as a language it is not written in.
    #[test]
    fn every_format_reads_back_from_its_word() {
        for format in [
            SchemaFormat::JsonSchema,
            SchemaFormat::Avro,
            SchemaFormat::Protobuf,
        ] {
            assert_eq!(SchemaFormat::from_word(format.word()), Some(format));
        }
    }

    /// Every compatibility mode reads back from the word it is written as,
    /// so a schema held to a mode is never read as held to none.
    #[test]
    fn every_compatibility_mode_reads_back_from_its_word() {
        for mode in [
            CompatibilityMode::None,
            CompatibilityMode::Backward,
            CompatibilityMode::Forward,
            CompatibilityMode::Full,
        ] {
            assert_eq!(CompatibilityMode::from_word(mode.word()), Some(mode));
        }
    }
}
