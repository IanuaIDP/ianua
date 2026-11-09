//! The words the kinds of payment event are stored as.

use ianua_app::ports::organization::PaymentStream;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    PaymentStream as "payment event kind" {
        Method => "method",
        Payment => "payment",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Each kind reads back from the word it is stored as.
    #[test]
    fn every_kind_reads_back_from_its_word() {
        for stream in [PaymentStream::Method, PaymentStream::Payment] {
            assert_eq!(PaymentStream::from_word(stream.word()), Some(stream));
        }
    }
}
