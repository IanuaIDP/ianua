//! The words a DNS record's choices are stored as.

use ianua_domain::domains::tenant::custom_domains::dns_zone::RecordKind;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    RecordKind as "DNS record type" {
        A => "A",
        Aaaa => "AAAA",
        Cname => "CNAME",
        Txt => "TXT",
        Mx => "MX",
        Srv => "SRV",
        Caa => "CAA",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every record type reads back from the word it is written as, and
    /// that word is the type's name in a zone file.
    #[test]
    fn every_record_type_reads_back_from_its_word() {
        for kind in RecordKind::ALL {
            assert_eq!(RecordKind::from_word(kind.word()), Some(kind));
            assert_eq!(kind.word(), kind.as_str());
        }
    }
}
