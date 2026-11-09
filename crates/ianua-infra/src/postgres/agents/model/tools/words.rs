//! The words a tool's choices are stored as.

use ianua_domain::domains::agents::execution::tool::{ToolMethod, ToolStatus};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ToolMethod as "tool method" {
        Get => "get",
        Post => "post",
        Put => "put",
        Patch => "patch",
        Delete => "delete",
    }
}

stored_words! {
    ToolStatus as "tool status" {
        Active => "active",
        Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every method reads back from its word, so a tool never calls with
    /// another verb than it was registered with.
    #[test]
    fn every_method_reads_back_from_its_word() {
        for method in [
            ToolMethod::Get,
            ToolMethod::Post,
            ToolMethod::Put,
            ToolMethod::Patch,
            ToolMethod::Delete,
        ] {
            assert_eq!(ToolMethod::from_word(method.word()), Some(method));
        }
    }

    /// Every status reads back from its word, so a disabled tool is never
    /// read as one a run may call.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [ToolStatus::Active, ToolStatus::Disabled] {
            assert_eq!(ToolStatus::from_word(status.word()), Some(status));
        }
    }
}
