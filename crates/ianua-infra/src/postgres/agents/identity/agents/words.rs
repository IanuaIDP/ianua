//! The words an agent's choices are stored as.

use ianua_domain::domains::agents::identity::status::AgentStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AgentStatus as "agent status" {
        Active => "active",
        Suspended => "suspended",
        Revoked => "revoked",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::agents::AgentSortField;
    use ianua_domain::domains::agents::identity::agent::{AgentIdentity, AgentIdentityRow};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::agents::agent_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [
            AgentStatus::Active,
            AgentStatus::Suspended,
            AgentStatus::Revoked,
        ] {
            let agent: AgentIdentity<ResolvedTenant> =
                AgentIdentity::reconstitute(AgentIdentityRow {
                    status,
                    ..agent_row("nightly-report")
                })
                .unwrap();

            assert_eq!(
                agent.sort_key(AgentSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(AgentStatus::from_word(status.word()), Some(status));
        }
    }
}
