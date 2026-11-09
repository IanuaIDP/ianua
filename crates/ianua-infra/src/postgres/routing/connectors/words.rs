//! The words a connector's status is stored as.

use ianua_domain::domains::routing::connector::ConnectorStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ConnectorStatus as "connector status" {
        Active => "active",
        Revoked => "revoked",
    }
}
