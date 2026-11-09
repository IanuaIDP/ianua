//! The words a route's status is stored as, and whether workflows may
//! reach a route or a stream route. Services and stream routes share the
//! status, and store it the same way.

use ianua_domain::domains::routing::route::WorkflowUse;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::stream::StreamWorkflowUse;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    RouteStatus as "route status" {
        Active => "active",
        Disabled => "disabled",
    }
}

stored_words! {
    WorkflowUse as "workflow use" {
        Closed => "closed",
        Open => "open",
    }
}

stored_words! {
    StreamWorkflowUse as "stream workflow use" {
        Closed => "closed",
        Open => "open",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::routing::RouteSortField;
    use ianua_domain::domains::routing::route::{Route, RouteRow};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::ServiceId;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::routing::route_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [RouteStatus::Active, RouteStatus::Disabled] {
            let route: Route<ResolvedTenant> = Route::reconstitute(RouteRow {
                status,
                ..route_row(ServiceId::new(), "projects")
            })
            .unwrap();

            assert_eq!(
                route.sort_key(RouteSortField::Status),
                SortKey::from(status.word())
            );
            assert_eq!(RouteStatus::from_word(status.word()), Some(status));
        }
    }
}
