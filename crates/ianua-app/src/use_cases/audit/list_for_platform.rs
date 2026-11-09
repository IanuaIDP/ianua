//! Reading the audit log across the whole platform, filtered and a page at
//! a time, for operators.

use std::sync::Arc;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::ports::audit::{AuditLogPage, PlatformAuditLogStore};
use crate::use_case::Query;
use crate::use_cases::audit::ListForOrgRequest;

/// The ports [`ListForPlatformUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListForPlatformPorts {
    /// Every audit record on the platform.
    pub audit_log: Arc<dyn PlatformAuditLogStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Lists audit records across every organization and tenant.
pub struct ListForPlatformUseCase {
    ports: ListForPlatformPorts,
}

impl ListForPlatformUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListForPlatformPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListForPlatformUseCase {
    type Caller = OperatorCaller;
    type Input = ListForOrgRequest;
    type Output = Result<AuditLogPage, AppError>;

    /// The page of the platform's audit log that `request` asks for,
    /// platform, organization and tenant records alike.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or the key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key is another operator's, no longer
    ///   works, or its operator is disabled.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        request: ListForOrgRequest,
    ) -> Result<AuditLogPage, AppError> {
        self.ports.operator_authorities.authority(caller).await?;
        self.ports
            .audit_log
            .query(&request.filter, &request.sort, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{Limit, PageRequest, SortOrder};
    use crate::ports::audit::AuditLogFilter;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::audit::WatchedAuditLog;
    use crate::test_support::block_on;
    use crate::test_support::operator::test_operator_caller;

    fn list_with(
        authorities: FakeOperatorAuthorities,
        log: Arc<WatchedAuditLog>,
    ) -> Result<AuditLogPage, AppError> {
        let uc = ListForPlatformUseCase::new(ListForPlatformPorts {
            audit_log: log,
            operator_authorities: Arc::new(authorities),
        });
        let request = ListForOrgRequest {
            filter: AuditLogFilter::default(),
            sort: SortOrder::default(),
            page: PageRequest::first(Limit::new(50).unwrap()),
        };
        block_on(uc.execute(&test_operator_caller(), request))
    }

    /// Olga, an operator, reads the platform's log. The whole platform's is
    /// read.
    #[test]
    fn an_operator_reads_the_platform_log() {
        let log = Arc::new(WatchedAuditLog::default());

        list_with(FakeOperatorAuthorities::admitting(), log.clone()).unwrap();

        assert_eq!(log.asked()[0].0, None);
    }

    /// A disabled operator's authority refusal prevents reading the
    /// platform log before the store is queried.
    #[test]
    fn a_disabled_operator_is_refused() {
        let log = Arc::new(WatchedAuditLog::default());

        let result = list_with(
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
            log.clone(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(log.asked().is_empty());
    }

    /// A removed operator key cannot authenticate a platform-log read.
    #[test]
    fn a_removed_key_is_refused() {
        let result = list_with(
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
            Arc::new(WatchedAuditLog::default()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
