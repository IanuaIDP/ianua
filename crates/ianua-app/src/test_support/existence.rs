//! Checkers that say whether a user or a principal exists,
//! the way a test sets them.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, TenantId, UserId};

use crate::ports::TenantScoped;
use crate::ports::shared::{
    CrossTenantUserChecker, PrincipalExistenceChecker, UserExistenceChecker,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Whether a checker finds what it is asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Everything asked about exists.
    Present,
    /// Nothing asked about exists.
    Absent,
}

/// User existence checker that answers every question one way.
pub struct FakeUserChecker {
    presence: Presence,
}

impl TenantScoped for FakeUserChecker {}

impl FakeUserChecker {
    /// A checker that finds every user.
    #[must_use]
    pub fn accepting() -> Self {
        Self {
            presence: Presence::Present,
        }
    }

    /// A checker that finds no user.
    #[must_use]
    pub fn rejecting() -> Self {
        Self {
            presence: Presence::Absent,
        }
    }
}

#[async_trait]
impl UserExistenceChecker for FakeUserChecker {
    async fn user_exists(
        &self,
        _tenant_id: &ScopedTenant,
        _user_id: &UserId,
    ) -> Result<bool, DomainError> {
        Ok(self.presence == Presence::Present)
    }
}

/// Principal existence checker that answers every question one way.
pub struct FakePrincipalChecker {
    presence: Presence,
}

impl TenantScoped for FakePrincipalChecker {}

impl FakePrincipalChecker {
    /// A checker that finds every principal.
    #[must_use]
    pub fn accepting() -> Self {
        Self {
            presence: Presence::Present,
        }
    }

    /// A checker that reports every principal as gone.
    #[must_use]
    pub fn rejecting() -> Self {
        Self {
            presence: Presence::Absent,
        }
    }
}

#[async_trait]
impl PrincipalExistenceChecker for FakePrincipalChecker {
    async fn principal_exists(
        &self,
        _tenant_id: &ScopedTenant,
        _principal: &PrincipalRef,
    ) -> Result<bool, DomainError> {
        Ok(self.presence == Presence::Present)
    }
}

impl Fake for Arc<dyn PrincipalExistenceChecker> {
    fn fake() -> Self {
        Arc::new(FakePrincipalChecker::accepting())
    }
}

impl Fake for Arc<dyn UserExistenceChecker> {
    fn fake() -> Self {
        Arc::new(FakeUserChecker::accepting())
    }
}

/// Cross-tenant user checker that answers every question one way.
pub struct FakeCrossTenantUserChecker {
    presence: Presence,
}

impl FakeCrossTenantUserChecker {
    /// A checker that finds every user.
    #[must_use]
    pub fn accepting() -> Self {
        Self {
            presence: Presence::Present,
        }
    }

    /// A checker that finds no user.
    #[must_use]
    pub fn rejecting() -> Self {
        Self {
            presence: Presence::Absent,
        }
    }
}

#[async_trait]
impl CrossTenantUserChecker for FakeCrossTenantUserChecker {
    async fn exists_in_tenant(
        &self,
        _tenant_id: &TenantId,
        _user_id: &UserId,
    ) -> Result<bool, DomainError> {
        Ok(self.presence == Presence::Present)
    }
}

impl Fake for Arc<dyn CrossTenantUserChecker> {
    fn fake() -> Self {
        Arc::new(FakeCrossTenantUserChecker::accepting())
    }
}
