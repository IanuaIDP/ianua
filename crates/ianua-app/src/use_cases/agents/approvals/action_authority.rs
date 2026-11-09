//! The delegation an action uses, with every delegation above it, loaded as
//! the store holds them now.
//!
//! An approval allows one action under one live authority. Deciding on it,
//! spending it and naming the people behind it all need the delegation and
//! the chain it was cut or minted from, read fresh, so a revoke anywhere up
//! the chain is seen.

use ianua_domain::domains::agents::authority::delegation::{ActingUnder, Delegation, Lineage};
use ianua_domain::domains::agents::oversight::approval::ActionAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::PrincipalRef;

use crate::error::AppError;
use crate::ports::agents::DelegationStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::lookup::{delegations_above, existing_delegation};

/// The authority an action uses, as loaded.
pub(in crate::use_cases::agents) struct LoadedAuthority {
    chain: Option<Chain>,
}

/// A delegation and the delegations above it.
struct Chain {
    delegation: Delegation<ResolvedTenant>,
    above: Vec<Delegation<ResolvedTenant>>,
}

impl LoadedAuthority {
    /// The authority, as the domain reads it.
    pub(in crate::use_cases::agents) fn authority(&self) -> ActionAuthority<'_, ResolvedTenant> {
        match &self.chain {
            None => ActionAuthority::NoDelegation,
            Some(chain) => ActionAuthority::Delegation {
                delegation: &chain.delegation,
                above: &chain.above,
            },
        }
    }

    /// The delegation the action uses, when it uses one.
    pub(in crate::use_cases::agents) fn delegation(&self) -> Option<&Delegation<ResolvedTenant>> {
        self.chain.as_ref().map(|chain| &chain.delegation)
    }

    /// Every principal the chain names as granting part of it.
    pub(in crate::use_cases::agents) fn grantors(&self) -> Vec<PrincipalRef> {
        let Some(chain) = &self.chain else {
            return Vec::new();
        };
        let mut grantors = Vec::new();
        for delegation in std::iter::once(&chain.delegation).chain(&chain.above) {
            grantors.push(*delegation.delegator());
            if let Lineage::Minted { delegator, .. } = delegation.lineage() {
                grantors.push(*delegator);
            }
        }
        grantors.dedup();
        grantors
    }
}

/// The authority `under` names, loaded with its chain.
///
/// # Errors
///
/// - `AppError::NotFound` when the delegation it names no longer exists.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents) async fn loaded_authority(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    under: &ActingUnder,
) -> Result<LoadedAuthority, AppError> {
    let Some(id) = under.delegation() else {
        return Ok(LoadedAuthority { chain: None });
    };
    let delegation = existing_delegation(store, tenant, id).await?;
    loaded_from(store, tenant, delegation).await
}

/// `delegation`, already loaded, with the chain above it.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents) async fn loaded_from(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    delegation: Delegation<ResolvedTenant>,
) -> Result<LoadedAuthority, AppError> {
    let above = delegations_above(store, tenant, &delegation).await?;
    Ok(LoadedAuthority {
        chain: Some(Chain { delegation, above }),
    })
}
