mod certificates;

use std::fmt;
use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use crate::domains::tenant::custom_domains::verification_status::{TlsStatus, VerificationStatus};
use crate::domains::tenant::events::custom_domains::{
    TenantDomainRegistered, TenantDomainRemoved, TenantDomainVerificationLost, TenantDomainVerified,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{DomainId, DomainName, Lifetime};

/// Who holds the DNS for a registered domain.
///
/// It records how the domain was connected, and is never worked out from
/// anything else. The default is [`SelfManaged`](Self::SelfManaged).
/// Guessing "delegated" would claim the tenant handed over a name they never
/// touched, and then wait for records nobody will write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DomainConnection {
    /// The tenant runs the DNS and adds the records themselves.
    ///
    /// It is the default mode.
    #[default]
    SelfManaged,
    /// The tenant delegated the hostname to us, and we write its records.
    Delegated,
}

impl DomainConnection {
    /// The name this mode is stored and sent under.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SelfManaged => "SelfManaged",
            Self::Delegated => "Delegated",
        }
    }

    /// The mode stored under `s`, or `None` for a name no mode has.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "SelfManaged" => Some(Self::SelfManaged),
            "Delegated" => Some(Self::Delegated),
            _ => None,
        }
    }
}

/// What proves a registered domain is its tenant's.
///
/// One answer for the first check and every later one. A domain proved one
/// way and checked again another fails on every check, whatever the tenant
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofRoute {
    /// A `TXT` record holding the registration's own token.
    Token,
    /// `NS` records pointing at the registration's own nameservers.
    Delegation,
    /// The tenant's own registration of this parent, which must carry the
    /// wildcard, see [`RegisteredDomain::ensure_carries_wildcard`], and
    /// whose own proof must still hold.
    Parent(DomainName),
}

/// Where a domain's DNS proof stands, with when it was proved and lost.
///
/// The status and its times are one value. So a lost proof always says when
/// it went, which is where the grace before release starts. A verified one
/// always says when it was proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainProof {
    /// Never proved.
    Unproved,
    /// Proved at `at`.
    Verified {
        /// When the proof was made.
        at: OffsetDateTime,
    },
    /// Proved once, and the proof is now gone.
    Lost {
        /// When it was proved.
        verified_at: OffsetDateTime,
        /// When the proof went.
        failed_at: OffsetDateTime,
    },
}

impl DomainProof {
    /// The status label this proof carries.
    #[must_use]
    pub fn status(self) -> VerificationStatus {
        match self {
            Self::Unproved => VerificationStatus::Pending,
            Self::Verified { .. } => VerificationStatus::Verified,
            Self::Lost { .. } => VerificationStatus::Failed,
        }
    }

    /// Reads a proof back from its stored status and times.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a verified domain has no proof
    ///   time.
    /// - [`DomainError::Infrastructure`] when a failed domain lacks a proof
    ///   time or a failure time.
    /// - [`DomainError::Infrastructure`] when a pending domain has either
    ///   time, or a verified one has a failure time.
    pub fn from_stored(
        status: VerificationStatus,
        verified_at: Option<OffsetDateTime>,
        failed_at: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, verified_at, failed_at) {
            (VerificationStatus::Pending, None, None) => Ok(Self::Unproved),
            (VerificationStatus::Verified, Some(at), None) => Ok(Self::Verified { at }),
            (VerificationStatus::Failed, Some(verified_at), Some(failed_at)) => Ok(Self::Lost {
                verified_at,
                failed_at,
            }),
            (status, _, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} domain has proof times that contradict it"
            ))),
        }
    }

    /// When it was last proved, or `None` if it never was. Storage keeps
    /// this time.
    #[must_use]
    pub fn verified_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Verified { at }
            | Self::Lost {
                verified_at: at, ..
            } => Some(at),
            Self::Unproved => None,
        }
    }

    /// When the proof went, while it stays gone. Storage keeps this time.
    #[must_use]
    pub fn failed_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Lost { failed_at, .. } => Some(failed_at),
            Self::Unproved | Self::Verified { .. } => None,
        }
    }
}

/// A domain a tenant has registered, and how far it has proved it.
///
/// It is read and written only through stores opened for the resolved
/// tenant. See [`crate::isolation`].
///
/// # Domain uniqueness
///
/// Only one tenant may hold a domain. The repository checks this across all
/// tenants. If Acme registers `acme.com`, Globex cannot claim it until an
/// unproved claim lapses, see [`has_lapsed`](Self::has_lapsed). So no
/// tenant can take over another's domain.
///
/// # Use
///
/// Once verified, the tenant has proved it owns the name. Routes, app
/// sign-in and identity-provider connections may only use hostnames and
/// email domains the tenant has verified.
#[derive(Debug)]
pub struct RegisteredDomain<T: TenantScope> {
    id: DomainId,
    domain: DomainName,
    connection: DomainConnection,
    proof: DomainProof,
    dns_challenge_token: DomainVerificationToken,
    tls_status: TlsStatus,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a tenant gives to claim a domain.
#[derive(Debug, Clone)]
pub struct NewDomain {
    /// The name claimed.
    pub domain: DomainName,
    /// Who holds its DNS.
    pub connection: DomainConnection,
    /// The token the tenant publishes to prove it controls the name.
    pub dns_challenge_token: DomainVerificationToken,
}

/// How long a claim on a name holds it against other tenants without a
/// standing proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimLifetimes {
    /// How long a claim that was never proved holds its name.
    pub unproved: Lifetime,
    /// How long a proved claim holds its name after its proof failed. It
    /// runs for days, long enough to survive a bad DNS answer or a record
    /// briefly removed. It still ends, so a domain that was sold goes to its
    /// new owner.
    pub failed_grace: Lifetime,
}

impl<T: TenantScope> RegisteredDomain<T> {
    /// Registers a new domain of the tenant `scope` stands for, in `Pending`
    /// verification status, for a person who may add domains to it.
    ///
    /// A claim holds its name against every other tenant until it lapses.
    /// Sam may only view settings. Without this check, he claims names a
    /// sibling tenant is about to prove, and holds them up.
    ///
    /// The caller makes the challenge token. A self-managed domain proves
    /// ownership by publishing it in a TXT record. A delegated domain starts
    /// with its certificate provisioning. A self-managed one needs none
    /// until the tenant asks. Raises `tenant.domain_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` was worked out for another
    ///   tenant, or may not add domains to it.
    pub fn register(new: NewDomain, scope: &T, by: TenantControl<'_>) -> Result<Self, DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::DomainClaims)?;
        let mut registered = Self {
            id: DomainId::new(),
            domain: new.domain,
            connection: new.connection,
            proof: DomainProof::Unproved,
            dns_challenge_token: new.dns_challenge_token,
            tls_status: initial_tls_status(new.connection),
            created_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        registered.raised.raise(TenantDomainRegistered {
            domain: registered.domain.clone(),
            occurred_at: registered.created_at,
        });
        Ok(registered)
    }

    /// Rebuilds a registered domain from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the domain was
    ///   verified before it was registered.
    /// - [`DomainError::Infrastructure`] when the row says the proof was lost
    ///   before it was made.
    /// - [`DomainError::Infrastructure`] when the row gives a name never
    ///   proved an active certificate.
    pub fn reconstitute(row: RegisteredDomainRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            domain: row.domain,
            connection: row.connection,
            proof: row.proof,
            dns_challenge_token: row.dns_challenge_token,
            tls_status: row.tls_status,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &RegisteredDomainRow) -> Result<(), DomainError> {
        RowCheck::of("registered domain")
            .in_order_if(
                row.created_at,
                row.proof.verified_at(),
                "verified before it was registered",
            )
            .holds(
                row.proof
                    .verified_at()
                    .zip(row.proof.failed_at())
                    .is_none_or(|(verified, failed)| verified <= failed),
                "lost before it was verified",
            )
            .holds(
                !matches!(
                    (row.proof, row.tls_status),
                    (DomainProof::Unproved, TlsStatus::Active)
                ),
                "a certificate serving a name never proved",
            )
            .finish()
    }

    /// The registration's id.
    #[must_use]
    pub fn id(&self) -> &DomainId {
        &self.id
    }

    /// The registered domain name.
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Who holds the DNS for this domain.
    #[must_use]
    pub fn connection(&self) -> DomainConnection {
        self.connection
    }

    /// Current DNS verification status.
    #[must_use]
    pub fn verification_status(&self) -> VerificationStatus {
        self.proof.status()
    }

    /// Where its DNS proof stands, with when it was proved and lost.
    #[must_use]
    pub fn proof(&self) -> DomainProof {
        self.proof
    }

    /// The DNS TXT record value the tenant must set to prove ownership.
    #[must_use]
    pub fn dns_challenge_token(&self) -> &DomainVerificationToken {
        &self.dns_challenge_token
    }

    /// TLS certificate status: `NotRequired` until a certificate is wanted.
    #[must_use]
    pub fn tls_status(&self) -> TlsStatus {
        self.tls_status
    }

    /// When DNS verification was completed, if at all.
    #[must_use]
    pub fn verified_at(&self) -> Option<OffsetDateTime> {
        self.proof.verified_at()
    }

    /// When this domain was registered.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the domain's proof last failed, while it stays failed.
    #[must_use]
    pub fn failed_at(&self) -> Option<OffsetDateTime> {
        self.proof.failed_at()
    }

    /// Whether the domain is verified and ready to serve.
    ///
    /// A domain that needs a certificate also needs it to be active. For one
    /// whose TLS status is `NotRequired`, verification alone is enough.
    #[must_use]
    pub fn is_active(&self) -> bool {
        let verified = matches!(self.proof, DomainProof::Verified { .. });
        let tls_ok = matches!(self.tls_status, TlsStatus::NotRequired | TlsStatus::Active);
        verified && tls_ok
    }

    /// Whether this registers a wildcard, such as `*.acme.com`.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.domain.is_wildcard()
    }

    /// What proves this domain is its tenant's, the first time and on every
    /// later check.
    ///
    /// A wildcard is proved through its parent, whatever its connection
    /// says. It has no token and no delegation of its own.
    #[must_use]
    pub fn proof_route(&self) -> ProofRoute {
        if let Some(parent) = self.domain.wildcard_parent() {
            return ProofRoute::Parent(parent);
        }
        match self.connection {
            DomainConnection::SelfManaged => ProofRoute::Token,
            DomainConnection::Delegated => ProofRoute::Delegation,
        }
    }

    /// Refuses this registration as the one `wildcard` stands on, unless it
    /// is the name the wildcard stands in front of, delegated to us and
    /// verified.
    ///
    /// `*.auth.acme.com` is a record inside the zone for `auth.acme.com`.
    /// The certificate challenge and the `NS` records that make it answer
    /// belong to that parent. A parent run at the tenant's own provider
    /// leaves nowhere to publish the challenge. One not proved, or proved
    /// no longer, proves nothing beneath it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when this is not the wildcard's parent.
    /// - [`DomainError::Validation`] when it is run at the tenant's own
    ///   provider.
    /// - [`DomainError::Validation`] when it is not verified now.
    pub fn ensure_carries_wildcard(&self, wildcard: &DomainName) -> Result<(), DomainError> {
        if wildcard.wildcard_parent().as_ref() != Some(&self.domain) {
            return Err(DomainError::invalid(message!(
                "tenant-does-not-stand-in-front-of",
                format!("{wildcard} does not stand in front of {}", self.domain)
            )));
        }
        if self.connection != DomainConnection::Delegated {
            return Err(DomainError::invalid(message!(
                "tenant-is-managed-at-your-own-dns",
                format!(
                    "{} is managed at your own DNS provider, so there is nowhere for us to \
                 publish the proof a wildcard certificate needs; delegate {} to us first",
                    self.domain, self.domain
                )
            )));
        }
        if !matches!(self.proof, DomainProof::Verified { .. }) {
            return Err(DomainError::invalid(message!(
                "tenant-is-not-verified-finish-delegating-it",
                format!(
                    "{} is not verified; finish delegating it before registering a wildcard over it",
                    self.domain
                )
            )));
        }
        Ok(())
    }

    /// Proof that the tenant `scope` names holds this domain, for it to
    /// become the tenant's primary domain or be bound to an identity
    /// provider connection.
    ///
    /// `scope` is the tenant the store was opened for, so the registration
    /// is that tenant's own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the domain is not verified now, or is
    ///   a wildcard, which names no single host or address domain.
    pub fn owned_by(&self, scope: &T) -> Result<OwnedDomain, DomainError> {
        if !matches!(self.proof, DomainProof::Verified { .. }) {
            return Err(DomainError::conflict(message!(
                "tenant-must-be-verified-before-the-tenant",
                format!(
                    "{} must be verified before the tenant may use it",
                    self.domain
                )
            )));
        }
        if self.is_wildcard() {
            return Err(DomainError::conflict(message!(
                "tenant-a-wildcard-domain-cannot-be-used",
                "a wildcard domain cannot be used"
            )));
        }
        Ok(OwnedDomain::new(*scope.tenant_id(), self.domain.clone()))
    }

    /// Removes this domain from the tenant `scope` stands for, once `by` may
    /// delete the tenant's domains. Raises `tenant.domain_removed`, taken
    /// once the registration is deleted from storage.
    ///
    /// Removing a domain takes down every route and sign-in page served on
    /// it, and frees the name for any other tenant to claim. Sam may only
    /// view Acme's domains. Without this check, he removes `login.acme.com`
    /// and Acme's people can no longer sign in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` was worked out for another
    ///   tenant, or may not delete the tenant's domains.
    pub fn remove(&mut self, scope: &T, by: TenantControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::DomainRemoval)?;
        self.raised.raise(TenantDomainRemoved {
            domain: self.domain.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Whether this claim has stopped holding its name against other
    /// tenants.
    ///
    /// A name is claimed for everyone the moment it is registered, proof or
    /// not. Without a limit, anyone could register a name they do not own and
    /// keep its real owner out for good by never proving it, or keep a name
    /// they once owned after it was sold.
    ///
    /// - Never proved: lapses `lifetimes.unproved` after it was made.
    /// - Verified: never lapses.
    /// - Proof failed: lapses `lifetimes.failed_grace` after it failed. One
    ///   bad DNS answer does not release it. A domain that was sold is
    ///   released to its new owner.
    #[must_use]
    pub fn has_lapsed(&self, now: OffsetDateTime, lifetimes: &ClaimLifetimes) -> bool {
        match self.proof {
            DomainProof::Unproved => now >= lifetimes.unproved.ends_after(self.created_at),
            DomainProof::Verified { .. } => false,
            DomainProof::Lost { failed_at, .. } => {
                now >= lifetimes.failed_grace.ends_after(failed_at)
            }
        }
    }

    /// Marks DNS verification as successful. Raises
    /// `tenant.domain_verified`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the domain is already
    ///   verified.
    pub fn mark_verified(&mut self) -> Result<(), DomainError> {
        let at = self.proved_now()?;
        self.raised.raise(TenantDomainVerified {
            domain: self.domain.clone(),
            occurred_at: at,
        });
        Ok(())
    }

    /// Marks a domain verified the moment it is registered: a name the
    /// operator vouches for, or a wildcard whose verified, delegated parent
    /// was checked before it was registered. Raises nothing of its own, the
    /// registration's `tenant.domain_registered` is the record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the domain is already
    ///   verified.
    pub fn prove_on_arrival(&mut self) -> Result<(), DomainError> {
        self.proved_now()?;
        Ok(())
    }

    /// Moves the proof to verified as of now, giving back when.
    fn proved_now(&mut self) -> Result<OffsetDateTime, DomainError> {
        let at = crate::shared::clock::now();
        self.move_proof_to(DomainProof::Verified { at })?;
        Ok(at)
    }

    /// Records that a verified domain's DNS proof has disappeared, and when.
    /// The grace before the claim lapses runs from now. Raises
    /// `tenant.domain_verification_lost`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] unless the domain is verified.
    pub fn mark_verification_failed(&mut self) -> Result<(), DomainError> {
        let DomainProof::Verified { at } = self.proof else {
            return Err(self.refused(
                "verification",
                self.proof.status(),
                VerificationStatus::Failed,
            ));
        };
        let failed_at = crate::shared::clock::now();
        self.move_proof_to(DomainProof::Lost {
            verified_at: at,
            failed_at,
        })?;
        self.raised.raise(TenantDomainVerificationLost {
            domain: self.domain.clone(),
            occurred_at: failed_at,
        });
        Ok(())
    }

    fn move_proof_to(&mut self, to: DomainProof) -> Result<(), DomainError> {
        self.proof
            .status()
            .try_transition(to.status())
            .map_err(|refused| self.refused("verification", refused.from, refused.to))?;
        self.proof = to;
        Ok(())
    }

    fn refused(&self, what: &str, from: impl fmt::Debug, to: impl fmt::Debug) -> DomainError {
        DomainError::invalid_transition(message!(
            "tenant-of-cannot-move-from-to",
            format!(
                "{what} of {} cannot move from {from:?} to {to:?}",
                self.domain
            )
        ))
    }
}

impl<T: TenantScope> Raises for RegisteredDomain<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Stored fields of a [`RegisteredDomain`], read back by repositories.
pub struct RegisteredDomainRow {
    /// The registration's id.
    pub id: DomainId,
    /// The registered domain name.
    pub domain: DomainName,
    /// Who holds the DNS for this domain.
    pub connection: DomainConnection,
    /// Where its DNS proof stands. See [`DomainProof::from_stored`].
    pub proof: DomainProof,
    /// The DNS TXT record value the tenant must set to prove ownership.
    pub dns_challenge_token: DomainVerificationToken,
    /// TLS certificate status.
    pub tls_status: TlsStatus,
    /// When this domain was registered.
    pub created_at: OffsetDateTime,
}

/// Where a newly registered domain's certificate starts.
///
/// We run the DNS for a delegated domain and point it at the proxy as soon
/// as the zone opens. It will be reached over TLS, so it needs a certificate
/// at once. A self-managed one may never point here, so nothing is issued
/// until the tenant asks.
fn initial_tls_status(connection: DomainConnection) -> TlsStatus {
    match connection {
        DomainConnection::Delegated => TlsStatus::Provisioning,
        DomainConnection::SelfManaged => TlsStatus::NotRequired,
    }
}

text_value! {
    /// The token a tenant publishes in a TXT record to prove it controls a
    /// domain.
    pub struct DomainVerificationToken;
}

impl TextValue for DomainVerificationToken {
    const FIELD: &'static str = "dns_challenge_token";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{DomainAction, SystemPermission};
    use crate::domains::tenant::custom_domains::certificate::{
        CertificateBundle, IssuedCertificate,
    };
    use crate::domains::tenant::fixtures::{ADMIN, active, holding, person};
    use crate::domains::tenant::lifecycle::Tenant;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::shared::security::secret::Secret;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{CertificatePem, TenantId};

    /// A 90-day certificate issued now.
    fn cert() -> CertificateBundle {
        let now = crate::shared::clock::now();
        CertificateBundle::new(IssuedCertificate {
            domain_id: DomainId::new(),
            certificate_pem: CertificatePem::new(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )
            .unwrap(),
            private_key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            ),
            issued_at: now,
            expires_at: now + time::Duration::days(90),
        })
        .unwrap()
    }

    /// Each connection mode is turned into its stored name and parsed back
    /// as the same mode.
    #[test]
    fn connection_roundtrips_via_as_str_and_parse() {
        for connection in [DomainConnection::SelfManaged, DomainConnection::Delegated] {
            assert_eq!(
                DomainConnection::parse(connection.as_str()),
                Some(connection)
            );
        }
    }

    /// A stored mode reads `Managed`, which no mode is named. Parsing gives
    /// none rather than a guess.
    #[test]
    fn connection_parse_unknown_returns_none() {
        assert_eq!(DomainConnection::parse("Managed"), None);
    }

    /// What Acme's tenant gives to claim `name`, connected as `connection`.
    fn claim(name: &str, connection: DomainConnection, token: &str) -> NewDomain {
        NewDomain {
            domain: DomainName::new(name).unwrap(),
            connection,
            dns_challenge_token: DomainVerificationToken::new(token).unwrap(),
        }
    }

    /// `new` claimed in Acme's tenant by an admin who may add domains.
    fn registered(new: NewDomain) -> RegisteredDomain<ResolvedTenant> {
        let acme = active();
        let admin = person("admin@acme.test");
        RegisteredDomain::register(new, &scope_of(&acme), holding(&admin, &acme, ADMIN)).unwrap()
    }

    fn scope_of(tenant: &Tenant) -> ResolvedTenant {
        ResolvedTenant::new(*tenant.id(), tenant.slug().clone())
    }

    /// Domain viewers and administrators of another tenant cannot register a
    /// domain. Creation rights in the target tenant allow registration.
    #[test]
    fn only_someone_who_may_add_the_tenants_domains_claims_one() {
        let acme = active();
        let theirs = active();
        let (sam, ann) = (person("sam@acme.test"), person("ann@other.test"));
        let view = [SystemPermission::Domains(DomainAction::View)];
        let create = [SystemPermission::Domains(DomainAction::Create)];
        let claimed_by = |by: TenantControl<'_>| {
            let new = claim("login.acme.com", DomainConnection::SelfManaged, "token");
            RegisteredDomain::register(new, &scope_of(&acme), by)
        };

        let by_sam = claimed_by(holding(&sam, &acme, &view));
        let by_ann = claimed_by(holding(&ann, &theirs, ADMIN));
        let by_adder = claimed_by(holding(&sam, &acme, &create));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert!(by_adder.is_ok());
    }

    /// Domain removal rejects viewing rights, update rights and administrative
    /// rights from another tenant. Deletion rights in this tenant are accepted.
    #[test]
    fn only_someone_who_may_delete_the_tenants_domains_removes_one() {
        let acme = active();
        let theirs = active();
        let (sam, ann) = (person("sam@acme.test"), person("ann@other.test"));
        let scope = scope_of(&acme);
        let new = claim("login.acme.com", DomainConnection::SelfManaged, "token");
        let admin = holding(&sam, &acme, ADMIN);
        let mut domain = RegisteredDomain::register(new, &scope, admin).unwrap();
        let view = [SystemPermission::Domains(DomainAction::View)];
        let update = [SystemPermission::Domains(DomainAction::Update)];
        let delete = [SystemPermission::Domains(DomainAction::Delete)];

        let by_sam = domain.remove(&scope, holding(&sam, &acme, &view));
        let by_ann = domain.remove(&scope, holding(&ann, &theirs, ADMIN));
        let by_bob = domain.remove(&scope, holding(&sam, &acme, &update));
        let by_admin = domain.remove(&scope, holding(&sam, &acme, &delete));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
        assert!(by_admin.is_ok());
    }

    fn claim_made(ago: time::Duration) -> RegisteredDomain<ResolvedTenant> {
        let _clock = crate::shared::clock::freeze(crate::shared::clock::now() - ago);
        registered(claim(
            "login.bigcorp.com",
            DomainConnection::SelfManaged,
            "token",
        ))
    }

    fn lifetimes() -> ClaimLifetimes {
        ClaimLifetimes {
            unproved: Lifetime::seconds(7 * 24 * 3600).unwrap(),
            failed_grace: Lifetime::seconds(14 * 24 * 3600).unwrap(),
        }
    }

    fn bigcorp() -> ResolvedTenant {
        ResolvedTenant::new(
            TenantId::new(),
            crate::types::TenantSlug::new("bigcorp", &crate::shared::config::SlugLimits::default())
                .unwrap(),
        )
    }

    /// An unverified registration cannot produce ownership proof. After
    /// verification, the proof names the resolved tenant and registered domain.
    #[test]
    fn only_a_verified_domain_proves_ownership() {
        let scope = bigcorp();
        let mut claim = claim_made(time::Duration::ZERO);

        let unproved = claim.owned_by(&scope);
        claim.mark_verified().unwrap();
        let proved = claim.owned_by(&scope).unwrap();

        assert!(matches!(unproved, Err(DomainError::Conflict(_))));
        assert_eq!(proved.tenant(), scope.tenant_id());
        assert_eq!(proved.domain().as_str(), "login.bigcorp.com");
    }

    /// With a seven-day lifetime, an unproved claim remains valid at six days
    /// and has lapsed by eight days.
    #[test]
    fn an_unproved_claim_lapses_after_its_lifetime() {
        let now = crate::shared::clock::now();

        let fresh = claim_made(time::Duration::days(6));
        let stale = claim_made(time::Duration::days(8));

        assert!(!fresh.has_lapsed(now, &lifetimes()));
        assert!(stale.has_lapsed(now, &lifetimes()));
    }

    /// A claim made 30 days ago and proved never lapses. A proved claim is
    /// the name's owner, however old.
    #[test]
    fn a_proved_claim_never_lapses() {
        let mut claim = claim_made(time::Duration::days(30));
        claim.mark_verified().unwrap();

        assert!(!claim.has_lapsed(crate::shared::clock::now(), &lifetimes()));
    }

    /// A claim whose proof was lost has not lapsed thirteen days into its
    /// fourteen-day grace period.
    #[test]
    fn a_failed_proof_holds_its_name_through_the_grace() {
        let mut claim = claim_made(time::Duration::days(30));
        claim.mark_verified().unwrap();
        claim.mark_verification_failed().unwrap();
        let failed = claim.failed_at().unwrap();

        assert!(!claim.has_lapsed(failed + time::Duration::days(13), &lifetimes()));
    }

    /// A domain was sold and the old tenant's proof failed. Fourteen days
    /// later the grace is over and the claim lapses, so the new owner can
    /// register it.
    #[test]
    fn a_failed_proof_releases_its_name_once_the_grace_is_over() {
        let mut claim = claim_made(time::Duration::days(30));
        claim.mark_verified().unwrap();
        claim.mark_verification_failed().unwrap();
        let failed = claim.failed_at().unwrap();

        assert!(claim.has_lapsed(failed + time::Duration::days(14), &lifetimes()));
    }

    /// A proof fails and then comes back. The failure time is cleared and
    /// the claim no longer lapses, even a year later.
    #[test]
    fn a_proof_that_returns_clears_the_failure() {
        let mut claim = claim_made(time::Duration::days(30));
        claim.mark_verified().unwrap();
        claim.mark_verification_failed().unwrap();

        claim.mark_verified().unwrap();

        assert_eq!(claim.failed_at(), None);
        assert!(!claim.has_lapsed(
            crate::shared::clock::now() + time::Duration::days(365),
            &lifetimes()
        ));
    }

    /// A domain with no mode given reads as self-managed. Nobody is then
    /// assumed to have delegated a name they never handed over.
    #[test]
    fn the_default_connection_is_self_managed() {
        assert_eq!(DomainConnection::default(), DomainConnection::SelfManaged);
    }

    /// Acme registers `hello.acme.com` as delegated. The registration reads
    /// back as delegated.
    #[test]
    fn a_registration_keeps_the_connection_it_was_made_with() {
        let delegated = registered(claim(
            "hello.acme.com",
            DomainConnection::Delegated,
            "token",
        ));

        assert_eq!(delegated.connection(), DomainConnection::Delegated);
    }

    fn primary_domain() -> RegisteredDomain<ResolvedTenant> {
        registered(claim(
            "acme.com",
            DomainConnection::SelfManaged,
            "challenge_abc123",
        ))
    }

    fn delegated_domain() -> RegisteredDomain<ResolvedTenant> {
        registered(claim(
            "auth.acme.com",
            DomainConnection::Delegated,
            "challenge_xyz789",
        ))
    }

    /// Acme registers `acme.com`. It starts pending and is not yet usable.
    #[test]
    fn a_registration_starts_pending() {
        let d = primary_domain();

        assert_eq!(d.verification_status(), VerificationStatus::Pending);
        assert!(!d.is_active());
    }

    /// Acme delegates `auth.acme.com`. Its certificate starts provisioning at
    /// once, since we point it at the proxy as soon as the zone opens.
    #[test]
    fn a_delegated_domain_starts_provisioning_tls() {
        let d = delegated_domain();

        assert_eq!(d.tls_status(), TlsStatus::Provisioning);
        assert!(!d.is_active());
    }

    /// Acme registers `acme.com` and keeps its own DNS. No certificate is
    /// wanted yet, since the name may never point here and the challenge
    /// would go unanswered.
    #[test]
    fn a_tenant_managed_domain_needs_no_certificate_yet() {
        let d = primary_domain();

        assert_eq!(d.tls_status(), TlsStatus::NotRequired);
    }

    /// A self-managed domain with no certificate needed is verified. It is
    /// usable at once and records when it was proved.
    #[test]
    fn a_verified_tenant_managed_domain_is_active() {
        let mut d = primary_domain();

        d.mark_verified().unwrap();

        assert!(d.is_active());
        assert!(d.verified_at().is_some());
    }

    /// A verified domain is verified a second time. It is refused and the
    /// first proof time stays.
    #[test]
    fn a_verified_domain_cannot_be_verified_again() {
        let mut d = primary_domain();
        d.mark_verified().unwrap();
        let first = d.verified_at();

        let again = d.mark_verified();

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert_eq!(d.verified_at(), first);
    }

    /// A delegated domain is verified but still waits on its certificate. It
    /// is not usable until the certificate is active.
    #[test]
    fn verified_auth_needs_tls_to_be_active() {
        let mut d = delegated_domain();

        d.mark_verified().unwrap();

        assert!(!d.is_active());

        d.mark_tls_active(&cert()).unwrap();

        assert!(d.is_active());
    }

    /// An unverified delegated domain cannot activate a certificate, and its
    /// TLS status stays provisioning.
    #[test]
    fn an_unverified_domain_cannot_be_given_a_certificate() {
        let mut d = delegated_domain();

        let result = d.mark_tls_active(&cert());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(d.tls_status(), TlsStatus::Provisioning);
    }

    /// A self-managed domain is verified and then given a certificate. Its
    /// TLS status reads active.
    #[test]
    fn a_tenant_managed_domain_can_be_given_a_certificate_once_verified() {
        let mut d = primary_domain();
        d.mark_verified().unwrap();

        d.mark_tls_active(&cert()).unwrap();

        assert_eq!(d.tls_status(), TlsStatus::Active);
    }

    /// A verified domain's TXT record is removed. It is marked failed.
    #[test]
    fn a_verified_domain_whose_proof_disappears_is_marked_failed() {
        let mut d = primary_domain();
        d.mark_verified().unwrap();

        d.mark_verification_failed().unwrap();

        assert_eq!(d.verification_status(), VerificationStatus::Failed);
    }

    /// A domain that was never proved is marked failed. It is refused and
    /// stays pending, so its unproved lifetime still applies.
    #[test]
    fn an_unproved_domain_cannot_be_marked_failed() {
        let mut d = primary_domain();

        let result = d.mark_verification_failed();

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(d.verification_status(), VerificationStatus::Pending);
    }

    /// A failed domain's TXT record is put back. It is verified again.
    #[test]
    fn a_failed_domain_is_verified_again_when_its_proof_returns() {
        let mut d = primary_domain();
        d.mark_verified().unwrap();
        d.mark_verification_failed().unwrap();

        d.mark_verified().unwrap();

        assert_eq!(d.verification_status(), VerificationStatus::Verified);
    }

    /// A verified delegated domain with an active certificate lets it lapse.
    /// The domain is no longer usable.
    #[test]
    fn tls_expired_makes_auth_domain_inactive() {
        let mut d = delegated_domain();
        d.mark_verified().unwrap();
        d.mark_tls_active(&cert()).unwrap();
        assert!(d.is_active());

        d.mark_tls_expired().unwrap();

        assert!(!d.is_active());
    }

    /// Acme's certificate for `auth.acme.com` lapsed before it could be
    /// renewed. The renewal sets it serving again; renewing one still
    /// serving keeps it so.
    #[test]
    fn a_renewal_sets_a_lapsed_certificate_serving_again() {
        let mut d = delegated_domain();
        d.mark_verified().unwrap();
        d.mark_tls_active(&cert()).unwrap();
        d.mark_tls_renewed(&cert()).unwrap();
        d.mark_tls_expired().unwrap();

        d.mark_tls_renewed(&cert()).unwrap();

        assert_eq!(d.tls_status(), TlsStatus::Active);
        assert!(d.is_active());
    }

    /// Renewal rejects lost domain proof and a domain that never requested a certificate.
    /// A self-managed domain without a certificate keeps its not-required status.
    #[test]
    fn only_a_verified_domain_with_a_certificate_is_renewed() {
        let mut lost = delegated_domain();
        lost.mark_verified().unwrap();
        lost.mark_tls_active(&cert()).unwrap();
        lost.mark_verification_failed().unwrap();
        let mut never_asked = primary_domain();
        never_asked.mark_verified().unwrap();

        assert!(matches!(
            lost.ensure_renewable(),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            never_asked.mark_tls_renewed(&cert()),
            Err(DomainError::Conflict(_))
        ));
        assert_eq!(never_asked.tls_status(), TlsStatus::NotRequired);
    }

    /// A self-managed domain with no certificate is marked expired. It is
    /// refused.
    #[test]
    fn a_domain_that_never_had_a_certificate_cannot_expire_one() {
        let mut d = primary_domain();

        let result = d.mark_tls_expired();

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A verified, delegated `auth.globex.com` with an active certificate is
    /// read back. Its id, name and mode match and it is usable.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let now = crate::shared::clock::now();
        let id = DomainId::new();

        let d = RegisteredDomain::<ResolvedTenant>::reconstitute(RegisteredDomainRow {
            id,
            domain: DomainName::new("auth.globex.com").unwrap(),
            connection: DomainConnection::Delegated,
            proof: DomainProof::Verified { at: now },
            dns_challenge_token: DomainVerificationToken::new("token123").unwrap(),
            tls_status: TlsStatus::Active,
            created_at: now,
        })
        .unwrap();

        assert_eq!(*d.id(), id);
        assert_eq!(d.domain().as_str(), "auth.globex.com");
        assert_eq!(d.connection(), DomainConnection::Delegated);
        assert!(d.is_active());
    }

    /// Acme registers `*.acme.com`. It reads as a wildcard and keeps the
    /// name as given.
    #[test]
    fn wildcard_domain_is_detected() {
        let d = registered(claim(
            "*.acme.com",
            DomainConnection::SelfManaged,
            "challenge",
        ));

        assert!(d.is_wildcard());
        assert_eq!(d.domain().as_str(), "*.acme.com");
    }

    /// Acme registers `acme.com`. It does not read as a wildcard.
    #[test]
    fn non_wildcard_domain_is_not_detected() {
        let d = primary_domain();

        assert!(!d.is_wildcard());
    }

    /// Acme's own `acme.com` is proved by its token, its delegated
    /// `auth.acme.com` by its delegation, and `*.auth.acme.com` through
    /// `auth.acme.com`. The wildcard has no zone of its own, so asking DNS
    /// for its delegation would mark it lost on every check.
    #[test]
    fn each_kind_of_domain_is_proved_its_own_way() {
        let own = registered(claim("acme.com", DomainConnection::SelfManaged, "t"));
        let delegated = registered(claim("auth.acme.com", DomainConnection::Delegated, "t"));
        let wildcard = registered(claim("*.auth.acme.com", DomainConnection::Delegated, "t"));

        assert_eq!(own.proof_route(), ProofRoute::Token);
        assert_eq!(delegated.proof_route(), ProofRoute::Delegation);
        assert_eq!(
            wildcard.proof_route(),
            ProofRoute::Parent(DomainName::new("auth.acme.com").unwrap())
        );
    }

    /// `auth.acme.com` is delegated to us and verified. It carries
    /// `*.auth.acme.com`.
    #[test]
    fn a_verified_delegated_parent_carries_its_wildcard() {
        let mut parent = registered(claim("auth.acme.com", DomainConnection::Delegated, "t"));
        parent.mark_verified().unwrap();

        let carried = parent.ensure_carries_wildcard(&DomainName::new("*.auth.acme.com").unwrap());

        assert!(carried.is_ok());
    }

    /// A wildcard's parent is rejected when it is unverified, self-managed or
    /// registered under a different name.
    #[test]
    fn only_its_own_verified_delegated_parent_carries_a_wildcard() {
        let wildcard = DomainName::new("*.auth.acme.com").unwrap();
        let unverified = registered(claim("auth.acme.com", DomainConnection::Delegated, "t"));
        let mut own = registered(claim("auth.acme.com", DomainConnection::SelfManaged, "t"));
        own.mark_verified().unwrap();
        let mut other = registered(claim("www.acme.com", DomainConnection::Delegated, "t"));
        other.mark_verified().unwrap();

        for parent in [&unverified, &own, &other] {
            assert!(
                matches!(
                    parent.ensure_carries_wildcard(&wildcard),
                    Err(DomainError::Validation(_))
                ),
                "{}",
                parent.domain()
            );
        }
    }

    /// A hex token such as `4f8c1d2e9a7b` is accepted.
    #[test]
    fn a_well_formed_domain_verification_token_is_accepted() {
        assert!(DomainVerificationToken::new("4f8c1d2e9a7b").is_ok());
    }

    /// An empty token, one with a space and one with a line break are all
    /// refused.
    #[test]
    fn a_malformed_domain_verification_token_is_refused() {
        for value in ["", "a b", "a\nb"] {
            assert!(
                DomainVerificationToken::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }

    /// A stored row says the proof was lost an hour before it was made. It
    /// is refused as corrupt when read.
    #[test]
    fn a_stored_domain_lost_before_it_was_verified_is_refused() {
        let domain = primary_domain();
        let row = RegisteredDomainRow {
            id: domain.id,
            domain: domain.domain.clone(),
            connection: domain.connection,
            proof: DomainProof::Lost {
                verified_at: domain.created_at + time::Duration::hours(2),
                failed_at: domain.created_at + time::Duration::hours(1),
            },
            dns_challenge_token: domain.dns_challenge_token.clone(),
            tls_status: domain.tls_status,
            created_at: domain.created_at,
        };

        assert!(refused_as_corrupt(
            &RegisteredDomain::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored unproved domain with an active certificate is rejected as
    /// corrupt.
    #[test]
    fn a_stored_unproved_domain_with_an_active_certificate_is_refused() {
        let domain = delegated_domain();
        let row = RegisteredDomainRow {
            id: domain.id,
            domain: domain.domain.clone(),
            connection: domain.connection,
            proof: DomainProof::Unproved,
            dns_challenge_token: domain.dns_challenge_token.clone(),
            tls_status: TlsStatus::Active,
            created_at: domain.created_at,
        };

        assert!(refused_as_corrupt(
            &RegisteredDomain::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// `domain` with what it raised so far taken out.
    fn quiet(mut domain: RegisteredDomain<ResolvedTenant>) -> RegisteredDomain<ResolvedTenant> {
        raised_names(&mut domain);
        domain
    }

    /// Acme registers `acme.com`. The registration is raised for the audit
    /// trail.
    #[test]
    fn registering_raises_tenant_domain_registered() {
        let mut d = primary_domain();

        assert_eq!(raised_names(&mut d), ["tenant.domain_registered"]);
    }

    /// `auth.globex.com` is read back from storage. Loading it is no
    /// change, so it has raised nothing.
    #[test]
    fn a_domain_read_back_from_storage_has_raised_nothing() {
        let now = crate::shared::clock::now();

        let mut d = RegisteredDomain::<ResolvedTenant>::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: DomainName::new("auth.globex.com").unwrap(),
            connection: DomainConnection::Delegated,
            proof: DomainProof::Verified { at: now },
            dns_challenge_token: DomainVerificationToken::new("token123").unwrap(),
            tls_status: TlsStatus::Active,
            created_at: now,
        })
        .unwrap();

        assert!(raised_names(&mut d).is_empty());
    }

    /// Acme proves `acme.com`, its TXT record later goes, and it comes
    /// back. Each move of the proof is raised, in order.
    #[test]
    fn the_proof_moves_raise_verified_and_lost() {
        let mut d = quiet(primary_domain());

        d.mark_verified().unwrap();
        d.mark_verification_failed().unwrap();
        d.mark_verified().unwrap();

        assert_eq!(
            raised_names(&mut d),
            [
                "tenant.domain_verified",
                "tenant.domain_verification_lost",
                "tenant.domain_verified"
            ]
        );
    }

    /// The operator vouches for `acme.com`, so it is proved as it is
    /// registered. Only the registration is raised; it is the record.
    #[test]
    fn a_proof_on_arrival_raises_nothing_of_its_own() {
        let mut d = quiet(primary_domain());

        d.prove_on_arrival().unwrap();

        assert_eq!(d.verification_status(), VerificationStatus::Verified);
        assert!(raised_names(&mut d).is_empty());
    }

    /// Acme asks for a certificate for its verified `acme.com`. The request
    /// is raised and nothing about the domain changes.
    #[test]
    fn asking_for_a_certificate_raises_tenant_domain_tls_requested() {
        let mut d = primary_domain();
        d.mark_verified().unwrap();
        let mut d = quiet(d);

        d.request_certificate().unwrap();

        assert_eq!(raised_names(&mut d), ["tenant.domain_tls_requested"]);
        assert_eq!(d.tls_status(), TlsStatus::NotRequired);
    }

    /// A certificate is issued for `auth.acme.com` and later renewed. Each
    /// is raised with the certificate's expiry.
    #[test]
    fn serving_a_certificate_raises_tenant_domain_tls_provisioned() {
        let mut d = delegated_domain();
        d.mark_verified().unwrap();
        let mut d = quiet(d);
        let issued = cert();

        d.mark_tls_active(&issued).unwrap();
        d.mark_tls_renewed(&issued).unwrap();

        let events = raised(&mut d);
        let expiry = issued.expires_at().to_string();
        assert_eq!(events.len(), 2);
        for event in &events {
            assert_eq!(
                event.event_type().to_string(),
                "tenant.domain_tls_provisioned"
            );
            assert_eq!(event.payload().get("expires_at"), Some(expiry.as_str()));
        }
    }

    /// An admin removes `acme.com`. The removal is raised.
    #[test]
    fn removing_raises_tenant_domain_removed() {
        let acme = active();
        let admin = person("admin@acme.test");
        let scope = scope_of(&acme);
        let new = claim("acme.com", DomainConnection::SelfManaged, "token");
        let mut d =
            quiet(RegisteredDomain::register(new, &scope, holding(&admin, &acme, ADMIN)).unwrap());

        d.remove(&scope, holding(&admin, &acme, ADMIN)).unwrap();

        assert_eq!(raised_names(&mut d), ["tenant.domain_removed"]);
    }

    /// Removal by a viewer, certificate activation and requests for an
    /// unverified domain, and loss of a proof never made all fail without events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let acme = active();
        let sam = person("sam@acme.test");
        let scope = scope_of(&acme);
        let view = [SystemPermission::Domains(DomainAction::View)];
        let mut d = quiet(primary_domain());

        let removed = d.remove(&scope, holding(&sam, &acme, &view));
        let served = d.mark_tls_active(&cert());
        let asked = d.request_certificate();
        let lost = d.mark_verification_failed();

        assert!(removed.is_err());
        assert!(served.is_err());
        assert!(asked.is_err());
        assert!(lost.is_err());
        assert!(raised_names(&mut d).is_empty());
    }
}
