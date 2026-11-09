//! The second step of a password sign-in: risk, step-up, the second factor
//! owed, the session and the events.

use crate::domains::authentication::credentials::breach::{BreachPolicy, BreachStatus};
use crate::domains::authentication::events::credential::PasswordBreachDetected;
use crate::domains::authentication::events::login::{
    LoginFailureReason, RiskSign, RiskySignIn, SignInCheck, SignInCheckUnavailable,
};
use crate::domains::authentication::mfa::owed::{Demand, FactorOwed, SecondFactor};
use crate::domains::authentication::operations::password_login::{
    LoginFailure, LoginResult, LoginRules, SecurityContext, VerifiedLogin,
};
use crate::domains::authentication::risk_engine::assessment::{
    LoginRiskAssessment, RiskAction, RiskLevel, TravelEvidence, TravelVelocity,
};
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use crate::domains::authentication::risk_engine::step_up::{
    AuthenticationContext, Sensitivity, SignInSignals, StepUpDecision,
};
use crate::domains::authentication::sessions::account_check::MaySignIn;
use crate::domains::authentication::sessions::session::{CreateSessionParams, Session};
use crate::domains::authentication::sessions::sign_in_progress::SignInProgress;
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use crate::isolation::scope::ResolvedTenant;
use crate::shared::events::event::DomainEvent;
use crate::types::{EventLabel, Fact, SessionId, TokenHash};

impl VerifiedLogin<'_> {
    /// Finishes the sign-in with what the application learned about it. It
    /// weighs the risk, decides what second factor is owed and opens the
    /// session.
    ///
    /// While the account is under attack, a device the person did not trust
    /// adds a risk signal, as [`AccountAttack::demand`] says: the password
    /// alone does not finish the sign-in.
    ///
    /// [`AccountAttack::demand`]: crate::domains::authentication::risk_engine::attack::AccountAttack::demand
    ///
    /// A lookup that was unavailable does not stop the sign-in. An unchecked
    /// password counts as clean, and an address that could not be placed
    /// counts as no location. A [`SignInCheckUnavailable`] records each
    /// missing check.
    ///
    /// # Errors
    ///
    /// - [`LoginFailure::RiskDenied`] when the risk is critical or the
    ///   tenant's step-up rules refuse the sign-in.
    /// - [`LoginFailure::NothingToProveWith`] when the sign-in looks risky,
    ///   or comes from a new device while the account is under attack, the
    ///   person has no second factor, no mail can reach them, and no
    ///   accepted invitation vouches for them.
    /// - [`LoginFailure::MethodNotAdmitted`] when the sign-in would finish
    ///   below the baseline.
    /// - [`LoginFailure::Unavailable`] when no refresh token could be made.
    pub fn conclude(
        self,
        tracker: &mut LoginAttemptTracker,
        config: &LoginRules<'_, impl RefreshTokenGenerator>,
        security: &SecurityContext<'_>,
    ) -> Result<LoginResult, LoginFailure> {
        let risk_assessment = self.assess_risk(security);
        let context = Self::context(security, &risk_assessment);
        let step_up = config.step_up_policy.evaluate(&context);
        self.ensure_risk_accepted(tracker, &risk_assessment, step_up)?;
        let breach = security
            .breach
            .known()
            .copied()
            .unwrap_or(BreachStatus::Clean);
        let demand = security
            .attack
            .demand(config.step_up_policy.demand(&context), security.device);
        let owed = self.second_factor(config, breach, demand);
        let second_factor = self.ensure_provable(tracker, owed)?;
        let account = self.may_sign_in(tracker, config, second_factor)?;
        let (refresh_token, refresh_hash) = config
            .token_generator
            .generate()
            .map(RefreshToken::into_parts)
            .map_err(LoginFailure::Unavailable)?;
        let second_factor = account.progress().owed();
        Ok(LoginResult {
            session: self.create_session(config, account, refresh_hash),
            refresh_token,
            second_factor,
            password_due: self.candidate.password_due,
            events: self.security_events(breach, security, &risk_assessment),
            risk_assessment,
            occurred_at: self.login.at,
        })
    }

    fn assess_risk(&self, security: &SecurityContext<'_>) -> LoginRiskAssessment {
        let travel = match (security.location.fact(), security.history.last()) {
            (Fact::Known(current), Fact::Known((prev_geo, prev_time))) => Fact::Known(
                TravelVelocity::compute(prev_geo, current, prev_time, self.login.at),
            ),
            (Fact::Unknown, _) | (_, Fact::Unknown) => Fact::Unknown,
        };
        let (risk_level, action) = match &travel {
            Fact::Known(v) if v.is_impossible() => (RiskLevel::Critical, RiskAction::Block),
            Fact::Known(v) if v.is_suspicious() => (RiskLevel::High, RiskAction::StepUpMfa),
            Fact::Known(_) | Fact::Unknown => (RiskLevel::Low, RiskAction::Allow),
        };
        LoginRiskAssessment::new(
            risk_level,
            action,
            TravelEvidence {
                current_location: security.location.fact().cloned(),
                travel_velocity: travel,
            },
            Vec::new(),
        )
    }

    /// What the tenant's step-up rules read of this sign-in: its risk, the
    /// device, and whether it comes from a country the person has signed in
    /// from before.
    fn context(
        security: &SecurityContext<'_>,
        assessment: &LoginRiskAssessment,
    ) -> AuthenticationContext {
        AuthenticationContext::new(
            AssuranceLevel::Aal1,
            assessment.risk_level(),
            SignInSignals {
                device: security.device,
                country: security
                    .history
                    .country_familiarity(assessment.current_location()),
                operation: Sensitivity::Ordinary,
            },
        )
    }

    fn ensure_risk_accepted(
        &self,
        tracker: &mut LoginAttemptTracker,
        assessment: &LoginRiskAssessment,
        step_up: StepUpDecision,
    ) -> Result<(), LoginFailure> {
        if step_up == StepUpDecision::HardwareKeyRequired {
            return Err(self.method_not_admitted(tracker));
        }
        let refused =
            assessment.risk_level() == RiskLevel::Critical || step_up == StepUpDecision::Denied;
        if !refused {
            return Ok(());
        }
        let events = self
            .login
            .failure_events(tracker, LoginFailureReason::RiskTooHigh);
        Err(LoginFailure::RiskDenied { events })
    }

    /// The refusal for a password that cannot reach the tenant's baseline.
    /// It is about the method, not about how risky the sign-in looked.
    fn method_not_admitted(&self, tracker: &mut LoginAttemptTracker) -> LoginFailure {
        LoginFailure::MethodNotAdmitted {
            events: self
                .login
                .failure_events(tracker, LoginFailureReason::MethodDisabled),
        }
    }

    /// The second factor owed. A breached password is a risk signal. Someone
    /// with a factor must use it, and someone without one confirms by email.
    /// A breach never lets setting a factor up stand in for that proof.
    /// Where no mail can reach them it is refused, unless an accepted
    /// invitation vouches for this, their first sign-in: then a factor is
    /// set up before they are let in.
    fn second_factor(
        &self,
        config: &LoginRules<'_, impl RefreshTokenGenerator>,
        breach: BreachStatus,
        demand: Demand,
    ) -> FactorOwed {
        let breach_asks = breach.is_breached() && config.breach_policy == BreachPolicy::StepUp;
        let demand = if breach_asks {
            demand.with_signal()
        } else {
            demand
        };
        FactorOwed::under(
            config.mfa_policy,
            demand,
            self.candidate.enrolment,
            config.mail,
            self.candidate.vouching,
        )
    }

    /// What the session owes, once `owed` is something the person can
    /// give. A refusal is counted and recorded as a failed sign-in.
    fn ensure_provable(
        &self,
        tracker: &mut LoginAttemptTracker,
        owed: FactorOwed,
    ) -> Result<SecondFactor, LoginFailure> {
        owed.owed().map_err(|_| LoginFailure::NothingToProveWith {
            events: self
                .login
                .failure_events(tracker, LoginFailureReason::RiskTooHigh),
        })
    }

    /// The sign-in the checked password begins for the account, which
    /// `verify` found active before this login could reach here, owing
    /// `second_factor`. It is refused when it would finish below the
    /// tenant's baseline.
    fn may_sign_in(
        &self,
        tracker: &mut LoginAttemptTracker,
        config: &LoginRules<'_, impl RefreshTokenGenerator>,
        second_factor: SecondFactor,
    ) -> Result<MaySignIn<ResolvedTenant>, LoginFailure> {
        let way_in = WayIn::by_password(self.candidate.user_id.into());
        let progress = SignInProgress::start(way_in, second_factor, config.step_up_policy)
            .map_err(|_| self.method_not_admitted(tracker))?;
        Ok(MaySignIn::active(self.candidate.user_id, progress))
    }

    /// The session for the account and the sign-in begun for it.
    fn create_session(
        &self,
        config: &LoginRules<'_, impl RefreshTokenGenerator>,
        account: MaySignIn<ResolvedTenant>,
        refresh_token_hash: TokenHash,
    ) -> Session<ResolvedTenant> {
        Session::create(
            account,
            CreateSessionParams {
                id: SessionId::new(),
                refresh_token_hash,
                ip_address: self.login.ip_address.clone(),
                user_agent: self.login.user_agent.clone(),
                timeout: *config.timeout_policy,
            },
        )
    }

    /// A breach found, and every check that could not run.
    fn security_events(
        &self,
        breach: BreachStatus,
        security: &SecurityContext<'_>,
        assessment: &LoginRiskAssessment,
    ) -> Vec<DomainEvent> {
        let unavailable = [
            (SignInCheck::Breach, security.breach.is_unavailable()),
            (SignInCheck::Location, security.location.is_unavailable()),
        ];
        self.breach_event(breach)
            .into_iter()
            .chain(self.risky_event(security, assessment))
            .chain(
                unavailable
                    .into_iter()
                    .filter(|(_, missing)| *missing)
                    .map(|(check, _)| self.check_unavailable_event(check)),
            )
            .collect()
    }

    /// The record of a sign-in that went ahead though it looked risky: a
    /// fast journey, a country the person never signed in from, or both.
    fn risky_event(
        &self,
        security: &SecurityContext<'_>,
        assessment: &LoginRiskAssessment,
    ) -> Option<DomainEvent> {
        let sign = risk_sign(security, assessment)?;
        Some(
            self.login.recorded(RiskySignIn {
                user_id: self.candidate.user_id,
                user_label: EventLabel::of(self.login.email.as_str()),
                country: assessment
                    .current_location()
                    .known()
                    .map_or(Fact::Unknown, |place| {
                        Fact::Known(place.country_code().clone())
                    }),
                sign,
                occurred_at: self.login.at,
            }),
        )
    }

    fn breach_event(&self, breach: BreachStatus) -> Option<DomainEvent> {
        let BreachStatus::Breached(count) = breach else {
            return None;
        };
        Some(self.login.recorded(PasswordBreachDetected {
            user_id: self.candidate.user_id,
            user_label: EventLabel::of(self.login.email.as_str()),
            occurrence_count: count,
            occurred_at: self.login.at,
        }))
    }

    fn check_unavailable_event(&self, check: SignInCheck) -> DomainEvent {
        self.login.recorded(SignInCheckUnavailable {
            user_id: self.candidate.user_id,
            user_label: EventLabel::of(self.login.email.as_str()),
            check,
            occurred_at: self.login.at,
        })
    }
}

/// What made a sign-in that went ahead look risky, if anything: a journey
/// fast enough to rate it high risk, a placed country the person never
/// signed in from before, or both. A refused sign-in never gets here.
fn risk_sign(security: &SecurityContext<'_>, assessment: &LoginRiskAssessment) -> Option<RiskSign> {
    let fast = assessment.risk_level() == RiskLevel::High;
    let new_country = security
        .history
        .is_new_country(assessment.current_location());
    match (fast, new_country) {
        (true, true) => Some(RiskSign::FastTravelToNewCountry),
        (true, false) => Some(RiskSign::FastTravel),
        (false, true) => Some(RiskSign::NewCountry),
        (false, false) => None,
    }
}
