/// NIST 800-63 Authentication Assurance Level.
///
/// How strongly the current session proved who the user is. Higher levels
/// need stronger factors.
///
/// Routes and resources can require a minimum level. A session below it is
/// asked to step up, for example with MFA to go from AAL1 to AAL2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AssuranceLevel {
    /// One factor, such as a password, a magic link or a social login.
    /// Enough for low-risk applications.
    Aal1,

    /// Two independent factors, such as a password and a TOTP code, or a
    /// password and `WebAuthn`. Needed for sensitive operations.
    Aal2,

    /// Two factors, at least one of them a hardware device such as a
    /// `WebAuthn` security key or a smart card. Needed where security
    /// matters most, such as financial admin operations.
    Aal3,
}

/// The strongest factor a sign-in used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrongestFactor {
    /// A password, a magic link or single sign-on, and nothing more.
    PasswordOrSso,
    /// A second factor from software, such as an authenticator app.
    SoftwareMfa,
    /// A second factor bound to hardware, such as a security key.
    HardwareMfa,
}

impl AssuranceLevel {
    /// Every level, weakest first.
    pub const ALL: [Self; 3] = [Self::Aal1, Self::Aal2, Self::Aal3];

    /// The OIDC `acr` value (Authentication Context Class Reference) this
    /// level is named by: `aal1`, `aal2` or `aal3`.
    #[must_use]
    pub fn acr(self) -> &'static str {
        match self {
            Self::Aal1 => "aal1",
            Self::Aal2 => "aal2",
            Self::Aal3 => "aal3",
        }
    }

    /// The level an `acr` value names, if it names one.
    #[must_use]
    pub fn from_acr(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.acr() == value)
    }

    /// Whether this level satisfies a required minimum.
    ///
    /// Levels are ordered: `AAL3 > AAL2 > AAL1`.
    #[must_use]
    pub fn satisfies(&self, required: Self) -> bool {
        *self >= required
    }

    /// The level the strongest factor used reaches.
    ///
    /// - A password, magic link or single sign-on alone gives AAL1.
    /// - A software second factor, such as TOTP, gives AAL2.
    /// - A hardware second factor, such as a `WebAuthn` key, gives AAL3.
    #[must_use]
    pub fn from_factor(strongest: StrongestFactor) -> Self {
        match strongest {
            StrongestFactor::PasswordOrSso => Self::Aal1,
            StrongestFactor::SoftwareMfa => Self::Aal2,
            StrongestFactor::HardwareMfa => Self::Aal3,
        }
    }
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aal1 => f.write_str("AAL1"),
            Self::Aal2 => f.write_str("AAL2"),
            Self::Aal3 => f.write_str("AAL3"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each level reads back from its `acr` value; any other value names
    /// none.
    #[test]
    fn each_level_reads_back_from_its_acr() {
        for level in AssuranceLevel::ALL {
            assert_eq!(AssuranceLevel::from_acr(level.acr()), Some(level));
        }
        assert_eq!(AssuranceLevel::from_acr("gold"), None);
    }

    /// AAL3 sorts above AAL2, and AAL2 above AAL1.
    #[test]
    fn levels_are_ordered() {
        assert!(AssuranceLevel::Aal3 > AssuranceLevel::Aal2);
        assert!(AssuranceLevel::Aal2 > AssuranceLevel::Aal1);
    }

    /// A session meets a requirement at its own level or below. An AAL1
    /// session does not meet AAL2, and an AAL2 session does not meet AAL3.
    #[test]
    fn satisfies_same_or_higher() {
        assert!(AssuranceLevel::Aal3.satisfies(AssuranceLevel::Aal3));
        assert!(AssuranceLevel::Aal3.satisfies(AssuranceLevel::Aal2));
        assert!(AssuranceLevel::Aal3.satisfies(AssuranceLevel::Aal1));
        assert!(AssuranceLevel::Aal2.satisfies(AssuranceLevel::Aal1));
        assert!(!AssuranceLevel::Aal1.satisfies(AssuranceLevel::Aal2));
        assert!(!AssuranceLevel::Aal2.satisfies(AssuranceLevel::Aal3));
    }

    /// A sign-in with only a password or single sign-on reaches AAL1.
    #[test]
    fn password_only_is_aal1() {
        assert_eq!(
            AssuranceLevel::from_factor(StrongestFactor::PasswordOrSso),
            AssuranceLevel::Aal1
        );
    }

    /// A sign-in whose strongest factor is an authenticator app reaches AAL2.
    #[test]
    fn software_mfa_is_aal2() {
        assert_eq!(
            AssuranceLevel::from_factor(StrongestFactor::SoftwareMfa),
            AssuranceLevel::Aal2
        );
    }

    /// A sign-in whose strongest factor is a hardware key reaches AAL3.
    #[test]
    fn hardware_mfa_is_aal3() {
        assert_eq!(
            AssuranceLevel::from_factor(StrongestFactor::HardwareMfa),
            AssuranceLevel::Aal3
        );
    }

    /// The levels print as "AAL1", "AAL2" and "AAL3", the names NIST uses.
    #[test]
    fn assurance_levels_print_as_their_aal_names() {
        assert_eq!(AssuranceLevel::Aal1.to_string(), "AAL1");
        assert_eq!(AssuranceLevel::Aal2.to_string(), "AAL2");
        assert_eq!(AssuranceLevel::Aal3.to_string(), "AAL3");
    }
}
