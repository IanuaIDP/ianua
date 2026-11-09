/// Validation limits for the whole platform, read from configuration.
///
/// They are built once at startup from config files or environment
/// variables. Value object constructors take them as input, so no deployment
/// number is fixed in the domain.
///
/// # Examples
///
/// ```
/// # use ianua_domain::shared::config::DomainLimits;
/// let limits = DomainLimits::default();
/// assert_eq!(limits.slug.min_length, 2);
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainLimits {
    /// Limits for tenant slugs.
    pub slug: SlugLimits,

    /// Limits for display names.
    pub display_name: DisplayNameLimits,

    /// Limits on input size for validation.
    pub validation: ValidationLimits,
}

/// Limits for a tenant's slug, the DNS label in its address.
///
/// A slug appears in a host name such as `acme.ianua.example.com`, so it
/// keeps the DNS label rules.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlugLimits {
    /// The shortest slug, in bytes. DNS allows 1, and 2 is the default.
    pub min_length: usize,

    /// The longest slug, in bytes. A DNS label holds at most 63.
    pub max_length: usize,
}

/// Limits for display names.
///
/// Used for tenant names, user names and other labels shown in admin
/// screens and branding.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DisplayNameLimits {
    /// The shortest name, in Unicode characters. The default is 1.
    pub min_length: usize,

    /// The longest name, in Unicode characters. The default is 255.
    pub max_length: usize,
}

/// Limits on how much input validation reads.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidationLimits {
    /// The largest input in bytes a validator should accept.
    ///
    /// No code reads this field. A [`Validator`] takes its limit as an
    /// argument to `max_bytes`.
    ///
    /// [`Validator`]: crate::shared::validation::Validator
    pub max_input_bytes: usize,
}

impl Default for DomainLimits {
    /// Limits for development and tests.
    ///
    /// A production deployment loads its limits from configuration.
    fn default() -> Self {
        Self {
            slug: SlugLimits::default(),
            display_name: DisplayNameLimits::default(),
            validation: ValidationLimits::default(),
        }
    }
}

impl Default for SlugLimits {
    fn default() -> Self {
        Self {
            min_length: 2,
            max_length: 63,
        }
    }
}

impl Default for DisplayNameLimits {
    fn default() -> Self {
        Self {
            min_length: 1,
            max_length: 255,
        }
    }
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1_048_576,
        }
    }
}
