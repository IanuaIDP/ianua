//! The secrets every key is made from, the keys stored secrets are sealed
//! under, and how hard passwords are hashed.
//!
//! Read by role. [`SharedKeys`] are what both planes hold: the shared root
//! (`HMAC_SECRET`) and the sealing keys. [`control_root`] reads the control
//! plane's own root (`EVENT_SIGNING_SECRET`), which only the control plane
//! holds, so the gateway reads its keys without ever reading that one.
//! [`CryptoConfig`] is the control plane's whole set.

use std::num::NonZeroUsize;
use std::time::Duration;

use ianua_infra::crypto::{
    Argon2PasswordHasher, Argon2Settings, EventSeal, RootSecret, SealingKey,
};

use crate::env::{ConfigError, Env, Read};

/// The keys both planes hold.
#[derive(Debug, Clone)]
pub struct SharedKeys {
    /// `HMAC_SECRET`: the root the digests of handed-out secrets and the
    /// gateway's seals are made from. The gateway holds it too, with the
    /// same value, or their digests do not match.
    pub shared_root: RootSecret,
    /// `ENCRYPTION_KEY` under `ENCRYPTION_KEY_ID` (`k1`): the key stored
    /// secrets are sealed under now.
    pub sealing_key: SealingKey,
    /// `ENCRYPTION_RETIRED_KEYS`: keys values sealed earlier are still
    /// opened with, `id:key` pairs, comma-separated.
    pub retired_keys: Vec<SealingKey>,
}

impl SharedKeys {
    /// The shared root and the sealing keys `vars` holds, and nothing of
    /// the control plane's root.
    ///
    /// # Errors
    ///
    /// A missing or unreadable key, or a retired key filed under the
    /// current key's id or twice.
    pub fn read(vars: &Env) -> Read<Self> {
        let shared_root = root(vars, "HMAC_SECRET")?;
        let key_id = vars.text("ENCRYPTION_KEY_ID", "k1")?;
        let sealing_key =
            SealingKey::parse(&key_id, vars.required_secret("ENCRYPTION_KEY")?.expose())
                .map_err(|cause| ConfigError::rejected("ENCRYPTION_KEY", cause))?;
        Ok(Self {
            shared_root,
            retired_keys: retired_keys(vars, &key_id)?,
            sealing_key,
        })
    }
}

/// `EVENT_SIGNING_SECRET`: the control plane's own root, for the seals on
/// events, live updates, delivery receipts and the audit chain, and for
/// the passkey ceremonies, the file links, the pairwise `NameID`s SAML
/// apps are sent and the sign-in puzzles. The gateway never holds it, so
/// it cannot forge any of them. Read beside the `shared` keys, which it
/// must not equal.
///
/// # Errors
///
/// A missing or unreadable root, or one equal to the shared root.
pub fn control_root(vars: &Env, shared: &SharedKeys) -> Read<RootSecret> {
    let control = root(vars, "EVENT_SIGNING_SECRET")?;
    ensure_roots_apart(&shared.shared_root, &control)?;
    Ok(control)
}

/// How hard passwords are hashed, and how many at once.
#[derive(Debug, Clone, Copy)]
pub struct HashSettings {
    /// `ARGON2_MEMORY_KIB` (65536), `ARGON2_ITERATIONS` (3) and
    /// `ARGON2_LANES` (4).
    pub argon2: Argon2Settings,
    /// `ARGON2_MAX_CONCURRENCY`: password hashes run at once; `0`, the
    /// default, means one per CPU.
    pub concurrency: NonZeroUsize,
    /// `ARGON2_PERMIT_WAIT_MS` (500): how long a sign-in waits for a free
    /// hash before it is answered busy.
    pub wait: Duration,
}

impl HashSettings {
    /// The hash settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A setting that does not read, or settings Argon2 refuses.
    pub fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            argon2: argon2(vars)?,
            concurrency: hash_concurrency(vars)?,
            wait: vars.millis("ARGON2_PERMIT_WAIT_MS", Duration::from_millis(500))?,
        })
    }
}

/// The control plane's keys and the work of hashing.
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// The keys the gateway holds too.
    pub shared: SharedKeys,
    /// The control plane's own root, which the gateway never holds.
    pub control_root: RootSecret,
    /// How hard passwords are hashed.
    pub hashing: HashSettings,
}

impl CryptoConfig {
    /// The keys `vars` holds.
    ///
    /// # Errors
    ///
    /// A missing or unreadable key, the control plane's root equal to the
    /// shared one, a retired key filed under the current key's id or twice,
    /// or hash settings Argon2 refuses.
    pub fn read(vars: &Env) -> Read<Self> {
        let shared = SharedKeys::read(vars)?;
        Ok(Self {
            control_root: control_root(vars, &shared)?,
            hashing: HashSettings::read(vars)?,
            shared,
        })
    }
}

/// The root secret `name` holds.
fn root(vars: &Env, name: &str) -> Read<RootSecret> {
    RootSecret::parse(vars.required_secret(name)?.expose())
        .map_err(|cause| ConfigError::rejected(name, cause))
}

/// Refuses the control plane's root being the shared one, which the
/// gateway holds: the gateway could then seal any event, such as a
/// `tenant.deleted`. Compared by what each seals, so two spellings of one
/// key are caught too.
fn ensure_roots_apart(shared: &RootSecret, control: &RootSecret) -> Read<()> {
    let probe = |root: &RootSecret| EventSeal::control_plane(root).seal("ianua.config.probe", b"");
    if probe(shared) == probe(control) {
        return Err(ConfigError::contradicts(
            "EVENT_SIGNING_SECRET",
            "is the same key as HMAC_SECRET, which the gateway holds; give it a key of its own",
        ));
    }
    Ok(())
}

/// `ENCRYPTION_RETIRED_KEYS`, each `id:key`, none under `current_id` and
/// no id twice.
fn retired_keys(vars: &Env, current_id: &str) -> Read<Vec<SealingKey>> {
    let name = "ENCRYPTION_RETIRED_KEYS";
    let Some(list) = vars.secret(name)? else {
        return Ok(Vec::new());
    };
    let mut ids: Vec<&str> = Vec::new();
    let mut keys = Vec::new();
    for entry in list
        .expose()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((id, key)) = entry.split_once(':') else {
            return Err(ConfigError::invalid(
                name,
                "must list id:key pairs, comma-separated",
            ));
        };
        let id = id.trim();
        ensure_retired_id(id, current_id, &ids)?;
        keys.push(
            SealingKey::parse(id, key.trim())
                .map_err(|cause| ConfigError::rejected(name, cause))?,
        );
        ids.push(id);
    }
    Ok(keys)
}

/// Refuses a retired key identifier already assigned to another sealing key.
fn ensure_retired_id(id: &str, current_id: &str, ids: &[&str]) -> Read<()> {
    if id == current_id || ids.contains(&id) {
        return Err(ConfigError::contradicts(
            "ENCRYPTION_RETIRED_KEYS",
            format!("files two keys under the id {id:?}; every key needs an id of its own"),
        ));
    }
    Ok(())
}

/// The Argon2 settings, checked by building a hasher with them.
fn argon2(vars: &Env) -> Read<Argon2Settings> {
    let standard = Argon2Settings::default();
    let settings = Argon2Settings {
        memory_kib: vars.number("ARGON2_MEMORY_KIB", standard.memory_kib)?,
        iterations: vars.number("ARGON2_ITERATIONS", standard.iterations)?,
        lanes: vars.number("ARGON2_LANES", standard.lanes)?,
    };
    Argon2PasswordHasher::new(settings).map_err(|cause| {
        ConfigError::rejected(
            "ARGON2_MEMORY_KIB, ARGON2_ITERATIONS and ARGON2_LANES",
            cause,
        )
    })?;
    Ok(settings)
}

/// `ARGON2_MAX_CONCURRENCY`, with `0` as one hash per CPU.
fn hash_concurrency(vars: &Env) -> Read<NonZeroUsize> {
    let asked = vars.number("ARGON2_MAX_CONCURRENCY", 0_usize)?;
    let cpus = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    Ok(NonZeroUsize::new(asked).unwrap_or(cpus))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const CONTROL: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const SEALING: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const OLD: &str = "0000000000000000000000000000000000000000000000000000000000000004";

    fn keys() -> Vec<(&'static str, &'static str)> {
        vec![
            ("HMAC_SECRET", SHARED),
            ("EVENT_SIGNING_SECRET", CONTROL),
            ("ENCRYPTION_KEY", SEALING),
        ]
    }

    /// The three keys read, with the documented hash settings.
    #[test]
    fn the_keys_read_with_the_documented_hash_settings() {
        let config = CryptoConfig::read(&Env::of(keys())).unwrap();

        assert_eq!(config.hashing.argon2, Argon2Settings::default());
        assert!(config.shared.retired_keys.is_empty());
    }

    /// Reading shared keys succeeds without consulting the control root,
    /// even when that setting is present.
    #[test]
    fn the_shared_keys_never_read_the_control_root() {
        let vars = Env::of(keys());

        let shared = SharedKeys::read(&vars);

        assert!(shared.is_ok());
        assert!(
            !vars
                .set_names()
                .contains(&"EVENT_SIGNING_SECRET".to_owned())
        );
    }

    /// The shared keys read with no control plane root set at all.
    #[test]
    fn the_shared_keys_read_without_a_control_root() {
        let pairs: Vec<_> = keys()
            .into_iter()
            .filter(|(name, _)| *name != "EVENT_SIGNING_SECRET")
            .collect();

        assert!(SharedKeys::read(&Env::of(pairs)).is_ok());
    }

    /// A short root secret is refused by setting name without exposing
    /// its passphrase in the error.
    #[test]
    fn a_short_root_is_refused_without_repeating_it() {
        let mut pairs = keys();
        pairs[0] = ("HMAC_SECRET", "correct-horse-battery");

        let read = CryptoConfig::read(&Env::of(pairs));

        let error = read.unwrap_err();
        assert!(matches!(&error, ConfigError::Rejected { name, .. } if name == "HMAC_SECRET"));
        assert!(!error.to_string().contains("correct-horse"));
    }

    /// The control root cannot reuse the shared key, even when one is
    /// written as base64 and the other as hexadecimal.
    #[test]
    fn the_control_root_equal_to_the_shared_one_is_refused() {
        let mut pairs = keys();
        pairs[1] = (
            "EVENT_SIGNING_SECRET",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
        );

        let read = CryptoConfig::read(&Env::of(pairs));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "EVENT_SIGNING_SECRET")
        );
    }

    /// A missing control plane root is refused.
    #[test]
    fn a_missing_control_root_is_refused() {
        let pairs: Vec<_> = keys()
            .into_iter()
            .filter(|(name, _)| *name != "EVENT_SIGNING_SECRET")
            .collect();

        let read = CryptoConfig::read(&Env::of(pairs));

        assert!(matches!(read, Err(ConfigError::Missing { .. })));
    }

    /// Retired keys read as `id:key` pairs.
    #[test]
    fn retired_keys_read_as_id_and_key_pairs() {
        let mut pairs = keys();
        let retired = format!("k0:{OLD}");
        pairs.push(("ENCRYPTION_KEY_ID", "k2"));
        pairs.push(("ENCRYPTION_RETIRED_KEYS", retired.as_str()));

        let config = CryptoConfig::read(&Env::of(pairs)).unwrap();

        assert_eq!(config.shared.retired_keys.len(), 1);
    }

    /// A retired key cannot take the current key's identifier; the
    /// configuration error names the retired-key setting.
    #[test]
    fn a_retired_key_under_the_current_id_is_refused() {
        let mut pairs = keys();
        let retired = format!("k1:{OLD}");
        pairs.push(("ENCRYPTION_RETIRED_KEYS", retired.as_str()));

        let read = CryptoConfig::read(&Env::of(pairs));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "ENCRYPTION_RETIRED_KEYS")
        );
    }

    /// A retired entry that is no pair is refused.
    #[test]
    fn a_retired_entry_that_is_no_pair_is_refused() {
        let mut pairs = keys();
        pairs.push(("ENCRYPTION_RETIRED_KEYS", OLD));

        assert!(CryptoConfig::read(&Env::of(pairs)).is_err());
    }

    /// Hash settings Argon2 refuses stop the start.
    #[test]
    fn hash_settings_argon2_refuses_are_refused() {
        let mut pairs = keys();
        pairs.push(("ARGON2_LANES", "0"));

        let read = CryptoConfig::read(&Env::of(pairs));

        assert!(matches!(read, Err(ConfigError::Rejected { .. })));
    }

    /// No concurrency asked for is one hash per CPU.
    #[test]
    fn no_concurrency_asked_for_is_one_hash_per_cpu() {
        let config = CryptoConfig::read(&Env::of(keys())).unwrap();

        assert!(config.hashing.concurrency.get() >= 1);
    }

    /// Configuration debug output omits the sealing key and shared root.
    #[test]
    fn the_keys_never_print() {
        let config = CryptoConfig::read(&Env::of(keys())).unwrap();

        let shown = format!("{config:?}");
        assert!(!shown.contains(SEALING));
        assert!(!shown.contains(SHARED));
    }
}
