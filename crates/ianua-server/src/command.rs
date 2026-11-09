//! What the binary was asked to do, from its command line.

use std::path::PathBuf;

use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::Email;

/// The words that make the platform's first operator, before the address.
const CREATE_OPERATOR: [&str; 2] = ["operator", "create"];

/// The flag naming the first operator's address.
const EMAIL_FLAG: &str = "--email";

/// What the binary was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Serve the API, run the worker, or both, as `MODE` says. The
    /// default.
    Serve,
    /// Bring the schema up to date and make the platform's roles, then
    /// exit.
    Migrate,
    /// Make a self-hosted installation's organization and owner, then
    /// exit.
    Install,
    /// Make the platform's first operator, signing in with `email` and the
    /// password `OPERATOR_PASSWORD` holds, then exit. Refused once any
    /// operator exists.
    CreateOperator {
        /// The address the operator signs in with.
        email: Email,
    },
    /// Seed a demonstration organization through the use cases, then exit.
    /// Development only.
    Demo,
    /// Issue the private authority and the certificates of the link the
    /// nameservers outside the cluster follow the zones on, write them to a
    /// folder, then exit. Reads no setting and builds no platform.
    LinkPki(LinkPkiRequest),
    /// Issue the connector authority and the certificate of the gateway's
    /// connector listener, write them to a folder, then exit. Reads no
    /// setting and builds no platform.
    ConnectorPki(ConnectorPkiRequest),
    /// Issue the internal authority, the certificates of the gateway's
    /// workflow and runner listeners and the API's relay listener, and
    /// those of the worker and the gateway calling them, write them to a
    /// folder, then exit. Reads no setting and builds no platform.
    InternalPki(InternalPkiRequest),
    /// Serve the sandbox gate, the one process holding the container
    /// engine's socket, until stopped. Builds no platform.
    SandboxGate,
    /// Serve the network filter code reaches its allowed hosts through,
    /// until stopped. Builds no platform.
    SandboxProxy,
}

/// What `ianua link-pki` issues, and where it writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPkiRequest {
    /// `--server-name`: the name, or address, the nameservers dial the
    /// listener by.
    pub server_name: String,
    /// `--nameservers`: one client certificate per name, such as
    /// `ns1,ns2`.
    pub nameservers: Vec<String>,
    /// `--out`: the folder the files are written to. It must not hold any
    /// of them already.
    pub out: PathBuf,
}

/// What `ianua connector-pki` issues, and where it writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorPkiRequest {
    /// `--listener-names`: the names, or addresses, connectors dial the
    /// gateway's connector listener by, such as `connect.ianua.io`.
    pub listener_names: Vec<String>,
    /// `--out`: the folder the files are written to. It must not hold any
    /// of them already.
    pub out: PathBuf,
}

/// What `ianua internal-pki` issues, and where it writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalPkiRequest {
    /// `--gateway-name`: the name, or address, the worker dials the
    /// gateway's workflow listener by, such as `gateway.ianua.svc`.
    pub gateway_name: String,
    /// `--api-name`: the name, or address, the gateway dials the API's
    /// relay listener by, such as `api.ianua.svc`.
    pub api_name: String,
    /// `--out`: the folder the files are written to. It must not hold any
    /// of them already.
    pub out: PathBuf,
}

/// The word that issues the nameserver link's certificates.
const LINK_PKI: &str = "link-pki";

/// The word that issues the internal links' certificates.
const INTERNAL_PKI: &str = "internal-pki";

/// The word that issues the connector authority.
const CONNECTOR_PKI: &str = "connector-pki";

/// The command line named nothing the binary does.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// No command has these words.
    #[error(
        "usage: ianua [serve | migrate | install | demo | sandbox-gate | sandbox-proxy | \
         operator create --email <address> | \
         link-pki --server-name <host> --nameservers <ns1,ns2> --out <folder> | \
         connector-pki --listener-names <host,...> --out <folder> | \
         internal-pki --gateway-name <host> --api-name <host> --out <folder>], got {given:?}"
    )]
    Unknown {
        /// What was given after the binary's name.
        given: Vec<String>,
    },
    /// The first operator's address is not one.
    #[error("--email {given:?} is not an email address")]
    Email {
        /// What was given as the address.
        given: String,
        /// Why it is not one.
        #[source]
        cause: ValidationError,
    },
}

impl Command {
    /// The command `args`, the words after the binary's name, ask for:
    /// none is `serve`.
    ///
    /// # Errors
    ///
    /// [`CommandError::Unknown`] for words no command has, and
    /// [`CommandError::Email`] for an operator address that is not one.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, CommandError> {
        let given: Vec<String> = args.into_iter().collect();
        let command = match given.as_slice() {
            [] => Some(Ok(Self::Serve)),
            [word] => Self::named(word).map(Ok),
            [first, second, flags @ ..] if [first.as_str(), second.as_str()] == CREATE_OPERATOR => {
                Self::create_operator(flags)
            }
            [first, flags @ ..] if first == LINK_PKI => Self::link_pki(flags).map(Ok),
            [first, flags @ ..] if first == CONNECTOR_PKI => Self::connector_pki(flags).map(Ok),
            [first, flags @ ..] if first == INTERNAL_PKI => Self::internal_pki(flags).map(Ok),
            _ => None,
        };
        command.unwrap_or(Err(CommandError::Unknown { given }))
    }

    /// The command `word` names.
    fn named(word: &str) -> Option<Self> {
        match word {
            "serve" => Some(Self::Serve),
            "migrate" => Some(Self::Migrate),
            "install" => Some(Self::Install),
            "demo" => Some(Self::Demo),
            "sandbox-gate" => Some(Self::SandboxGate),
            "sandbox-proxy" => Some(Self::SandboxProxy),
            _ => None,
        }
    }

    /// The link certificates `flags` ask for: `--server-name`,
    /// `--nameservers` and `--out`, each once with its value, in any order,
    /// and nothing else; `None` when they are not that.
    fn link_pki(flags: &[String]) -> Option<Self> {
        let (mut server_name, mut nameservers, mut out) = (None, None, None);
        for pair in flags.chunks(2) {
            let [flag, value] = pair else {
                return None;
            };
            let slot = match flag.as_str() {
                "--server-name" => &mut server_name,
                "--nameservers" => &mut nameservers,
                "--out" => &mut out,
                _ => return None,
            };
            if slot.replace(value.clone()).is_some() {
                return None;
            }
        }
        let nameservers: Vec<String> = nameservers?
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();
        if nameservers.is_empty() {
            return None;
        }
        Some(Self::LinkPki(LinkPkiRequest {
            server_name: server_name?,
            nameservers,
            out: PathBuf::from(out?),
        }))
    }

    /// The connector authority `flags` ask for: `--listener-names` and
    /// `--out`, each once with its value, in any order, and nothing else;
    /// `None` when they are not that.
    fn connector_pki(flags: &[String]) -> Option<Self> {
        let (mut names, mut out) = (None, None);
        for pair in flags.chunks(2) {
            let [flag, value] = pair else {
                return None;
            };
            let slot = match flag.as_str() {
                "--listener-names" => &mut names,
                "--out" => &mut out,
                _ => return None,
            };
            if slot.replace(value.clone()).is_some() {
                return None;
            }
        }
        let listener_names: Vec<String> = names?
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();
        if listener_names.is_empty() {
            return None;
        }
        Some(Self::ConnectorPki(ConnectorPkiRequest {
            listener_names,
            out: PathBuf::from(out?),
        }))
    }

    /// The internal links' certificates `flags` ask for: `--gateway-name`,
    /// `--api-name` and `--out`, each once with its value, in any order,
    /// and nothing else; `None` when they are not that.
    fn internal_pki(flags: &[String]) -> Option<Self> {
        let (mut gateway_name, mut api_name, mut out) = (None, None, None);
        for pair in flags.chunks(2) {
            let [flag, value] = pair else {
                return None;
            };
            let slot = match flag.as_str() {
                "--gateway-name" => &mut gateway_name,
                "--api-name" => &mut api_name,
                "--out" => &mut out,
                _ => return None,
            };
            if slot.replace(value.clone()).is_some() {
                return None;
            }
        }
        Some(Self::InternalPki(InternalPkiRequest {
            gateway_name: gateway_name?,
            api_name: api_name?,
            out: PathBuf::from(out?),
        }))
    }

    /// The first operator `flags` name, as `--email <address>` or
    /// `--email=<address>`, or `None` when they are not that.
    fn create_operator(flags: &[String]) -> Option<Result<Self, CommandError>> {
        let address = match flags {
            [flag, address] if flag == EMAIL_FLAG => address.as_str(),
            [joined] => joined.strip_prefix(EMAIL_FLAG)?.strip_prefix('=')?,
            _ => return None,
        };
        Some(
            Email::new(address)
                .map(|email| Self::CreateOperator { email })
                .map_err(|cause| CommandError::Email {
                    given: address.to_owned(),
                    cause,
                }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| (*word).to_owned()).collect()
    }

    fn parsed(line: &[&str]) -> Result<Command, CommandError> {
        Command::parse(words(line))
    }

    /// An empty argument list selects the normal serving mode.
    #[test]
    fn no_command_serves() {
        assert_eq!(parsed(&[]).unwrap(), Command::Serve);
    }

    /// The documented subcommands select their matching startup actions.
    #[test]
    fn each_command_is_read_by_its_word() {
        assert_eq!(parsed(&["migrate"]).unwrap(), Command::Migrate);
        assert_eq!(parsed(&["install"]).unwrap(), Command::Install);
        assert_eq!(parsed(&["demo"]).unwrap(), Command::Demo);
        assert_eq!(parsed(&["serve"]).unwrap(), Command::Serve);
        assert_eq!(parsed(&["sandbox-gate"]).unwrap(), Command::SandboxGate);
        assert_eq!(parsed(&["sandbox-proxy"]).unwrap(), Command::SandboxProxy);
    }

    /// A misspelled subcommand or an extra command word returns an unknown-command error.
    #[test]
    fn an_unknown_command_is_refused() {
        assert!(matches!(
            parsed(&["migrat"]),
            Err(CommandError::Unknown { .. })
        ));
        assert!(matches!(
            parsed(&["migrate", "now"]),
            Err(CommandError::Unknown { .. })
        ));
    }

    /// The first operator is named by their address, given either way.
    #[test]
    fn the_first_operator_is_named_by_their_address() {
        let email = Email::new("root@ianua.dev").unwrap();
        let expected = Command::CreateOperator { email };

        assert_eq!(
            parsed(&["operator", "create", "--email", "root@ianua.dev"]).unwrap(),
            expected
        );
        assert_eq!(
            parsed(&["operator", "create", "--email=root@ianua.dev"]).unwrap(),
            expected
        );
    }

    /// Operator creation refuses a missing email value, an unknown flag
    /// or trailing arguments.
    #[test]
    fn creating_an_operator_needs_their_address_and_nothing_else() {
        let lines: [&[&str]; 4] = [
            &["operator", "create"],
            &["operator", "create", "--email"],
            &["operator", "create", "--name", "root"],
            &["operator", "create", "--email", "root@ianua.dev", "--now"],
        ];
        for line in lines {
            assert!(
                matches!(parsed(line), Err(CommandError::Unknown { .. })),
                "{line:?} was taken"
            );
        }
    }

    /// The connector authority is asked for by its two flags, in any order;
    /// one without a name, or with a flag nothing reads, is refused.
    #[test]
    fn the_connector_authority_is_asked_for_by_its_flags() {
        let asked = parsed(&[
            "connector-pki",
            "--out",
            "pki",
            "--listener-names",
            "connect.ianua.io, 203.0.113.7",
        ])
        .unwrap();

        assert_eq!(
            asked,
            Command::ConnectorPki(ConnectorPkiRequest {
                listener_names: vec!["connect.ianua.io".to_owned(), "203.0.113.7".to_owned()],
                out: PathBuf::from("pki"),
            })
        );
        assert!(parsed(&["connector-pki", "--listener-names", ",", "--out", "pki"]).is_err());
        assert!(
            parsed(&[
                "connector-pki",
                "--listener-names",
                "a",
                "--out",
                "pki",
                "--key",
                "k"
            ])
            .is_err()
        );
    }

    /// Internal-PKI commands missing, duplicating or adding an unsupported flag.
    const INTERNAL_PKI_REFUSALS: [&[&str]; 4] = [
        &["internal-pki", "--out", "pki", "--api-name", "a"],
        &["internal-pki", "--out", "pki", "--gateway-name", "g"],
        &[
            "internal-pki",
            "--out",
            "a",
            "--out",
            "b",
            "--gateway-name",
            "g",
            "--api-name",
            "a",
        ],
        &[
            "internal-pki",
            "--gateway-name",
            "g",
            "--api-name",
            "a",
            "--out",
            "pki",
            "--key",
            "k",
        ],
    ];

    /// The internal links' certificates are asked for by their three
    /// flags, in any order; a flag missing, given twice or unknown is
    /// refused.
    #[test]
    fn the_internal_certificates_are_asked_for_by_their_flags() {
        let asked = parsed(&[
            "internal-pki",
            "--out",
            "pki",
            "--api-name",
            "api.ianua.svc",
            "--gateway-name",
            "gateway.ianua.svc",
        ])
        .unwrap();

        assert_eq!(
            asked,
            Command::InternalPki(InternalPkiRequest {
                gateway_name: "gateway.ianua.svc".to_owned(),
                api_name: "api.ianua.svc".to_owned(),
                out: PathBuf::from("pki"),
            })
        );
        for line in INTERNAL_PKI_REFUSALS {
            assert!(parsed(line).is_err(), "{line:?}");
        }
    }

    /// The link's certificates are asked for by their three flags, in any
    /// order.
    #[test]
    fn the_link_certificates_are_asked_for_by_their_flags() {
        let parsed = parsed(&[
            "link-pki",
            "--nameservers",
            "ns1, ns2",
            "--out",
            "pki",
            "--server-name",
            "grpc.ianua.io",
        ])
        .unwrap();

        assert_eq!(
            parsed,
            Command::LinkPki(LinkPkiRequest {
                server_name: "grpc.ianua.io".to_owned(),
                nameservers: vec!["ns1".to_owned(), "ns2".to_owned()],
                out: PathBuf::from("pki"),
            })
        );
    }

    /// Link-PKI commands with missing or empty nameservers, repeated names or extra flags.
    const LINK_PKI_REFUSALS: [&[&str]; 4] = [
        &["link-pki", "--server-name", "grpc.ianua.io", "--out", "pki"],
        &[
            "link-pki",
            "--server-name",
            "a",
            "--nameservers",
            ",",
            "--out",
            "pki",
        ],
        &[
            "link-pki",
            "--server-name",
            "a",
            "--server-name",
            "b",
            "--nameservers",
            "ns1",
            "--out",
            "pki",
        ],
        &[
            "link-pki",
            "--server-name",
            "a",
            "--nameservers",
            "ns1",
            "--out",
            "pki",
            "--ca",
        ],
    ];

    /// Link PKI refuses missing or empty nameservers, a repeated server
    /// name and an unsupported trailing flag.
    #[test]
    fn link_certificates_need_every_flag_once_and_nothing_else() {
        for line in LINK_PKI_REFUSALS {
            assert!(
                matches!(parsed(line), Err(CommandError::Unknown { .. })),
                "{line:?} was taken"
            );
        }
    }

    /// An invalid operator email produces an email error retaining the
    /// supplied value.
    #[test]
    fn an_operator_address_that_is_not_one_is_refused() {
        let refused = parsed(&["operator", "create", "--email", "root"]);

        assert!(matches!(refused, Err(CommandError::Email { given, .. }) if given == "root"));
    }
}
