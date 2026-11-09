//! The lists the conventions read: the patterns they look for, and the
//! places that keep a pattern on purpose, each with its reason.

/// The bounded contexts under `domains/`, in layers from the foundation up.
///
/// A context uses only contexts in a lower layer, never one beside or above
/// it, so no two contexts depend on each other and a new context is placed
/// on purpose. The shared kernel (`shared/`, `types/`, `isolation/`) sits
/// below every layer and uses none of them.
pub(crate) const CONTEXT_LAYERS: &[&[&str]] = &[
    &[
        "audit",
        "crypto",
        "data_classification",
        "identity",
        "metrics",
        "scheduling",
        "signals",
    ],
    &["activity"],
    &["authentication"],
    &["authorization"],
    &["tenant"],
    &["consumers"],
    &["routing"],
    &["branding", "federation", "messaging", "oauth", "operator"],
    &["organization"],
    &["agents", "notifications"],
    &["proxy", "webhooks", "workflows"],
];

/// Fields that hold a bare `Uuid` on purpose, with the reason.
pub(crate) const UUID_FIELDS_ALLOWED: &[(&str, &str)] = &[];

/// Fields that hold a digest as a `String` on purpose, with the reason.
pub(crate) const HASH_FIELDS_ALLOWED: &[(&str, &str)] = &[];

/// Text wrappers that deserialize without a constructor on purpose: each is
/// a digest computed by trusted code, never typed by a person.
pub(crate) const PLAIN_DESERIALIZE_ALLOWED: &[&str] = &["TokenHash", "PasswordHash"];

/// Types whose inherent methods sit in more than one `impl` block on
/// purpose, with the reason.
pub(crate) const SPLIT_IMPLS_ALLOWED: &[(&str, &str)] = &[
    (
        "SignalStream",
        "what one update changes lives in `stream/changes.rs`, and what its receiver asks of it, subjects and verification events, in `stream/receiver_requests.rs`",
    ),
    (
        "WebhookSubscription",
        "what a person changes after creating it, its parts and its signing secret, lives in `subscription/changes.rs`",
    ),
    (
        "User",
        "a directory.s moves, the account.s status moves, the holder.s profile, opening an account from an import and the records an account raises each have a file of their own",
    ),
    (
        "Role",
        "moving a role to the permissions wanted in one change has a file of its own",
    ),
    (
        "AttributeDefinition",
        "the records a declaration raises have a file of their own",
    ),
    (
        "OrgToken",
        "anyone may issue a mailed link, but only founding an installation issues the setup token, only a sign-in confirmation proves the mailbox to a sign-in, and only a magic link signs a member in",
    ),
    (
        "Validator",
        "each rules file adds the checks for its own kind of text",
    ),
    (
        "Session",
        "carrying a session on under a new token, by a refresh or a single sign-on's code, lives in `session/rotation.rs`, freezing it and lifting the freeze in `session/suspension.rs`, what it records beside its own changes in `session/records.rs`, and keeping it through its own holder's change of how the account signs in in `session/kept_through.rs`",
    ),
    (
        "WorkflowExecution",
        "each kind of step drives the execution from its own file",
    ),
    (
        "Workflow",
        "making an agent flow, published at once, and deleting it with its run live in `workflow/flow.rs`; the accounts a version acts through and holding it for want of one live in `workflow/hold.rs`",
    ),
    (
        "IntegrationAccount",
        "whether it lends itself to someone's workflow, asked by a step, a registration and a version's check alike, lives in `account/lending.rs`",
    ),
    (
        "BreakGlassGrant",
        "what a grant records, its granting and its early end, lives in `break_glass/records.rs`",
    ),
    (
        "BreakGlassPolicy",
        "what a policy records when it changes lives in `break_glass/records.rs`, beside the grant's records",
    ),
    (
        "SystemPermission",
        "how a permission is written as text lives in `written.rs`",
    ),
    (
        "Route",
        "what a route declares about the data and actions behind it, which agents are judged against, lives in `route/declarations.rs`, and the header and cookie conditions it matches on in `route/conditions.rs`",
    ),
    (
        "StreamRoute",
        "whether workflows may reach a stream route, and opening and closing it to them, lives in `stream/workflows.rs`",
    ),
    (
        "Consumer",
        "how a consumer signs in with its working credentials lives in `consumers/sign_in.rs`, beside the proof it makes",
    ),
    (
        "FederatedIdpConnection",
        "how far the provider is believed, for the factors it reports and the addresses it vouches for, lives in `connection/trust.rs`, what the people it signs in are given in `connection/provisioning.rs`, and what only a SAML connection does in `connection/saml.rs`",
    ),
    (
        "Tenant",
        "its moves and its settings live in `lifecycle/moves.rs` and `lifecycle/settings.rs`, and the sign-in gate is its own file, beside the organization's",
    ),
    (
        "TenantAuthConfig",
        "the sign-in gate is its own file, beside the organization's",
    ),
    (
        "RegisteredDomain",
        "how a domain gets, renews and loses its certificate lives in `registered_domain/certificates.rs`",
    ),
    (
        "StageKind",
        "the rules each kind's settings keep sit in `stages/rules.rs`",
    ),
    (
        "Pipeline",
        "changing a stage's settings in place lives in `pipeline/settings.rs`, and reordering its stages in one step in `pipeline/order.rs`",
    ),
    (
        "CredentialChange",
        "how a change is told as a security signal belongs to signals, and the shared kernel uses no context",
    ),
    (
        "Fact",
        "a borrowed fact is a type of its own, with methods only it has",
    ),
    (
        "AgentRun",
        "pausing for approval, stepping, counting spend and a person's pause each drive the run from their own file",
    ),
    (
        "AgentIdentity",
        "how an agent proves itself by attesting lives in `agent/attesting.rs`, and how its ownership moves in `agent/ownership.rs`",
    ),
    (
        "Delegation",
        "how its delegator renews it lives in `delegation/renewal.rs`, and how it gains and loses one resource capability in `delegation/resources.rs`",
    ),
    (
        "TenantAccess",
        "what an account's holdings mean for a provider's word is federation's rule, so `privilege_of` lives in `federation/account_privilege.rs`",
    ),
    (
        "Organization",
        "how it is named and reached, its names and contact address, lives in `lifecycle/profile.rs`",
    ),
    (
        "OrgUser",
        "how a member signs in and changes it lives in `org_user/credentials.rs`, how they are named and reached in `org_user/profile.rs`, how their account closes for an erasure in `org_user/closing.rs`, how an owner hands the organization over in `org_user/ownership.rs`",
    ),
    (
        "OrgSession",
        "moving a session to another tenant lives in `session/switch.rs`, and keeping it through its own member's change of how they sign in in `session/kept_through.rs`",
    ),
];

/// Traits a file imports only to call their methods, so the name never
/// appears in its code, with the file and the reason.
pub(crate) const TRAITS_IMPORTED_FOR_METHODS: &[(&str, &str, &str)] = &[(
    "shared/security/constant_time.rs",
    "ConstantTimeEq",
    "brings `ct_eq` into scope",
)];

/// Events whose accessors cannot come from the event macros, with the reason.
pub(crate) const HAND_WRITTEN_EVENTS: &[(&str, &str)] = &[
    (
        "InOrganization",
        "puts a notification read in the organization's trail, carrying the read itself",
    ),
    (
        "OrgUserTenantAccessChanged",
        "picks its event type from the change it carries",
    ),
    (
        "AgentResourceRelationGranted",
        "wraps the relation event it shares a payload with",
    ),
    (
        "AgentResourceRelationRevoked",
        "wraps the relation event it shares a payload with",
    ),
    (
        "AgentTaskTemplateChanged",
        "picks its event type from the change it carries",
    ),
    (
        "AgentDelegationAsked",
        "picks its event type from the step of the request it carries",
    ),
    (
        "AgentSightingChanged",
        "picks its event type from the change it carries",
    ),
    (
        "AgentRunSteered",
        "picks its event type from how the person steered the run",
    ),
    (
        "NoticeSent",
        "picks its event type from whether the notice offers access",
    ),
    (
        "StreamRouteStatusChanged",
        "picks its event type from the status it moved to",
    ),
    (
        "EgressPolicyChanged",
        "picks its event type from the change it carries",
    ),
    (
        "ConnectorChanged",
        "picks its event type from the change it carries",
    ),
];

/// The proxy saw it in traffic; nothing the domain keeps changed.
const SEEN_IN_TRAFFIC: &str = "the proxy sees it in traffic; no aggregate changes, and the proxy names the tenant whose route it served";

/// A gateway or the message relay decided on an agent's traffic; nothing the
/// domain keeps changed.
const AGENT_TRAFFIC: &str = "a gateway or the relay decides on an agent's traffic; no aggregate changes, and the tenant is the one the agent's token was issued for";

/// A member's own sign-in or mail; nothing the organization keeps changes.
const MEMBER_ACTIVITY: &str = "a step of the member's own sign-in or mail; nothing the organization keeps changes, and the member names the organization";

/// Something kept under the member alone changed: a device, a ceremony, a
/// factor's setup or a passkey. It has no organization of its own, so the
/// record takes the member's.
const KEPT_UNDER_THE_MEMBER: &str = "what changed is kept under the member and holds no organization of its own; the member names the organization the record goes to";

/// Functions that build a whole event outside an aggregate, rather than an
/// aggregate raising it and the application taking it after the save, with
/// the type (or, for a free function, its file), the function and the
/// reason no aggregate raises it.
pub(crate) const OBSERVATIONS: &[(&str, &str, &str)] = &[
    (
        "OperatorAuthority",
        "dead_job_retried",
        "the job belongs to the queue, a layer below operators, so the record of who retried it is built where the operator is known",
    ),
    (
        "ChainHistory",
        "alarm",
        "a broken audit chain is something the sweep found, not a change it made; it is raised the first time the break is seen",
    ),
    (
        "PressureShift",
        "recorded",
        "rising or easing sign-in pressure is something the failure count shows, not a change to an aggregate",
    ),
    (
        "AuditChainVerification",
        "events",
        "a walk of the audit chain reads and changes nothing; the tenant walked is the one the record names",
    ),
    (
        "RetentionPurge",
        "events",
        "a retention purge deletes records in storage without loading them; the tenant purged is the one the record names",
    ),
    (
        "ExpiredApiKeys",
        "events",
        "a sweep deletes expired keys in storage without loading them; each record names the tenant its key was deleted from",
    ),
    (
        "InboxRead",
        "events",
        "marking a reader's notifications read changes many rows in storage at once, and no aggregate is loaded",
    ),
    (
        "domains/notifications/reading.rs",
        "recorded_for",
        "one read as `InboxRead::events` puts it in the trail of the reader's own plane",
    ),
    (
        "MailUndelivered",
        "observed",
        "the delivery worker gives up on a mail; nothing kept changes",
    ),
    (
        "CloudDisconnection",
        "events",
        "the connection is deleted without being loaded; the disconnection that `CloudAccount::disconnect` allowed carries what its record names",
    ),
    (
        "domains/workflows/events/mod.rs",
        "execution_events",
        "an execution hands back the records of what it did, and one path turns them into events at the execution's chain depth",
    ),
    (
        "domains/workflows/events/pass.rs",
        "started_event",
        "the start of an execution, or of a loop's pass, as `execution_events` stamps it with the execution's tenant",
    ),
    (
        "domains/workflows/events/pass.rs",
        "ended_event",
        "the end of an execution, or of a loop's pass, as `execution_events` stamps it with the execution's tenant",
    ),
    (
        "domains/workflows/events/mod.rs",
        "step_event",
        "one step's record as `execution_events` stamps it with the execution's tenant",
    ),
    (
        "domains/workflows/events/pass.rs",
        "run_ended_event",
        "the end of a run that is no pass, a real run's or a test's, as `execution_events` stamps it with the execution's tenant",
    ),
    (
        "domains/workflows/events/test.rs",
        "failed_step_event",
        "one failed step of a test, as `execution_events` stamps it with the execution's tenant",
    ),
    (
        "ReopenedAccount",
        "recorded",
        "the reopening is recorded once the factors and tenants the account held are withdrawn, which the counts in the record need",
    ),
    (
        "TenantSwitched",
        "recorded",
        "the session opened is the target tenant's and the group of linked accounts does not change, so no organization aggregate changes",
    ),
    (
        "OrgUserTenantAccessChanged",
        "replaced",
        "the member's roles in a tenant are one grant per role, each its own record, so the replacement as a whole has no aggregate",
    ),
    ("OrgLoginSucceeded", "observed", MEMBER_ACTIVITY),
    ("OrgLoginFailed", "observed", MEMBER_ACTIVITY),
    (
        "OrgAccountUnderAttack",
        "observed",
        "failures from many networks against a member's account are something the counts show; nothing the organization keeps changes, and the member names the organization",
    ),
    ("OrgPasskeySignInStarted", "observed", MEMBER_ACTIVITY),
    ("OrgMagicLinkRequested", "observed", MEMBER_ACTIVITY),
    (
        "OrgSsoSignInStarted",
        "observed",
        "a sign-in sent to the organization's provider before anyone is known; nothing the organization keeps changes, and the organization names itself",
    ),
    (
        "OrgCheckoutStarted",
        "observed",
        "the payment provider's page is opened; nothing the organization keeps changes until the provider reports a method, and the organization names itself",
    ),
    (
        "OrgPasskeyChallengeIssued",
        "observed",
        "a discoverable passkey challenge names nobody yet, so it is a platform record and nothing kept changes",
    ),
    ("OrgMfaVerified", "observed", MEMBER_ACTIVITY),
    ("OrgVerificationEmailSent", "observed", MEMBER_ACTIVITY),
    ("OrgWelcomeEmailSent", "observed", MEMBER_ACTIVITY),
    (
        "OrgUserPasswordResetRequested",
        "observed",
        KEPT_UNDER_THE_MEMBER,
    ),
    ("OrgDeviceTrusted", "observed", KEPT_UNDER_THE_MEMBER),
    ("OrgDeviceRevoked", "observed", KEPT_UNDER_THE_MEMBER),
    ("OrgMfaEnrollmentStarted", "observed", KEPT_UNDER_THE_MEMBER),
    (
        "OrgPasskeyRegistrationStarted",
        "observed",
        KEPT_UNDER_THE_MEMBER,
    ),
    ("OrgPasskeyRenamed", "observed", KEPT_UNDER_THE_MEMBER),
    ("HoneypotHit", "observed", SEEN_IN_TRAFFIC),
    ("PersonTurnedAway", "observed", SEEN_IN_TRAFFIC),
    ("AutomatedThreatDetected", "observed", SEEN_IN_TRAFFIC),
    ("CanaryTokenTriggered", "observed", SEEN_IN_TRAFFIC),
    ("CanaryTokenLeaked", "observed", SEEN_IN_TRAFFIC),
    ("AgentActionAuthorized", "observed", AGENT_TRAFFIC),
    ("AgentActionDenied", "observed", AGENT_TRAFFIC),
    ("AgentEgressDenied", "observed", AGENT_TRAFFIC),
    ("AgentMessageAuthorized", "observed", AGENT_TRAFFIC),
    ("AgentMessageDenied", "observed", AGENT_TRAFFIC),
    (
        "AgentTokenAttackRefused",
        "observed",
        "a refused agent sign-in changes nothing stored; the agent is only read, and the tenant is the one that agent belongs to",
    ),
    (
        "AgentIntentDrift",
        "observed_at_egress",
        "the egress gateway reports a refused way out by ids only; the delegation may be gone and nothing it holds changes",
    ),
    (
        "AgentsConverged",
        "observed",
        "the convergence detector reads a meeting off the touch ledger; no aggregate changes, and the tenant is the one whose traffic the ledger holds",
    ),
    (
        "StartRefusal",
        "recorded",
        "a trigger fired a version that may not start for its publisher; the version is only read and nothing is saved, so the tenant is the one it was read for",
    ),
    (
        "PasswordLogin",
        "recorded",
        "a sign-in attempt changes nothing stored; it holds the id of the tenant record that admitted it, and each failure, lockout and missing check is recorded there",
    ),
    (
        "PasswordLogin",
        "locked_out",
        "the lockout lives in the counts the application keeps, not in an aggregate; only the attempt whose failure reached the limit knows it set one, and it records it in the tenant that admitted it",
    ),
    (
        "PasswordLogin",
        "under_attack",
        "an attack on an account is something the counts show, not a change to an aggregate; the attempt that found it records it once in the tenant that admitted it",
    ),
    (
        "RaisedEvents",
        "raise_tenant",
        "the tenant aggregate and the records that hold their tenant's id raise their own events, naming the tenant they already are",
    ),
];

/// Libraries that belong to adapters. A domain file reaching for one is the
/// sign that a port is missing.
pub(crate) const ADAPTER_LIBRARIES: &[&str] = &[
    "utoipa",
    "rand",
    "tokio",
    "sqlx",
    "reqwest",
    "hyper",
    "axum",
    "async_nats",
];

/// Text types written by hand rather than with `text_value!`, and why.
pub(crate) const HAND_WRITTEN_TEXT: &[(&str, &str)] = &[
    ("Label", "the caller names the field its errors carry"),
    ("Text", "the caller names the field its errors carry"),
    (
        "PermissionSegment",
        "the caller names the field its errors carry",
    ),
    ("DisplayName", "its length limits come from settings"),
    ("TenantSlug", "its length limits come from settings"),
    ("FieldPath", "it is split into segments as it is checked"),
    (
        "CronSchedule",
        "it is split into fields as it is checked, and kept with single spaces",
    ),
    ("IpAddress", "it is checked by parsing it as an address"),
    ("CidrRange", "it is checked by parsing it as a network"),
    (
        "UntrustedText",
        "it cleans text it is given rather than refusing it",
    ),
    (
        "EventLabel",
        "it cleans a name it is given rather than refusing it",
    ),
    (
        "DelegationLabel",
        "it is only built from an id or read back from storage",
    ),
    (
        "UrlOrigin",
        "it is only cut from a URL already checked, so nothing can name a full address as one",
    ),
    (
        "TokenHash",
        "a stored digest, read back rather than checked",
    ),
    (
        "PasswordHash",
        "a stored digest, read back rather than checked",
    ),
    ("Secret", "secret material, wiped when dropped"),
    (
        "Refusal",
        "it cleans the words it is given rather than refusing them",
    ),
    (
        "InfraMessage",
        "an error's words carried as its source, not a value of the domain",
    ),
    ("CloudSecret", "secret material, wiped when dropped"),
    (
        "ParameterKey",
        "a comparison key folded from a name, never stored, shown or refused",
    ),
];

/// What a hand-written input check looks like, and the shared rule that
/// replaces it.
pub(crate) const HAND_CHECKS: &[(&str, &str)] = &[
    (".is_empty()", "`Validator::not_empty` or `validate_count`"),
    (".len() >", "`Validator::length` or `validate_count`"),
    (" == 0 ", "`validate_range`"),
    (".chars().any(", "a `Validator` rule"),
    (".chars().all(", "a `Validator` rule"),
    (".bytes().any(", "a `Validator` rule"),
    (".bytes().all(", "a `Validator` rule"),
    ("is_ascii()", "`Validator::ascii_only`"),
    ("starts_with(\"http", "the shared URL rule"),
];

/// Checks that are rules of a record rather than of its input, kept by hand
/// on purpose: what they compare is not one value's shape.
pub(crate) const HAND_CHECKS_ALLOWED: &[(&str, &str)] = &[
    (
        "domains/agents/authority/task_template.rs",
        "params.ceiling.is_empty()",
    ),
    (
        "domains/agents/authority/task_template.rs",
        "params.classes.is_empty()",
    ),
    (
        "domains/identity/attribute/definition/rules.rs",
        "options.is_empty()",
    ),
    ("domains/oauth/clients/rules.rs", "redirect_uris.is_empty()"),
    (
        "domains/proxy/stages/checks/geo_fence.rs",
        "self.allowed_countries.is_empty()",
    ),
    ("domains/proxy/stages/rules.rs", "self.denylist.is_empty()"),
    ("domains/authorization/ladder.rs", "index == 0"),
    ("domains/identity/attribute/schema.rs", "count == 0"),
    (
        "domains/messaging/schema.rs",
        "self.versions.len() >= MAX_VERSIONS",
    ),
    (
        "domains/tenant/custom_domains/dns_zone/record_set.rs",
        "values.len() > 1",
    ),
    ("types/naming/field_path.rs", "segment.is_empty()"),
];

/// Fields that hold text on purpose, and why. Every other field on a domain
/// type holds a type that says what the value is and checks it.
pub(crate) const TEXT_FIELDS_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "domains/workflows/guardrail/words.rs",
        "Word.text",
        "one word of a text a guardrail is checking, lower-cased to be matched and never kept",
    ),
    (
        "domains/workflows/guardrail/scan.rs",
        "Place.rule_path",
        "the path classification rules name a field by, built while a guardrail walks a value and never kept",
    ),
    (
        "domains/workflows/sandbox/image.rs",
        "PinnedImage.full",
        "the whole name its typed registry, path and digest were checked into, kept so it can be lent as text; it never changes apart from them",
    ),
    (
        "shared/errors.rs",
        "Refusal.text",
        "the sentence a person reads, made safe to show and log when it is made; it names no single value",
    ),
    (
        "shared/errors.rs",
        "RefusalValue.value",
        "a value as the refusal's sentence shows it, formatted by the caller and made safe like the sentence",
    ),
    (
        "domains/federation/provider_values.rs",
        "ProviderValues.by_name",
        "claim and attribute names and values exactly as an outside provider sent them; each reader turns the ones it needs into a typed value",
    ),
    (
        "domains/agents/execution/chat.rs",
        "ChatMessage.content",
        "what a model or a person wrote",
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "RequestParameters.captured",
        "path parts exactly as the client sent them; screening them is the point",
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "RequestParameters.headers",
        "headers exactly as the client sent them; screening them is the point",
    ),
    (
        "domains/agents/execution/chat.rs",
        "Completion.content",
        "what a model wrote",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "PendingCall.tool",
        "the tool a model asked for, as it asked",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "PendingCall.arguments",
        "the arguments a model sent",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "PendingCallRef.tool",
        "the tool a model asked for, as it asked",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "PendingCallRef.arguments",
        "the arguments a model sent",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepCall.tool",
        "the tool a model asked for, even one that does not exist",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepCall.arguments",
        "the arguments a model sent",
    ),
    (
        "domains/audit/record.rs",
        "AuditTarget.Entity",
        "the id of any kind of resource, written out",
    ),
    (
        "domains/authentication/risk_engine/assessment.rs",
        "IpGeolocation.city",
        "a geolocation database's answer",
    ),
    (
        "domains/authentication/risk_engine/assessment.rs",
        "LoginRiskAssessment.reasons",
        "explanations the assessment writes",
    ),
    (
        "domains/authorization/policy/simulator/mod.rs",
        "RuleEvaluation.failed_conditions",
        "explanations the simulator writes",
    ),
    (
        "domains/branding/renderer.rs",
        "RenderedEmail.subject",
        "a rendered email",
    ),
    (
        "domains/branding/renderer.rs",
        "RenderedEmail.html",
        "a rendered email",
    ),
    (
        "domains/branding/renderer.rs",
        "RenderedEmail.text",
        "a rendered email",
    ),
    (
        "domains/crypto/jwk.rs",
        "JwkComponents.kid",
        "encoded key material this platform produces",
    ),
    (
        "domains/crypto/jwk.rs",
        "JwkComponents.n",
        "encoded key material this platform produces",
    ),
    (
        "domains/crypto/jwk.rs",
        "JwkComponents.e",
        "encoded key material this platform produces",
    ),
    (
        "domains/crypto/jwk.rs",
        "JwkComponents.crv",
        "encoded key material this platform produces",
    ),
    (
        "domains/crypto/jwk.rs",
        "JwkComponents.x",
        "encoded key material this platform produces",
    ),
    (
        "domains/crypto/jwk.rs",
        "JwkComponents.y",
        "encoded key material this platform produces",
    ),
    (
        "domains/federation/service_provider/attributes.rs",
        "ReleasedAttribute.values",
        "attribute values, escaped as they are written into XML",
    ),
    (
        "domains/federation/saml/logout_builder.rs",
        "BuiltLogoutMessage.xml",
        "a built document",
    ),
    (
        "domains/federation/saml/assertion_builder.rs",
        "BuiltAssertion.xml",
        "a built document",
    ),
    (
        "domains/federation/saml/assertion_builder.rs",
        "SignedAssertion.xml",
        "a built document",
    ),
    (
        "domains/federation/saml/idp_metadata_builder.rs",
        "BuiltIdpMetadata.xml",
        "a built document",
    ),
    (
        "domains/federation/saml/response_builder.rs",
        "BuiltSamlResponse.xml",
        "a built document",
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.amr",
        "what an identity provider said",
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.name",
        "what an identity provider said",
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.given_name",
        "what an identity provider said",
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.family_name",
        "what an identity provider said",
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.picture",
        "what an identity provider said",
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.locale",
        "what an identity provider said",
    ),
    (
        "domains/federation/saml/assertion.rs",
        "SamlAssertion.attributes",
        "what an identity provider asserted",
    ),
    (
        "domains/federation/saml/assertion.rs",
        "AssertionFacts.authn_context",
        "what an identity provider asserted",
    ),
    (
        "domains/federation/saml/assertion.rs",
        "AssertionFacts.attributes",
        "what an identity provider asserted",
    ),
    (
        "domains/identity/attribute/schema.rs",
        "TextCondition.values",
        "values a filter compares against, borrowed",
    ),
    (
        "domains/notifications/notification.rs",
        "AboutResource.Resource",
        "the id of any kind of resource",
    ),
    (
        "domains/proxy/stages/decision.rs",
        "StageDecision.reason",
        "a stage's own words",
    ),
    (
        "domains/proxy/observation.rs",
        "RequestOutcome.reason",
        "a stage's own words",
    ),
    (
        "domains/proxy/request/graphql.rs",
        "GraphQlOperation.name",
        "read from a request's GraphQL document",
    ),
    (
        "domains/proxy/request/graphql.rs",
        "GraphQlOperation.fingerprint",
        "a digest of a request's GraphQL document",
    ),
    (
        "domains/proxy/stages/stage/config.rs",
        "TerminateConfig.body",
        "a response body, which may hold anything",
    ),
    (
        "domains/scheduling/job.rs",
        "ScheduledJob.payload",
        "a job's own payload, read by its handler",
    ),
    (
        "domains/scheduling/job.rs",
        "ScheduledJobRow.payload",
        "a job's own payload, read by its handler",
    ),
    (
        "shared/events/data.rs",
        "Reference.id",
        "an event payload, which is text",
    ),
    (
        "shared/events/data.rs",
        "Reference.label",
        "an event payload, which is text",
    ),
    (
        "shared/events/data.rs",
        "Change.from",
        "an event payload, which is text",
    ),
    (
        "shared/events/data.rs",
        "Change.to",
        "an event payload, which is text",
    ),
    (
        "shared/events/data.rs",
        "EventData.fields",
        "an event payload, which is text",
    ),
    (
        "types/network/http_url.rs",
        "HttpUrl.text",
        "the URL as written, beside its parsed form",
    ),
    (
        "types/network/https_url.rs",
        "HttpsUrl.text",
        "the URL as written, beside its parsed form",
    ),
    (
        "types/network/redirect_uri.rs",
        "RedirectUri.text",
        "the redirect as written, which is what is matched and sent back to",
    ),
    (
        "types/network/redirect_uri.rs",
        "RedirectKind.portless",
        "the loopback redirect with its port taken out, kept for matching",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepOutcome.Allowed",
        "what a tool returned",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepOutcome.Denied",
        "a refusal as it was given",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepOutcome.Answered",
        "what a model wrote",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepOutcome.Replied",
        "what a person wrote back, checked as a reply before it was kept",
    ),
    (
        "domains/agents/execution/run/call.rs",
        "StepOutcome.CheckFailed",
        "what a check's code said of an answer, recorded as it said it",
    ),
    (
        "domains/authorization/policy/simulator/conditions.rs",
        "Verdict.Fails",
        "why a condition failed, shown in a simulation",
    ),
    (
        "domains/authorization/policy/simulator/conditions.rs",
        "Verdict.Unknown",
        "which fact was missing, shown in a simulation",
    ),
    (
        "domains/identity/metadata_value.rs",
        "MetadataValue.String",
        "a value a tenant keeps on a user, whatever it says",
    ),
    (
        "domains/identity/metadata_value.rs",
        "MetadataValue.StringArray",
        "values a tenant keeps on a user, whatever they say",
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "BodyFields.Fields",
        "a request body's fields as sent, which the check reads",
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "BodyValue.Text",
        "a string from a request body, as sent, which the check reads",
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "BodyValue.Number",
        "a number from a request body, as it was written",
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "BodyValue.Object",
        "an object from a request body, its keys as sent",
    ),
    (
        "domains/workflows/design/condition.rs",
        "Test.Contains",
        "text a workflow's designer looks for in step data, whatever it says",
    ),
    (
        "domains/workflows/data.rs",
        "Value.Text",
        "text that moves between workflow steps, whatever it says",
    ),
    (
        "shared/events/data.rs",
        "FieldValue.Text",
        "a payload value its event already rendered",
    ),
];

/// Durations kept as a plain number on purpose, and why.
pub(crate) const PLAIN_DURATIONS_ALLOWED: &[(&str, &str)] = &[(
    "TravelVelocity.duration_seconds",
    "worked out from two timestamps, never configured",
)];

/// Links mailed to a person. Each is spent, and asked about, only together
/// with the account it is for, so a link read from a mailbox the account has
/// left, or meant for another account, does nothing.
pub(crate) const EMAILED_LINKS: &[&str] = &[
    "SecureToken",
    "OrgToken",
    "PasswordResetRequest",
    "PendingEmailChange",
];

/// Ways of spending or checking a link without naming its account. None of
/// them may be public on an emailed link.
pub(crate) const LINK_SHORTCUTS: &[&str] = &[
    "consume",
    "is_consumed",
    "is_expired",
    "is_valid",
    "is_valid_for",
    "is_usable",
    "is_pending",
    "is_confirmed",
    "state",
];

/// Proofs: values whose existence says something was checked. Only the
/// domain makes them, so none has a public constructor.
pub(crate) const PROOFS: &[(&str, &str)] = &[
    (
        "AccessReviewDraft",
        "a tenant authority validated review creation before its atomic snapshot",
    ),
    (
        "ReviewCompletion",
        "the review authorized a caller or its deadline before the complete snapshot was traversed",
    ),
    ("VerifiedEmail", "someone was shown to hold the address"),
    (
        "InstallerProof",
        "the installation's setup token was spent by the person who ran the install",
    ),
    (
        "AcceptedAddress",
        "an invitation's link was followed and the invitation accepted, proving the mailbox when it was mailed",
    ),
    ("BaselineMet", "a sign-in reached its tenant's baseline"),
    (
        "AccountUse",
        "an integration account lets this person's workflows use it for this operation",
    ),
    (
        "ProviderSignIn",
        "a provider's factor passed the connection's trust setting",
    ),
    ("SignedIn", "this account finished signing in this way"),
    (
        "SignInAdmitted",
        "the boundary's gate let this way in through from this address",
    ),
    (
        "OwnedDomain",
        "a tenant proved it holds this domain, and its proof stands",
    ),
    (
        "FederatedAdmission",
        "admission let this vouched identity in through its connection, and says what it may do",
    ),
    ("OperatorSignIn", "an operator gave their password just now"),
    (
        "ConsumerSignIn",
        "a consumer presented its own key, certificate or token just now",
    ),
    (
        "FactorOffer",
        "the boundary's settings offer this kind of second factor now",
    ),
    (
        "ServiceAccountBind",
        "a directory service account's secret was checked just now",
    ),
    (
        "WebhookCall",
        "a call of a workflow's webhook carried the secret its publisher issued, checked just now",
    ),
    (
        "ServiceDelivery",
        "a service's event carried the signature of a live registration's secret, checked just now, for the version in service",
    ),
    (
        "RegistrationAdmission",
        "an app presented a working initial access token and spent one of its uses",
    ),
    (
        "SelfManagement",
        "a self-registered client presented its own registration access token",
    ),
    (
        "StreamReceiver",
        "a signal stream's receiver presented the key its stream was registered with",
    ),
    (
        "PlanMove",
        "a subscription checked who moved the plan, how it is paid and that usage fits",
    ),
    (
        "AuditLogAccess",
        "the authority of a tenant, an organization or the platform found its reader may export its audit log",
    ),
];

/// Text types that carry a secret, and so are declared `redacted`.
pub(crate) const SECRET_TEXT: &[(&str, &str)] = &[
    ("DeviceSecret", "lets a sign-in skip its second factor"),
    (
        "DeviceUserCode",
        "approves a waiting device sign-in while it waits",
    ),
    (
        "HeaderValue",
        "often an API key, a fetched secret or a minted token",
    ),
    (
        "SealedSecret",
        "a stored secret, sealed but still not for logs",
    ),
];

/// Secrets and digests of secrets held outside `text_value!`, so they write
/// their own equality: one that takes the same time wherever two values
/// differ, never a derived `PartialEq`.
pub(crate) const SECRET_DIGESTS: &[(&str, &str)] = &[
    ("TokenHash", "a presented token is checked against it"),
    ("PasswordHash", "an offline-crackable form of a password"),
    ("CloudSecret", "a cloud provider's plaintext secret"),
];

/// Values whose fields would let a caller step around their rules, so none
/// has a public field.
pub(crate) const GUARDED_VALUES: &[&str] = &[
    "Human",
    "SignInProgress",
    "ProviderSignIn",
    "BaselineMet",
    "VerifiedEmail",
    "AcceptedAddress",
    "ChangingAccount",
    "TokenRefused",
    "Reservation",
    "TokenCharge",
    "CustomCss",
    "GcpServiceAccountKey",
    "Conferred",
    "ProvenAccount",
    "FactorOffer",
    "ServiceAccountBind",
    "WayIn",
    "FreshSignIn",
    "ProvedFactor",
    "SpentPasskey",
    "MaySignIn",
    "EnrolmentProof",
    "OrgSignInStart",
    "Founding",
    "FederatedAdmission",
    "TenantAuthority",
    "HeldByGranter",
    "AccountControl",
    "PolicyApprover",
    "TenantControl",
    "FederationControl",
    "WorkflowControl",
    "AgentControl",
    "OrgControl",
    "OrgStanding",
    "RoutingControl",
    "MessagingControl",
    "WebhookControl",
    "ConsumerControl",
    "HeldBy",
    "ActingAgent",
    "HeldResources",
    "ConsumerTakeover",
    "ConsumerAuthority",
    "RunStarter",
    "AnsweredCode",
    "OAuthControl",
    "OperatorAuthority",
    "OperatorSignIn",
    "BrandingControl",
    "SelfSignUp",
    "RegistrationAdmission",
    "SelfManagement",
    "TokenExchange",
    "AcceptedAuthnRequest",
    "IssuedNameId",
    "WebhookCall",
    "ServiceDelivery",
    "PlanMove",
];

/// The proofs a public change to an aggregate takes to name who makes it:
/// what they hold, as authorization worked it out, or that they signed in
/// or proved themselves just now.
pub(crate) const CALLER_PROOFS: &[&str] = &[
    "Founding",
    "StartingRolesGrant",
    "TenantAuthority",
    "HeldByGranter",
    "AccountControl",
    "AccountControlCheck",
    "PolicyApprover",
    "TenantControl",
    "FederationControl",
    "WorkflowControl",
    "StepApprover",
    "AgentControl",
    "Approver",
    "OrgControl",
    "ActedBy",
    "Steward",
    "SignedIn",
    "SignedInPerson",
    "FreshSignIn",
    "RecentProof",
    "FactorSetupProof",
    "ProvedFactor",
    "VerifiedEmail",
    "InstallerProof",
    "AcceptedAddress",
    "Revoker",
    "SuspendedBy",
    "AttestedIdentity",
    "ReleasedCall",
    "DeniedCall",
    "ServiceDelivery",
    "RevisedCall",
    "CancelOrder",
    "RunCancelled",
    "ActionAuthority",
    "ResourceCeiling",
    "RoutingControl",
    "MessagingControl",
    "WebhookControl",
    "ConsumerControl",
    "ProfileEditor",
    "ActingAgent",
    "ConsumerTakeover",
    "ConsumerAuthority",
    "HeldBy",
    "RunStarter",
    "AccountKeeper",
    "FactorWithdrawal",
    "MaySignIn",
    "SessionCheck",
    "OrgSessionCheck",
    "AnsweredCode",
    "OrgSignInStart",
    "OAuthControl",
    "RegistrationAdmission",
    "SelfManagement",
    "OperatorAuthority",
    "LinkGrounds",
    "UnlinkGrounds",
    "BrandingControl",
    "CryptoControlCheck",
    "ClassificationControlCheck",
    "SignalsControlCheck",
    "AccountCreator",
    "TenantDirectory",
    "SchemaControlCheck",
    "InvitedRole",
    "ProvenAccount",
    "OrgAccountControl",
    "DirectoryControlCheck",
    "PlanMove",
    "AuditLogAccess",
];

/// Parameters that carry a caller proof in one of their fields, with the
/// field. A function taking one names its caller through it.
pub(crate) const CALLER_PROOF_CARRIERS: &[(&str, &str)] = &[
    (
        "ReviewCompletion",
        "the authorized manual or overdue completion origin",
    ),
    ("MintAgentCredentialParams", "source"),
    ("OwnedTokenRequest", "agent"),
    ("CodeExchange", "client"),
    ("LinkRemoval", "Holder or Organization"),
    ("AddedBy", "Founding or Member"),
    ("GrantRequest", "issuer"),
    ("NewBreakGlass", "approval"),
    ("MessagingCreator", "Person or Consumer"),
    ("MessagingReader", "Person or Consumer"),
    ("Subscriber", "Itself or Enrolled"),
];

/// A step the agent runtime takes inside a run, decided by the run's gate
/// against its delegation and the agent, not by a person.
const RUN_STEP: &str = "a step of the run itself, admitted by its gate against the delegation";

/// Records a move a run or an approval request already made.
const ANNOUNCED: &str = "records a move the run or request already made, with the names the audit trail knows; it changes and grants nothing";

/// A step the workflow engine takes, decided by the published version and
/// the clock, with each call checked by its own authority when it starts.
const ENGINE_STEP: &str = "a step the workflow engine takes, as the published version says";

/// Why an evaluation's own steps name no caller.
const EVALUATION_STEP: &str = "a step the evaluation job takes for the person who started it, whose right to test is checked again as each case starts; it records outcomes and grants nothing";

/// A WebAuthn challenge being opened or spent.
const CEREMONY: &str =
    "a WebAuthn challenge opened or spent; it proves nothing until its answer is checked";

/// A wrong answer counted towards a lock.
const WRONG_ANSWER_COUNTED: &str = "counts a wrong answer towards a lock; it only takes away";

/// A one-time code being checked.
const CODE_SPENT: &str = "a one-time code being checked and spent; the code is the proof";

/// A link mailed to the account's own address.
const LINK_MAILED: &str =
    "a link mailed to the account's own address; anyone may ask, only that mailbox can use it";

/// A mailed link being followed.
const LINK_SPENT: &str = "an emailed link being followed; holding that mailbox is the proof";

/// A link whose time ran out.
const LINK_RAN_OUT: &str = "its link ran out; the clock decides, and lapsing grants nothing";

/// A dead link traded for a new one.
const LINK_RENEWED: &str =
    "a dead link traded by its holder for a new one, while the account stands as it was";

/// A short-lived code for a session a sign-in just opened.
const ISSUED_AFTER_SIGN_IN: &str =
    "a short-lived code issued for a session a sign-in just opened and checked";

/// Bookkeeping after a checked sign-in.
const AFTER_SIGN_IN: &str =
    "bookkeeping after a sign-in the authentication context already checked";

/// A step that follows a checked credential change.
const CREDENTIAL_FOLLOW_UP: &str =
    "follows a password or factor change already checked; it only ends sessions and devices";

/// A step of an erasure already asked for.
const ERASURE_STEP: &str = "a step of carrying out an erasure already asked for, once its grace period is over; it only removes";

/// What the platform's own check found.
const PROBE_OUTCOME: &str =
    "records what the platform's own check found: a DNS lookup or a cloud credential probe";

/// A step of issuing a certificate.
const CERTIFICATE_STEP: &str =
    "a step of issuing a certificate for a domain the tenant proved; the platform takes it";

/// Something issued after the consent or approval it carries was checked.
const ISSUED_AFTER_A_CHECK: &str =
    "issued after the consent or approval it carries was already checked; it grants nothing more";

/// Work queue bookkeeping.
const JOB_QUEUE: &str = "queue bookkeeping: the system enqueues work after a step already checked, and the worker records each run";

/// A step the worker takes through an import someone was allowed to start.
const IMPORT_STEP: &str = "the worker's progress through an import whose sender was checked when it was kept; it opens only the records that import holds";

/// A stage value before a pipeline takes it.
const UNATTACHED_STAGE: &str = "a stage value that does nothing until a pipeline takes it; adding one needs the pipeline right through RoutingControl";

/// A step of a tenant clone a member with the right to make tenants
/// started.
const CLONE_STEP: &str = "a step the clone worker takes; the clone was started by a member who may make tenants in the organization, and it copies only between its own two tenants";

/// A step of a tenant's setup, which the platform runs for a tenant made
/// by someone who was checked then.
const SETUP_STEP: &str = "the platform's own setup of a tenant made by someone checked when it was made; it begins only for a tenant still provisioning and grants nothing itself";

/// A step of a deleted tenant's teardown, which the platform runs once the
/// deletion, checked when it was made, is recorded.
const TEARDOWN_STEP: &str = "the platform's own teardown of a tenant deleted by someone checked when it was deleted; it begins only for a deleted tenant and removes, never grants";

/// What an outbound delivery found.
const DELIVERY_OUTCOME: &str =
    "records how a send the worker made went; it only counts failures or clears them";

/// What the payment provider reported.
const PAYMENT_PROVIDER: &str = "records what the payment provider reported about a checkout or a charge; the provider, not a person, decides it";

/// Public creations and changes of stored values that nobody makes, so
/// they name no caller, with the reason.
pub(crate) const UNCALLED_CHANGES: &[(&str, &str, &str)] = &[
    (
        "MappedHoldings",
        "none",
        "an empty record of what a mapping gave, before a person's first sign-in through it; it grants nothing",
    ),
    (
        "PrivateConnector",
        "enroll",
        "the connector's agent proves itself with the one-time code an admin created it with; the code is spent on use and good for an hour",
    ),
    (
        "PrivateConnector",
        "renew",
        "the connector's agent proves itself with a signing request made by the key it enrolled with; any other key is refused, and a renewal only extends that key's certificate by a day",
    ),
    ("AgentRun", "await_approval", RUN_STEP),
    ("AgentRun", "record_allowed", RUN_STEP),
    ("AgentRun", "record_denied", RUN_STEP),
    ("AgentRun", "complete", RUN_STEP),
    ("AgentRun", "fail", RUN_STEP),
    ("AgentRun", "halt", RUN_STEP),
    ("AgentRun", "record_model_usage", RUN_STEP),
    (
        "AgentRun",
        "pause_at_spend_check",
        "the run holds itself back before it spends more, at the amount its starter set; it only pauses and grants nothing",
    ),
    (
        "AgentRun",
        "fail_at_approval_limit",
        "the tenant's plan, not a person, has no room for another approval request; it only ends the run failed and grants nothing",
    ),
    (
        "AgentSighting",
        "observe",
        "the gateway or a scan sees an unregistered agent at work; a sighting grants nothing and is answered by a person who manages agents",
    ),
    (
        "AgentSighting",
        "record_sighting",
        "the gateway or a scan sees the same unregistered agent again; it only counts and grants nothing",
    ),
    ("AgentRun", "announce_start", ANNOUNCED),
    ("AgentRun", "announce_pause", ANNOUNCED),
    ("AgentRun", "announce_end", ANNOUNCED),
    ("ApprovalRequest", "announce_request", ANNOUNCED),
    ("ApprovalRequest", "announce_decision", ANNOUNCED),
    (
        "AgentIdentity",
        "issue_attestation_challenge",
        "the agent asks for its own bootstrap challenge before it can prove anything; the challenge grants nothing until a bootstrap spends it with an attestation the agent's policy trusts",
    ),
    (
        "PendingSignup",
        "request",
        "a stranger asks before anyone is signed in; it founds nothing until the link mailed to the address comes back and proves the mailbox",
    ),
    (
        "Delegation",
        "record_drift",
        "the platform's drift monitor records an action leaving the delegation's intent; nothing stored changes and it grants nothing",
    ),
    (
        "Memory",
        "purge",
        "its waiting period ran out; the clock decides, a person already asked for the deletion and could bring it back until then",
    ),
    (
        "ApprovalRequest",
        "expire",
        "its window ran out; the clock decides, and expiring grants nothing",
    ),
    ("WorkflowExecution", "begin_action", ENGINE_STEP),
    ("WorkflowExecution", "begin_code", ENGINE_STEP),
    ("WorkflowExecution", "begin_loop", ENGINE_STEP),
    ("WorkflowExecution", "begin_wait", ENGINE_STEP),
    ("WorkflowExecution", "defer_agent_run", ENGINE_STEP),
    ("WorkflowExecution", "elapse", ENGINE_STEP),
    ("WorkflowExecution", "expire", ENGINE_STEP),
    ("WorkflowExecution", "lapse_approval", ENGINE_STEP),
    ("WorkflowExecution", "refuse", ENGINE_STEP),
    ("WorkflowExecution", "request_approval", ENGINE_STEP),
    ("WorkflowExecution", "settle_action", ENGINE_STEP),
    ("WorkflowExecution", "settle_agent_run", ENGINE_STEP),
    ("WorkflowExecution", "settle_code", ENGINE_STEP),
    ("WorkflowExecution", "settle_pass", ENGINE_STEP),
    (
        "SandboxVersion",
        "finish_build",
        "the build job records the bundle the registry's checked packages made for the version saved; it changes nothing the person saved and grants nothing",
    ),
    (
        "SandboxVersion",
        "fail_build",
        "the build job records why the version's packages could not be bundled; it only takes away",
    ),
    (
        "SandboxTrial",
        "settle",
        "the trial job records how the code went on the version and input its starter chose; it grants nothing and only ends the trial",
    ),
    ("WorkflowExecution", "start_agent_run", ENGINE_STEP),
    ("WorkflowExecution", "start_held_agent", ENGINE_STEP),
    ("WorkflowExecution", "check_guardrail", ENGINE_STEP),
    (
        "WorkflowExecution",
        "start_case",
        "the evaluation job starts a case's test run for the person who started the evaluation, checked again as the case starts; a test run acts on nothing outside",
    ),
    ("Evaluation", "start_case", EVALUATION_STEP),
    ("Evaluation", "skip_case", EVALUATION_STEP),
    ("Evaluation", "settle", EVALUATION_STEP),
    ("Evaluation", "stop_waiting", EVALUATION_STEP),
    ("Evaluation", "give_up", EVALUATION_STEP),
    ("AgentRun", "record_answer", RUN_STEP),
    (
        "AgentRun",
        "record_check",
        "the run records what its check said of the answer its model gave; a failed check only turns the answer back, and it grants nothing",
    ),
    (
        "SandboxVersion",
        "finish_scan",
        "the scan job records what scanning the company's image found; a critical finding fails the version, and it grants nothing",
    ),
    ("WorkflowExecution", "stop_pass", ENGINE_STEP),
    (
        "IntegrationAccount",
        "renew_credential",
        "the service renewed the credential of the grant the account's owner connected, as a step used it; the service chose it, and it grants nothing the owner had not",
    ),
    (
        "PendingConnection",
        "answer",
        "the service sent back the browser holding the connection's state, whose digest is checked first; it only holds the credential until the person who began it finishes",
    ),
    (
        "AccountChannel",
        "open",
        "the platform's own bookkeeping as a version its publisher put in service first waits on the account; it reads no delivery until it is live",
    ),
    (
        "AccountChannel",
        "register",
        "records that the service took the channel, on a call only the platform makes; it grants nothing",
    ),
    (
        "AccountChannel",
        "receive_token",
        "the service sends it to the channel's address before anything can prove who sent it; it is only held until the account's owner confirms, and a live channel refuses it",
    ),
    (
        "AccountChannel",
        "lapse",
        "the service dropped or refused the channel, or its time ran out; lapsing only takes away",
    ),
    (
        "AccountChannel",
        "note_cursor",
        "the platform's own note of how far it read a service's history; it grants nothing",
    ),
    (
        "AccountChannel",
        "note_workflow_added",
        "the platform's own note that a publish is using the channel, so the idle sweep leaves it; it changes nothing but the time",
    ),
    (
        "AccountChannel",
        "close",
        "the idle sweep's record that no workflow waits on the channel any more; closing only takes away",
    ),
    (
        "ServiceSubscription",
        "open",
        "the platform's own bookkeeping for a version its publisher put in service; it starts nothing until the service takes it and a signed event arrives",
    ),
    (
        "ServiceSubscription",
        "register",
        "records that the service took the registration; it grants nothing",
    ),
    (
        "ServiceSubscription",
        "lapse",
        "the service dropped or refused the registration, or its time ran out; lapsing only takes away",
    ),
    (
        "ServiceSubscription",
        "remove",
        "the platform's own bookkeeping as the version leaves service; removing only takes away",
    ),
    (
        "Workflow",
        "hold_for",
        "an account the version acts through stopped lending itself to its publisher; holding only stops starts until someone publishes a usable account",
    ),
    (
        "WebhookSubscription",
        "record_success",
        "delivery bookkeeping after an attempt; it grants and changes no rights",
    ),
    (
        "WebhookSubscription",
        "record_failure",
        "delivery bookkeeping after an attempt; switching off after repeated failures only takes away",
    ),
    (
        "WebhookSubscription",
        "report_attempt",
        "raises the delivery record only; nothing stored changes, the store counted the attempt already",
    ),
    (
        "WebhookSubscription",
        "report_switched_off",
        "raises the switch-off the store's failure count caused; nothing stored changes, and switching off only takes away",
    ),
    ("User", "record_login", AFTER_SIGN_IN),
    ("User", "record_credential_change", CREDENTIAL_FOLLOW_UP),
    (
        "Tenant",
        "release_domain",
        "follows a domain being removed, handed over or losing its proof; nobody chooses it",
    ),
    (
        "OrgSubscription",
        "end_trial",
        "the trial's time ran out; the clock decides, and the organization pays or owes from then",
    ),
    ("OrgSubscription", "record_payment_method", PAYMENT_PROVIDER),
    ("OrgSubscription", "record_payment_failed", PAYMENT_PROVIDER),
    (
        "OrgSubscription",
        "record_payment_settled",
        PAYMENT_PROVIDER,
    ),
    (
        "OrgBranding",
        "platform_default",
        "made with the platform's own look before anyone changes it; it shows nothing of the organization's",
    ),
    (
        "Organization",
        "create",
        "founding is open sign-up; the founder becomes the first owner through the Founding it returns",
    ),
    (
        "Organization",
        "create_installation",
        "made once by the installer for a self-hosted deployment, before anyone exists",
    ),
    (
        "Organization",
        "suspend_for_non_payment",
        "the billing sweep finds a payment owed past the grace; the clock and the debt decide, and suspending only takes away",
    ),
    (
        "Organization",
        "lift_non_payment_suspension",
        PAYMENT_PROVIDER,
    ),
    (
        "ApprovalRequest",
        "request",
        "opening a request grants nothing; approving it needs an Approver",
    ),
    ("WorkflowExecution", "start_on_trigger", ENGINE_STEP),
    (
        "WorkflowExecution",
        "start_on_webhook",
        "a webhook call its trigger's secret admitted; it acts for the version's publisher, who issued that secret",
    ),
    (
        "AttestationChallenge",
        "issue",
        "issuing a nonce grants nothing; only signing it with the attested key bootstraps the agent",
    ),
    (
        "AttestationChallenge",
        "spend",
        "a single-use challenge being spent on one proof; it only takes away",
    ),
    (
        "PasskeyCredential",
        "update_sign_count",
        "records a use the WebAuthn adapter verified; a counter that does not go up refuses the sign-in",
    ),
    ("PasskeyCeremony", "open", CEREMONY),
    ("PasskeyCeremony", "open_discoverable", CEREMONY),
    ("PasskeyCeremony", "consume", CEREMONY),
    ("OrgPasskeyCeremony", "open", CEREMONY),
    ("OrgPasskeyCeremony", "open_discoverable", CEREMONY),
    ("OrgPasskeyCeremony", "consume", CEREMONY),
    ("TrustedDevice", "record_login", AFTER_SIGN_IN),
    (
        "Topic",
        "accept_publish",
        "raises the publish record only; nothing stored changes, and the publish right is checked before the topic is loaded, so a refused caller never learns it exists",
    ),
    (
        "RegisteredDomain",
        "prove_on_arrival",
        "a name the operator vouches for, or a wildcard whose verified delegated parent the registration just checked; the registration's own record covers it",
    ),
    (
        "RegisteredDomain",
        "request_certificate",
        "raises the request record only; nothing stored changes, and the domains right is checked before the domain is loaded, so a refused caller never learns it exists",
    ),
    (
        "ConsentRecord",
        "name_person",
        "names the person on the record once its own proof allowed it; staff may read the account only after that check",
    ),
    (
        "User",
        "close_directory_change",
        "ends a directory's change whose moves switch_by_directory already checked, raising its one status record",
    ),
    (
        "User",
        "note_verification_mailed",
        "raises the mail record only; nothing stored changes",
    ),
    (
        "User",
        "note_welcome_mailed",
        "raises the mail record only; nothing stored changes",
    ),
    ("Session", "bind_to_app", AFTER_SIGN_IN),
    (
        "Session",
        "record_signed_in_from",
        "names the remembered device whose secret the sign-in just presented and matched; it is held to the device being the holder's own and trusted, and grants nothing",
    ),
    (
        "Session",
        "record_sign_in",
        "raises the sign-in record only, once the session it opened is kept; nothing stored changes",
    ),
    (
        "Session",
        "record_factor_verified",
        "raises the record of a factor the session already took; nothing stored changes",
    ),
    (
        "Session",
        "record_app_token",
        "raises the record of a token issued under a live session the app sign-in already checked; nothing stored changes",
    ),
    (
        "Session",
        "record_token_theft",
        "raises the theft record for a retired session whose swapped token came back; nothing stored changes, the platform ends every session of its holder",
    ),
    (
        "MfaEnrollment",
        "record_failed_attempt",
        WRONG_ANSWER_COUNTED,
    ),
    ("MfaChallenge", "record_failure", WRONG_ANSWER_COUNTED),
    ("MfaEnrollment", "answer", CODE_SPENT),
    ("RecoveryCodeSet", "redeem", CODE_SPENT),
    (
        "OneTimeCode",
        "issue",
        "a code sent to the factor's own address or number; only its holder reads it, and sending grants nothing",
    ),
    ("OneTimeCode", "redeem", CODE_SPENT),
    ("OrgToken", "sign_in", LINK_SPENT),
    ("PasswordResetRequest", "create", LINK_MAILED),
    ("OrgToken", "issue", LINK_MAILED),
    ("PasswordResetRequest", "complete", LINK_SPENT),
    (
        "PasswordResetRequest",
        "in_sign_in",
        "begun by the password sign-in that just proved the account's current password; its token goes back to that sign-in or to the account's own mailbox, and sets nothing until it is spent",
    ),
    (
        "PasswordResetRequest",
        "complete_in_sign_in",
        "the sign-in's own change token being spent, beside the factor code or mailbox its change proof asks for; holding the token is the proof",
    ),
    ("OrgToken", "redeem", LINK_SPENT),
    ("OrgToken", "confirm", LINK_SPENT),
    (
        "OrgToken",
        "confirm_installer",
        "the setup token the install showed its installer being spent; holding it is the proof, and it is refused for anyone but the owner it was issued to",
    ),
    (
        "SessionHandoff",
        "issue",
        "a short-lived code issued for a live session its own cookie presented, bound to the browser that asked",
    ),
    (
        "SessionHandoff",
        "redeem",
        "a one-time code being checked and spent in the browser it was bound to; the code and that browser's value are the proof",
    ),
    ("SignInCode", "redeem", CODE_SPENT),
    ("MfaChallenge", "issue", ISSUED_AFTER_SIGN_IN),
    ("MfaChallenge", "consume", CODE_SPENT),
    ("SignInCode", "issue", ISSUED_AFTER_SIGN_IN),
    (
        "Session",
        "suspend",
        "frozen on a risk or binding signal the platform raised; it only takes away until the holder proves a factor again",
    ),
    (
        "OrgSession",
        "touch",
        "activity on a session its check already admitted; it only keeps the session from going idle",
    ),
    ("OrgApiKey", "record_usage", LAST_SEEN),
    ("ApiKey", "record_usage", LAST_SEEN),
    (
        "ApiKey",
        "note_country",
        "the country a sign-in its check already admitted came from; it records news, it grants nothing",
    ),
    ("ScimEndpoint", "record_sync", LAST_SEEN),
    ("AccessToken", "issue", ISSUED_AFTER_A_CHECK),
    (
        "AccessToken",
        "issue_for_tunnel",
        "issued as `issue` is, after the consent was checked; the client is checked to be the token's and to take readable tokens, and the route to open an active signed-in tunnel",
    ),
    (
        "AccessToken",
        "for_client",
        "the client asks with its own secret at the token endpoint; the client is checked to hold the grant and the scopes",
    ),
    (
        "AccessToken",
        "exchanged",
        "follows a TokenExchange that checked the client, the subject and actor tokens, the audience and the scopes",
    ),
    (
        "InitialAccessToken",
        "admit",
        "the registering app presents the token itself; holding it is the proof, and admitting only spends a use",
    ),
    (
        "PushedRequest",
        "push",
        "the client pushes its own request after proving itself at the endpoint; it is screened as the browser's would be",
    ),
    (
        "PushedRequest",
        "redeem",
        "a browser brings the request_uri back for the client that pushed it; it is used once, within sixty seconds",
    ),
    (
        "OAuthRefreshToken",
        "from_code",
        "follows a code its client just swapped, carrying that grant on; the code and client are checked",
    ),
    (
        "OAuthRefreshToken",
        "from_device",
        "follows a device approval its client just collected, carrying that grant on; the approval and client are checked",
    ),
    (
        "OAuthRefreshToken",
        "rotated",
        "replaces a token its client just used, carrying the same grant on, never past its family's end",
    ),
    (
        "OAuthRefreshToken",
        "rotate",
        "the client holding the token uses it at the token endpoint; the token is checked to be its own and unused",
    ),
    (
        "OAuthRefreshToken",
        "lose_rotation",
        "storage turned down a rotation another refresh with the same token won; it only records the reuse, and grants nothing",
    ),
    (
        "OAuthRefreshToken",
        "revoke",
        "revoking a token only takes it away; the client holding it asks, or signing out or a reuse leads to it",
    ),
    (
        "OAuthRefreshToken",
        "revoke_by_holder",
        "the client holding the token revokes it at the revocation endpoint after proving itself; it is checked to be its own, and revoking only takes away",
    ),
    (
        "AccessToken",
        "revoke_by_holder",
        "the client holding the token revokes it at the revocation endpoint after proving itself; it is checked to be its own, and revoking only takes away",
    ),
    (
        "DeviceAuthorization",
        "poll",
        "the device polls with its own device code; it only records the time and may lengthen the wait",
    ),
    ("AuthorizationCode", "create", ISSUED_AFTER_A_CHECK),
    (
        "AccessToken",
        "revoke",
        "revoking a token only takes it away; the client holding it asks, or a withdrawn consent or revoked client leads to it",
    ),
    (
        "DeviceAuthorization",
        "create",
        "a device asks to start a sign-in; it grants nothing until the signed-in person approves",
    ),
    (
        "DeviceAuthorization",
        "redeem",
        "the client that started the flow collects an approval already given, and is checked against the request",
    ),
    (
        "DeviceAuthorization",
        "expire",
        "its window ran out; the clock decides, and expiring grants nothing",
    ),
    (
        "Operator",
        "install_first",
        "made once by the installer for the platform, before any operator exists",
    ),
    (
        "TenantBranding",
        "default_branding",
        "made once by the platform as it provisions the tenant; it shows only the platform's own look",
    ),
    (
        "SigningKey",
        "create",
        "a new key signs nothing until a key set takes it, which needs the crypto right; the first is made at provisioning",
    ),
    (
        "AssertionKey",
        "create",
        "the platform makes a tenant's assertion keys at its setup and on its rotation schedule; no person makes or changes one",
    ),
    (
        "SignalStream",
        "record_success",
        "delivery bookkeeping after an attempt; it grants and changes no rights",
    ),
    (
        "SignalStream",
        "record_failure",
        "delivery bookkeeping after an attempt; switching off after repeated failures only takes away",
    ),
    (
        "SignalStream",
        "confirm_endpoint",
        "the endpoint proves itself by echoing the challenge a person with the update right had sent to it",
    ),
    (
        "Notification",
        "create",
        "made by the fan-out worker from an event that already happened; only holders of the event's view right see it",
    ),
    (
        "Notification",
        "mark_read",
        "the recipient's own read mark in an inbox the store opens only for them; it grants and hides nothing",
    ),
    (
        "NotificationPreference",
        "new",
        "a category and channel pair the platform fills in; it decides nothing, and delivery does not read it yet",
    ),
    ("ScheduledJob", "new", JOB_QUEUE),
    ("ScheduledJob", "mark_running", JOB_QUEUE),
    ("ScheduledJob", "mark_completed", JOB_QUEUE),
    ("ScheduledJob", "mark_failed", JOB_QUEUE),
    ("ScheduledJob", "abandon", JOB_QUEUE),
    ("ScheduledJob", "supersede", JOB_QUEUE),
    (
        "ScheduledJob",
        "retry",
        "takes the order only an operator's authority can make; the operator is named on the record that authority builds",
    ),
    (
        "Session",
        "note_use",
        "the platform notes where a session is used as it is used; nobody decides it",
    ),
    (
        "Session",
        "stop_taken_over",
        "the platform stops a session whose use no longer looks like its holder; nobody decides it, and the record says why",
    ),
    (
        "Tenant",
        "announce_provisioning",
        "the reconciliation sweep repeats an announcement a member who may make tenants already caused; it changes and grants nothing",
    ),
    (
        "FederatedIdpConnection",
        "refresh_metadata",
        "the scheduled refresh reads again the address an admin who may trust connections chose; it takes only metadata naming the same provider",
    ),
    (
        "SecuritySignal",
        "new",
        "raised by the platform from an event already recorded, to tell receivers; it grants nothing",
    ),
    ("TenantClone", "mark_copied", CLONE_STEP),
    ("TenantClone", "fail", CLONE_STEP),
    ("TenantSetup", "begin", SETUP_STEP),
    ("TenantSetup", "finish", SETUP_STEP),
    ("TenantSetup", "fail", SETUP_STEP),
    ("TenantTeardown", "begin", TEARDOWN_STEP),
    ("TenantTeardown", "finish", TEARDOWN_STEP),
    ("TenantTeardown", "fail", TEARDOWN_STEP),
    ("Tenant", "copy_settings_from", CLONE_STEP),
    ("AuditStream", "record_delivered", DELIVERY_OUTCOME),
    ("AuditStream", "record_failed", DELIVERY_OUTCOME),
    (
        "TenantMailProvider",
        "platform_mail",
        "made once by the platform as it provisions the tenant; it sends through the platform's own mail as before",
    ),
    ("TenantMailProvider", "record_test_send", DELIVERY_OUTCOME),
    ("StageConfig", "locked", UNATTACHED_STAGE),
    ("StageConfig", "new", UNATTACHED_STAGE),
    ("Invitation", "lapse", LINK_RAN_OUT),
    ("Invitation", "decline", LINK_SPENT),
    ("OrgInvitation", "accept", LINK_SPENT),
    ("OrgInvitation", "decline", LINK_SPENT),
    ("OrgInvitation", "lapse", LINK_RAN_OUT),
    ("ErasureRequest", "start_processing", ERASURE_STEP),
    ("ErasureRequest", "complete", ERASURE_STEP),
    ("ErasureRequest", "fail", ERASURE_STEP),
    ("ErasureRequest", "retry", ERASURE_STEP),
    ("ErasureRequest", "cancel_from_link", LINK_SPENT),
    ("OrgErasureRequest", "start_processing", ERASURE_STEP),
    ("OrgErasureRequest", "complete", ERASURE_STEP),
    ("OrgErasureRequest", "fail", ERASURE_STEP),
    ("OrgErasureRequest", "retry", ERASURE_STEP),
    ("OrgErasureRequest", "cancel_from_link", LINK_SPENT),
    ("UserImport", "take_up", IMPORT_STEP),
    ("UserImport", "record_chunk", IMPORT_STEP),
    ("UserImport", "give_up", IMPORT_STEP),
    (
        "DataExportRequest",
        "mark_ready",
        "the file asked for was gathered; the worker records it, and only the person downloads it",
    ),
    (
        "DataExportRequest",
        "expire",
        "its download window ran out; the clock decides, and expiring only takes the file away",
    ),
    (
        "AuditLogExport",
        "mark_written",
        "the worker wrote the file a reader who may read the log asked for; only such a reader downloads it",
    ),
    (
        "AuditLogExport",
        "give_up",
        "the worker did not write the file in time; the clock decides, and giving up keeps nothing",
    ),
    (
        "AuditLogExport",
        "expire",
        "its download window ran out; the clock decides, and expiring only takes the file away",
    ),
    (
        "ChainVerdict",
        "of",
        "the scheduled sweep keeps what its walk of the chain found; it changes no record and grants nothing",
    ),
    (
        "SecureToken",
        "create",
        "a link mailed to the address the account holds; only its reader can spend it, and issuing grants nothing",
    ),
    ("SecureToken", "redeem", LINK_SPENT),
    ("PendingEmailChange", "confirm", LINK_SPENT),
    ("PendingEmailChange", "cancel_from_old_address", LINK_SPENT),
    ("PendingEmailChange", "reissue", LINK_RENEWED),
    ("Invitation", "renew_from_link", LINK_RENEWED),
    ("OrgInvitation", "renew_from_link", LINK_RENEWED),
    (
        "Session",
        "sign_out",
        "ended by whoever presents its own refresh token; ending a session only takes away",
    ),
    (
        "Session",
        "end_with_account",
        "follows the holder's account being locked, switched off or closed by someone checked when they moved it; the shut-out account is the proof, and ending a session only takes away",
    ),
    (
        "VerifyingKey",
        "of",
        "the public half read off a signing key as it stands; it copies what the key holds, changes nothing and grants nothing",
    ),
    (
        "BreakGlassPolicy",
        "off",
        "the policy every tenant starts with; it lets nobody give themselves anything",
    ),
    (
        "RoleAssignment",
        "by_default",
        "follows an account being opened; whoever made the role a default was checked for all it grants",
    ),
    (
        "RoleAssignment",
        "from_accepted_invitation",
        "follows an invitation being accepted, which checked the role against what the inviter holds now",
    ),
    (
        "RoleAssignment",
        "from_approved_request",
        "follows an access request being approved, which checked the approver for the right and the role",
    ),
    (
        "RoleAssignment",
        "lapse",
        "its end has passed; the clock decides, and sweeping it only takes away",
    ),
    (
        "GroupMembership",
        "from_approved_request",
        "follows an access request being approved, which checked the approver for the right and what the group brings",
    ),
    (
        "GroupMembership",
        "lapse",
        "its end has passed; the clock decides, and sweeping it only takes away",
    ),
    (
        "AccessRequest",
        "expire",
        "nobody answered it in time; the clock decides, and it grants nothing",
    ),
    (
        "AccessRequestPolicy",
        "widest",
        "the limit every tenant starts with; it lets nobody ask for longer than anyone may",
    ),
    (
        "AccessReview",
        "complete_overdue",
        "its due date has passed; the clock decides, and the reviewers' choices and the rule it was started with say who loses access",
    ),
    (
        "RoleAssignment",
        "withdraw_by_review",
        "follows an overdue review being completed; only that review's own removals name the holder, and it only takes away",
    ),
    (
        "GroupMembership",
        "withdraw_by_review",
        "follows an overdue review being completed; only that review's own removals name the member, and it only takes away",
    ),
    (
        "ClearanceRules",
        "none",
        "the rules every tenant starts with; no app permission clears for anything",
    ),
    (
        "OrgUser",
        "change_own_password",
        "the person proves themselves with their current password, checked here before anything changes",
    ),
    (
        "OrgUser",
        "record_sign_in",
        "follows a sign-in the authentication context already checked; it only spends what the setup token or an invitation vouched for",
    ),
    ("OrgUser", "record_credential_change", CREDENTIAL_FOLLOW_UP),
    ("OrgUser", "record_mfa_enrolled", CREDENTIAL_FOLLOW_UP),
    ("OrgUser", "record_mfa_turned_off", CREDENTIAL_FOLLOW_UP),
    ("OrgUser", "record_mfa_reset", CREDENTIAL_FOLLOW_UP),
    (
        "OrgUser",
        "record_recovery_codes_generated",
        CREDENTIAL_FOLLOW_UP,
    ),
    ("OrgUser", "record_passkey_registered", CREDENTIAL_FOLLOW_UP),
    ("OrgUser", "record_passkey_removed", CREDENTIAL_FOLLOW_UP),
    ("CloudAccount", "mark_verified", PROBE_OUTCOME),
    ("CloudAccount", "mark_failed", PROBE_OUTCOME),
    ("RegisteredDomain", "mark_verified", PROBE_OUTCOME),
    (
        "RegisteredDomain",
        "mark_verification_failed",
        PROBE_OUTCOME,
    ),
    ("RegisteredDomain", "mark_tls_active", CERTIFICATE_STEP),
    ("RegisteredDomain", "mark_tls_renewed", CERTIFICATE_STEP),
    ("RegisteredDomain", "mark_tls_expired", CERTIFICATE_STEP),
    (
        "RegisteredDomain",
        "report_expiring",
        "warns that a certificate the tenant uploaded runs out soon; the clock decides, and it changes nothing stored",
    ),
    ("AcmeChallenge", "open", CERTIFICATE_STEP),
    ("CertificateBundle", "new", CERTIFICATE_STEP),
    ("PlatformCertificate", "issued", CERTIFICATE_STEP),
];

/// Text or a picture a person may leave out; nothing decides on it.
const LEFT_BLANK: &str = "a person may leave it out, and no rule reads it";

/// When something last happened, kept to be shown.
const LAST_SEEN: &str = "when it last happened, shown to people; no rule reads it";

/// A field a protocol or file format marks optional, read or written as it is.
const AS_THE_PROTOCOL_HAS_IT: &str =
    "optional in the protocol it carries, so absent is a value the other side may send";

/// A half of a request's double-submit CSRF pair, which HTTP lets a client
/// leave out.
const CSRF_HALF_NOT_SENT: &str = "a client may send the CSRF cookie or header or neither; only both sent, not empty and equal match, so a half not sent refuses";

/// A true or false someone sent or stored, not a choice the domain makes.
const TRUE_OR_FALSE_DATA: &str =
    "a true or false value as it was sent or stored, not a choice the domain makes";

/// A platform subdomain built from a tenant's names, which may not form a
/// domain name.
const NAME_MAY_NOT_FORM: &str = "built from the tenant's names, it is left out when it forms no domain name, never shortened into what could be another tenant's";

/// The space at a service a connection's account works in, named only for
/// a sign-in that asks for one.
const PLACE_ONLY_WHEN_ASKED: &str = "only a sign-in reaching several spaces at its service asks for one, such as Azure DevOps' organization; every other has nothing to name, and the use case refuses one given or left out against what the sign-in asks";

/// Fields that stay an `Option` or a `bool`, each with the reason it stays.
///
/// An entry whose reason says what it is to become is work still to do; the
/// list only shrinks.
pub(crate) const UNTYPED_CHOICES_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "domains/operator/events.rs",
        "DeadJobRetried.tenant_id",
        "a job of the platform's own work belongs to no tenant; there is no other case",
    ),
    (
        "domains/workflows/evaluation/outcome.rs",
        "Difference.found",
        "nothing was at the check's path; there is no other case",
    ),
    (
        "domains/workflows/events/mod.rs",
        "WorkflowApprovalGranted.shown",
        "an approval of every item of a loop says what was shown; an approval step's own approval shows no items",
    ),
    (
        "domains/workflows/events/sandbox.rs",
        "SandboxVersionSaved.agent",
        "a version holds an agent or its code is the step's work; the record names the agent only for the first",
    ),
    (
        "domains/workflows/guardrail/finding.rs",
        "FindingPlace.field",
        "a finding is in a field of the checked value, or in the value itself when it is plain text",
    ),
    (
        "domains/workflows/guardrail/finding.rs",
        "FindingPlace.span",
        "a finding is a span of a text, or a whole field a classification rule names",
    ),
    (
        "domains/workflows/guardrail/scan.rs",
        "Guard.rules",
        "a tenant that classified nothing has no rules to read; it is not an empty set it could have saved",
    ),
    (
        "domains/workflows/guardrail/scan.rs",
        "Place.field",
        "the walk is at a field of the checked value, or at the value itself",
    ),
    (
        "domains/workflows/design/workflow/row.rs",
        "CreateWorkflowParams.description",
        LEFT_BLANK,
    ),
    (
        "domains/workflows/design/workflow/row.rs",
        "WorkflowRow.description",
        LEFT_BLANK,
    ),
    (
        "domains/workflows/design/workflow.rs",
        "Workflow.description",
        LEFT_BLANK,
    ),
    (
        "domains/workflows/design/workflow.rs",
        "DraftStart.description",
        LEFT_BLANK,
    ),
    (
        "domains/workflows/integration/form.rs",
        "InputForm.example",
        "an integration may give no example; the box is then simply empty",
    ),
    (
        "domains/workflows/integration/form.rs",
        "InputForm.warning",
        "most inputs need no warning; one is shown only where an integration gives it",
    ),
    (
        "domains/workflows/integration/form.rs",
        "Picker.depends_on",
        "a list depends on another input or on none; `FieldName` is everything depending on one means, so there is no second case with data of its own to name",
    ),
    (
        "domains/workflows/integration/guide.rs",
        "OperationGuide.preview",
        "an operation is previewed or it is not; `Preview` holds everything a preview means, so there is no second case with data of its own to name",
    ),
    (
        "domains/workflows/account/connection.rs",
        "ConnectionRequest.place",
        PLACE_ONLY_WHEN_ASKED,
    ),
    (
        "domains/workflows/account/connection.rs",
        "PendingConnection.place",
        PLACE_ONLY_WHEN_ASKED,
    ),
    (
        "domains/workflows/execution/mod.rs",
        "WorkflowExecution.pass",
        "a run is the pass of a loop or it is not; `PassOf` holds everything being one means, the loop's run, its step and the item, so there is no second case with data of its own to name",
    ),
    (
        "domains/workflows/design/workflow/hold.rs",
        "UsedAccount.operation",
        "a trigger registers through its account for no operation; only a step acts through one with an operation, and `at` already says which it is",
    ),
    (
        "domains/tenant/hosts.rs",
        "PlatformHosts.readable",
        NAME_MAY_NOT_FORM,
    ),
    (
        "domains/tenant/hosts.rs",
        "PlatformHosts.stable",
        NAME_MAY_NOT_FORM,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.event_type",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.after",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.before",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.actor",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.tenant_id",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.target",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/filter.rs",
        "AuditExportFilterParts.ip_address",
        NOT_FILTERED,
    ),
    (
        "domains/audit/export/mod.rs",
        "AuditLogExport.seal",
        "only a ready tenant export is sealed; the export ties the seal to its log and state when written and when read back",
    ),
    (
        "domains/audit/export/seal.rs",
        "WrittenFile.seal",
        "only a tenant's file is sealed; marking it written refuses a tenant file without one and any other with one",
    ),
    (
        "domains/authentication/risk_engine/challenge.rs",
        "GateSignals.proof",
        "a sign-in may come without a challenge proof; the gate decides what its absence means under each pressure",
    ),
    (
        "domains/federation/admission.rs",
        "KnownRecords.subject_link",
        MAY_FIND_NOTHING,
    ),
    (
        "domains/federation/admission.rs",
        "KnownRecords.address_holder",
        MAY_FIND_NOTHING,
    ),
    (
        "domains/federation/admission.rs",
        "KnownRecords.holder_link",
        MAY_FIND_NOTHING,
    ),
    (
        "shared/errors.rs",
        "CorruptRow.broken_rule",
        "an error's source, which a row that breaks no single value's rule does not have",
    ),
    (
        "domains/agents/identity/agent.rs",
        "AgentIdentity.description",
        LEFT_BLANK,
    ),
    (
        "domains/agents/authority/delegation/mod.rs",
        "Delegation.name",
        LEFT_BLANK,
    ),
    (
        "domains/agents/authority/delegation/record.rs",
        "GrantDelegationParams.name",
        LEFT_BLANK,
    ),
    (
        "domains/agents/authority/delegation/record.rs",
        "AttenuateParams.name",
        LEFT_BLANK,
    ),
    (
        "domains/agents/authority/delegation/record.rs",
        "DelegationRow.name",
        LEFT_BLANK,
    ),
    (
        "domains/agents/execution/model_provider/status.rs",
        "LastTest.reason",
        LEFT_BLANK,
    ),
    (
        "domains/authentication/events/session.rs",
        "SessionRevoked.user_label",
        LEFT_BLANK,
    ),
    (
        "domains/authentication/risk_engine/assessment.rs",
        "IpGeolocation.city",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/events/policies.rs",
        "PolicySimulated.matched_rule",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/events/policies.rs",
        "PolicySimulated.simulated_path",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/events/roles.rs",
        "RoleAssigned.granted_by_label",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/policy/simulator/mod.rs",
        "SimulationResult.matched_rule",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/resource_type/mod.rs",
        "NewResourceType.description",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/resource_type/mod.rs",
        "ResourceType.description",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/resource_type/mod.rs",
        "ResourceTypeChange.description",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/role/permission_moves.rs",
        "WantedPermissions.system",
        "None keeps the built-in permissions as they are; an empty list takes them all away",
    ),
    (
        "domains/authorization/role/permission_moves.rs",
        "WantedPermissions.custom",
        "None keeps the tenant's permissions as they are; an empty list takes them all away",
    ),
    (
        "domains/branding/renderer.rs",
        "RenderedEmail.html",
        LEFT_BLANK,
    ),
    (
        "domains/consumers/consumer.rs",
        "Consumer.description",
        LEFT_BLANK,
    ),
    (
        "domains/identity/attribute/definition/mod.rs",
        "AttributeDefinition.description",
        LEFT_BLANK,
    ),
    (
        "domains/identity/attribute/definition/mod.rs",
        "DeclareAttribute.description",
        LEFT_BLANK,
    ),
    (
        "domains/identity/privacy/erasure.rs",
        "ErasureRequest.reason",
        LEFT_BLANK,
    ),
    (
        "domains/organization/members/privacy/erasure.rs",
        "OrgErasureRequest.reason",
        LEFT_BLANK,
    ),
    (
        "domains/identity/invitations/invitation.rs",
        "CreateInvitationParams.message",
        LEFT_BLANK,
    ),
    (
        "domains/identity/invitations/invitation.rs",
        "InvitationRow.message",
        LEFT_BLANK,
    ),
    (
        "domains/identity/invitations/offer.rs",
        "InvitationOffer.message",
        LEFT_BLANK,
    ),
    (
        "domains/messaging/schema.rs",
        "EventSchema.description",
        LEFT_BLANK,
    ),
    (
        "domains/messaging/topic.rs",
        "Topic.description",
        LEFT_BLANK,
    ),
    (
        "domains/notifications/notification.rs",
        "Notification.body",
        LEFT_BLANK,
    ),
    (
        "domains/operator/events.rs",
        "OperatorApiKeyRevoked.key_prefix",
        LEFT_BLANK,
    ),
    (
        "domains/organization/billing/catalog.rs",
        "PlanTier.badge",
        LEFT_BLANK,
    ),
    (
        "domains/organization/billing/catalog.rs",
        "PlanTier.footnote",
        LEFT_BLANK,
    ),
    (
        "domains/organization/billing/catalog.rs",
        "PlanTier.heading",
        LEFT_BLANK,
    ),
    (
        "domains/organization/billing/catalog.rs",
        "PlanTier.price",
        LEFT_BLANK,
    ),
    (
        "domains/organization/billing/catalog.rs",
        "PlanTier.requirements_description",
        LEFT_BLANK,
    ),
    (
        "domains/organization/members/invitation.rs",
        "CreateOrgInvitationParams.message",
        LEFT_BLANK,
    ),
    (
        "domains/organization/members/invitation.rs",
        "OrgInvitationRow.message",
        LEFT_BLANK,
    ),
    (
        "domains/proxy/request/graphql.rs",
        "GraphQlOperation.name",
        LEFT_BLANK,
    ),
    (
        "domains/proxy/request/transform/response.rs",
        "ResponseMutation.body",
        LEFT_BLANK,
    ),
    (
        "domains/proxy/request/transform/response.rs",
        "ResponseMutationRules.body",
        LEFT_BLANK,
    ),
    (
        "domains/scheduling/job.rs",
        "ScheduledJob.error",
        LEFT_BLANK,
    ),
    (
        "domains/scheduling/job.rs",
        "ScheduledJob.tenant_id",
        "the platform's own work runs for no tenant; the queue reads it only to share workers out fairly",
    ),
    (
        "domains/scheduling/job.rs",
        "ScheduledJob.key",
        "most work may run twice; only work that must not is keyed, and the queue reads it only to queue that work once",
    ),
    (
        "domains/tenant/events/custom_domains.rs",
        "TenantPrimaryDomainChanged.new_domain",
        LEFT_BLANK,
    ),
    (
        "domains/tenant/events/custom_domains.rs",
        "TenantPrimaryDomainChanged.old_domain",
        LEFT_BLANK,
    ),
    (
        "domains/webhooks/subscription.rs",
        "WebhookSubscription.description",
        LEFT_BLANK,
    ),
    ("shared/events/data.rs", "Change.from", LEFT_BLANK),
    ("shared/events/data.rs", "Change.to", LEFT_BLANK),
    (
        "domains/agents/identity/agent.rs",
        "AgentIdentity.last_attested_at",
        LAST_SEEN,
    ),
    (
        "domains/authentication/credentials/passkey.rs",
        "PasskeyCredential.last_used_at",
        LAST_SEEN,
    ),
    (
        "domains/federation/scim.rs",
        "ScimEndpoint.last_sync_at",
        LAST_SEEN,
    ),
    (
        "domains/identity/account/user/mod.rs",
        "User.last_login_at",
        LAST_SEEN,
    ),
    (
        "domains/oauth/clients/api_key.rs",
        "ApiKey.last_used_at",
        LAST_SEEN,
    ),
    (
        "domains/oauth/clients/api_key.rs",
        "ApiKey.last_used_ip",
        LAST_SEEN,
    ),
    (
        "domains/organization/access/api_key.rs",
        "OrgApiKey.last_used_at",
        LAST_SEEN,
    ),
    (
        "domains/scheduling/job.rs",
        "ScheduledJob.last_attempted_at",
        LAST_SEEN,
    ),
    (
        "domains/webhooks/subscription.rs",
        "WebhookSubscription.last_delivered_at",
        LAST_SEEN,
    ),
    (
        "domains/agents/execution/chat.rs",
        "CompletionRequest.max_tokens",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/proxy/request/cross_site.rs",
        "CsrfEcho.cookie",
        CSRF_HALF_NOT_SENT,
    ),
    (
        "domains/proxy/request/cross_site.rs",
        "CsrfEcho.header",
        CSRF_HALF_NOT_SENT,
    ),
    (
        "domains/federation/saml/assertion_builder.rs",
        "AssertionParams.in_response_to",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/saml/authn_request.rs",
        "InboundAuthnRequest.acs_url",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/saml/authn_request.rs",
        "InboundAuthnRequest.issuer",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/saml/idp_metadata_builder.rs",
        "IdpMetadataParams.slo_url",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityClaims.family_name",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityClaims.given_name",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityClaims.locale",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityClaims.name",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityClaims.picture",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/oidc/identity.rs",
        "OidcIdentityParams.email_verified",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/scoped_claims.rs",
        "ScopedClaims.email_verified",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/federation/saml/response_builder.rs",
        "SamlResponseParams.in_response_to",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/id_token.rs",
        "IdTokenClaims.nonce",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/scoped_claims.rs",
        "ScopedClaims.email",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/scoped_claims.rs",
        "ScopedClaims.name",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/scoped_claims.rs",
        "ScopedClaims.locale",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/scoped_claims.rs",
        "ScopedClaims.zoneinfo",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/oauth/grants/scoped_claims.rs",
        "ScopedClaims.roles",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/organization/cloud/credential.rs",
        "GcpKeyFacts.universe_domain",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/identity/metadata_value.rs",
        "MetadataValue.Bool",
        TRUE_OR_FALSE_DATA,
    ),
    (
        "domains/routing/matching/parameter/screening.rs",
        "BodyValue.Flag",
        TRUE_OR_FALSE_DATA,
    ),
    (
        "domains/workflows/data.rs",
        "Value.Bool",
        TRUE_OR_FALSE_DATA,
    ),
    (
        "domains/workflows/data.rs",
        "FlowValue.Bool",
        TRUE_OR_FALSE_DATA,
    ),
    (
        "domains/signals/stream.rs",
        "StreamUpdate.endpoint",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/signals/stream.rs",
        "StreamUpdate.delivery_method",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/signals/stream.rs",
        "StreamUpdate.signal_types",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/signals/stream.rs",
        "StreamUpdate.authorization",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/webhooks/subscription.rs",
        "WebhookUpdate.url",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/webhooks/subscription.rs",
        "WebhookUpdate.event_types",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/webhooks/subscription.rs",
        "WebhookUpdate.description",
        LEFT_AS_IT_IS,
    ),
    (
        "domains/webhooks/subscription.rs",
        "WebhookUpdate.retry",
        LEFT_AS_IT_IS,
    ),
];

/// A part of an update that, left out, stays as it is.
const LEFT_AS_IT_IS: &str = "a part of one update that, left out, stays as it is; the update records one change for all it names";

/// A lookup's answer, which may be that it found nothing.
const MAY_FIND_NOTHING: &str = "the answer of a lookup, which may find nothing";

const NOT_FILTERED: &str = "a filter of an audit export; left out, it does not narrow the export";

/// Function parameters that stay an `Option`, each with the reason it stays,
/// as `function.parameter`.
pub(crate) const OPTIONAL_PARAMETERS_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "domains/workflows/data.rs",
        "of_field.base",
        "a path starts at the root value or under another path",
    ),
    (
        "domains/workflows/data.rs",
        "of_index.base",
        "a path starts at the root list or under another path",
    ),
    (
        "domains/workflows/data.rs",
        "extended.base",
        "a path starts at the root value or under another path",
    ),
    (
        "domains/workflows/evaluation/set.rs",
        "ensure_publishable.last",
        "a draft may never have been evaluated; that refuses it like a failed evaluation when the gate is on",
    ),
    (
        "domains/workflows/guardrail/finding.rs",
        "new.field",
        "a finding is in a field of the checked value, or in the value itself",
    ),
    (
        "domains/workflows/guardrail/finding.rs",
        "new.span",
        "a finding is a span of a text, or a whole field",
    ),
    (
        "domains/workflows/design/workflow/edits.rs",
        "describe.description",
        LEFT_BLANK,
    ),
    (
        "domains/messaging/message_type.rs",
        "admits.message_type",
        "a message may be published with no type; a filter then never admits it, which is the rule this answers",
    ),
    (
        "domains/agents/execution/run/status.rs",
        "next_call.pending",
        "part of `RunState::from_stored`, reading the call storage kept, which a running or paused run may not have",
    ),
    (
        "domains/oauth/grants/logout.rs",
        "after_logout.client",
        "a sign-out request may name no app, or one the tenant does not have; the person then stays on the signed-out page",
    ),
    (
        "domains/oauth/grants/logout.rs",
        "after_logout.asked",
        "a sign-out request may name no address; the person then stays on the signed-out page",
    ),
    (
        "domains/oauth/grants/authorization_request.rs",
        "screen.client",
        "a request naming a client the tenant does not have is one the screen answers, to the browser only",
    ),
    (
        "domains/activity/calendar.rs",
        "graded_day.by_category",
        MAY_FIND_NOTHING,
    ),
    (
        "domains/agents/execution/chat.rs",
        "single.max_tokens",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/agents/execution/model_provider.rs",
        "record_test_result.message",
        "what the provider answered, when it answered anything",
    ),
    (
        "domains/agents/identity/agent.rs",
        "update_details.description",
        LEFT_BLANK,
    ),
    (
        "domains/authentication/risk_engine/assessment.rs",
        "new.city",
        MAY_FIND_NOTHING,
    ),
    (
        "domains/authorization/policy/simulator/mod.rs",
        "settled_by.matched_rule",
        "a decision the default action made names no rule",
    ),
    (
        "domains/authorization/resource_type/mod.rs",
        "describe.description",
        LEFT_BLANK,
    ),
    (
        "domains/authorization/role_assignment.rs",
        "raise_assigned.granted_by_label",
        "only an accepted invitation names who granted the role",
    ),
    (
        "domains/identity/account/user/profile.rs",
        "change_preferences.locale",
        "a setting not given stays as it is",
    ),
    (
        "domains/identity/account/user/profile.rs",
        "change_preferences.timezone",
        "a setting not given stays as it is",
    ),
    (
        "domains/crypto/jwt_type.rs",
        "accepted_as_credential.typ",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/crypto/jwt_type.rs",
        "is_named_by.typ",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/identity/attribute/definition/mod.rs",
        "describe.description",
        LEFT_BLANK,
    ),
    (
        "domains/identity/invitations/offer.rs",
        "open.message",
        LEFT_BLANK,
    ),
    (
        "domains/proxy/request/cross_site.rs",
        "new.cookie",
        CSRF_HALF_NOT_SENT,
    ),
    (
        "domains/proxy/request/cross_site.rs",
        "new.header",
        CSRF_HALF_NOT_SENT,
    ),
    (
        "domains/proxy/request/forwarded.rs",
        "client_address.forwarded_for",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/proxy/request/forwarded.rs",
        "forwarded_client.forwarded_for",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/proxy/request/transform/mod.rs",
        "apply_to_query.original",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/routing/stream/mod.rs",
        "accepts.server_name",
        AS_THE_PROTOCOL_HAS_IT,
    ),
    (
        "domains/workflows/design/condition.rs",
        "passes.found",
        MAY_FIND_NOTHING,
    ),
    (
        "domains/tenant/setup.rs",
        "of.setup",
        "the setup kept for the tenant, which one whose setup has not begun yet does not have; that reads as still running",
    ),
    (
        "domains/workflows/design/condition.rs",
        "number_of.found",
        MAY_FIND_NOTHING,
    ),
    (
        "shared/clock.rs",
        "set.value",
        "none goes back to the real clock",
    ),
    (
        "shared/model/row_check.rs",
        "in_order_if.later",
        "when something happened, if it did, as the stored state reports it",
    ),
];

/// Function parameters that stay a `bool`, each with the reason it stays,
/// as `function.parameter`. Only an answer read beside the words that say
/// what it answers belongs here, never a choice a caller makes.
pub(crate) const FLAG_PARAMETERS_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "domains/workflows/data.rs",
        "bool.value",
        "the true or false a workflow value holds, as data, not a choice",
    ),
    (
        "domains/workflows/stored.rs",
        "visit_bool.value",
        "the true or false a stored workflow value holds, as serde hands it over to become data",
    ),
    (
        "shared/model/row_check.rs",
        "holds.rule",
        "whether a stored row keeps a rule, passed beside the reason naming that rule",
    ),
];

/// Files that keep their folder's name, with the reason.
pub(crate) const FILE_NAMES_ALLOWED: &[(&str, &str)] = &[
    ("types/actor/actor_ref.rs", "`ref` is a Rust keyword"),
    (
        "domains/oauth/grants/id_token_grant.rs",
        "`id_token.rs` beside it already holds the ID token; this is the grant that issues one",
    ),
];
