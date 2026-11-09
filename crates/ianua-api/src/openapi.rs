//! The OpenAPI document: the shared header and tags here, and each
//! context's paths and schemas from its `routes/<context>.rs`.
//!
//! Served at `/api/v1/docs` (Swagger UI) and `/api/v1/reference` (Scalar).

use utoipa::openapi::Required;
use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Registers the bearer-token security scheme so Swagger UI shows an
/// "Authorize" button and sends `Authorization: Bearer <token>` on requests.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("Session token")
                        .build(),
                ),
            );
        }
    }
}

/// Adds path parameters (`{org_slug}`, `{tenant_slug}`, `{id}`, …) to every
/// route from its URL template, so Swagger UI renders input fields for them.
///
/// Handlers extract these through the custom `Scope` extractor, which utoipa
/// cannot inspect, so without this every parameterized route would show "No
/// parameters". Applied once at the path level (covers all of its operations).
struct PathParamsAddon;

impl Modify for PathParamsAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        for (path, item) in openapi.paths.paths.iter_mut() {
            let mut params = item.parameters.take().unwrap_or_default();
            for name in path_param_names(path) {
                if params.iter().any(|p| p.name == name) {
                    continue;
                }
                params.push(
                    ParameterBuilder::new()
                        .name(name)
                        .parameter_in(ParameterIn::Path)
                        .required(Required::True)
                        .schema(Some(Schema::Object(
                            ObjectBuilder::new().schema_type(Type::String).build(),
                        )))
                        .build(),
                );
            }
            if !params.is_empty() {
                item.parameters = Some(params);
            }
        }
    }
}

/// Extracts `{name}` placeholders from an OpenAPI path template.
fn path_param_names(path: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let Some(close_rel) = rest[open..].find('}') else {
            break;
        };
        let name = &rest[open + 1..open + close_rel];
        if !name.is_empty() {
            names.push(name.to_owned());
        }
        rest = &rest[open + close_rel + 1..];
    }
    names
}

/// Sets the SPDX license identifier required by OpenAPI 3.1.
///
/// The `license(...)` attribute only sets the name, so the identifier,
/// which validators expect, is applied here.
struct LicenseAddon;

impl Modify for LicenseAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(license) = openapi.info.license.as_mut() {
            license.identifier = Some("LicenseRef-Proprietary".to_owned());
        }
    }
}

/// Guarantees a unique `operationId` for every operation.
///
/// utoipa derives the id from the handler name, so identically named handlers
/// in different modules (messaging vs webhook subscriptions) would collide.
/// A duplicate is disambiguated with the operation's tag.
struct UniqueOperationIds;

impl Modify for UniqueOperationIds {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let mut seen = std::collections::HashSet::new();
        for item in openapi.paths.paths.values_mut() {
            for op in operations_mut(item) {
                let Some(id) = op.operation_id.clone() else {
                    continue;
                };
                if seen.insert(id.clone()) {
                    continue;
                }
                let prefix = op
                    .tags
                    .as_ref()
                    .and_then(|tags| tags.first())
                    .map(|tag| tag.to_lowercase())
                    .unwrap_or_default();
                let unique = format!("{prefix}_{id}");
                seen.insert(unique.clone());
                op.operation_id = Some(unique);
            }
        }
    }
}

/// Mutable references to every operation defined on a path item.
fn operations_mut(
    item: &mut utoipa::openapi::path::PathItem,
) -> Vec<&mut utoipa::openapi::path::Operation> {
    [
        item.get.as_mut(),
        item.put.as_mut(),
        item.post.as_mut(),
        item.delete.as_mut(),
        item.patch.as_mut(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ianua Identity Provider API",
        version = "1.0.0",
        description = r#"
Ianua is a **multi-tenant identity provider** with an integrated **zero-trust proxy**.
This API covers everything you operate it with: authentication, authorization, OAuth2,
SAML/OIDC federation, organization and tenant management, routing and policy for the
proxy, webhooks, messaging, and real-time event streams.

## Identity planes

Endpoints are scoped to one of three planes, from widest to narrowest:

- **Platform**: operators who run the deployment itself. Manage organizations,
  operators, and impersonation. Paths under `/api/v1/operators` and `/api/v1/organizations`.
- **Organization**: owners and members who administer a customer organization and its
  tenants through the dashboard. Paths under `/api/v1/organizations/{org_slug}/…`.
- **Tenant**: the end users that an organization's tenants serve. Paths under
  `/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/…`.

A request can only reach what its plane allows; anything more returns `403`.

## Authentication

All authenticated requests use a **bearer token**:

```
Authorization: Bearer <session-token>
```

Obtain one by logging in:

- **Organization users** → `POST /api/v1/login` with `{ "email", "password" }`.
- **Tenant users** → `POST /api/v1/organizations/{org_slug}/tenants/{tenant_slug}/login`.

Both return a `refresh_token`: use it as the bearer token above. Some operations require
multi-factor authentication or a stepped-up session and will respond `401` until satisfied.

## Conventions

- **Pagination**: list endpoints page by cursor. Send `limit` (1 to 100, default 20) and,
  for the next page, `after` set to the `next_cursor` of the page before. Each page is
  `{ items, next_cursor, limit }`, and `next_cursor` is `null` on the last page. A cursor
  is opaque and belongs to the `sort` it was made with; sent with another sort, it is
  refused with `422`. SCIM lists keep `startIndex` and `totalResults`, as SCIM requires.
- **Sorting**: `?sort=-created_at,name` (prefix `-` for descending). Allowed fields are
  listed in each `sort` parameter's description.
- **Timestamps**: RFC 3339 / ISO 8601 (e.g. `2026-07-01T14:22:09Z`).
- **Errors**: a consistent envelope: `{ "error", "message", "details" }`. Common statuses:
  `401` unauthenticated, `403` forbidden, `404` not found, `409` conflict, `422` validation,
  `429` rate limited.

## Real-time

Endpoints under the **Real-time** tag are **WebSocket** upgrades (documented with a `101`
response). Connect with a WebSocket client and the same bearer token to receive live
notification and dashboard streams.
"#,
        license(name = "Proprietary")
    ),
    security(("bearer_auth" = [])),
    tags(
        (
            name = "Authentication",
            description = r#"
Everything about proving **who** is calling: password and passkey login, MFA step-up,
session refresh, recovery, device trust, tenant switching, and emergency break-glass access.

Several of these endpoints move a resource through a small **status lifecycle**: a session,
an MFA enrollment, a trusted device. Where that applies, the endpoint documents the status it
lands the resource in and which transitions are legal, so you always know where you stand.

## Ground rules

- Login responses never reveal whether an email exists: unknown account and wrong password
  look identical.
- Refresh tokens are single-use; replaying a rotated token revokes the entire session.
- Recovery codes and trusted-device grants are single-use and revocable.
"#
        ),
        (
            name = "Authorization",
            description = r#"
Roles, permissions, groups, and policy simulation within a tenant.

A role carries two kinds of permissions: **system** permissions (IdP-enforced admin
gates (user/role management, audit) which form an `implies` hierarchy so
`ManageUsers` also covers `Users(View)`), and **custom** permissions (customer-defined
`resource:action` strings, wildcard-supported, carried in JWT claims for the customer's
application to enforce). `is_default` roles are auto-assigned to new users.

**Delegation.** You can only grant system permissions you already hold: granting one
you lack is `403` (anti-privilege-escalation). Roles and groups have no lifecycle status;
the rules that matter are name uniqueness, the tenant plan limit, and the delete guards:
a role can't be deleted while any user holds it, and a group can't be deleted while it has
child groups.
"#
        ),
        (
            name = "Branding",
            description = r#"
Per-tenant look-and-feel for the login experience: logo, brand colors, custom CSS, the
email sender identity, and overrides for the transactional email templates.

**Branding config has no lifecycle status**: it's a set of optional fields, patched one
field at a time. Each PATCH field is three-valued: *absent* leaves it unchanged, `null`
clears it back to the platform default, and a value sets it (and is validated). **Email
templates do have a small state**: each template type is either on the *platform default*
or holds a *tenant customization* (`PUT` to customize, `DELETE` to reset), and the
`is_custom` flag on a template response tells you which.

Custom-domain routing (which host serves the login page) is configured on the tenant, not
here. Every mutation emits a tenant-scoped `branding.updated` event.
"#
        ),
        (
            name = "Classification",
            description = r#"
Field-level data-sensitivity rules that the proxy's redaction stage enforces. Each rule maps
a dot-notation field path (`user.ssn`, `billing.card_number`) to a sensitivity *level* and a
*redaction strategy*; at response time the proxy strips or masks any field at or above the
configured threshold before the body leaves.

**Sensitivity levels**, lowest to highest: `Public`, `Internal`, `Confidential`, `Restricted`.
**Redaction strategies**: `Remove` (drop the field), `Mask` (such as `***`), `Hash`. `Encrypt`
parses but is refused, since nothing behind it encrypts yet.

A tenant has one rule set, made on the first rule added: until then `GET` answers `200` with
an empty `rules` array and a `null` `id`. Each field path has at most one rule: adding a
second rule for a field already classified answers `409`. Rules have no status: add creates,
`PUT` changes a rule's level and redaction in place, keeping its id and field, and delete
removes it.
"#
        ),
        (
            name = "Crypto",
            description = r#"
The tenant's JWT signing keys: rotation, revocation, and zero-downtime algorithm migration.
Private keys live in secure storage (KMS/Vault); only a reference and the public key are held,
and the public keys are published via JWKS for relying parties to verify tokens.

**Key lifecycle**: each key is `active` (signs new tokens), `rotated` (no longer signs but
stays in JWKS through the grace period so existing tokens still verify), or `revoked`
(terminal; removed from JWKS). Rotation demotes the current key to `rotated` and mints a new
`active` one. Revoking the *only* active key is refused (`409`) so a tenant is never left
unable to sign.

**Algorithm migration** moves a tenant from one signing algorithm to another with no downtime.
At most one migration is active per tenant; legal status transitions are:

- `planned → in_progress`: target key created, both keys sign (dual-signing)
- `in_progress → validating`: old key revoked, new key is the sole signer
- `validating → completed`: finalized (terminal)
- `planned → cancelled`: abandoned before any keys were created (terminal)
- `in_progress | validating → rolled_back`: new key revoked (terminal)

`completed`, `rolled_back`, and `cancelled` are terminal. An illegal step returns `422`; a
second migration while one is active, or migrating to the same algorithm, returns `409`.

**Assertion keys** are a second, separate key set: the gateway signs the `X-Ianua-Assertion`
header it hands the services behind it with them, never with the signing keys above, and
publishes their public halves at `/.well-known/ianua-assertion-keys.json`. The platform
makes, rotates (every thirty days) and retires them itself; nothing here changes them.
"#
        ),
        (
            name = "Domains",
            description = r#"
Custom domains a tenant registers, DNS-verifies, and (for auth endpoints) gets a TLS
certificate for. Every endpoint here requires the org **Owner** role on the tenant.

Each domain has a **purpose**: `Primary` (the email/federation domain, e.g. `acme.com`), `Auth`
(a custom authentication endpoint, e.g. `auth.acme.com`: the only purpose that gets a TLS
certificate), or `Additional` (any other verified domain the tenant owns). A domain name is
globally unique: once one tenant claims it, no other tenant can.

**Verification** flows `pending → verified | failed`: on register the tenant publishes a TXT
record at `_ianua-verify.{domain}` with `ianua-verify={token}` (both returned by the API), then
calls verify. Development TLDs (`.test`, `.local`, `.localhost`, `.example`, `.internal`) and
`localhost` auto-verify. **TLS** only applies to `Auth` domains: `not_required` for
Primary/Additional, `provisioning` on register, → `active` once a cert is issued (or `expired`).
A domain is "active" only when verified *and* (for Auth) TLS is active.

A tenant may instead **upload its own certificate** for a verified domain, replacing whatever
serves it, and renews it by uploading another. Removing an uploaded certificate leaves the
domain with `NoCertificate` until another is uploaded or one is asked for through ACME. The
private key is sealed when stored and never answered.
"#
        ),
        (
            name = "Federation",
            description = r#"
Connections to external identity providers (SAML 2.0 and OpenID Connect), plus inbound SCIM
provisioning. Each connection is tenant-scoped and independently configured with protocol
settings, optional JIT user provisioning, attribute mapping, and an email domain hint that
routes logins to the right IdP.

**Connection status** is a reversible toggle: `active` (users can authenticate) ⇄ `disabled`
(off, but re-enableable). Connections are created `active`; self-transitions are rejected
(`422`). Separate permissions gate create / view / update / delete.

**SCIM** is a separate on/off endpoint per tenant with its own bearer token: enable returns
the token once (only its hash is stored), rotate invalidates the old token immediately, and
disable stops inbound requests while keeping the config. Token values are shown exactly once.

**OIDC login** is a browser redirect flow: a public `login` endpoint redirects to the IdP,
which calls back to exchange the code and create a session.
"#
        ),
        (
            name = "Messaging",
            description = r#"
A tenant-scoped pub/sub system: topics, subscriptions, versioned event schemas, publishing,
pull-based consumption, and real-time WebSocket streaming. Routing is isolated per tenant at
the NATS subject level (`ianua.msg.{tenant}.{topic}`).

**Topics** carry a lifecycle `active → paused → archived`: active topics accept publishes and
deliver to subscribers; paused topics reject messages but keep subscriptions; archived is
read-only. A topic can only be deleted once it's no longer active (pause/archive first).

**Subscriptions** bind a service to a topic with a delivery `mode`: `push` (webhook) or
`pull` (API poll), an optional `consumer_group` (load-balanced) or fan-out, and an optional
filter. **Schemas** are versioned (`JsonSchema` / `Avro` / `Protobuf`) with a compatibility
mode (`none` / `backward` / `forward` / `full`) that gates each new version; the registry
is a typed contract for services and codegen, not enforced at publish time. Separate
permissions gate create / view / publish / delete.
"#
        ),
        (
            name = "Notifications",
            description = r#"
The in-app notification inbox, exposed at three identity tiers: each tier sees only its own
notifications on its own path:

- **Platform** (`/api/v1/notifications`): for operators running the deployment.
- **Organization** (`/api/v1/organizations/{org_slug}/notifications`): for org users; requires
  org `Member` or higher.
- **Tenant** (`/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/notifications`): for
  tenant users; the list and unread-count are additionally filtered to the categories the
  caller's permissions cover (implied permissions count), so a user never sees notifications
  for an area they can't access.

Each notification records the domain `event_type` that produced it, a `category` (one of
`Identity`, `Crypto`, `OAuth`, `Authorization`, `Federation`, `Routing`, `Pipeline`,
`Signals`, `Webhooks`, `Branding`, `Authentication`, `Organization`, `Tenant`), and a
`severity` (`Info` < `Warning` < `Critical`). The only state is a read/unread boolean:
`unread → read` via mark-read or mark-all-read, irreversible (there is no mark-unread). Tenant
users can also tune per-category delivery (`InApp`, `InAppAndEmail`, or `Disabled`) through
preferences; the platform and org tiers have no preference endpoints.
"#
        ),
        (
            name = "OAuth",
            description = r#"
OAuth2 client and API-key management, plus the authorization-code (with PKCE) and
device-authorization grant flows: all tenant-scoped under `{tenant_slug}/oauth`.

**Clients and API keys** are the two credential kinds a tenant issues. Both are created with
the raw secret/key returned **once** (only the hash is stored). An OAuth client is revoked to
a terminal `Revoked` status; an API key is revoked by **deletion**: a revoked key is removed
outright (it stops authenticating and no longer appears in the list), and a key otherwise
lives until its optional `expires_at`. Both share one permission family:
`ApiKeys(Create | View | Update | Revoke)`.

**Flows.** The browser's `GET authorize` (or a `request_uri` from `par`) goes on to the
dashboard's consent page, whose `POST authorize` issues a short-lived code under mandatory
PKCE. `token` (public) answers every grant by `grant_type`: `authorization_code`,
`refresh_token` (rotated on use), `client_credentials`, the device code and token exchange,
with refusals in the RFC 6749 shape (`invalid_client` is `401` with a challenge). The device
flow is `device/code` → the person `device/approve`s or `device/deny`s it → the device polls
`token` until it is handed tokens. `introspect` and `revoke` take the same client proof;
`logout` sends the browser to the dashboard's sign-out page, which calls `end-session`.

**Registration.** An admin issues `initial-access-tokens`; an app registers itself at
`register` with one (RFC 7591) and manages its registration at `register/{client_id}` with
the registration access token it was handed (RFC 7592). A person lists the apps they
authorized at `my-apps`.
"#
        ),
        (
            name = "OIDC Provider",
            description = r#"
The public-facing OpenID Connect provider endpoints a relying party uses to discover this
tenant's IdP and validate its tokens. All three are tenant-scoped under `{tenant_slug}`:

- **discovery** (`/.well-known/openid-configuration`): the standard metadata document
  (issuer, endpoint URLs, supported scopes/claims/algorithms/auth methods).
- **jwks** (`/.well-known/jwks.json`): the tenant's public signing keys (active and rotated,
  not revoked) for token signature verification.
- **userinfo** (`/oauth/userinfo`, `GET` or `POST`): the claims the access token's scopes let
  out (`sub`, and `email`, `email_verified`, `name`, `locale`, `zoneinfo`, `roles` by scope).

`discovery` and `jwks` are public (no auth); `userinfo` requires a valid access token. These
are read-only spec endpoints: no state transitions.
"#
        ),
        (
            name = "Onboarding",
            description = r#"
Self-service signup: the public endpoint that creates a new organization, its first tenant,
and the admin user in a single call. No authentication: this is how a new customer lands on
the platform. The tenant is created in `Provisioning` status and is promoted to `Active` once
the tenant's setup (started by the `tenant.provisioned` event) finishes.
"#
        ),
        (
            name = "Operators",
            description = r#"
Platform-level administration: the staff accounts that run the deployment itself, not scoped
to any organization or tenant. Every endpoint requires an operator session.

An **operator account** toggles between `Active` and `Disabled` (reversible); disabling one
also revokes all their impersonation grants. **Impersonation grants** let an active operator
act as a specific tenant user until an expiry (with a recorded reason): support and
break-glass access, revocable any time. **Operator API keys** authenticate programmatic
platform access; the raw key is shown once (only the hash is stored), identified by a prefix
for targeted revocation, or all revoked at once. **Dead jobs** are the background jobs that
used up their tries, listed newest first without their payloads.
"#
        ),
        (
            name = "Cloud accounts",
            description = r#"
Connecting an organization's **own** cloud account, so its tenants' databases can be created
there: in your AWS, GCP, Azure or DigitalOcean, on your bill, in your region, administered by
us. Owner only, on every endpoint: granting a third party the ability to build infrastructure in
your cloud is at least as consequential as changing the organization itself.

**The flow is three steps**, because you leave in the middle of it. `POST .../cloud-accounts/{provider}`
returns an **external id** and the steps to follow; you complete your side in your own cloud
console; then `PUT .../credential` submits the grant and proves it in one call.

**The external id matters.** A role ARN is not a secret, so without a shared secret in the trust
policy anyone who learned yours could name it in *their* settings and have us assume it on their
behalf. Put the value we give you in the role's trust policy. Calling begin again returns the
same id rather than a new one: replacing it would break a policy you had already built.

**A rejected credential is an answer, not an error.** It comes back `200` with the connection in
`failed` state and a reason, because that is the result of asking "does this work". Only being
unable to *ask*, our own outage, is a `500`, and that leaves the connection retryable rather
than marked failed.

**Nothing here ever returns a credential.** Responses carry the account we reached, the state,
and whether the grant is one you can revoke yourself: a role or service account you can delete,
versus a bearer token that stays valid until we delete our copy.

`GET .../networks?region=` lists what you already have in that region, named the way you named
it. An empty list is a real answer: it means we would build a network instead.
"#
        ),
        (
            name = "Organizations",
            description = r#"
Managing a customer organization and its team: the organization itself, its members, sessions,
and API keys. All endpoints are scoped to `{org_slug}`; most require org `Member` or higher,
with lifecycle and member-management actions limited to org `Owner`. Organization creation and
platform-wide listing are operator-only (`PlatformOnly`).

**Organization lifecycle** is `Active → Suspended → Active` (reversible freeze for billing or
policy issues) and `Active | Suspended → Closed` (terminal: data scheduled for deletion).
**Org user lifecycle** is `Invited → Active`, then `Active ↔ Locked` and `Active ↔
Deactivated`, with `Locked | Deactivated → Active` to unlock/reactivate; members join via a
magic-link invitation or direct creation. **Org API keys** authenticate programmatic org
access: the raw key is shown once, identified by a prefix, revocable individually. The tag
also covers MFA enrollment, password/email self-service, cross-tenant identity links, active
sessions, metrics, and the audit log (list + CSV export).
"#
        ),
        (
            name = "Pipeline",
            description = r#"
The per-tenant proxy request-processing pipeline: an ordered set of stages each request passes
through (WAF, geo-fence, identity, policy, rate-limit, redaction, custom WASM, …). Configure
it once, then add/remove stages and toggle it live.

**Status** flows `Draft → Active` (go live), `Active → Disabled` (kill switch: traffic falls
back to deny-by-default), `Disabled → Active` (re-enable), and `Disabled → Draft` (major
rework). Stages are **immutable while `Active`**: add/remove only in `Draft` or `Disabled`
(attempts on a live pipeline return `403`). New stages are added disabled and non-mandatory;
the default pipeline ships with mandatory `Identity` and `Policy` stages.
"#
        ),
        (
            name = "Routing",
            description = r#"
The tenant's proxy routes: each maps a path pattern (and HTTP methods) to an upstream service,
gated by an authorization policy, with a priority that breaks path overlaps. Requests are
matched against active routes and forwarded through the pipeline.

**Route status** is a reversible toggle: `Active` (accepts traffic) ⇄ `Disabled` (returns
`503`, no longer matches). Routes are created `Active`. A route must be `Disabled` before it
can be deleted (you can't delete a live route). Separate permissions gate create / view /
update / delete.
"#
        ),
        (
            name = "SAML IdP",
            description = r#"
The public-facing SAML Identity Provider endpoints a service provider uses for SSO, scoped to a
tenant. `metadata` publishes the IdP metadata XML (entity ID, SSO URL, signing cert) SPs trust;
`sso` completes SP-initiated SSO (SP sends an AuthnRequest, the IdP returns a signed Response
for the authenticated user); `sso/initiate` does IdP-initiated SSO (the user picks an SP, no
AuthnRequest needed). All signed responses require the tenant to have a signing key set.
"#
        ),
        (
            name = "Consumers",
            description = r#"
Consumers within a tenant: non-human callers that authenticate to the proxy with a credential
instead of a user session. Each consumer has a display name and a single authentication
credential (an API key, a client certificate, or a JWT bearer).

**What a consumer may reach** is not configured here. A consumer is a principal, so it holds
roles through the same role assignment a person does, and the proxy authorizes it against the
route's own policy. A consumer with no roles assigned reaches nothing.

**Status** is a reversible toggle: `Active` (credential accepted) ⇄ `Disabled` (all its
requests denied). Consumers are created `Active`; one must be `Disabled` before it can be
deleted. Credentials can be rotated without changing the consumer's status: the old one stops
at once, or keeps working beside the new one for an overlap of up to seven days, which can be
ended early. Each credential may carry an expiry. A consumer may have a request quota of its
own (so many per minute, hour, day or month); past it the gateway answers `429`. Separate
permissions gate create / view / update / delete.
"#
        ),
        (
            name = "Agents",
            description = r#"
AI-agent identities within a tenant: autonomous or semi-autonomous callers that act with
**delegated**, attenuated authority rather than their own fixed scope. Each agent has a display
name, an optional description, an owning principal (a user, an org user, or another agent), and
a lifecycle `status`: `Active` ⇄ `Suspended` (reversible) and `Revoked` (terminal).

**Delegations** grant a slice of the caller's authority to an agent, attenuated so an agent can
never exceed what its delegator holds; each is time-bound, depth-bounded, and revocable.
Revoking a delegation transitively invalidates its whole subtree. `effective-capabilities`
resolves what an agent may do right now; `authorize-check` is a side-effect-free dry run of the
proxy's decision. Separate permissions gate view / create / update / delete / delegate.
"#
        ),
        (
            name = "Signals",
            description = r#"
Security signal streaming (CAEP / SSE SETs): a tenant pushes security events to registered
receiver endpoints. Each stream targets an HTTPS `endpoint` with a `delivery_method` (`Push` or
`Poll`) and a set of `signal_types` (empty = all).

**Stream status** is `Active` (delivering), `Paused` (signals queue but aren't delivered, →
resume), or `Disabled` (permanent: no resume; delete to remove). Illegal transitions return
`409` (e.g. pausing an already-paused stream, resuming a non-paused one). `Signals(View)` gates
listing; `Signals(Manage)` gates everything else.
"#
        ),
        (
            name = "Tenants",
            description = r#"
A tenant is an isolated environment within an organization: the unit that holds users, routes,
keys, and configuration. All endpoints are scoped to `{org_slug}` (and most to `{tenant_slug}`)
and require org `Owner` (metrics allows `Member`).

**Lifecycle** flows `Provisioning → Active` (go live once infra is ready), `Active ↔ Suspended`
(freeze: sessions killed, logins refused, data kept), `Active → Archived` (soft delete:
retention countdown), and `Archived → Deleted` (terminal wipe). Each illegal step returns
`422`; provision also returns `409` on a duplicate slug. Provisioning and deletion are the
irreversible edges of the graph.
"#
        ),
        (
            name = "Webhooks",
            description = r#"
Outbound event delivery: a tenant registers webhook subscriptions, and the IdP POSTs matching
events (signed with a per-subscription secret) to the subscriber's URL. Each subscription
targets a `url` and a set of `event_types`.

**Status** is `Active` (delivering), `Paused` (events queue but aren't delivered, → resume), or
`Disabled` (terminal: set automatically after too many consecutive failures; replace by
deleting and recreating). The signing secret is shown once at creation; rotate it any time (the
old secret stops working immediately). Delivery attempts are logged for debugging.
`Webhooks(View)` gates listing; `Webhooks(Update)` gates everything else.
"#
        ),
        (
            name = "Health",
            description = r#"
Whether the server is up. `/health` answers `200` with `ok` while it is, and asks no
dependency. The orchestrator's probes, `/health/live` and `/health/ready`, and the metrics
scrape are served on the internal listener, never this one: readiness asks the database, the
message bus and the cache on every call, and nobody outside the deployment may make it do so or
learn which of them is down.
"#
        ),
        (
            name = "Files",
            description = r#"
Files the platform hands out by address. An export file is downloaded through the link the
export answered with: it works for a few minutes, opens its file once, and every reason it opens
nothing answers `404`. A tenant's logo is served at the address its branding gave out, public
and cached for good, since a new logo gets a new address. The platform also publishes two files
of its own, public and the same for everyone: the logo its mail shows, and the CloudFormation
template a customer runs to make the AWS role the platform assumes.
"#
        ),
        (
            name = "Real-time",
            description = r#"
Live WebSocket streams: push channels for notifications, security dashboards, and workflow
progress, so the UI updates without polling. Each endpoint upgrades the HTTP connection
(`101`) to a WebSocket scoped to the caller's tier (operator / org / tenant) and forwards
matching events as JSON frames until the client disconnects. Notification streams mirror the
notification inbox; dashboard and workflow streams open with a `connected` frame then push
events.
"#
        ),
    ),
    components(schemas(crate::error::ErrorBody, crate::error::ErrorCode))
)]
struct Shell;

/// The internal listener's document: the endpoints the gateway relays
/// sign-ins and approval questions to, the probes, and the metrics scrape,
/// which the public document leaves out.
#[must_use]
pub fn internal_document() -> utoipa::openapi::OpenApi {
    let mut document = crate::routes::authentication::InternalDocument::openapi();
    document.merge(crate::routes::agents::InternalDocument::openapi());
    document.merge(crate::routes::runtime::InternalDocument::openapi());
    document
}

/// The whole document: the shell, every context's paths and schemas, and
/// the touches that need all of them in place.
#[must_use]
pub fn document() -> utoipa::openapi::OpenApi {
    let mut document = Shell::openapi();
    for part in crate::routes::documents() {
        document.merge(part);
    }
    for modifier in [
        &SecurityAddon as &dyn Modify,
        &PathParamsAddon,
        &LicenseAddon,
        &UniqueOperationIds,
    ] {
        modifier.modify(&mut document);
    }
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relay endpoints appear in the internal document, while the public
    /// document contains no internal paths.
    #[test]
    fn the_public_document_leaves_out_the_internal_listener() {
        let public = document();
        let internal = internal_document();

        assert!(
            public
                .paths
                .paths
                .keys()
                .all(|path| !path.starts_with("/internal"))
        );
        assert!(internal.paths.paths.contains_key("/internal/app-sign-in"));
        assert!(
            internal
                .paths
                .paths
                .contains_key("/internal/agent-approvals")
        );
    }

    /// The metrics endpoint appears only in the internal API document.
    #[test]
    fn the_metrics_scrape_is_documented_on_the_internal_listener_alone() {
        let public = document();
        let internal = internal_document();

        assert!(!public.paths.paths.contains_key("/metrics"));
        assert!(internal.paths.paths.contains_key("/metrics"));
    }

    /// Liveness and readiness probes are documented internally; the public
    /// document retains the health endpoint.
    #[test]
    fn the_probes_are_documented_on_the_internal_listener_alone() {
        let public = document();
        let internal = internal_document();

        assert!(!public.paths.paths.contains_key("/health/live"));
        assert!(!public.paths.paths.contains_key("/health/ready"));
        assert!(public.paths.paths.contains_key("/health"));
        assert!(internal.paths.paths.contains_key("/health/live"));
        assert!(internal.paths.paths.contains_key("/health/ready"));
    }
}
