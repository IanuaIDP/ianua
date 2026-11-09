---
title: Introduction
description: What ianua is, why it is worth trying, and what makes its AI agent controls different.
sidebar:
  order: 1
---

**Ianua is a self-hosted access control plane with governed automation, for people and AI agents.**

It signs your users in, stands in front of your apps, and checks every single request before it reaches them. It is the first place where an AI agent gets an identity of its own, carries only the access a real person lent it, and can be switched off in the middle of what it is doing. And its workflows automate work without ever going further than the person behind them: every run acts with exactly the rights of the person who published it, through accounts lent to them, and risky steps wait for an approval.

## Why teams try it

### One tool instead of three

To protect internal apps properly today, you usually stitch together an identity provider, an access proxy, and something home-grown for machine and agent access. Three systems, three configurations, three audit logs that disagree.

Ianua is all three, with one set of users, one set of rules, and one audit log. A rule you write once applies whether the caller is a person, a backend service, or an agent.

### Safe by default, not by configuration

Most security tools are only as safe as their settings. Ianua starts from "no":

- A request with no valid identity is refused.
- A request no rule explicitly allows is refused.
- If anything along the way fails or times out, the request is refused. It never "fails open" to keep traffic flowing.
- Identity headers a caller tries to set themselves are thrown away. Your app receives a **signed** statement of who the user is, so it never has to trust a plain header.
- The audit log can be sealed so that even ianua itself cannot rewrite or delete it.

Every one of these is covered by automated tests that check the refusal, not just the happy path. The project has more than ten thousand tests, and its storage and end-to-end tests run against a real database.

### Yours, end to end

- **You run it.** On your own Kubernetes cluster with one Helm command, or on one machine with Docker Compose.
- **Your domains.** Use your own hostnames directly. Domains you list as trusted work straight away.
- **Your data.** Everything lives in your own Postgres. There is no phoning home: the only outside services ianua talks to are ones with a clear job, such as Let's Encrypt for certificates and the password breach check, which never sends the password itself.
- **No per-user pricing.** Add as many users, apps and agents as your hardware allows.

## Why its AI agent controls go further

Today an AI agent usually gets an API key or an OAuth token copied from a person. That key can do everything the person can, often for months, on every system it reaches. When something goes wrong, nobody can say who authorized what, and the only fix is to rotate the key and hope.

Ianua treats an agent as a real principal with **borrowed, bounded and revocable** authority. Each point below is enforced by the gateway on every request.

| What ianua does | Why it matters |
| --- | --- |
| **Every agent acts for a named person.** Authority starts with a human and is handed down a chain: person, agent, sub-agent. | You can always answer "who allowed this?" The app at the end of the chain receives the whole lineage. |
| **Authority only ever shrinks.** An agent can pass on part of what it holds, never more. A person cannot give an agent more than their own role. | A compromised agent cannot grant itself, or another agent, new powers. |
| **Take it back, and it stops now.** Revoke one link, or deactivate the person behind it, and every agent below is refused on its **next request**, not when its token expires. | No waiting hours for tokens to run out during an incident. |
| **A kill switch that scales.** Suspend one agent, or every agent in a tenant, in a single step, however large the chain. | The moment you most need speed is when the most agents are involved. |
| **Purpose, not just permission.** A token can be minted for a stated purpose. An action the agent is technically allowed but that falls outside that purpose is refused. | Stops an agent that was talked into doing "something else" by a prompt injection. |
| **Tool by tool.** For MCP (the protocol AI tools use), the gateway reads which tool is being called and allows only granted ones. A batch that hides one forbidden call is refused whole. | You grant "read the calendar", not "anything this server can do". |
| **Data cannot leak sideways.** An agent that has read confidential data cannot then write to a place cleared only for public data. | Closes the classic "read secrets, post them somewhere public" path. |
| **No fetching whatever it is told.** For services that fetch a URL, you list which hosts are allowed. Anything else is refused before the service sees it. | Closes the path where an agent uses one of your services to reach the internet. |
| **A person approves the risky steps.** Chosen actions pause until someone approves or denies them. The person asking cannot be the person approving. | Payments, deletions and other one-way actions get a human check. |
| **A hard cap.** A delegation can carry a request budget. Once used up, every further request is refused. | An agent stuck in a loop stops on its own. |
| **Independent watchers.** One agent can review another, but only if it answers to different people and shares no authority with the one it watches. | A reviewer cannot be steered by the same person it is meant to check. |
| **Locked in, locked out.** Agents run in isolated sandboxes. Their only way out is through ianua, which proves who they are on every request. Outbound calls go through an egress gateway that allows only listed websites. | An escaped or misbehaving agent has nowhere to go. |

To watch an agent's life from its key to its revocation for yourself, check out the source and run:

```sh
cargo nextest run -p ianua-scenarios --test agents --no-capture
```

The scenarios start the whole platform and the gateway against their own database, so there is nothing to set up first.

## How your data is organized

- Your installation has one **organization**, created the first time ianua starts.
- The organization has one or more **tenants**. A tenant is a separate space with its own users, apps, rules and agents, for example "Production" and "Staging".
- **Users**, **routes** (protected apps), **policies** and **agents** each belong to one tenant. Nothing in one tenant can see or reach another.

There is no public sign-up: a self-hosted installation refuses anyone founding an organization on it. You decide who gets in. Inside a tenant, people sign themselves up only if you switch that on.

## Everything it does

<details>
<summary><strong>Sign-in</strong></summary>

- Passwords, checked against known data breaches when they are set. Each tenant chooses whether a breached password is refused, allowed with a warning, or not checked. Only the first 5 characters of the password's hash ever leave your server.
- Magic links sent by email.
- Passkeys.
- A second factor: an authenticator app (TOTP), or a code sent by email or text message, as each tenant chooses. Off, optional or required per tenant.
- Sign-in through your company identity provider over OIDC or SAML, with a "Sign in with ..." button on the tenant's sign-in page.
- Password reset by an emailed link. Someone whose second factor is an emailed or texted code gets a fresh code to finish the reset. Recovery codes for a lost authenticator.
- A risk check on each login, and remembered devices.
- Break-glass access: time-limited emergency access for an on-call engineer, fully recorded.

</details>

<details>
<summary><strong>Users and access rules</strong></summary>

- Users, groups and roles, with permissions per tenant.
- Policies that decide who may reach which app, and under which conditions.
- SCIM, so an HR system or another identity provider can create and remove users automatically.
- A read-only LDAP view of your users, for older tools that only speak LDAP.

</details>

<details>
<summary><strong>An identity provider for your own apps</strong></summary>

- OpenID Connect and OAuth 2: your apps send users to ianua to sign in, with a consent screen, and a device flow for devices without a keyboard.
- SAML: ianua can act as the SAML identity provider for apps that need it.
- API keys for programmatic access.
- Security signals (CAEP / Shared Signals): connected apps are told the moment a session is revoked.

</details>

<details>
<summary><strong>The gateway</strong></summary>

Every request to a protected app goes through a pipeline of checks. Each tenant chooses which ones apply to which route.

- **Who is calling**: a token, an API key, or a client certificate. Step-up sign-in for sensitive paths. Proof-of-possession tokens (DPoP), so a stolen token alone is useless.
- **May they**: the policy decision. If it is missing or fails, the answer is no.
- **What your app receives**: identity headers set by the caller are removed, and a signed statement of who the user is is added (`X-Ianua-Assertion`).
- **Protection**: rate limits, a web application firewall, country restrictions, IP reputation, device checks, and a risk score per request.
- **Traps**: decoy paths and decoy credentials. Anyone who touches one is flagged and blocked. Clients that behave like scanners are slowed down or blocked.
- **Data**: tag requests by how sensitive their data is, and strip or mask fields in responses.
- **Responses**: security headers, CORS, response caching and response rewriting.
- **Special traffic**: understands GraphQL and MCP, so rules can apply to a single query or tool call.
- **Your own checks**: write a custom stage in any language that compiles to WebAssembly. It runs in a sandbox.
- **Not only HTTP**: databases, message brokers and other TCP services can go through the gateway too.
- **Backends**: several backends per app, health checks, path rewrites, and discovery of backends that come and go.

</details>

<details>
<summary><strong>Non-human callers</strong></summary>

Backend services, cron jobs and partner integrations get their own identity, using an API key, a client certificate or their own JWT. They hold no permissions of their own; what they may reach is set by the same rules as everyone else.

</details>

<details>
<summary><strong>AI agents</strong></summary>

- Agent identities that sign in with a key pair. The private key never leaves the agent.
- Delegation from a person to an agent, and from agent to agent, always narrowing.
- Credentials that expire and can be rotated.
- Attestation: an agent can be required to prove where it runs before it gets a credential.
- Human approval for chosen actions.
- Request budgets, and tracking of how many AI model tokens an agent uses.
- Model providers: OpenAI, Anthropic, or your own model server.
- Tools and MCP, allowed one by one.
- Flows: several agents working in stages, each run governed on its own.
- Independent reviewers.
- Isolated sandboxes, and an egress gateway for outbound traffic.
- Messaging between agents, where every message is checked and signed.
- A kill switch for one agent or all of them.

</details>

<details>
<summary><strong>Integrations, audit and branding</strong></summary>

- Webhooks for events in your tenant, with retries.
- Publish and subscribe messaging for your own services, isolated per tenant.
- Live notifications in the dashboard.
- An audit record for every decision: who asked, for what, and whether it was allowed. Tokens and passwords are never written to it.
- A sealable audit log, and signed events between the parts of the system.
- Dashboards for logins, traffic, latency and health.
- Your logo, colors and email sender on sign-in pages and emails, per tenant.

</details>

## The parts

| Part | Job |
| --- | --- |
| **Control plane** (`ianua-server`) | The API behind the dashboard. Where you set things up: users, apps, rules, agents. It also runs background work. |
| **Gateway** (`ianua-zero`) | Receives the real traffic for your apps and decides, request by request, whether to let it through. It cannot change any settings; it only enforces them. |
| **Agent runner and egress gateway** | Run agents in isolated containers, and control which outside websites they may reach. Only needed if you use agents. |
| **Dashboard** | The web interface, in its own repository. |

Postgres stores everything. NATS carries events between the parts. Redis holds background jobs and counters the gateways share.

The server, the gateway and the storage code behind them (`ianua-server`, `ianua-zero` and `ianua-infra`) are being rebuilt on top of the new application layer. What this page says about them describes their code as it is today.

## Where to go next

- **Quickstart** gets ianua running on your machine in a few minutes.
- **How it works** follows one request through the gateway, step by step.
- If you are here for AI agents, start with the **Agents** page under Concepts.
