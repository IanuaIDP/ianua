import type { HelpArticle, HelpCategory } from '@/types/help-center';

function article(
  partial: Omit<HelpArticle, 'sections'> & { sections?: HelpArticle['sections'] },
): HelpArticle {
  return { sections: [], ...partial };
}

export const HELP_CENTER_CATEGORIES: HelpCategory[] = [
  {
    slug: 'getting-started',
    title: 'Getting Started',
    topics: [
      article({
        slug: 'what-is-ianua',
        title: 'What is ianua',
        lastUpdated: '2026-10-03',
        intro:
          'ianua is a multi-tenant identity provider with a zero-trust proxy built in. It is the thing a request passes through on its way to one of your applications, and the thing that decides — every single time — whether that request gets to continue.',
        sections: [
          {
            id: 'the-short-version',
            heading: 'The short version',
            blocks: [
              {
                type: 'paragraph',
                text: 'Most identity providers stop at authentication: they tell you who someone is, and then hand the request off to your own backend to decide what that person is allowed to do. ianua does both halves. It authenticates the caller — a human signing in, or an AI agent presenting a credential — and it sits in front of your services as a proxy, so the same system that knows who is calling also decides what they can reach.',
              },
              {
                type: 'paragraph',
                text: 'That combination is what makes the rest of the product make sense: routes, policies, and audit logs all live in one place because one system is responsible for the whole decision, not just the login screen.',
              },
            ],
          },
          {
            id: 'organizations-and-tenants',
            heading: 'Organizations and tenants',
            blocks: [
              {
                type: 'paragraph',
                text: 'Everything in ianua is scoped to one of two levels.',
              },
              {
                type: 'list',
                items: [
                  'An organization is your company’s account on ianua. It is where billing lives, where you invite the teammates who will administer ianua itself, and where you create tenants.',
                  'A tenant is a workspace inside your organization — typically one per product, environment, or customer deployment. Each tenant has its own users, its own routes, its own authentication rules, and its own audit trail. A tenant’s users are the end users of whatever you are building, not people managing ianua.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'If your company only runs one product, you will likely only ever create one tenant — the organization/tenant split still matters because it is what keeps billing, your own admin team, and your product’s actual users cleanly separated.',
              },
            ],
          },
          {
            id: 'what-it-actually-does',
            heading: 'What ianua actually does',
            blocks: [
              {
                type: 'list',
                items: [
                  'Authenticates people and AI agents — password, passkey, magic link, or single sign-on through a SAML or OIDC identity provider, or a workload-attestation credential for an agent.',
                  'Sits in front of your services as a proxy, and decides per-request whether a caller is allowed through, based on routes and access policy you define.',
                  'Governs AI agent access specifically: scoped, time-boxed grants instead of long-lived API keys, with a kill switch if one is compromised.',
                  'Keeps a complete audit trail of every decision it makes, so "who did this, and were they allowed to" always has an answer.',
                ],
              },
            ],
          },
          {
            id: 'where-to-go-next',
            heading: 'Where to go next',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Create your organization if you have not already.',
                  'Create your first tenant — this is the workspace your product or environment will live in.',
                  'Invite your team so others can help administer it.',
                  'Protect your first route to see a real request go through ianua end to end.',
                ],
              },
            ],
          },
        ],
      }),
      article({
        slug: 'creating-your-organization',
        title: 'Creating your organization',
        lastUpdated: '2026-10-12',
        intro:
          'Your organization is created once, as part of signing up for ianua. This article walks through what that form actually sets up, and where to change it afterward.',
        sections: [
          {
            id: 'when-sign-up-is-offered',
            heading: 'When sign-up is offered',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'The Sign Up button only appears when the installation takes sign-ups. A self-hosted installation doesn’t: it has one organization, created when ianua is installed, and you sign in at /login with the owner account set up then.',
              },
            ],
          },
          {
            id: 'the-sign-up-form',
            heading: 'The sign-up form',
            blocks: [
              {
                type: 'paragraph',
                text: 'Signing up asks for two groups of information: details about your organization, and details about the account you will use to manage it.',
              },
              {
                type: 'list',
                items: [
                  'Company Name — becomes your organization’s display name. You can rename it later.',
                  'Full Name and Admin Email — the first user in the organization, created with the Owner role.',
                  'Password — must meet ianua’s password policy; the form shows the requirements as you type.',
                ],
              },
            ],
          },
          {
            id: 'what-gets-created',
            heading: 'What gets created',
            blocks: [
              {
                type: 'paragraph',
                text: 'Submitting the form does three things at once: it creates the organization, creates a first tenant named “Production” inside it, and creates your user as an Owner of that organization.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'You do not need to create a tenant separately to get started — “Production” is ready to use as soon as sign-up finishes. Rename or replace it later if it does not fit how you want to organize things.',
              },
            ],
          },
          {
            id: 'after-you-sign-up',
            heading: 'After you sign up',
            blocks: [
              {
                type: 'paragraph',
                text: 'You will be sent to a check-your-email screen. Verifying your email confirms the admin account before you can sign in.',
              },
              {
                type: 'steps',
                items: [
                  'Open the verification email and follow the link.',
                  'Sign in with the admin email and password you chose.',
                  'Land on the Overview page for your new organization.',
                ],
              },
            ],
          },
          {
            id: 'changing-it-later',
            heading: 'Changing it later',
            blocks: [
              {
                type: 'paragraph',
                text: 'Company name and other organization-level details live under Organization Settings once you are signed in — nothing from the sign-up form is locked in permanently.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'creating-your-first-tenant',
        title: 'Creating your first tenant',
        lastUpdated: '2026-10-09',
        intro:
          'Signing up already gave you one tenant, named “Production.” This article covers creating additional tenants — one per product, environment, or customer deployment — and what each field on that form controls.',
        sections: [
          {
            id: 'when-you-need-another-tenant',
            heading: 'When you need another tenant',
            blocks: [
              {
                type: 'paragraph',
                text: 'Reach for a new tenant when you are standing up a separate environment (staging next to production), a separate product, or a dedicated deployment for one customer. Each tenant has its own users, routes, policies, and audit trail — nothing is shared between them.',
              },
            ],
          },
          {
            id: 'the-create-tenant-form',
            heading: 'The create tenant form',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Tenants, click Create Tenant and fill in:',
              },
              {
                type: 'list',
                items: [
                  'Name — the tenant’s display name (e.g. “Staging” or “Acme — EU”).',
                  'Slug — auto-generated from the name as you type; this is what shows up in tenant-scoped URLs, and you can still edit it by hand. It cannot be changed after the tenant is created.',
                  'Contact Email — an operational contact for the tenant, separate from your organization’s.',
                  'Timezone and Locale — defaults used for that tenant’s scheduling and formatting.',
                ],
              },
            ],
          },
          {
            id: 'data-residency',
            heading: 'Data residency',
            blocks: [
              {
                type: 'paragraph',
                text: 'The form also asks where the tenant’s data lives:',
              },
              {
                type: 'list',
                items: [
                  'This installation — the default. Your tenant’s data is stored in the database this ianua installation already uses.',
                  'Your cloud account — pick a connected cloud provider and region, and ianua creates and runs the database in your account (with a private network it builds, or one you point it at).',
                  'A database you already run — give ianua a connection; it creates no infrastructure.',
                ],
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'Choosing a customer cloud requires connecting that cloud account first, under Settings → Cloud. The form will tell you if the provider you picked is not connected yet.',
              },
            ],
          },
          {
            id: 'tenant-status',
            heading: 'Tenant status',
            blocks: [
              {
                type: 'paragraph',
                text: 'A new tenant starts in Provisioning for a few seconds while its default roles, sign-in settings and signing keys are created, then moves to Active on its own. From there it can be Suspended (reversible) or Archived (not reversible — the only step after it is deletion). See Creating & managing tenants.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'inviting-your-team',
        title: 'Inviting your team',
        lastUpdated: '2026-10-09',
        intro:
          'Team members are the people who administer ianua itself — not your product’s end users. This article covers adding them, the two ways to do it, and the roles available at the organization level.',
        sections: [
          {
            id: 'two-ways-to-add-someone',
            heading: 'Two ways to add someone',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Team, click Add team member. You get a choice right at the top:',
              },
              {
                type: 'list',
                items: [
                  'Send Invite — they receive an email and set their own password. Nothing is created until they accept.',
                  'Create Member — you set a password for them now (or generate one), with an option to auto-verify the email and skip the verification step entirely. Useful for onboarding someone on the spot, or for accounts that will not check email right away.',
                ],
              },
            ],
          },
          {
            id: 'organization-roles',
            heading: 'Organization roles',
            blocks: [
              {
                type: 'list',
                items: [
                  'Member — the default. Reads the organization and has no tenant access until an Owner or Admin grants it through Tenant Access.',
                  'Admin — runs the organization and can open every tenant, but cannot close the organization or change what it pays.',
                  'Billing — manages the subscription and cannot open any tenant.',
                  'Viewer — reads the organization and its audit log and cannot open any tenant.',
                  'Owner — governs the organization itself and can open every tenant, with full permissions in each.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Give Owner to the few people who manage ianua itself. Everyone else should be a Member with access to just the tenants they work on. An invitation link works for one day.',
              },
            ],
          },
          {
            id: 'filling-in-the-form',
            heading: 'Filling in the form',
            blocks: [
              {
                type: 'paragraph',
                text: 'Both modes ask for Full Name, Email Address, and Organization Role. Create Member additionally asks for a password — type one in, or click Generate to have ianua build one that meets the password policy — and whether to auto-verify their email.',
              },
            ],
          },
          {
            id: 'managing-existing-members',
            heading: 'Managing existing members',
            blocks: [
              {
                type: 'paragraph',
                text: 'The Team list is filterable by status — All, Active, Locked, Invited, Pending Verification, Invitation Expired — so you can see at a glance who still needs to accept, and who is stuck. From there you can change a member’s role, reset their password, or remove them.',
              },
              {
                type: 'paragraph',
                text: 'A new Member can’t reach any tenant yet — give them access next. See Team members & roles.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'protecting-your-first-route',
        title: 'Protecting your first route',
        lastUpdated: '2026-10-12',
        intro:
          'A route is what makes ianua a proxy and not just a login screen: it is a rule that matches incoming requests and decides whether they are allowed through to one of your services. This article walks through creating one.',
        sections: [
          {
            id: 'what-a-route-does',
            heading: 'What a route does',
            blocks: [
              {
                type: 'paragraph',
                text: 'Every request that hits ianua is matched against your tenant’s routes by path and HTTP method. Once a route matches, its policy decides whether the request continues — and if it does, ianua forwards it to the service the route points at.',
              },
            ],
          },
          {
            id: 'before-you-start',
            heading: 'Before you start: create a Service',
            blocks: [
              {
                type: 'paragraph',
                text: 'A route needs somewhere to send traffic. If you have not already, create a Service first — it holds the upstream URL ianua forwards to, a request timeout, and optional settings like health checks, an expected token audience, and whether to require a client certificate (mTLS).',
              },
            ],
          },
          {
            id: 'the-route-form',
            heading: 'The route form',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Routes, click Add Route and fill in:',
              },
              {
                type: 'list',
                items: [
                  'Name and Priority — priority breaks ties when more than one route could match the same request; lower values are matched first.',
                  'Path Pattern — the path to match, e.g. /api/users/* for /api/users and everything under it, or /orders/{id} for one segment.',
                  'Hosts — leave as All domains, or restrict the route to specific domains. Only the tenant’s verified domains can be picked.',
                  'Pipeline — the request-processing chain this route runs before the request reaches your service. Every route names one; there is no default.',
                  'Methods — which HTTP methods this route matches (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).',
                  'Service — which upstream service this route forwards matching requests to.',
                  'Path rewrite — forward the path as-is, strip the matched prefix, or build a new path from a template before it reaches your service.',
                ],
              },
            ],
          },
          {
            id: 'access-policies',
            heading: 'Access policies',
            blocks: [
              {
                type: 'paragraph',
                text: 'The Policy field is the actual access decision. Pick one:',
              },
              {
                type: 'list',
                items: [
                  'Public — no authentication required.',
                  'Authenticated — any signed-in caller is allowed through.',
                  'Require system permission — caller must hold a specific built-in permission.',
                  'Require custom permission — caller must hold a permission you have defined for this tenant.',
                  'Require scope — caller must present a specific scope, typically used for AI agent or API client access.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Start a new route as Authenticated or with a narrow permission/scope requirement rather than Public, and loosen it later once you have confirmed it works — it is a smaller mistake to make.',
              },
            ],
          },
          {
            id: 'testing-it',
            heading: 'Testing it',
            blocks: [
              {
                type: 'paragraph',
                text: 'Once saved, send a real request through ianua to the route’s path. Check the audit log if it does not behave as expected — every allow and deny decision ianua makes is recorded there, with the reason.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'organizations-and-billing',
    title: 'Organizations & Billing',
    topics: [
      article({
        slug: 'organization-settings',
        title: 'Organization settings',
        lastUpdated: '2026-11-09',
        intro:
          'Settings → General is where your organization’s identity lives: its name, contact details, and the read-only facts about it.',
        sections: [
          {
            id: 'editable-fields',
            heading: 'Editable fields',
            blocks: [
              {
                type: 'list',
                items: [
                  'Name — the organization’s legal/primary name.',
                  'Display name (optional) — shown in the UI instead of Name when set.',
                  'Contact Email — the operational contact for this organization.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Owners and Admins can edit these fields. Everyone else sees the same page read-only.',
              },
            ],
          },
          {
            id: 'url-slug',
            heading: 'URL slug',
            blocks: [
              {
                type: 'paragraph',
                text: 'The URL Slug is set once, at sign-up, and cannot be changed afterward — it is part of your organization’s URLs throughout the dashboard.',
              },
            ],
          },
          {
            id: 'details',
            heading: 'Details',
            blocks: [
              {
                type: 'paragraph',
                text: 'Below the editable form, a Details card shows read-only facts: current Status, how many Tenants exist under this organization, and when it was Created.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'plans-and-billing',
        title: 'Plans & billing',
        lastUpdated: '2026-11-09',
        intro:
          'Your plan determines the limits your organization runs under — how many users, tenants, routes, and other resources you can create. Settings → Subscription shows your current plan, billing cycle and standing; Owners and Billing contacts can change the plan or add a payment method there.',
        sections: [
          {
            id: 'plan-tiers',
            heading: 'Plan tiers',
            blocks: [
              {
                type: 'paragraph',
                text: 'ianua is offered on four tiers: Free, Starter, Business, and Custom. Each tier carries its own limits — maximum users, tenants per organization, routes, services, API keys, agents, audit log retention, API rate limits, and more — plus which data residency options are available to you.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'New organizations start on Free. Custom is a contact-sales tier for limits beyond what Business offers.',
              },
            ],
          },
          {
            id: 'where-to-manage-it',
            heading: 'Where to manage it',
            blocks: [
              {
                type: 'paragraph',
                text: 'Settings → Subscription shows the organization’s plan, billing cycle and standing, including a trial’s end or a payment that is owed. Owners and Billing contacts can pick another plan and billing cycle there, and add a payment method when none is on file. Admins and Viewers can see it but not change it.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'cloud-account-connections',
        title: 'Cloud account connections',
        lastUpdated: '2026-10-03',
        intro:
          'Connecting your own cloud account lets you create tenants whose data lives in your infrastructure instead of in the ianua installation’s own database — you keep control of where it runs.',
        sections: [
          {
            id: 'supported-providers',
            heading: 'Supported providers',
            blocks: [
              {
                type: 'list',
                items: [
                  'Amazon Web Services — grants a role in your account that only ianua can assume.',
                  'Google Cloud — grants a service account key you can delete at any time.',
                  'Microsoft Azure — grants a service principal scoped to one subscription.',
                  'DigitalOcean — uses a personal access token.',
                  'Your own Kubernetes cluster — uses a service account bound to one namespace.',
                ],
              },
            ],
          },
          {
            id: 'connecting-one',
            heading: 'Connecting one',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Settings → Cloud, click Connect Cloud, pick a provider, and supply the credential it asks for. ianua verifies the grant immediately — if it doesn’t work, you’ll see why right away rather than finding out later while creating a tenant.',
              },
            ],
          },
          {
            id: 'using-it',
            heading: 'Using it',
            blocks: [
              {
                type: 'paragraph',
                text: 'Once connected and verified, that provider becomes available in the data residency step of Create Tenant — you can pick it, choose a region, and either let ianua build a private network for you or point it at one you already have.',
              },
              {
                type: 'paragraph',
                text: 'A connected account can be reverified at any time if its grant needs refreshing, or disconnected — disconnecting does not affect tenants already running on it.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'team-members-and-roles',
        title: 'Team members & roles',
        lastUpdated: '2026-11-09',
        intro:
          'This is the reference for organization-level team membership and roles — the people who administer ianua itself. For the step-by-step walkthrough of adding your first teammate, see Inviting your team.',
        sections: [
          {
            id: 'the-roles',
            heading: 'The roles',
            blocks: [
              {
                type: 'list',
                items: [
                  'Viewer — reads the organization, its team and its audit log. Cannot open a tenant.',
                  'Billing — manages the subscription. Cannot open a tenant, and sees no tenants or team.',
                  'Member — reads the organization and reaches only the tenants granted to them per-tenant.',
                  'Admin — runs the organization day to day and can open every tenant, but cannot close it or change what it pays.',
                  'Owner — governs the organization and can access every tenant in it.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'An Admin can make Admins, Members and Viewers. Only an Owner can make an Owner or a Billing contact, or act on someone who holds one of those roles.',
              },
            ],
          },
          {
            id: 'changing-a-role',
            heading: 'Changing someone’s role',
            blocks: [
              {
                type: 'paragraph',
                text: 'Use the Role column in Team to change someone’s role. A few rules keep you from locking yourself out:',
              },
              {
                type: 'list',
                items: [
                  'You cannot change your own role.',
                  'You cannot change the role of the only person on the team.',
                  'Only Active accounts can have their role changed.',
                ],
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'Turning an Owner or Admin into a Member takes away their access to every tenant until you give them some through Tenant Access. Billing and Viewer reach no tenant at all.',
              },
            ],
          },
          {
            id: 'tenant-access',
            heading: 'Giving a member access to tenants',
            blocks: [
              {
                type: 'paragraph',
                text: 'A Member has no tenant access until you give it:',
              },
              {
                type: 'steps',
                items: [
                  'Go to Team and open the member’s ⋯ menu.',
                  'Choose Tenant Access.',
                  'For each tenant, pick the roles that member should hold there.',
                  'Leave a tenant empty to keep them out of it, then choose Save access. Only tenants whose roles you changed are updated.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Inside each tenant the member holds exactly the roles you picked — the same roles that tenant’s own users can hold — so the sidebar and actions they see follow those roles. They see the change the next time the dashboard loads their access. To take someone out of a tenant, clear its roles and save.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Tenant Access appears only for members with the Member role who are Active, Invited, or Pending Verification — Owners already reach every tenant. It’s hidden on your own row.',
              },
            ],
          },
          {
            id: 'member-statuses',
            heading: 'Member statuses',
            blocks: [
              {
                type: 'paragraph',
                text: 'The Team list filters by status: All, Active, Locked, Invited, Pending Verification, and Invitation Expired — useful for spotting who hasn’t accepted yet or is stuck.',
              },
              {
                type: 'list',
                items: [
                  'Active — Lock stops them signing in and ends their sessions; Reset Password gives them a new one, shown once; Delete Forever removes them.',
                  'Locked — Restore Access lets them sign in again.',
                  'Invited — Revoke Invitation makes the link stop working.',
                  'Invitation Expired — Resend Invitation sends a fresh link.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'You cannot lock or delete yourself, and you cannot remove the last person on the team.',
              },
            ],
          },
          {
            id: 'resetting-a-password',
            heading: 'Resetting a password',
            blocks: [
              {
                type: 'paragraph',
                text: 'For members created with a password (not invited by email), an Owner can reset their password directly from the Team list — a new temporary password is generated and shown once, to be shared with that person directly.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'organization-api-keys',
        title: 'Organization API keys',
        lastUpdated: '2026-10-03',
        intro:
          'Organization API keys let scripts and CI/CD pipelines act against ianua’s own management API, scoped to exactly the permissions you grant them.',
        sections: [
          {
            id: 'creating-a-key',
            heading: 'Creating a key',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Settings → API Key, click Create Key, give it a descriptive name, and pick its permissions from the scope picker.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'A key can only do what you explicitly grant it — never more than your own account can do.',
              },
            ],
          },
          {
            id: 'the-secret',
            heading: 'The secret',
            blocks: [
              {
                type: 'paragraph',
                text: 'Keys use an oak_ prefix, which lets automated secret scanners recognize and flag them if one is accidentally committed or leaked. The full key value is shown exactly once, right after creation — store it somewhere safe, since ianua does not keep a retrievable copy.',
              },
            ],
          },
          {
            id: 'revoking-a-key',
            heading: 'Revoking a key',
            blocks: [
              {
                type: 'paragraph',
                text: 'Revoke a key from the same list at any time. Revocation is immediate and cannot be undone — issue a new key if the integration still needs access.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'audit-log',
        title: 'Audit log',
        lastUpdated: '2026-10-03',
        intro:
          'Every meaningful action in your organization — at both the organization and tenant level — is recorded in the audit log, with who did it, from where, and when.',
        sections: [
          {
            id: 'reading-an-entry',
            heading: 'Reading an entry',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each row shows a scope badge (Organization, or the specific tenant it happened in — click it to jump straight to that tenant), the event itself, the author, their IP address, and a timestamp. Entries with extra detail can be expanded in place.',
              },
            ],
          },
          {
            id: 'searching-and-filtering',
            heading: 'Searching and filtering',
            blocks: [
              {
                type: 'paragraph',
                text: 'Search by event, and narrow by date range. Both combine, and a Clear All button appears whenever a filter is active.',
              },
            ],
          },
          {
            id: 'exporting',
            heading: 'Exporting',
            blocks: [
              {
                type: 'paragraph',
                text: 'Export CSV exports the audit log using whatever search and date filters are currently applied — useful for compliance records or handing a slice of history to someone outside ianua.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'suspending-or-closing-an-organization',
        title: 'Suspending or closing an organization',
        lastUpdated: '2026-10-03',
        intro:
          'Settings → Danger Zone holds the two irreversible-feeling actions for an organization. One of them actually is irreversible — read carefully before using either.',
        sections: [
          {
            id: 'suspend-organization',
            heading: 'Suspend Organization',
            blocks: [
              {
                type: 'paragraph',
                text: 'Temporarily disables access for everyone in the organization. Reversible by an operator.',
              },
              {
                type: 'list',
                items: [
                  'All users lose access immediately.',
                  'Running sessions are terminated.',
                  'Organization data remains intact.',
                  'The organization can be reactivated at any time.',
                ],
              },
            ],
          },
          {
            id: 'close-organization',
            heading: 'Close Organization',
            blocks: [
              {
                type: 'paragraph',
                text: 'Permanently closes the organization. This cannot be undone.',
              },
            ],
          },
          {
            id: 'confirming-the-action',
            heading: 'Confirming the action',
            blocks: [
              {
                type: 'paragraph',
                text: 'Both actions require typing the organization’s name to confirm, specifically to prevent an accidental click from suspending or closing the wrong thing.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'tenants',
    title: 'Tenants',
    topics: [
      article({
        slug: 'what-is-a-tenant',
        title: 'What is a tenant',
        lastUpdated: '2026-10-03',
        intro:
          'A tenant is a workspace inside your organization — typically one per product, environment, or customer deployment. This article is the reference for what belongs to a tenant and what doesn’t.',
        sections: [
          {
            id: 'what-belongs-to-a-tenant',
            heading: 'What belongs to a tenant',
            blocks: [
              {
                type: 'paragraph',
                text: 'Everything a tenant needs to run is scoped to it, and nothing is shared with any other tenant:',
              },
              {
                type: 'list',
                items: [
                  'Its own users, groups, roles, and custom permissions.',
                  'Its own routes, services, and pipelines.',
                  'Its own domains, signing keys, and agent configuration.',
                  'Its own audit trail.',
                ],
              },
            ],
          },
          {
            id: 'what-is-not-tenant-scoped',
            heading: 'What is not tenant-scoped',
            blocks: [
              {
                type: 'paragraph',
                text: 'Organization-level concerns — billing, the organization’s own Team members, cloud account connections, and the organization-wide audit log — live one level up and are shared across every tenant in the organization.',
              },
            ],
          },
          {
            id: 'tenant-users-vs-team-members',
            heading: 'Tenant users vs. team members',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'A tenant’s users are the end users of whatever you are building — not the people administering ianua. Those are your organization’s Team members, covered under Organizations & Billing.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'two-ways-to-reach-a-tenant',
        title: 'Two ways to reach a tenant',
        lastUpdated: '2026-11-09',
        intro:
          'The same tenant management screens are reachable through two different URLs, depending on who is looking at them and how they signed in.',
        sections: [
          {
            id: 'from-the-organization',
            heading: 'From the organization',
            blocks: [
              {
                type: 'paragraph',
                text: 'An organization Owner or Member signs in to the organization dashboard, then opens a tenant from the Tenants list. URLs are shaped like /tenants/{tenant}/..., and the header includes a crumb back to the tenant’s overview. Owners and Admins can open every tenant. A Member sees only the tenants an Owner or Admin gave them access to, and inside each one only the sections their roles there allow.',
              },
            ],
          },
          {
            id: 'directly-into-a-tenant',
            heading: 'Directly into a tenant',
            blocks: [
              {
                type: 'paragraph',
                text: 'A tenant’s own users sign in on the tenant’s sign-in page, /organizations/{org}/tenants/{tenant}/login, and land in that tenant’s screens with URLs shaped like /organizations/{org}/tenants/{tenant}/... — there is no organization dashboard around it, because they are not part of your team.',
              },
            ],
          },
          {
            id: 'why-this-matters',
            heading: 'Why this matters',
            blocks: [
              {
                type: 'paragraph',
                text: 'Both views render the same screens — Users, Roles, Permissions, Groups, Domains, Routes, and the rest. What someone can see and do in them depends on their roles in that tenant, the same way for a team Member and for a tenant user. Owners see everything.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'creating-and-managing-tenants',
        title: 'Creating & managing tenants',
        lastUpdated: '2026-10-09',
        intro:
          'This is the reference for a tenant’s own management screens, once it exists. For the creation form field-by-field, see Creating your first tenant.',
        sections: [
          {
            id: 'tenant-general-settings',
            heading: 'General settings',
            blocks: [
              {
                type: 'paragraph',
                text: 'A tenant’s own Settings → General covers the same fields as the creation form — name, domain, contact email, timezone, and locale — editable at any point after creation. The slug is fixed once the tenant is created.',
              },
            ],
          },
          {
            id: 'tenant-lifecycle',
            heading: 'Tenant lifecycle',
            blocks: [
              {
                type: 'list',
                items: [
                  'Provisioning — its data space, signing keys and default roles are being created. Nobody can sign in yet. Moves to Active on its own within a few seconds.',
                  'Active — normal operation.',
                  'Suspended — frozen. Every session ends, new sign-ins are refused, and the gateway stops serving the tenant’s apps. All data is kept, and Restore Access brings it back.',
                  'Archived — on its way out. It stops working as when suspended, but cannot come back; the only next step is Delete forever.',
                  'Deleted — the tenant’s data is removed from every table. This cannot be undone.',
                ],
              },
              {
                type: 'paragraph',
                text: 'The tenant’s menu in Tenants, and the Danger zone in its Settings, offer only what fits its current status: Suspend or Archive while Active; Restore Access or Archive while Suspended; Delete forever once Archived. Only Owners and Admins can do these, and someone without the right does not see the menu.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'Use Suspend as the “stop everything now” switch during an incident — nothing is lost. Archive and Delete are for tenants you are finished with, and Delete is the only step that removes data.',
              },
            ],
          },
          {
            id: 'account-and-security',
            heading: 'Account and security',
            blocks: [
              {
                type: 'paragraph',
                text: 'A tenant also has its own Account section (your own name and email in that tenant) and Security section (your own password, second factor, passkeys and remembered devices), separate from the organization’s equivalents.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'tenant-users',
        title: 'Tenant users',
        lastUpdated: '2026-10-12',
        intro:
          'Tenant users are the end users of what you’re building — managed from Users inside a tenant, separately from your organization’s own Team members.',
        sections: [
          {
            id: 'adding-a-user',
            heading: 'Adding a user',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Users, Add User offers the same choice as team invites: Send Invite (they set their own password) or Create Member with a generated or chosen password. You can assign one or more roles right away.',
              },
              {
                type: 'list',
                items: [
                  'Send Invite — the person gets an email and chooses a password that meets the tenant’s rules. The link works for one day; you can resend it (a fresh link) or revoke it.',
                  'Create Member — set a password or generate one (a generated password is shown once). With Auto-verify email on, the account is active at once; with it off, the person confirms their address before they can sign in.',
                ],
              },
            ],
          },
          {
            id: 'other-ways-in',
            heading: 'Other ways people get in',
            blocks: [
              {
                type: 'list',
                items: [
                  'Sign-up — if the tenant lets people sign themselves up (see Password). The account waits for email confirmation.',
                  'Single sign-on — with just-in-time provisioning on, a person signing in through a connection is created on the spot (see Single sign-on).',
                  'SCIM — your identity provider creates and updates users on its own schedule (see SCIM provisioning).',
                ],
              },
            ],
          },
          {
            id: 'account-statuses',
            heading: 'What each status means',
            blocks: [
              {
                type: 'list',
                items: [
                  'Invited — has an invitation and hasn’t accepted it. Cannot sign in.',
                  'Pending Verification — the email address isn’t confirmed yet. Cannot sign in until they follow the link.',
                  'Active — signs in normally.',
                  'Locked — blocked by an administrator or by SCIM. Every session ends, and so does every delegation the user gave an agent. Restore Access brings the account back.',
                  'Deactivated — switched off for good. Sessions and delegations end as with locking, and the account can’t be restored; its data is kept for the audit trail.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Too many wrong passwords is different: the account is held for a short time and then works again on its own, without its status changing.',
              },
            ],
          },
          {
            id: 'changing-an-email',
            heading: 'Changing an email address',
            blocks: [
              {
                type: 'paragraph',
                text: 'When an administrator changes a user’s address, ianua emails a confirmation link to the new one, and the old address keeps working until it’s followed. The old address then gets a notice that the change happened. Changes from SCIM take effect at once.',
              },
            ],
          },
          {
            id: 'removing-people',
            heading: 'Removing people',
            blocks: [
              {
                type: 'list',
                items: [
                  'Delete Forever — removes the account at once, with its sessions, role assignments and credentials. Every delegation the user gave an agent is revoked first. The audit log keeps its record that the account existed.',
                  'Erasure — for a person exercising their right to be forgotten (GDPR Article 17). The person or an administrator can request it; nothing happens for 30 days, during which it can be cancelled, and then the account and everything attached to it is removed.',
                ],
              },
            ],
          },
          {
            id: 'statuses-and-filtering',
            heading: 'Statuses and filtering',
            blocks: [
              {
                type: 'paragraph',
                text: 'The list filters by status — All, Active, Locked, Invited, Pending Verification, Invitation Expired — the same shape as the organization Team list.',
              },
            ],
          },
          {
            id: 'custom-fields-on-users',
            heading: 'Custom fields on users',
            blocks: [
              {
                type: 'paragraph',
                text: 'If the tenant has declared any User attributes, the ones shown in the user list appear as extra columns here. Manage fields opens the panel where fields are added, edited, archived and restored, and Edit user fields in a row’s ⋯ menu fills in one person’s values. See User attributes for the full picture.',
              },
            ],
          },
          {
            id: 'resetting-a-password',
            heading: 'Resetting a password',
            blocks: [
              {
                type: 'paragraph',
                text: 'For a user created with a password, reset it from the same list — a new temporary password is generated and shown once, and every session the user had ends.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'roles',
        title: 'Roles',
        lastUpdated: '2026-10-09',
        intro:
          'A role is a named bundle of permissions, assigned to users (directly, or through a Group) to decide what they can do inside the tenant.',
        sections: [
          {
            id: 'two-kinds-of-permission',
            heading: 'Two kinds of permission a role can grant',
            blocks: [
              {
                type: 'list',
                items: [
                  'System permissions — built into ianua itself (managing users, routes, domains, and so on).',
                  'Custom permissions — ones your own application declared under Permissions, scoped to whatever that application protects.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A single role can mix both kinds freely.',
              },
            ],
          },
          {
            id: 'creating-a-role',
            heading: 'Creating a role',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Roles, click Create Role, give it a name, and pick its permissions from both catalogues. Role names are unique within a tenant. When you edit a role, the permissions you save are its whole new set — anything left out is taken away.',
              },
            ],
          },
          {
            id: 'starting-roles',
            heading: 'The roles a tenant starts with',
            blocks: [
              {
                type: 'list',
                items: [
                  'Admin — every ianua permission. Not given to new users automatically.',
                  'Member — viewing the tenant’s metrics. Given to every new user by default.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Both are ordinary roles: rename, change or delete them as you like. A role marked as a default is given to every new user, however they arrive — except an invitation, which gives exactly the role it names.',
              },
            ],
          },
          {
            id: 'how-permissions-add-up',
            heading: 'How permissions add up',
            blocks: [
              {
                type: 'list',
                items: [
                  'A person holds roles directly, through a group, or from the start as a default role. What they may do is everything all their roles give them, added together.',
                  'ianua’s own permissions name an area and an action. A Manage action includes every action in its area, and any permission over users also lets someone see roles.',
                  'Taking a role away works on the person’s very next request — no waiting for a token to expire.',
                ],
              },
            ],
          },
          {
            id: 'only-what-you-hold',
            heading: 'You can only hand out what you hold',
            blocks: [
              {
                type: 'paragraph',
                text: 'To give someone a role — directly, through a group, in an invitation, as a default role, or as the role an SSO or SCIM connection gives — you must already hold every permission in it. Anything that would break this is refused.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'The one exception is for your app’s own (custom) permissions: whoever may escalate roles can give those out without holding them. The Admin role has it. It never applies to ianua’s own permissions.',
              },
            ],
          },
          {
            id: 'deleting-a-role',
            heading: 'Deleting a role',
            blocks: [
              {
                type: 'paragraph',
                text: 'A role someone holds directly can’t be deleted on its own: either take it away from them first, or pick a replacement role — everyone who held the deleted role is moved onto it in one step.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'permissions',
        title: 'Permissions',
        lastUpdated: '2026-10-09',
        intro:
          'Permissions here means custom permissions — the Resources screen is where you declare what your own application protects, so routes and roles have something real to grant.',
        sections: [
          {
            id: 'declaring-a-resource',
            heading: 'Declaring a resource',
            blocks: [
              {
                type: 'paragraph',
                text: 'Click Add Resource and name a kind of thing your application protects — a project, a document, an invoice — along with the actions it accepts (read, write, delete, or whatever makes sense for it).',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Declaring one from a fixed catalogue is what stops project:write and projects:write silently becoming two different permissions nobody notices are meant to be the same thing.',
              },
            ],
          },
          {
            id: 'where-it-gets-used',
            heading: 'Where it gets used',
            blocks: [
              {
                type: 'paragraph',
                text: 'Once declared, a resource’s actions show up wherever a custom permission can be granted: in Roles, and in a route’s Require custom permission policy.',
              },
              {
                type: 'list',
                items: [
                  'An action can include others on the same resource — if admin includes write and write includes read, a role with orders:admin also passes orders:write and orders:read.',
                  '* stands for “any”: orders:* is every action on orders, and *:read is reading anything.',
                  'A resource can’t be named idp, or start with idp_ or idp-. Those names belong to ianua’s own permissions.',
                ],
              },
              {
                type: 'paragraph',
                text: 'When a signed-in caller passes a route, your app receives a signed X-Ianua-Assertion header listing their roles and every permission they hold, so it can decide for itself without keeping its own copy.',
              },
            ],
          },
          {
            id: 'editing-and-removing',
            heading: 'Editing and removing',
            blocks: [
              {
                type: 'paragraph',
                text: 'A resource’s key is fixed once declared, since roles and routes already refer to it by that key — only its display name, description, and actions can change. Deleting one only removes the declaration; it does not revoke anything a role already granted, and any role still granting it has to be changed first.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'groups',
        title: 'Groups',
        lastUpdated: '2026-10-09',
        intro:
          'A group bundles roles together and hands them out by membership, instead of assigning the same set of roles to people one at a time.',
        sections: [
          {
            id: 'creating-a-group',
            heading: 'Creating a group',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Groups, click Create Group and name it. A group can sit inside one other group, chosen when it’s created — members get the roles of their group and of every group above it.',
              },
            ],
          },
          {
            id: 'members-and-roles',
            heading: 'Members and roles',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each group has its own Members list and its own set of granted Roles, managed from separate actions on the Groups table.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'A group can only grant what you already hold: to add someone to a group, or give a group a role, you need every permission the group would give them, including what it inherits from groups above it. SCIM is the exception — your identity provider decides who is in a group, but the group’s roles are still set only in ianua.',
              },
            ],
          },
          {
            id: 'deleting-a-group',
            heading: 'Deleting a group',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'Deleting a group removes only the group and the grants it carried — nobody in it is deleted. A group that has other groups inside it can’t be deleted until they are moved or removed.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'user-attributes',
        title: 'User attributes',
        lastUpdated: '2026-10-12',
        intro:
          'User attributes are custom fields you declare on a tenant’s users — anything from a plan tier to a loyalty number — beyond what ianua tracks by default.',
        sections: [
          {
            id: 'managing-fields',
            heading: 'Managing fields',
            blocks: [
              {
                type: 'paragraph',
                text: 'Open the tenant, go to Users, and click Manage fields. A panel opens with every field the tenant has declared.',
              },
              {
                type: 'list',
                items: [
                  'The switch on a field shows or hides it as a column in the user list.',
                  'Edit opens the field’s settings.',
                  'Archive takes a field out of use. Values already stored in it are kept, and it moves to Archived fields.',
                  'Under Archived fields, Restore puts a field back in use, and Delete removes it for good.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Hover any icon in the panel to see what it does.',
              },
            ],
          },
          {
            id: 'adding-a-field',
            heading: 'Adding a field',
            blocks: [
              {
                type: 'steps',
                items: [
                  'In Manage fields, click Add field.',
                  'Choose the Field type, and how it’s Shown as (for example a text box or a dropdown).',
                  'Give it a Name, and optionally Help text shown to people as a hint.',
                  'Fill in what the type needs: a Maximum length for text, Lowest and Highest values for numbers, or the Choices — one per line — for a choice field.',
                  'Turn on the switches you want (see below), and click Add field.',
                ],
              },
            ],
          },
          {
            id: 'kinds-of-field',
            heading: 'Kinds of field',
            blocks: [
              {
                type: 'paragraph',
                text: 'Pick from a fixed set of kinds — text, long text, whole number, decimal, money, percent, date, date & time, email, phone, link, colour, rating, yes/no, country, tags, and single- or multiple-choice — and ianua renders the right input and validation for it automatically.',
              },
            ],
          },
          {
            id: 'how-a-field-behaves',
            heading: 'How a field behaves',
            blocks: [
              {
                type: 'list',
                items: [
                  'Required — everyone must fill in a value.',
                  'Show in user list — display this field as a column in the list.',
                  'Allow filtering — let the user list be filtered by this field.',
                  'Allow sorting — let the user list be sorted by this field (not available for kinds that hold a list of values).',
                  'Sensitive — reading, filtering and sorting it need permission to manage users.',
                ],
              },
            ],
          },
          {
            id: 'who-maintains-it',
            heading: 'Who maintains it',
            blocks: [
              {
                type: 'paragraph',
                text: 'Under Advanced settings, “Who can manage this field?” is either Administrators only, or The person it describes — meaning the user themselves can set their own value for it. The same section shows the field’s Internal name, generated from its name and used in filters and exports.',
              },
            ],
          },
          {
            id: 'editing-a-users-values',
            heading: 'Filling in a user’s values',
            blocks: [
              {
                type: 'steps',
                items: [
                  'In Users, open the ⋯ menu on the person’s row and choose Edit user fields.',
                  'Fill in or change the values, and click Save changes. Clearing a value removes it.',
                ],
              },
            ],
          },
          {
            id: 'deleting-a-field',
            heading: 'Deleting a field',
            blocks: [
              {
                type: 'paragraph',
                text: 'Only an archived field can be deleted. Deleting asks you to confirm, because the field and every value saved in it are removed permanently. To stop using a field without losing its data, archive it instead.',
              },
            ],
          },
          {
            id: 'fixed-once-declared',
            heading: 'Fixed once declared',
            blocks: [
              {
                type: 'paragraph',
                text: 'A field’s type, internal name and who maintains it are fixed the moment it’s created, since every stored value is filed under them — name, help text, how it’s shown, and the switches can still change freely.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'domains',
        title: 'Domains',
        lastUpdated: '2026-10-03',
        intro:
          'A domain is a hostname verified as belonging to a tenant, so ianua will serve traffic — and issue TLS certificates — for it.',
        sections: [
          {
            id: 'adding-a-domain',
            heading: 'Adding a domain',
            blocks: [
              {
                type: 'paragraph',
                text: 'From Domains, click Add Domain and enter the hostname. ianua gives you DNS instructions to prove you control it.',
              },
            ],
          },
          {
            id: 'verifying-and-tls',
            heading: 'Verifying and TLS',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Add the DNS record ianua shows you, at your DNS provider.',
                  'Click Verify once it has propagated.',
                  'Provision TLS to issue a certificate for the domain.',
                ],
              },
              {
                type: 'paragraph',
                text: 'View setup instructions again at any time from the domain’s row if you need them a second time.',
              },
            ],
          },
          {
            id: 'transferring-a-domain',
            heading: 'Transferring a domain',
            blocks: [
              {
                type: 'paragraph',
                text: 'From the organization-scoped view, a verified domain can be offered to a different tenant in the same organization. The other tenant has to accept the offer before the domain moves; it does not need to be verified again.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'data-residency',
        title: 'Data residency',
        lastUpdated: '2026-10-09',
        intro:
          'Data residency is the choice, made once when a tenant is created, of where that tenant’s data physically lives.',
        sections: [
          {
            id: 'the-options',
            heading: 'The options',
            blocks: [
              {
                type: 'list',
                items: [
                  'This installation — the default. The tenant’s data is stored in the database this ianua installation already uses. Nothing to connect.',
                  'Your cloud account — ianua creates and runs the database in a cloud account you’ve connected. You own it and you pay for it.',
                  'A database you already run — you give ianua a connection to it. ianua creates no infrastructure.',
                ],
              },
            ],
          },
          {
            id: 'choosing-a-dedicated-instance',
            heading: 'Using your own cloud account',
            blocks: [
              {
                type: 'paragraph',
                text: 'Pick a connected provider and a region. From there, either let ianua build a private network for you with no public path to the database, or point it at a network you already have — useful when the database needs to sit alongside infrastructure you already run.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'The provider you want has to be connected first, under Settings → Cloud account connections — it won’t appear as an option otherwise.',
              },
            ],
          },
          {
            id: 'why-it-matters',
            heading: 'Why it matters',
            blocks: [
              {
                type: 'paragraph',
                text: 'Inside this installation’s database, a tenant’s rows sit alongside other tenants’ with each row tagged to its tenant, and the database itself refuses to show one tenant’s rows to another. A tenant can instead get a dedicated schema — its own set of tables in the same database — but that is chosen at creation through the API; the dashboard creates shared tenants.',
              },
              {
                type: 'paragraph',
                text: 'Data residency is primarily a compliance and control decision — some organizations are required to keep certain data in a specific jurisdiction or under their own cloud account rather than a shared installation, and this is where that gets decided for each tenant individually.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'authentication-and-security',
    title: 'Authentication & Security',
    topics: [
      article({
        slug: 'authentication-methods',
        title: 'Authentication methods',
        subArticles: [
          article({
            slug: 'password',
            title: 'Password',
            lastUpdated: '2026-10-09',
            intro:
              'Password is the default sign-in method, available for every user out of the box.',
            sections: [
              {
                id: 'setting-a-password',
                heading: 'Setting a password',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'A user sets their password when accepting an invite or when their password is reset — the form validates against the tenant’s active Password policy as they type, with live hint text showing exactly what’s still missing.',
                  },
                ],
              },
              {
                id: 'forgot-password',
                heading: 'Forgot password',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'The login screen links to a Forgot password flow that emails a reset link, scoped to the correct organization or tenant depending on where the sign-in happened.',
                  },
                ],
              },
              {
                id: 'self-registration',
                heading: 'Letting people sign themselves up',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'The “Let people sign themselves up” switch adds a “Create an account” link to the tenant’s sign-in page.',
                  },
                  {
                    type: 'steps',
                    items: [
                      'Open the tenant and go to Settings → Sign-in.',
                      'Make sure Password sign-in is on, then switch on “Let people sign themselves up” and save.',
                      'A new person opens the tenant’s sign-in page, chooses “Create an account”, and enters their name, email, and a password that meets the password policy.',
                      'They confirm their email from the link they’re sent, and can then sign in.',
                    ],
                  },
                  {
                    type: 'callout',
                    tone: 'info',
                    text: 'Self sign-up needs Password sign-in to be on. With the switch off, the sign-up page just says sign-up is closed.',
                  },
                ],
              },
              {
                id: 'passwordless-invites',
                heading: 'Invites when Password is off',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'If a tenant has no password sign-in, an invited person isn’t asked to create one: accepting the invite just activates their account, and they sign in another way.',
                  },
                ],
              },
              {
                id: 'turning-it-off',
                heading: 'Turning it off',
                blocks: [
                  {
                    type: 'callout',
                    tone: 'warning',
                    text: 'Password can be disabled per tenant from Settings → Sign-in, but at least one sign-in method must stay enabled — you can’t turn off every way in at once.',
                  },
                ],
              },
              {
                id: 'breach-check',
                heading: 'Breached passwords and lockout',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'Every password is checked against known data breaches at sign-in; only the first 5 characters of the password’s hash ever leave the server. If it turns up in a breach, someone who has a second factor is asked for it, and the breach is recorded in the audit log.',
                  },
                  {
                    type: 'paragraph',
                    text: 'After too many failed sign-ins the account is held for a while — 10 failures then 15 minutes by default — and then works again on its own. A wrong password and an unknown email get exactly the same answer, so the sign-in page can’t be used to find out who has an account.',
                  },
                ],
              },
            ],
          }),
          article({
            slug: 'passkey',
            title: 'Passkey',
            lastUpdated: '2026-10-09',
            intro:
              'A passkey lets a user sign in with their device’s own biometric or PIN unlock instead of typing a password — backed by the platform authenticator (Face ID, Windows Hello, a hardware key, and so on).',
            sections: [
              {
                id: 'registering-a-passkey',
                heading: 'Registering a passkey',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'A user can register one or more passkeys, name each one so it’s recognizable later, and remove any they no longer trust.',
                  },
                  {
                    type: 'steps',
                    items: [
                      'Open Account → Security.',
                      'In the Passkeys card, choose to add a passkey and approve the prompt from your device or browser.',
                      'Give the passkey a name you’ll recognize, and confirm.',
                    ],
                  },
                  {
                    type: 'callout',
                    tone: 'info',
                    text: 'Passkey sign-in is offered on a tenant’s sign-in page when the tenant has Passkey enabled under Settings → Sign-in → Ways in (it is on for a new tenant). A passkey sign-in counts as the strongest kind there is. If Every sign-in needs is set to a passkey, passwords and magic links are refused for everyone.',
                  },
                ],
              },
              {
                id: 'signing-in-with-one',
                heading: 'Signing in with one',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'On the login screen, entering an email offers a passkey option alongside password — on supporting browsers, the email field itself can autofill with a saved passkey.',
                  },
                ],
              },
            ],
          }),
          article({
            slug: 'magic-link',
            title: 'Magic link',
            lastUpdated: '2026-10-09',
            intro:
              'Magic link is passwordless sign-in: the user enters their email, ianua emails a one-time link, and clicking it signs them in.',
            sections: [
              {
                id: 'turning-it-on',
                heading: 'Turning it on',
                blocks: [
                  {
                    type: 'steps',
                    items: [
                      'Open the tenant and go to Settings → Sign-in.',
                      'Under Ways in, switch on Magic link. It is off for a new tenant.',
                      'Save your changes.',
                      'Open the tenant’s sign-in page and check that “Email me a sign-in link” appears under the email field.',
                    ],
                  },
                  {
                    type: 'paragraph',
                    text: 'Magic link is offered on a tenant’s sign-in page only — there’s no magic link for signing in to the organization dashboard itself.',
                  },
                ],
              },
              {
                id: 'signing-in',
                heading: 'Signing in with one',
                blocks: [
                  {
                    type: 'steps',
                    items: [
                      'On the tenant’s sign-in page, enter your email and choose “Email me a sign-in link”.',
                      'You’ll see a note that, if the address has an account, a link is on its way — the page never confirms whether an address exists.',
                      'Open the email and click the link. It works once, for 15 minutes, and signs you straight in.',
                    ],
                  },
                  {
                    type: 'callout',
                    tone: 'info',
                    text: 'Like a password sign-in, a magic link can still ask for a second factor if the tenant’s rules call for one. If Magic link is switched off, asking for a link is refused everywhere — not just hidden on the page.',
                  },
                ],
              },
            ],
          }),
          article({
            slug: 'sso',
            title: 'Single sign-on (SSO)',
            lastUpdated: '2026-11-09',
            intro:
              'Single sign-on lets people sign in to a tenant with an external identity provider (Okta, Entra ID, and the like) over SAML or OIDC, instead of a password.',
            sections: [
              {
                id: 'setting-it-up',
                heading: 'Setting it up',
                blocks: [
                  {
                    type: 'steps',
                    items: [
                      'Open the tenant and go to Connections.',
                      'Click Add connection, name the provider (for example “Microsoft Entra ID”), and choose SAML or OIDC.',
                      'Under Allowed domains, choose the email domains this provider may sign people in for. Only the tenant’s verified domains are offered — add and verify yours under Domains first.',
                      'Fill in the details your identity provider gave you — see SSO / SAML / OIDC connections for exactly which fields each protocol needs.',
                      'Save the connection. A new connection is active straight away.',
                      'Tell your identity provider about ianua: for SAML, give it the metadata document at /api/v1/organizations/{org}/tenants/{tenant}/federation/connections/{connection}/saml/metadata on your dashboard’s address (each connection has its own); for OIDC, register /api/v1/organizations/{org}/tenants/{tenant}/federation/oidc/callback as the redirect (return) address.',
                      'Go to Settings → Sign-in and, under Ways in, switch on SAML federation or OIDC federation (whichever your connection uses). Save.',
                      'Open the tenant’s sign-in page and check for a “Sign in with {provider name}” button.',
                    ],
                  },
                  {
                    type: 'callout',
                    tone: 'warning',
                    text: 'The button only appears when both are true: the connection is active, and its protocol is switched on under Ways in. If you don’t see it, check the Ways in switch first.',
                  },
                  {
                    type: 'callout',
                    tone: 'info',
                    text: 'Choosing allowed domains needs the Federation (Manage) permission. A provider can only sign in people whose address is at one of them: it can’t claim an account at any other address.',
                  },
                  {
                    type: 'paragraph',
                    text: 'The same identity provider can also keep users in sync through SCIM provisioning.',
                  },
                ],
              },
              {
                id: 'signing-in',
                heading: 'What people see',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'Each connection adds a “Sign in with {provider name}” button to the tenant’s sign-in page, on the first (email) step. Clicking it sends the person to the identity provider and brings them back signed in. If anything goes wrong on the way, they land back on the sign-in page with a “Single sign-on didn’t work” message and can try again or use another method.',
                  },
                  {
                    type: 'paragraph',
                    text: 'The first time someone signs in through a provider with an existing account, the account is linked to who they are at that provider, and they get an email saying so. From then on the provider signs them in by that link. If they have a second factor set up in the tenant, they’re still asked for it — unless the provider reports it already checked one.',
                  },
                  {
                    type: 'callout',
                    tone: 'info',
                    text: 'The button is on the tenant sign-in page only. The organization dashboard sign-in doesn’t offer SSO.',
                  },
                ],
              },
              {
                id: 'who-gets-in',
                heading: 'Matching people to users',
                blocks: [
                  {
                    type: 'paragraph',
                    text: 'ianua matches the person to a tenant user by email address. If nobody has that address, the connection’s just-in-time provisioning setting decides: with it on, the user is created on the spot, already active, with the tenant’s default roles plus the connection’s own default role if you set one; with it off, the sign-in is refused.',
                  },
                  {
                    type: 'paragraph',
                    text: 'People signing in through single sign-on aren’t asked for ianua’s second factor — the identity provider did the checking. They are still asked for it before a sensitive action, if they have one.',
                  },
                ],
              },
            ],
          }),
        ],
      }),
      article({
        slug: 'multi-factor-authentication',
        title: 'Multi-factor authentication',
        lastUpdated: '2026-10-09',
        intro:
          'A second factor — an authenticator app (TOTP) or a one-time backup code — adds a layer beyond a password or passkey, enforced per tenant from Settings → Sign-in.',
        sections: [
          {
            id: 'the-policy',
            heading: 'The policy',
            blocks: [
              {
                type: 'list',
                items: [
                  'Off — nobody can enrol a second factor.',
                  'Optional — users may enrol one, but aren’t forced to.',
                  'Required — everyone must set one up and use it.',
                ],
              },
              {
                type: 'paragraph',
                text: 'When a tenant requires one, someone who signs in without a second factor is taken through set-up right there: scan a QR code into an authenticator app, enter the 6-digit code, and then save their recovery codes before continuing.',
              },
            ],
          },
          {
            id: 'assurance-levels',
            heading: 'Assurance levels',
            blocks: [
              {
                type: 'paragraph',
                text: 'Two settings decide the minimum bar: Every sign-in needs (the floor for all sign-ins) and Sensitive actions need (a higher bar for sensitive actions — changing a password, second factor or passkey, or trusting a device — asked of people who have a second factor). Options run from password only, through password and a second factor, up to a passkey.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'The step-up options that ask for a second factor (new device, new country, risk level) do nothing while the second-factor policy is Off, and the settings are greyed out with a note saying so.',
              },
            ],
          },
          {
            id: 'enrolling-a-factor',
            heading: 'Enrolling a factor',
            blocks: [
              {
                type: 'paragraph',
                text: 'A user can also set up their own second factor ahead of time:',
              },
              {
                type: 'steps',
                items: [
                  'Open Account → Security and enable two-factor authentication.',
                  'Scan the QR code with an authenticator app.',
                  'Enter the 6-digit code the app shows to confirm.',
                  'Save your recovery codes somewhere safe.',
                ],
              },
              {
                type: 'paragraph',
                text: 'You get 10 recovery codes, shown once, right after set-up — each signs you in a single time if you lose your device, and they can’t be shown again.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'After 5 wrong codes in a row — authenticator or recovery codes alike — the second factor is locked for 15 minutes. While it’s locked, even the right code is refused.',
              },
            ],
          },
          {
            id: 'sensitive-actions',
            heading: 'Sensitive actions',
            blocks: [
              {
                type: 'paragraph',
                text: 'Some actions could lock a person out or hand their account to someone else, so Sensitive actions need sets a higher bar for them (a second factor by default): changing a password, adding or removing a passkey, switching off a second factor, trusting a device, asking for the account to be erased, and issuing a directory (LDAP) certificate.',
              },
              {
                type: 'paragraph',
                text: 'Someone who has a second factor but signed in with a password alone — or through single sign-on — is asked for their code first, and the action goes through after. Someone with no second factor isn’t asked, since there’s nothing stronger they could show.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'password-policy',
        title: 'Password policy',
        lastUpdated: '2026-10-09',
        intro:
          'The password policy sets what counts as a valid password for a tenant, enforced the moment someone sets or changes one — existing passwords aren’t retroactively invalidated.',
        sections: [
          {
            id: 'what-you-can-set',
            heading: 'What you can set',
            blocks: [
              {
                type: 'list',
                items: [
                  'Minimum length.',
                  'Require an uppercase letter.',
                  'Require a lowercase letter.',
                  'Require a digit.',
                  'Require a special character.',
                ],
              },
              {
                type: 'paragraph',
                text: 'By default a password needs at least 12 characters, with an uppercase letter, a lowercase letter and a digit. When an administrator resets someone’s password, the new one is shown once and every session that person had ends.',
              },
            ],
          },
          {
            id: 'where-it-shows-up',
            heading: 'Where it shows up',
            blocks: [
              {
                type: 'paragraph',
                text: 'Set from Settings → Sign-in, this same policy applies to every password however it is set — accepting an invite, signing up, changing or resetting a password, or an admin creating a user — and drives the live validation and hint text on each of those forms. A generated password always meets it.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'device-trust',
        title: 'Device trust',
        lastUpdated: '2026-10-03',
        intro:
          'Trusting a device lets a user skip their second factor on that device for future sign-ins, without lowering the bar everywhere else.',
        sections: [
          {
            id: 'how-a-device-gets-trusted',
            heading: 'How a device gets trusted',
            blocks: [
              {
                type: 'paragraph',
                text: 'If Ask for a second factor on a new device is on, completing that challenge offers the option to trust the device — after that, sign-ins from it skip the second-factor prompt.',
              },
            ],
          },
          {
            id: 'managing-trusted-devices',
            heading: 'Managing trusted devices',
            blocks: [
              {
                type: 'paragraph',
                text: 'Account → Security lists every device currently trusted on an account. Revoke any you don’t recognize — revoking takes effect immediately, and that device will be challenged again next time.',
              },
            ],
          },
          {
            id: 'when-trust-is-overridden',
            heading: 'When trust is overridden',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'If Every sign-in needs is set above password-only, every sign-in is already challenged regardless — trusting a device makes no difference in that case.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'break-glass-access',
        title: 'Break-glass access',
        lastUpdated: '2026-10-03',
        intro: 'Coming soon.',
        sections: [
          {
            id: 'coming-soon',
            heading: 'Coming soon',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'A dedicated emergency-access path that bypasses normal sign-in policy for a designated account isn’t available yet. For now, an organization Owner can always reach Settings to adjust sign-in policy directly.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'session-and-step-up-policy',
        title: 'Session & step-up policy',
        lastUpdated: '2026-10-09',
        intro:
          'Beyond who can sign in, Settings → Sign-in also controls how long a session lasts, what happens after repeated failed attempts, when a sign-in gets challenged based on risk, and which networks are allowed in at all.',
        sections: [
          {
            id: 'sessions',
            heading: 'Sessions',
            blocks: [
              {
                type: 'list',
                items: [
                  'Session length — how long a session lasts from sign-in, regardless of activity. 8 hours by default; anything from 5 minutes to 30 days.',
                  'Idle timeout — how long without activity before it ends early. 1 hour by default, at least 1 minute, and never longer than the session itself.',
                ],
              },
              {
                type: 'paragraph',
                text: 'For example, with the defaults, someone who signs in at 9:00 is signed out at 17:00 at the latest — or at 13:00 if they leave for a two-hour lunch at 12:00. Refreshing a session never moves its end time.',
              },
            ],
          },
          {
            id: 'lockout',
            heading: 'Lockout',
            blocks: [
              {
                type: 'paragraph',
                text: 'Failed attempts allowed and Locked for (seconds) decide how many wrong passwords trigger a lockout, and how long it lasts — 10 failures and 15 minutes by default, adjustable from 2 to 100 failures and from 30 seconds to a day. The account unlocks on its own afterwards; its status doesn’t change.',
              },
            ],
          },
          {
            id: 'risk-based-step-up',
            heading: 'Risk-based step-up',
            blocks: [
              {
                type: 'list',
                items: [
                  'Ask for a second factor on a new device, or from a new country — both based on where the sign-in is coming from.',
                  'Always ask for a second factor from risk level — a chosen tier always triggers a challenge: Low (every sign-in), Medium (any unusual travel), High (travel faster than is likely), or Critical (travel no one could make).',
                  'Refuse the sign-in from risk level — a chosen tier is refused outright rather than challenged.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Risk is judged by comparing each sign-in with the person’s last one. Travel nobody could make (Berlin, then Sydney an hour later) is always refused, whatever these settings say. A person’s first sign-in sets their home country, so it is never a “new country”, and each person can trust up to 10 devices.',
              },
            ],
          },
          {
            id: 'allowed-addresses',
            heading: 'Allowed addresses',
            blocks: [
              {
                type: 'paragraph',
                text: 'An IP allowlist (one CIDR range per line, such as 10.0.0.0/8) restricts sign-ins to specific networks — left empty, sign-ins are accepted from anywhere. Once set, everything outside the listed ranges is refused, and so is a sign-in whose address can’t be told. It applies to every way in, single sign-on included.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'sso-saml-oidc-connections',
        title: 'SSO / SAML / OIDC connections',
        lastUpdated: '2026-10-09',
        intro:
          'A connection links a tenant to an external identity provider over SAML or OIDC — configured from Connections, inside a tenant.',
        sections: [
          {
            id: 'adding-a-connection',
            heading: 'Adding a connection',
            blocks: [
              {
                type: 'paragraph',
                text: 'Click Add Connection, name the provider (e.g. “Microsoft Entra ID”), and pick a protocol — SAML or OIDC. Each protocol asks for what it actually needs:',
              },
              {
                type: 'list',
                items: [
                  'SAML — Entity ID, SSO URL, the identity provider’s X.509 certificate (PEM), and the NameID format.',
                  'OIDC — Issuer, Authorization URL, Token URL, Client ID, Client Secret, and scopes (defaults to openid email profile).',
                ],
              },
            ],
          },
          {
            id: 'managing-connections',
            heading: 'Managing connections',
            blocks: [
              {
                type: 'paragraph',
                text: 'A new connection is active straight away. Existing connections can be disabled or removed from the same list at any time — disabling one removes its button from the sign-in page.',
              },
            ],
          },
          {
            id: 'on-the-sign-in-page',
            heading: 'On the sign-in page',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each active connection appears on the tenant’s sign-in page as a “Sign in with {provider name}” button, as long as its protocol (SAML federation or OIDC federation) is switched on under Settings → Sign-in → Ways in — see Single sign-on (SSO) for the full set-up.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'scim-provisioning',
        title: 'SCIM provisioning',
        lastUpdated: '2026-10-09',
        intro:
          'SCIM lets an external identity provider create, update, and deactivate a tenant’s users automatically, instead of managing them by hand in ianua.',
        sections: [
          {
            id: 'enabling-it',
            heading: 'Enabling it',
            blocks: [
              {
                type: 'paragraph',
                text: 'To turn it on:',
              },
              {
                type: 'steps',
                items: [
                  'Open the tenant and go to Connections.',
                  'In the SCIM Provisioning card, click Enable SCIM.',
                  'Copy the bearer token shown — it appears only once.',
                  'In your identity provider, enter the SCIM base path shown on the card and paste the token as its credential.',
                ],
              },
              {
                type: 'paragraph',
                text: 'The bearer token is what the identity provider authenticates with when it calls ianua’s SCIM endpoint.',
              },
            ],
          },
          {
            id: 'scim-settings',
            heading: 'Settings and status',
            blocks: [
              {
                type: 'paragraph',
                text: 'Once enabled, the card shows the SCIM base path to give your identity provider and when it last made contact (or that it hasn’t connected yet), plus a few settings:',
              },
              {
                type: 'list',
                items: [
                  'Default role — every user your identity provider creates gets this role, on top of the tenant’s default roles.',
                  'Activate new users straight away (on by default) — when off, new users first confirm their email address.',
                  'Deactivate instead of deleting (on by default) — when your identity provider removes someone, keep their account switched off rather than deleting it.',
                ],
              },
              {
                type: 'paragraph',
                text: 'The full SCIM base URL is your API’s address followed by the path on the card. ianua supports users and groups, filtering by userName and displayName, and both full replacement and partial updates. When your identity provider switches a user off, ianua locks the account and ends its sessions; switching them back on unlocks it.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'The SCIM token can create, change and remove every user and group in the tenant. Treat it like an administrator’s password: keep it only in your identity provider. Rotating it makes the old token stop working immediately.',
              },
            ],
          },
          {
            id: 'rotating-the-token',
            heading: 'Rotating the token',
            blocks: [
              {
                type: 'paragraph',
                text: 'Rotate the bearer token at any time if it may have leaked — the identity provider’s SCIM configuration will need the new value to keep syncing.',
              },
            ],
          },
          {
            id: 'disabling-it',
            heading: 'Disabling it',
            blocks: [
              {
                type: 'paragraph',
                text: 'Disable SCIM stops the identity provider from syncing further changes. Users already created by it remain in the tenant.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'ldap-certificates',
        title: 'LDAP certificates',
        lastUpdated: '2026-10-09',
        intro: 'Coming soon.',
        sections: [
          {
            id: 'coming-soon',
            heading: 'Coming soon',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'ianua includes an LDAP directory so older apps that only speak LDAP can look people up and check passwords, but managing it — including issuing the client certificates needed to change entries — isn’t available in the dashboard yet. SAML and OIDC connections, and SCIM provisioning, are the supported ways to integrate an external identity provider from the dashboard today.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'mutual-tls',
        title: 'Mutual TLS (mTLS)',
        lastUpdated: '2026-10-03',
        intro:
          'mTLS requires a caller to present a client certificate ianua trusts, on top of (or instead of) any other sign-in method — set per tenant from Settings → Security.',
        sections: [
          {
            id: 'the-mode',
            heading: 'The mode',
            blocks: [
              {
                type: 'list',
                items: [
                  'Disabled — no client certificate is requested.',
                  'Optional — a client certificate is accepted if presented, but not required.',
                  'Required — every request to a route with mTLS enabled must present a trusted client certificate.',
                ],
              },
            ],
          },
          {
            id: 'trusted-ca-certificates',
            heading: 'Trusted CA certificates',
            blocks: [
              {
                type: 'paragraph',
                text: 'Paste one or more full PEM-encoded CA certificates — any client certificate signed by one of them is trusted. A route also has to have mTLS enabled on its own service for this to apply to it; see Protecting your first route.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'data-classification',
        title: 'Data classification',
        lastUpdated: '2026-10-03',
        intro:
          'Classification rules strip, mask, or hash specific fields from proxied responses before they leave ianua — for data that shouldn’t pass through in the clear even to an authenticated, authorized caller.',
        sections: [
          {
            id: 'classifying-a-field',
            heading: 'Classifying a field',
            blocks: [
              {
                type: 'paragraph',
                text: 'Click Classify field and name the field using dot notation matching the shape of your JSON (e.g. user.ssn), a sensitivity level, and what to do with it:',
              },
              {
                type: 'list',
                items: [
                  'Public, Internal, Confidential, or Restricted — the sensitivity level.',
                  'Remove — the field is dropped from the response entirely.',
                  'Replace with a mask — the field stays, with its value replaced.',
                  'Replace with a hash — the same value always hashes the same way, so records still match without exposing the real value.',
                ],
              },
            ],
          },
          {
            id: 'removing-a-rule',
            heading: 'Removing a rule',
            blocks: [
              {
                type: 'paragraph',
                text: 'Removing a rule stops that field being redacted going forward — it has no effect on responses already sent.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'routing-and-proxy',
    title: 'Routing & Proxy',
    topics: [
      article({
        slug: 'services',
        title: 'Services',
        lastUpdated: '2026-10-12',
        intro:
          'A service is a backend. Address, timeout, and health checks live on it once, so every route that forwards to it shares the same definition instead of repeating those settings per route.',
        sections: [
          {
            id: 'creating-a-service',
            heading: 'Creating a service',
            blocks: [
              {
                type: 'paragraph',
                text: 'Give it a name and an upstream URL — the primary backend routes forward to — and a timeout in seconds for how long it will wait on that backend.',
              },
              {
                type: 'list',
                items: [
                  'Weighted backends — add extra backends beyond the primary one, each with its own URL and a weight, to split traffic for a canary rollout. The upstream URL takes part with a weight of 100; list it among the backends to give it a different weight.',
                  'Resolve backends from DNS — instead of a fixed address, give it a DNS name and a record type, and it re-resolves on a refresh interval you set, picking up new backends as they appear.',
                  'Expected audience — the JWT aud claim the upstream expects. A route that requires authentication is refused if its token’s audience doesn’t match this.',
                  'Sticky session — keep a caller’s requests landing on the same backend across a session rather than being load-balanced to a different one each time.',
                  'Probe backends for health — enable active health checking and give it a path to probe; a backend that fails its probe stops receiving traffic until it recovers.',
                  'Preserve host header — forward the original Host header to the backend instead of rewriting it to the backend’s own address.',
                  'Require client certificate (mTLS) — only forward requests that presented a trusted client certificate; configure the tenant’s trusted CA certificates under Settings › Security first.',
                ],
              },
            ],
          },
          {
            id: 'sign-in-on-this-app',
            heading: 'Sign-in on this app',
            blocks: [
              {
                type: 'paragraph',
                text: 'A saved service has a “Sign-in on this app” card. Turn on “Sign people in on this app’s domains” and the gateway answers sign-in, sign-up, second-factor, email-verification, and sign-out addresses on the app’s own domains, and sets the session cookie there. It needs an expected audience saved on the service first, since the session names it.',
              },
              {
                type: 'list',
                items: [
                  'Domains — verified domains that a route of this service answers on.',
                  'Address prefix — where the ready-made sign-in pages live (default /.ianua). Any address you move is served by your own app’s page instead.',
                  'After sign-in — where people land when they didn’t arrive from a page.',
                  'Signed-out visitors on a page that needs sign-in — answer 401, or send them to sign in.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A service that doesn’t host sign-in itself can accept sign-in from another service instead, in one of three ways: on the same domain as that service, on its own domain with its own cookie (the domains must be on the same site as the other service), or on its own domain using short-lived tokens that last 5 minutes and stop when the person signs out.',
              },
            ],
          },
          {
            id: 'services-and-routes',
            heading: 'Services and routes',
            blocks: [
              {
                type: 'paragraph',
                text: 'A service has no path or host of its own — it only exists so routes can point at it. Twenty routes forwarding to the same backend share one service, so a timeout or health-check change made here applies to all of them at once.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'pipelines',
        title: 'Pipelines',
        lastUpdated: '2026-10-03',
        intro:
          'A pipeline is a named, reusable chain of request-processing stages — WAF, rate limiting, and more — that a route can be pointed at. Build the chain once on the pipeline, then attach it to as many routes as need it.',
        sections: [
          {
            id: 'creating-a-pipeline',
            heading: 'Creating a pipeline',
            blocks: [
              {
                type: 'paragraph',
                text: 'Creating a pipeline only asks for a name. Stages are added afterward, from the pipeline’s own detail page.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'A stage takes effect within seconds of being added to an active pipeline that a route uses — there is no review step.',
              },
            ],
          },
          {
            id: 'stage-kinds',
            heading: 'Stage kinds',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each kind of stage can be added to a pipeline at most once. The kinds available:',
              },
              {
                type: 'list',
                items: [
                  'WAF — blocks requests that score at or above an anomaly threshold against a set of rule sets you choose, and rejects bodies over a configured size outright.',
                  'Rate limit — caps requests to a maximum count within a time window, keyed by caller IP address or another key.',
                  'Canary token — flags a request as compromised if it uses one of a list of decoy token values you supply.',
                  'Token rate limit — for LLM traffic, caps spend by token budget rather than request count, since one request can cost a thousand times another. Set a budget, a window, what to key it by, and which provider’s response shape to read token counts from — the wrong provider reads nothing. You can also choose whether an answer that reports no cost is charged, and if so how much.',
                  'GraphQL — caps query depth and a complexity score, with a configurable cost per complexity point so a flat query asking for thousands of fields is caught even though it isn’t deeply nested.',
                  'Request transform — set or remove request headers and query parameters before the backend sees them. A header value can reference a secret instead of being written in the clear.',
                  'Response transform — set or remove response headers and query parameters before the caller sees them.',
                  'Custom (WASM module) — upload a WebAssembly module to run your own logic in the pipeline, with its own timeout and memory limit; a module that runs past its timeout is killed and the request denied.',
                ],
              },
            ],
          },
          {
            id: 'attaching-a-pipeline',
            heading: 'Attaching a pipeline to a route',
            blocks: [
              {
                type: 'paragraph',
                text: 'A route points at a pipeline the same way it points at a service — pick it from the route’s own settings. Changing the pipeline’s stages changes behavior for every route attached to it.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'http-routes',
        title: 'HTTP routes',
        lastUpdated: '2026-10-12',
        intro:
          'A route matches incoming HTTP requests by path, host, and method, and decides what happens to them: which service forwards it, which pipeline processes it, and who’s allowed through.',
        sections: [
          {
            id: 'matching',
            heading: 'Matching a request',
            blocks: [
              {
                type: 'list',
                items: [
                  'Name and priority — priority breaks ties when more than one route could match the same request; routes are checked in priority order.',
                  'Path pattern — the path a request must match.',
                  'Hosts — all of the tenant’s domains, or specific ones. Only verified domains can be picked; add and verify one under Domains first.',
                  'Methods — which HTTP methods this route matches; leave unset to match any.',
                  'Path rewrite — rewrite the matched path before forwarding it to the backend.',
                ],
              },
            ],
          },
          {
            id: 'service-and-pipeline',
            heading: 'Service and pipeline',
            blocks: [
              {
                type: 'paragraph',
                text: 'Every route points at one service — the backend it forwards to — and one pipeline to process the request through first. There is no default pipeline: to change a live pipeline, build the replacement alongside it and move routes across. See Services and Pipelines.',
              },
            ],
          },
          {
            id: 'policy',
            heading: 'Who may call this route',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each route has one policy, chosen from:',
              },
              {
                type: 'list',
                items: [
                  'Public — no authentication required.',
                  'Authenticated — any signed-in caller with a valid token.',
                  'Require system permission — caller must hold at least one of the permissions you pick from the tenant’s permission catalog.',
                  'Require custom permission — caller must hold a permission you define ad hoc on the route, as a resource/action pair.',
                  'Require scope — caller’s token must carry a scope string (resource:action) you define ad hoc on the route.',
                ],
              },
              {
                type: 'paragraph',
                text: 'This is per-route authorization, separate from the tenant’s access policy rules — see Access policy for the rule engine that evaluates every request regardless of which route it hit.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'tcp-udp-routes',
        title: 'TCP & UDP routes',
        lastUpdated: '2026-10-03',
        intro:
          'A port forwards traffic that isn’t HTTP — a database, a message broker, SSH — with its own access rules and the same audit trail as everything else, by opening a listen port on the platform and forwarding it to one or more backends.',
        sections: [
          {
            id: 'protocols',
            heading: 'Protocols',
            blocks: [
              {
                type: 'list',
                items: [
                  'TCP — forwarded byte for byte. No handshake, so nothing identifies the caller but its address.',
                  'TLS (terminated here) — the handshake ends at ianua, so a client certificate can be verified. The only protocol that can require one.',
                  'TLS (passed through) — encryption stays end to end; only the server name is read in passing, since the certificate itself stays inside the tunnel.',
                  'UDP — datagrams, with no handshake and no connection, so every flow is judged on its address alone.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Protocol and listen port can’t be changed after a port is opened — either is a different socket. Open a new port and delete the old one instead.',
              },
            ],
          },
          {
            id: 'who-may-connect',
            heading: 'Who may connect',
            blocks: [
              {
                type: 'paragraph',
                text: 'Public, or require a client certificate. Requiring one is only possible on TLS (terminated here), since that’s the only protocol where the handshake is verified at the platform rather than passed through untouched.',
              },
            ],
          },
          {
            id: 'backends-and-names',
            heading: 'Backends and server names',
            blocks: [
              {
                type: 'list',
                items: [
                  'Backends — one or more host:port destinations, each with a weight, to split traffic across backends.',
                  'Server names — on a TLS protocol, optionally restrict the port to answering only specific server names (SNI) rather than every handshake it receives.',
                  'Connect timeout and idle timeout (seconds) — idle timeout also bounds how long a connection can outlive the decision that first allowed it; a silent connection is closed once it’s exceeded.',
                ],
              },
            ],
          },
        ],
      }),
      article({
        slug: 'access-policy',
        title: 'Access policy',
        lastUpdated: '2026-10-09',
        intro:
          'Every tenant has one access policy — an ordered set of rules, checked top to bottom, that decides what happens to a request regardless of which route it hit. The first rule that matches wins; nothing below it is checked.',
        sections: [
          {
            id: 'policy-status',
            heading: 'Draft, review, active, archived',
            blocks: [
              {
                type: 'paragraph',
                text: 'A policy moves through four statuses: Draft (being written, not deciding anything yet), Review (waiting to be looked over, still not deciding anything), Active (live — these rules decide every request), and Archived (retired — nothing is deciding requests).',
              },
              {
                type: 'list',
                items: [
                  'From Draft: send for review, or archive it.',
                  'From Review: make it live, or send it back to draft.',
                  'From Active: take it out of service (archive).',
                  'Archived is final — write a new policy to start again.',
                ],
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'Editing is closed while a policy is Active — these rules are deciding real requests. Take it out of service first to change them.',
              },
              {
                type: 'paragraph',
                text: 'Writing rules needs permission to update the policy; moving it between states needs permission to activate it, because putting rules in front of live traffic deserves more trust. Each move is recorded in the audit log, and the gateway picks up a change within about 5 seconds.',
              },
            ],
          },
          {
            id: 'rules',
            heading: 'Rules',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each rule has a name, a priority (lower is checked first), an on/off switch, a list of conditions that must all be true for the rule to match, and one action.',
              },
              {
                type: 'paragraph',
                text: 'Condition kinds: path starts with, path is exactly, holds a given role, does not hold a given role, country is in a list, country is not in a list, method is one of a list, risk is at least a threshold, device is trusted, device is not trusted, and is a sensitive action. A rule with no conditions listed matches every request.',
              },
              {
                type: 'paragraph',
                text: 'Action kinds: let it through (Allow); refuse it (Deny, with a reason shown to the caller); ask for more proof of identity (RequireAal — a password, a second factor, or a hardware key); require a bound token (RequireDpop); or let it through but record it (AuditOnly).',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'The gateway only knows a request’s path, method, the caller’s roles, and the country their address is in. It can’t tell whether a device is trusted, how risky a request is, or whether an action is sensitive — so conditions about those never match at the gateway, and neither does a country condition when the country can’t be told. Write rules about what it can see.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'The policy applies after a request has passed its route’s own policy. If the gateway can’t read the tenant’s policy, it refuses the request with 503 rather than guessing.',
              },
            ],
          },
          {
            id: 'default-action',
            heading: 'When no rule matches',
            blocks: [
              {
                type: 'paragraph',
                text: 'Set a fallback action for requests that don’t match any rule, from the same list of action kinds. Refusing by default is the safer posture: anything not explicitly allowed is turned away.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'ai-agents',
    title: 'AI Agents',
    topics: [
      article({
        slug: 'what-are-agents',
        title: 'What are agents',
        lastUpdated: '2026-10-03',
        intro:
          'An agent is a non-human identity inside a tenant — something that acts on its own, rather than a person signing in. Give it a name, a description, and an owner, and it starts out able to reach nothing until you give it a credential and some access.',
        sections: [
          {
            id: 'creating-an-agent',
            heading: 'Creating an agent',
            blocks: [
              {
                type: 'list',
                items: [
                  'Name and description — what it is and what it does.',
                  'Owner — you may own the agent yourself, or hand it to another agent in the tenant, so one agent can be responsible for another.',
                ],
              },
            ],
          },
          {
            id: 'a-new-agent-is-inert',
            heading: 'A new agent is inert',
            blocks: [
              {
                type: 'paragraph',
                text: 'A freshly created agent can authenticate nothing and reach nothing. Its detail page prompts you through the two steps that change that: give it an identity (register a credential’s public key, under Credentials & attestation), then give it access (a delegation, under Granting access). Both steps show as done once completed and the prompt stops appearing.',
              },
            ],
          },
          {
            id: 'status',
            heading: 'Status',
            blocks: [
              {
                type: 'paragraph',
                text: 'An agent is Active, Suspended, or Revoked — see Agent lifecycle for what each means and how to move between them.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'credentials-and-attestation',
        title: 'Credentials & attestation',
        lastUpdated: '2026-10-03',
        intro:
          'An agent proves its identity with a key pair it generates and holds, not a password. The agent keeps the private key; you register only the public half with ianua, so the private key never passes through the dashboard.',
        sections: [
          {
            id: 'creating-a-credential',
            heading: 'Creating a credential',
            blocks: [
              {
                type: 'paragraph',
                text: 'Generate a key pair wherever the agent runs, then register its public key:',
              },
              {
                type: 'steps',
                items: [
                  'Open the agent and go to Credentials.',
                  'Click Create credential.',
                  'Choose the algorithm, paste the PEM public key, and pick an expiry.',
                  'Click Create credential to save.',
                ],
              },
              {
                type: 'paragraph',
                text: 'The fields:',
              },
              {
                type: 'list',
                items: [
                  'Algorithm — EdDSA, ES256, or RS256: the algorithm of the key pair the agent generated.',
                  'Public key — paste the PEM public key.',
                  'Expiry — when the credential must be rotated by: the default (30 days), 7 days, or 90 days. 90 days is the longest.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Creating an agent no longer hands back a key. A new agent has no credential until you register one here.',
              },
            ],
          },
          {
            id: 'rotating-a-credential',
            heading: 'Rotating a credential',
            blocks: [
              {
                type: 'paragraph',
                text: 'Rotate replaces a credential with a new key the agent generated: choose the algorithm and paste the new public key. The old key keeps verifying during a grace period, so the agent can switch over without a gap.',
              },
            ],
          },
          {
            id: 'attestation-policy',
            heading: 'Attestation policy',
            blocks: [
              {
                type: 'paragraph',
                text: 'Beyond its key pair, an agent can also be required to prove where it’s running before it’s trusted — this is attestation. Choose one or more trusted methods: SPIFFE, AWS instance identity, GCP instance identity, or TPM. If no method is trusted, the agent cannot bootstrap.',
              },
              {
                type: 'paragraph',
                text: 'Re-attest every — how often a bootstrapped agent must prove its identity again (15 minutes up to 24 hours). After this interval, attestation goes stale and tokens are refused until it re-attests.',
              },
              {
                type: 'paragraph',
                text: 'Allowed origins — the accounts, projects, or workloads the agent may attest from, for example aws:<account>, gcp:<project>, spiffe://<trust domain>/<path>, or tpm:aik:<fingerprint>. An attestation from anywhere else is refused.',
              },
            ],
          },
          {
            id: 'require-re-attestation',
            heading: 'Requiring re-attestation on demand',
            blocks: [
              {
                type: 'paragraph',
                text: 'Independent of the schedule above, you can force re-attestation at any time: the agent is blocked at the proxy until it proves its identity through the bootstrap process again. Existing tokens stop being accepted on the next request, not when they expire.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'granting-access-delegations',
        title: 'Granting access (delegations)',
        lastUpdated: '2026-10-03',
        intro:
          'A delegation is what an agent may reach, for how long, and under what limits. An agent with no delegation can authenticate but can’t call anything — delegations are where real access is actually handed out.',
        sections: [
          {
            id: 'access-level-presets',
            heading: 'Access level presets',
            blocks: [
              {
                type: 'list',
                items: [
                  'Tight — short-lived (15 minutes), no further delegation, up to 100 requests/hour, with approval required for every action.',
                  'Standard — 1 hour, no further delegation, up to 500 requests/hour, no approval required. The default.',
                  'Broad — 1 hour, one level of further delegation allowed, no request limit, no approval required.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A preset only writes starting values for the fields below — nothing is hidden behind it, and every value it sets can be changed under Advanced settings.',
              },
            ],
          },
          {
            id: 'tools-and-permissions',
            heading: 'Tools & permissions',
            blocks: [
              {
                type: 'paragraph',
                text: 'Choose from the tenant’s registered tools and the API permissions you yourself hold — a delegation can never grant more than the person granting it has. Tools you haven’t registered yet won’t appear; register one under Tools first.',
              },
            ],
          },
          {
            id: 'apps',
            heading: 'Apps',
            blocks: [
              {
                type: 'paragraph',
                text: 'Choose which apps behind the gateway this agent may call. Only services that pin an expected audience are listed. Without an app here, the agent reaches no app that requires sign-in. The delegation’s details show the apps it covers.',
              },
            ],
          },
          {
            id: 'advanced-settings',
            heading: 'Advanced settings',
            blocks: [
              {
                type: 'list',
                items: [
                  'Purpose — written down, this is enforced: once set, anything off-purpose is refused even if it was granted above.',
                  'Name — an optional label for the grant itself.',
                  'Expires after — 10 minutes up to 1 hour.',
                  'Delegation depth — how many further hops this access can itself be re-delegated: 0 (cannot delegate further), 1, or 2 hops.',
                  'Request limit, per a time window (15 minutes, 1 hour, or 24 hours) — leave the limit blank for no cap.',
                  'Path restrictions — comma-separated path patterns this delegation is confined to.',
                  'Bound to task — ties the grant to a named task.',
                  'Agent must be the direct caller — requests must come directly from this agent, not forwarded through another.',
                  'Require approval for every action — each action pauses and waits for a human to approve it; see Agent runs & approvals.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Granting access needs a tenant signing key. If the tenant doesn’t have an active one yet, you’ll be prompted to create one before you can grant.',
              },
            ],
          },
          {
            id: 'resource-level-access',
            heading: 'Resource-level access',
            blocks: [
              {
                type: 'paragraph',
                text: 'Beyond tools and permissions, a delegation can also grant specific resources with a relation — Reader, Writer, Approver, or Owner — added or revoked one at a time without touching the rest of the grant.',
              },
            ],
          },
          {
            id: 'revoking',
            heading: 'Revoking',
            blocks: [
              {
                type: 'paragraph',
                text: 'Revoking a delegation takes effect immediately. A delegation also expires on its own once its TTL runs out, and shows as Expired rather than Active from that point.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'testing-access-live',
        title: 'Testing access live',
        lastUpdated: '2026-10-03',
        intro:
          'Two ways to check what an agent can actually do, before or after you’ve granted it anything.',
        sections: [
          {
            id: 'check-authorization',
            heading: 'Check authorization (test without sending)',
            blocks: [
              {
                type: 'paragraph',
                text: 'From the Access card, "Test without sending" asks whether a request would be allowed by the agent’s current delegations, without sending anything. Check either by capability (pick one from what the agent could be granted) or by request (an HTTP method and path). The result is a plain Allowed/Denied with a reason.',
              },
            ],
          },
          {
            id: 'try-it',
            heading: 'Try it (send a real request)',
            blocks: [
              {
                type: 'paragraph',
                text: 'Right after a delegation is granted, the confirmation dialog offers "Try it" — this sends one real request through the gateway using the token that was just minted, against a tenant domain you choose, a method, and a path. The response shows Allowed or Refused, the HTTP status, how long it took, the reason given, and the response body.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'This is the only way to find out whether a grant actually works as described — the refusals are often the more useful half, surfacing things like a tool outside the grant or a purpose the token didn’t declare.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'agent-runs-and-approvals',
        title: 'Agent runs & approvals',
        lastUpdated: '2026-10-31',
        intro:
          'A run dispatches an agent toward a goal and tracks its progress step by step, using a model provider and (optionally) a delegation that limits what it can touch along the way.',
        sections: [
          {
            id: 'starting-a-run',
            heading: 'Starting a run',
            blocks: [
              {
                type: 'list',
                items: [
                  'Goal — a plain description of what the run should accomplish.',
                  'Model provider — one of the tenant’s active model providers.',
                  'Delegation — controls which tools and resources this run can access; choose None to run without one.',
                  'Purpose — which action classes (Read, Write, Delete, Configure, Communicate, Financial, Admin) the run is allowed to perform at all.',
                  'Require approval for — a subset of the selected purpose classes that must pause for a human to approve each time, rather than running straight through.',
                  'Step limit — the maximum number of steps (1–20) before the run stops on its own.',
                ],
              },
            ],
          },
          {
            id: 'run-status',
            heading: 'Run status',
            blocks: [
              {
                type: 'list',
                items: [
                  'Running — in progress.',
                  'AwaitingApproval — paused on a step that needs a human decision.',
                  'Completed — finished successfully.',
                  'Failed — stopped on an error.',
                  'Halted — stopped, for example by hitting the step limit.',
                  'Canceled — stopped by a person.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A run’s trace shows each step: the tool called, its arguments, and the outcome — allowed, answered, or denied.',
              },
              {
                type: 'steps',
                items: [
                  'With permission to view agents, open your tenant, select an agent and open Runs.',
                  'Browse the newest runs first. Use Next page and Previous page to move through the list, or choose Rows per page to show 20, 50 or 100 runs.',
                  'Open a run’s actions and choose View trace. Its steps load when the trace opens. If loading fails, choose Try again.',
                ],
              },
            ],
          },
          {
            id: 'approvals',
            heading: 'Approvals',
            blocks: [
              {
                type: 'paragraph',
                text: 'When a run hits an action in one of its "require approval" classes, it pauses and the action shows up under Approvals, waiting for someone with permission to approve or deny it. Approving lets the run continue past that step; denying stops it there. An approval can also expire on its own before anyone reviews it.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'A delegation can also require approval for every action it’s used for, independent of any run — see Granting access (delegations).',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'agent-activity',
        title: 'Agent activity',
        lastUpdated: '2026-10-03',
        intro:
          'Each agent has its own activity feed — a chronological record of its actions, approvals, and authorization decisions — separate from the tenant-wide audit log.',
        sections: [
          {
            id: 'reading-the-feed',
            heading: 'Reading the feed',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each entry shows what happened and a short summary of the relevant details, with how long ago it occurred. Sort oldest or newest first.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'agent-lifecycle',
        title: 'Agent lifecycle',
        lastUpdated: '2026-10-03',
        intro:
          'An agent is Active, Suspended, or Revoked. The lifecycle actions on its Overview page move it between these states, or react to a possible compromise.',
        sections: [
          {
            id: 'suspend-and-resume',
            heading: 'Suspend and resume',
            blocks: [
              {
                type: 'paragraph',
                text: 'Suspend stops the agent acting immediately — any run in flight halts at its next step — but keeps its delegations and credentials intact. Resume reactivates it exactly as it was.',
              },
            ],
          },
          {
            id: 'stop-all-agents',
            heading: 'Stop all agents',
            blocks: [
              {
                type: 'paragraph',
                text: 'On the tenant’s Agents list, “Stop all agents” suspends every active agent in the tenant at once — their tokens are refused and their runs halt. Use it when you can’t tell which agent went wrong; you confirm by typing the tenant’s slug, then resume each agent once you know it’s safe.',
              },
            ],
          },
          {
            id: 'require-re-attestation',
            heading: 'Require re-attestation',
            blocks: [
              {
                type: 'paragraph',
                text: 'Blocks the agent at the proxy until it proves its identity again through the bootstrap process. Reversible by a successful bootstrap. Existing tokens stop being accepted on the next request, not when they expire.',
              },
            ],
          },
          {
            id: 'contain',
            heading: 'Contain',
            blocks: [
              {
                type: 'paragraph',
                text: 'The kill switch, for an agent that may be compromised. Containing an agent suspends it, revokes every credential it holds, and revokes its whole delegation subtree — including any task tokens minted from those delegations. See Blast radius for what that preview shows before you confirm.',
              },
            ],
          },
          {
            id: 'revoke',
            heading: 'Revoke',
            blocks: [
              {
                type: 'paragraph',
                text: 'Permanent — the agent can never act again and cannot be resumed. To pause an agent you intend to bring back later, suspend it instead of revoking it.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'Deleting an agent removes it and everything recorded against it, except its audit history — what it did stays answerable even after deletion. An agent must already be revoked before it can be deleted.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'blast-radius',
        title: 'Blast radius',
        lastUpdated: '2026-10-03',
        intro:
          'Before you contain an agent, a preview shows exactly what that action is about to tear down — so containment isn’t a step taken blind.',
        sections: [
          {
            id: 'what-it-shows',
            heading: 'What it shows',
            blocks: [
              {
                type: 'list',
                items: [
                  'delegation_count — how many delegations, including sub-delegations, will be revoked.',
                  'agent_count — how many other agents sit in the delegation subtree being torn down.',
                  'Credentials revoked — how many active credentials this agent holds that will be revoked.',
                ],
              },
              {
                type: 'paragraph',
                text: 'This preview appears in the confirmation dialog for the Contain action specifically — containment is the action that revokes a whole delegation subtree at once, so it’s the one action where seeing the scope first matters most.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'automation-and-integrations',
    title: 'Automation & Integrations',
    topics: [
      article({
        slug: 'workflows-and-runs',
        title: 'Workflows and runs',
        lastUpdated: '2026-11-09',
        intro:
          'A workflow does a job by itself: something starts it, then its steps run in order. The Workflows page shows every workflow and every run in the tenant.',
        sections: [
          {
            id: 'seeing-workflows',
            heading: 'Seeing workflows',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Open the tenant and go to Workflows, under Automation.',
                  'Search or pick a status to narrow the workflows on this page.',
                  'Open the tab Runs to see every run, newest first.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'If you can only approve steps, Workflows says so. You still decide approvals from the link you are sent.',
              },
            ],
          },
          {
            id: 'runs',
            heading: 'Starting and following a run',
            blocks: [
              {
                type: 'steps',
                items: [
                  'For a by-hand workflow that is on, open its menu and choose Start a run.',
                  'Give the data as JSON and say how sensitive it is, then press Start the run.',
                  'The run page updates by itself. Open a step to see what went in and came out.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Data above your clearance is hidden: a step then shows only how far it got and how sensitive it is.',
              },
              {
                type: 'paragraph',
                text: 'The person a run acted for can Cancel the run, and anyone with full control of workflows too. For a failed run or one that ran out of time, only that person can press Retry or Start again. Any approval is asked for again.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'building-a-workflow',
        title: 'Building a workflow',
        lastUpdated: '2026-11-09',
        intro:
          'The builder shows a workflow as a picture: what starts it, each step, and the arrows between them. You change it there and turn it on when it is ready.',
        sections: [
          {
            id: 'making-one',
            heading: 'Making a workflow',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Open the tenant and go to Workflows, under Automation, then press New workflow.',
                  'Press the card on the left to choose what starts it: a person, a schedule, something that happens in your company such as a user being added, an event from a connected service, a call from another system, or a change about to happen.',
                  'Press Add a step and pick a step. Steps of a service appear once the tenant has connected an account for it. Connect another service, at the end of the list, takes you to Connected accounts.',
                  'Fill in the step on the right. A field holds a typed value, or one piece of data from an earlier step through the braces beside its name. It cannot hold both at once.',
                  'Drag from the dot on the right of a step to another step to draw an arrow. Press the plus on a selected arrow to put a step on it.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Your changes save by themselves once a workflow has at least one finished step, and Save does it at once, even for a new workflow with only a name. It then appears in the Workflows list. A step that is not filled in yet stays in this browser tab and is marked as not saved yet. Moving a card only changes where it sits.',
              },
              {
                type: 'paragraph',
                text: 'A step with no arrow into it starts as soon as the workflow does. The arrow from the first card shows this.',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Steps opens a numbered list of every step, where you can pick, add, connect and remove steps with the keyboard. The builder needs a desktop-sized screen.',
              },
            ],
          },
          {
            id: 'turning-it-on',
            heading: 'Turning it on',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Press Turn on. The sheet lists what changes for the next run and what the workflow can touch.',
                  'Press Turn on in the sheet. The version on today keeps running until you do.',
                  'If it is refused, the sheet says why. Show the step takes you to the step, and Ask a person first adds an approval right before a risky step.',
                ],
              },
              {
                type: 'paragraph',
                text: 'To change a workflow that is on, press Start the next draft. Versions lists the latest versions, and each opens read only.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'You need the right to update workflows to change or turn on a draft, and the right to create them to start one. If someone else changes a draft you have open, the builder tells you, and lets you keep yours or take theirs.',
              },
            ],
          },
          {
            id: 'trying-it',
            heading: 'Trying it',
            blocks: [
              {
                type: 'steps',
                items: [
                  'In the builder, press Try it, give example data as JSON and say how sensitive it is.',
                  'Watch the steps colour in on the board. Press a step, then Result, to see what it did.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Nothing outside changes. A step that would change something answers at once with what it would have used, and an approval passes at once. A test needs the right to update and to run workflows, and every step must be finished.',
              },
            ],
          },
          {
            id: 'more-steps',
            heading: 'Loops, agents and checks',
            blocks: [
              {
                type: 'list',
                items: [
                  'Loop: pick a list, then press Add a step inside. Each item gets one pass. Steps inside read trigger.item and trigger.index.',
                  'Agent: pick the agent and provider, write the goal, and set Stop past and Ask a person past in units of your billing currency.',
                  "Ask a person: choose Also ask in Slack to post it in a channel. As a loop's first step it can ask once about the whole loop.",
                  'Guardrail: checks a text for personal data, tricks aimed at a model, or banned words.',
                  'Wait: for a time, or until working hours.',
                ],
              },
              {
                type: 'paragraph',
                text: "Lists such as channels or repositories fill themselves through the step's account. If a list cannot be read, you can type the value. For a Protected apps or data step, first open the route to workflows from its menu under Routes.",
              },
            ],
          },
          {
            id: 'sample-cases',
            heading: 'Sample cases',
            blocks: [
              {
                type: 'steps',
                items: [
                  'In the builder, press Sample cases.',
                  'Press Add a case, give it a name, example data and at least one check, then press Save sample cases.',
                  'Press Evaluate. Each case runs as a test and ends passed, failed or not run.',
                ],
              },
              {
                type: 'paragraph',
                text: 'With Must pass before turning on, the draft can only be turned on after an evaluation of exactly this draft passed.',
              },
            ],
          },
          {
            id: 'build-it-for-me',
            heading: 'Build it for me',
            blocks: [
              {
                type: 'paragraph',
                text: 'On an empty workflow, press Build it for me, say what should happen and press Propose steps, or use one of the examples. Choose which steps to keep. To extend a workflow, open a step and press Suggest next steps. It needs a connected model provider. A proposal only joins your draft when you keep it.',
              },
            ],
          },
          {
            id: 'on-hold',
            heading: 'When a workflow is on hold',
            blocks: [
              {
                type: 'paragraph',
                text: 'A workflow that is on starts nothing while an account it uses cannot be used any more. The builder says which account and why, with buttons to the accounts and to the next draft. A step whose account is gone still opens and says so.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'deciding-an-approval',
        title: 'Deciding an approval',
        lastUpdated: '2026-11-09',
        intro:
          'A workflow can stop and ask a person first. You decide on the page the Approve and Deny buttons in Slack open, or from Needs a decision on the run page.',
        sections: [
          {
            id: 'deciding',
            heading: 'Saying yes or no',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Follow the link. If you are signed out, sign in and you come back to the same page.',
                  'Read the data shown. Your yes counts only for exactly this data.',
                  'Press Approve or Deny. Deny ends the run.',
                ],
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'Before something high-risk, two different people must say yes, each with a fresh code from their own second factor. After the first yes the page says Yours is counted. If you have no second factor, add one in your account settings first.',
              },
            ],
          },
          {
            id: 'whole-loop',
            heading: 'A yes for a whole list',
            blocks: [
              {
                type: 'paragraph',
                text: 'Sometimes one yes covers every item in a list. Approve stays off until you have opened every page of items with Show the next items.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'connected-accounts',
        title: 'Connected accounts',
        lastUpdated: '2026-11-09',
        intro:
          'Workflows act on outside services through accounts you connect once. You need the right to connect accounts.',
        sections: [
          {
            id: 'connecting',
            heading: 'Connecting an account',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Open the tenant and go to Connected accounts, under Automation.',
                  'Press Connect an account and select a service from the list.',
                  'Give it a name and choose who may use it.',
                  'Paste its key and press Connect, or press Sign in to connect and finish at the service.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A key is checked with the service first. If the service refuses it, nothing is saved. A key is never shown again.',
              },
            ],
          },
          {
            id: 'changing',
            heading: 'Changing an account',
            blocks: [
              {
                type: 'paragraph',
                text: 'From a row’s menu you can Rename it or Turn it off. Only the owner can Replace the key, Limit what it may do, or Share with the tenant. A workflow that needs a turned-off account waits until a next version is turned on.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'sandboxes',
        title: 'Sandboxes',
        lastUpdated: '2026-11-09',
        intro:
          'A sandbox holds your own code, in Python or JavaScript, or your company’s own container image. A workflow can run a saved version of it, locked away from everything else.',
        sections: [
          {
            id: 'making-a-sandbox',
            heading: 'Making a sandbox',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Open the tenant and go to Sandboxes, under Automation.',
                  'Press Make a sandbox, give it a name and pick what it runs. What it runs never changes afterwards.',
                  'Open it and press New version.',
                ],
              },
            ],
          },
          {
            id: 'saving-a-version',
            heading: 'Saving a version',
            blocks: [
              {
                type: 'paragraph',
                text: 'Each save is a new version that never changes, so a workflow always runs what was reviewed. Write the code in the box, press Write it from words to have your model provider draft it, or choose Import from a repository to read a file through a GitHub or GitLab account.',
              },
              {
                type: 'list',
                items: [
                  'Packages — each at one exact version. A range is refused.',
                  'Runtime — the version keeps the exact image this is offered in now.',
                  'Longest run and Memory — from 1 to 300 seconds, and from 64 to 2048 MiB.',
                  'Hosts it may reach — exact names, at most 20. With none, the code reaches no network at all.',
                ],
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'A workflow needs an approval right before a code step whose version names hosts.',
              },
            ],
          },
          {
            id: 'trying-a-version',
            heading: 'Building and trying',
            blocks: [
              {
                type: 'paragraph',
                text: 'After saving, the version builds its packages and the page shows how that went. If a pinned package needs another one that is not pinned, press Pin in the next version. Once a version is Ready, give it sample input and press Try it. A failed trial offers Ask the model to fix it, which opens a new version with the proposed code. Nothing is saved until you save it. A trial is kept for a day.',
              },
            ],
          },
          {
            id: 'more-options',
            heading: 'Agents, repositories and company images',
            blocks: [
              {
                type: 'list',
                items: [
                  'Holds an agent — an agent does the work and your code checks each answer. A spending cap is required. Trying such a version runs only the check.',
                  'Send to a repository — copies a saved version’s code and pins to a folder on a branch that already exists. The version saved here stays the one that runs.',
                  'Company image — names your own container image. Its registry must be listed under Image registries, and it works only where this installation allows it.',
                ],
              },
              {
                type: 'paragraph',
                text: 'You need the right to create workflows to make a sandbox, to change them to save, try or send a version, and to delete them to archive one. Image registries need the right to connect accounts. An archived sandbox takes no new versions.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'memories',
        title: 'Memories',
        lastUpdated: '2026-11-09',
        intro: 'A memory is a named store of texts that workflow steps keep and search by meaning.',
        sections: [
          {
            id: 'making-a-memory',
            heading: 'Making a memory',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Open the tenant and go to Memories, under Automation.',
                  'Press Make a memory and give it a name.',
                  'Under Filled by, pick the platform’s embedding server or a model provider that offers an embedding model.',
                  'Say how sensitive its texts may be, then press Make memory.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'A memory keeps its embedding model. If that model is no longer offered, the memory keeps its texts and takes no new ones.',
              },
            ],
          },
          {
            id: 'deleting-a-memory',
            heading: 'Reading and deleting',
            blocks: [
              {
                type: 'paragraph',
                text: 'Open a memory to see its texts, oldest first. You need the right to delete workflows for this. Deleting asks you to type the memory’s name. It then waits 30 days, and Bring back restores it with every text until then.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'raising-a-risk',
        title: 'Raising a step’s risk',
        lastUpdated: '2026-11-09',
        intro:
          'You can treat a step of a service as riskier than the service says, so it needs a person’s yes right before it.',
        sections: [
          {
            id: 'raising',
            heading: 'Raising a risk',
            blocks: [
              {
                type: 'steps',
                items: [
                  'Open the tenant, go to Workflows and open the Risks tab.',
                  'Press Raise a risk, then pick the service, the step and what it counts as.',
                  'Press Raise risk.',
                ],
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'A published workflow using this step now fails at this step until an approval is added and it is republished.',
              },
              {
                type: 'paragraph',
                text: 'A raised risk only makes things stricter. You need the right to change workflows to raise or change one, and full control of workflows to remove one.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'flows',
        title: 'Flows',
        lastUpdated: '2026-10-03',
        intro:
          'A flow is a multi-stage workflow built from agent nodes. Each stage runs after the one before it; a flow runs within whatever authority is already delegated to the agents inside it — it grants nothing of its own.',
        sections: [
          {
            id: 'stages-and-nodes',
            heading: 'Stages and nodes',
            blocks: [
              {
                type: 'paragraph',
                text: 'A flow is built as an ordered list of stages, each containing one or more nodes. Add a stage, then add nodes to it; nodes within the same stage can be reordered by dragging.',
              },
              {
                type: 'list',
                items: [
                  'Agent — which agent runs this node. It acts under its own delegations; the flow itself grants nothing.',
                  'Model provider — which connected provider it uses.',
                  'Goal — a plain description of what this node should accomplish.',
                  'Purpose — which action classes the node may perform at all; anything outside the selected classes is blocked.',
                  'Require approval for — a subset of the selected purpose classes that pause for a human to approve.',
                  'Tools — specific tools this node may call; leave empty to allow all tools within its purpose.',
                  'Step cap — maximum steps (1–20) before the node stops.',
                ],
              },
            ],
          },
          {
            id: 'running-a-flow',
            heading: 'Running a flow',
            blocks: [
              {
                type: 'paragraph',
                text: 'Once created, a flow can be started, canceled, or deleted from its detail page, which shows a timeline of each stage’s progress.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'tools',
        title: 'Tools',
        lastUpdated: '2026-10-03',
        intro:
          'A tool is an API endpoint registered so agents can call it by name. Registering a tool is what makes it offerable in a delegation or a flow node — nothing can call an endpoint that hasn’t been registered here.',
        sections: [
          {
            id: 'registering-a-tool',
            heading: 'Registering a tool',
            blocks: [
              {
                type: 'list',
                items: [
                  'Tool name — the name agents use to call it.',
                  'Description — what the tool does, shown to the model.',
                  'Method and path pattern — e.g. GET /orders/{id}.',
                  'Action class — Read, Write, Delete, Configure, Communicate, Financial, or Admin. Financial, Delete, and Admin actions require approval whenever they’re granted to an agent through a delegation.',
                  'Data class — how sensitive the data behind it is; a run that has already read more sensitive data than this tool is classified for can’t call it. Mark anything that publishes outside the tenant as Public.',
                  'Input JSON schema — describes the arguments the tool accepts.',
                ],
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'An “Add examples” shortcut registers a small set of example tools for trying the system out, skipping any that are already registered.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'model-providers',
        title: 'Model providers',
        lastUpdated: '2026-11-09',
        intro:
          'A model provider is a connection to a hosted or self-hosted LLM endpoint that agents and flow nodes draw on.',
        sections: [
          {
            id: 'connecting-a-provider',
            heading: 'Connecting a provider',
            blocks: [
              {
                type: 'list',
                items: [
                  'Name — a label, e.g. “Production OpenAI”.',
                  'Kind and model — the provider type and the specific model to use.',
                  'Endpoint — the API endpoint to call.',
                  'API key (optional) — leave blank if the endpoint doesn’t require authentication. Keys are encrypted and can’t be viewed again after saving.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A provider can be tested on demand to confirm ianua can reach it, and only providers in an Active state appear as choices when starting a run or building a flow node.',
              },
              {
                type: 'paragraph',
                text: 'To fill memories through a provider, choose Embedding model from its menu and name the model. Anthropic has no embeddings, so this is not offered there. A memory filled with another model stops taking new texts.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'oauth-clients',
        title: 'OAuth clients',
        lastUpdated: '2026-10-03',
        intro:
          'An OAuth client lets an external application authenticate end users against this tenant through a standard OAuth redirect flow.',
        sections: [
          {
            id: 'creating-a-client',
            heading: 'Creating a client',
            blocks: [
              {
                type: 'list',
                items: [
                  'Name — identifies the application.',
                  'Redirect URLs — one HTTPS URL per line; only these URLs may be redirected to after sign-in.',
                ],
              },
              {
                type: 'paragraph',
                text: 'A client secret is issued once, at creation, and shown only that one time. Revoking a client immediately invalidates it.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'tenant-api-keys',
        title: 'Tenant API keys',
        lastUpdated: '2026-10-03',
        intro:
          'A tenant API key authenticates a script, CI pipeline, or external service calling the tenant’s management API directly — distinct from an agent credential, which authenticates an agent at the proxy.',
        sections: [
          {
            id: 'creating-a-key',
            heading: 'Creating a key',
            blocks: [
              {
                type: 'paragraph',
                text: 'Give it a name and pick its scopes from your own permissions — a key can do only what you pick, never more than you yourself can do. Keys use the ik_live_ prefix so they’re recognizable to secret-scanning tools.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'The key value is shown once, at creation, and can’t be retrieved again. Revoke a key immediately if it’s exposed.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'webhooks-and-event-streams',
        title: 'Webhooks & event streams',
        lastUpdated: '2026-10-03',
        intro: 'Coming soon.',
        sections: [
          {
            id: 'coming-soon',
            heading: 'Coming soon',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'Outbound webhooks and event streams aren’t available yet. For now, the audit log and the agent activity feed are the way to see what happened after the fact; there’s no way to have ianua push events to an external endpoint in real time.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'crypto-and-signing-keys',
    title: 'Crypto & Signing Keys',
    topics: [
      article({
        slug: 'tenant-signing-keys',
        title: 'Tenant signing keys',
        lastUpdated: '2026-10-03',
        intro:
          'A tenant’s signing keys sign the tokens it issues and verify the tokens it receives. Granting a delegation to an agent, for instance, needs an active signing key to be in place first.',
        sections: [
          {
            id: 'rotating-a-key',
            heading: 'Rotating a key',
            blocks: [
              {
                type: 'paragraph',
                text: 'Rotating creates a new active key, with a chosen algorithm (RS256, ES256, or EdDSA), and marks the current active key as rotated rather than deleting it — tokens already signed with the old key keep verifying.',
              },
            ],
          },
          {
            id: 'revoking-a-key',
            heading: 'Revoking a key',
            blocks: [
              {
                type: 'paragraph',
                text: 'Revoking a key removes it from circulation. Tokens signed with a revoked key stop verifying — this is a harder break than rotation, since rotation keeps the old key valid for verification.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'jwks-endpoint',
        title: 'The JWKS endpoint',
        lastUpdated: '2026-10-03',
        intro:
          'The JWKS (JSON Web Key Set) view lists the tenant’s public signing keys — what relying parties fetch to verify tokens this tenant issues. Only public key material is ever shown or published here.',
        sections: [
          {
            id: 'reading-it',
            heading: 'Reading it',
            blocks: [
              {
                type: 'paragraph',
                text: 'The JWKS view is read-only: it mirrors whatever keys exist from Tenant signing keys and their rotation/migration state, and updates automatically as keys rotate, migrate, or get revoked.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'key-rotation-and-migration',
        title: 'Key rotation & migration',
        lastUpdated: '2026-10-03',
        intro:
          'Migration changes the tenant’s signing algorithm (say, RS256 to ES256) without interrupting token verification along the way — a bigger change than a same-algorithm rotation, handled as its own tracked process.',
        sections: [
          {
            id: 'planning-a-migration',
            heading: 'Planning a migration',
            blocks: [
              {
                type: 'paragraph',
                text: 'Plan a migration by choosing a target algorithm different from the current active key’s algorithm. This creates a migration record showing the source and target algorithms and key IDs, and its status.',
              },
            ],
          },
          {
            id: 'migration-status-and-actions',
            heading: 'Status and actions',
            blocks: [
              {
                type: 'list',
                items: [
                  'Planned — can be started, or canceled before it begins.',
                  'InProgress — can be rolled back, or promoted (make the new key active).',
                  'Validating — can be rolled back, or completed.',
                ],
              },
              {
                type: 'paragraph',
                text: 'Rolling back requires a reason, recorded for the audit trail — e.g. “Validation failed in downstream service.”',
              },
              {
                type: 'callout',
                tone: 'info',
                text: 'Only one migration can be active on a tenant at a time; starting a new one isn’t possible until the current migration is completed, canceled, or rolled back.',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'monitoring-and-troubleshooting',
    title: 'Monitoring & Troubleshooting',
    topics: [
      article({
        slug: 'metrics-dashboard',
        title: 'Metrics dashboard',
        lastUpdated: '2026-10-03',
        intro:
          'The organization and tenant Overview pages show usage and authentication metrics over a chosen window, so you can see what’s happening without digging through the audit log.',
        sections: [
          {
            id: 'what-it-shows',
            heading: 'What it shows',
            blocks: [
              {
                type: 'list',
                items: [
                  'Total users, active users, and active sessions, each with a trend against the previous period.',
                  'API requests, authentication success rate, and failed login attempts.',
                  'Average authentication time, last login, and an overall health score.',
                ],
              },
            ],
          },
          {
            id: 'time-window',
            heading: 'Time window',
            blocks: [
              {
                type: 'paragraph',
                text: 'Switch between Daily (today) and Monthly (a rolling window of recent days) — every metric and trend on the page recalculates for the selected window.',
              },
            ],
          },
          {
            id: 'permissions',
            heading: 'Permissions',
            blocks: [
              {
                type: 'paragraph',
                text: 'Viewing metrics requires the Metrics permission. Without it, the page still shows the tenant’s basic identity, just none of the numbers.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'notifications',
        title: 'Notifications',
        lastUpdated: '2026-10-03',
        intro:
          'Notifications tell you about activity in your organization or tenant — a running count badge appears in the sidebar, and the Notifications page lists them in full.',
        sections: [
          {
            id: 'reading-notifications',
            heading: 'Reading notifications',
            blocks: [
              {
                type: 'paragraph',
                text: 'Filter to All or Unread. Clicking an unread notification marks it read; "Mark all as read" clears every unread one at once. The sidebar badge updates automatically as new notifications arrive.',
              },
            ],
          },
          {
            id: 'scope',
            heading: 'Scope',
            blocks: [
              {
                type: 'paragraph',
                text: 'Notifications are scoped to whatever you’re currently viewing — organization-level notifications at the organization level, tenant-level notifications when you’re inside a specific tenant.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'common-errors',
        title: 'Common errors & status codes',
        lastUpdated: '2026-10-03',
        intro:
          'Most errors in the dashboard show up as a plain-language message pulled straight from the API’s response — this article covers how to read them, not a fixed list of codes.',
        sections: [
          {
            id: 'session-expired',
            heading: 'Signed out unexpectedly',
            blocks: [
              {
                type: 'paragraph',
                text: 'If a request comes back unauthorized and retrying it once still fails, the dashboard signs you out and sends you to the login page automatically — this is usually just an expired session, not a sign of a broken account.',
              },
            ],
          },
          {
            id: 'permission-errors',
            heading: '“You don’t have permission to…”',
            blocks: [
              {
                type: 'paragraph',
                text: 'Many actions and even whole sections check your permissions before you ever click anything, and hide or disable themselves if you don’t hold the right one — rather than letting you attempt it and fail. Seeing this message means your role doesn’t include that permission; ask an owner or admin to grant it if you need it.',
              },
            ],
          },
          {
            id: 'reading-error-messages',
            heading: 'Reading an error message',
            blocks: [
              {
                type: 'paragraph',
                text: 'When an action fails, the notification that appears is the message the API itself returned, not a generic dashboard string — so it usually names the specific thing that was wrong (a missing field, a conflicting value, a grant that doesn’t cover what you tried). If no specific message comes back, the dashboard falls back to a generic “failed, please try again.”',
              },
            ],
          },
        ],
      }),
    ],
  },
  {
    slug: 'account-settings',
    title: 'Account Settings',
    topics: [
      article({
        slug: 'your-profile-and-security',
        title: 'Your profile & security',
        lastUpdated: '2026-10-03',
        intro:
          'Your own account settings — name, email, password, and the ways you can prove it’s you — live under Account Settings, separate from anything tenant-specific.',
        sections: [
          {
            id: 'profile',
            heading: 'Profile',
            blocks: [
              {
                type: 'paragraph',
                text: 'Update your display name directly. Changing your email instead sends a confirmation link to the new address — the change doesn’t take effect until you click it, and resending is rate-limited.',
              },
            ],
          },
          {
            id: 'password',
            heading: 'Password',
            blocks: [
              {
                type: 'paragraph',
                text: 'Change your password by entering your current one plus a new one meeting your organization’s password policy.',
              },
            ],
          },
          {
            id: 'mfa-and-passkeys',
            heading: 'Two-factor authentication & passkeys',
            blocks: [
              {
                type: 'list',
                items: [
                  'Two-factor authentication (TOTP) — enable by scanning a QR code into an authenticator app and confirming a code; disabling asks for confirmation.',
                  'Passkeys — add one via your device or browser’s passkey flow, then name it so you can recognize it later; rename or remove any passkey individually.',
                ],
              },
            ],
          },
          {
            id: 'trusted-devices',
            heading: 'Trusted devices',
            blocks: [
              {
                type: 'paragraph',
                text: 'Lists devices that have signed in as you. Revoke any device you don’t recognize or no longer use — this signs that device out.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'notification-preferences',
        title: 'Notification preferences',
        lastUpdated: '2026-10-03',
        intro: 'Coming soon.',
        sections: [
          {
            id: 'coming-soon',
            heading: 'Coming soon',
            blocks: [
              {
                type: 'callout',
                tone: 'info',
                text: 'There’s no separate notification preferences page yet — notifications aren’t configurable per channel or event type. What you get today is the in-app Notifications list and sidebar badge described under Monitoring & Troubleshooting.',
              },
            ],
          },
        ],
      }),
      article({
        slug: 'personal-api-keys',
        title: 'Personal API keys',
        lastUpdated: '2026-10-03',
        intro:
          'An organization-level API key for your own account, for scripts and automation acting as you — distinct from a tenant API key, which is scoped to one tenant.',
        sections: [
          {
            id: 'creating-a-key',
            heading: 'Creating a key',
            blocks: [
              {
                type: 'paragraph',
                text: 'Give it a name and pick its scopes from your own permissions — the key can do only what you pick, never more than you yourself can do. These keys use the oak_ prefix, distinct from a tenant key’s ik_live_ prefix, so both are recognizable to secret-scanning tools.',
              },
              {
                type: 'callout',
                tone: 'warning',
                text: 'The key value is shown once, at creation, and can’t be retrieved again. Revoke a key immediately if it’s exposed.',
              },
            ],
          },
        ],
      }),
    ],
  },
];
