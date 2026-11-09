---
name: dashboard-sync-docs
description: Bring the ianua dashboard's developer docs (docs/src/content/docs/dashboard/) and Help Center back in step with the code after a change - find what changed, map it to the right doc sections, and update them from the code. Use after implementing a feature, after pulling others' commits, or when the user asks whether docs are up to date.
---

# Sync docs with code

Two sets of docs must follow the code:

- **Developer docs** in `docs/src/content/docs/dashboard/` (index: `docs/src/content/docs/dashboard/`).
- **Help Center** for end users in `dashboard/src/constants/help-center.ts` (see the `dashboard-help-center-article` skill).

## Steps

1. **List what changed.** For your own work: `git diff --ignore-cr-at-eol --stat HEAD` plus new files from `git ls-files --others --exclude-standard`. For pulled commits: `git log --stat <from>..<to>`. Ignore files that differ only in line endings.
2. **Map each change to a doc:**

   | Changed                                                                                    | Update                                     |
   | ------------------------------------------------------------------------------------------ | ------------------------------------------ |
   | `dashboard/src/components/ui/*`                                                                      | `docs/src/content/docs/dashboard/components/ui.mdx`                    |
   | `dashboard/src/components/landing`, `legal`, `help-center`, `auth`                                   | `docs/src/content/docs/dashboard/components/public-site.mdx`           |
   | `dashboard/src/components/dashboard/*.tsx`, `shared`, `overview`, `team`, `tenants`, `notifications` | `docs/src/content/docs/dashboard/components/dashboard-shell.mdx`       |
   | `dashboard/src/components/dashboard/settings`                                                        | `docs/src/content/docs/dashboard/components/organization-settings.mdx` |
   | tenant users, roles, groups, fields, connections, policy, tenant settings, page shells     | `docs/src/content/docs/dashboard/components/tenant.mdx`                |
   | domains, API keys, OAuth clients, signals, services, routes, pipelines, crypto             | `docs/src/content/docs/dashboard/components/tenant-infrastructure.mdx` |
   | agents, delegations, approvals, runs, credentials, flows, tools, model providers           | `docs/src/content/docs/dashboard/components/tenant-agents.mdx`         |
   | `dashboard/src/app/**/page.tsx`, new URLs                                                            | `docs/src/content/docs/dashboard/routing.mdx`                          |
   | `dashboard/src/hooks`, `dashboard/src/store`                                                                   | `docs/src/content/docs/dashboard/state-and-hooks.mdx`                  |
   | `dashboard/src/lib/api`, `dashboard/src/app/api`                                                               | `docs/src/content/docs/dashboard/api-layer.mdx`                        |
   | permissions, sessions, sign-in                                                             | `docs/src/content/docs/dashboard/auth-and-permissions.mdx`             |
   | `dashboard/src/utils`, `dashboard/src/constants`, `dashboard/src/schemas`, `dashboard/src/types`, scripts, Docker, CI              | `docs/src/content/docs/dashboard/reference.mdx`                        |
   | anything users see or can do                                                               | Help Center                                |

3. **Update from the code, not from the diff alone.** Open the component and describe what it does now: one row per component (name, file, what it does). Add rows for new components, fix rows for changed ones, remove rows for deleted ones.
4. **Coverage check** (every component file named in a component doc):
   ```bash
   for f in $(find dashboard/src/components -name '*.tsx' -o -name '*.ts'); do
     grep -rqF "$(basename "$f")" docs/components || echo "undocumented: $f"
   done
   ```
5. **Help Center**: if user-visible labels, steps or behaviour changed, search `help-center.ts` for the old wording and fix every article that mentions it.
6. Format: `npx prettier --write docs` and the Help Center file.

## Report

End with a short list: docs updated, Help Center articles updated, and anything you left unchanged on purpose (for example an internal refactor with no visible effect).
