---
name: dashboard-review-change
description: Review a change in the ianua dashboard before it is committed or opened as a pull request - check it against the project's rules (API layer, both tenant route trees, permissions, errors and toasts, icons, docs, Help Center) and run lint, type-check and format. Use when the user asks for a review, a pre-PR check, or "is this ready".
---

# Review a change

Review what changed, not the whole codebase. Report findings; fix them only if the user asks.

## 1. Collect the change

- Working tree: `git diff --ignore-cr-at-eol HEAD` and new files from `git ls-files --others --exclude-standard`.
- A branch: `git diff --ignore-cr-at-eol main...HEAD`.
- Ignore files that differ only in line endings.

## 2. Check against the project rules

**API layer**

- [ ] Every backend call is a typed function in `dashboard/src/lib/api/services`, exported from `dashboard/src/lib/api/index.ts`. No `fetch` or `apiClient` in components.
- [ ] Every method a service uses has a proxy route in `dashboard/src/app/api` (a missing one returns Next's HTML 404). Field names match the backend spec (`dashboard-add-api-endpoint` skill, step 0).

**Tenant screens**

- [ ] Works under both `/tenants/{tenant}/…` and `/organizations/{org}/tenants/{tenant}/…`: `useTenantRouteParams()`, `getTenantScopedPath`, page files in both trees. No hardcoded paths.
- [ ] Buttons and actions gated with `useTenantPermissions()` (`hasPermission` / `canView`); organization-only actions with `useOrgAccess()`. New sections mapped in `dashboard/src/utils/tenant-section-permissions.ts`.

**UI patterns**

- [ ] Tables use `DashboardDataCard` + `DashboardTableShell`; row menus use `DashboardActionsMenu` inside `DashboardTableActionsCell`, and the row has the `group` class.
- [ ] Mutation errors go through `getApiErrorMessage` into a `useNotification` toast; success shows a toast and invalidates the affected queries (and `invalidateAuditLogQueries`).
- [ ] Forms use React Hook Form with a Zod schema from `dashboard/src/schemas`. Types in `dashboard/src/types`, constants in `dashboard/src/constants`, pure helpers in `dashboard/src/utils`, not inline in components.
- [ ] Icon-only buttons have `aria-label` and a tooltip. Every new icon name is in `ICON_NAMES` (`dashboard-add-icon` skill).
- [ ] Classes merged with `cn()`; design tokens (`bg-cardBg`, `text-textGray`, `border-borderGray`) rather than raw colours.

**Docs and Help Center**

- [ ] Matching `docs/src/content/docs/dashboard/` updated (`dashboard-sync-docs` skill), including new components.
- [ ] Help Center updated for anything users see or can do (`dashboard-help-center-article` skill).

**Safety**

- [ ] No secrets, tokens or `.env*` content. No `console.log`. No new `eslint-disable` without a reason in a comment.

## 3. Run the checks

`npm run lint`, `npm run type-check`, `npm run format:check`. Report the real results; if a command could not run, say so.

## 4. Report

Group findings as **must fix**, **should fix** and **nice to have**, each with file and line. End with a suggested commit message in the project's lowercase conventional style, for example `feat(users): add manage fields popover`.
