---
name: dashboard-add-tenant-screen
description: Add a new section (sidebar entry plus page) inside a tenant in the ianua dashboard, wired for both route trees, with permission gating and the standard card, table, actions menu and modal pattern. Use when adding a tenant-level screen such as Groups, Roles or Domains.
---

# Add a tenant screen

A tenant section is reachable through two URL trees that share one page component:

- `/tenants/{tenant}/<section>` - organization session (Owners and Members).
- `/organizations/{org}/tenants/{tenant}/<section>` - tenant session.

Reference implementation: Groups. See `dashboard/src/components/dashboard/tenant-detail/sections/groups-card.tsx` and the `groups/` folder beside it.

## Steps

1. **Backend access first.** If the screen needs new endpoints, run the `dashboard-add-api-endpoint` skill.
2. **Card component** `dashboard/src/components/dashboard/tenant-detail/sections/<name>-card.tsx`, with helpers in a `<name>/` folder (`<name>-table.tsx`, `<name>-actions-menu.tsx`, `<name>-form-modal.tsx`). Build it like `GroupsCard`:
   - `useTenantRouteParams()` for `orgSlug` and `tenantSlug`, never from the URL by hand.
   - `useTenantPermissions()` and `hasPermission(resource, action)` for each button (create, update, delete). Pass `undefined` as `onActionClick` when the user may not create.
   - `useTableQueryState<SortField>()` for page, size and sort. `useQuery` for data.
   - `DashboardDataCard` with `DashboardPagination` as its footer, and the table inside.
   - Row actions through `DashboardActionsMenu`. Create and edit through `Modal` with React Hook Form and a Zod schema. Delete through a confirm `Modal`.
   - `deriveErrorMessage` for the load error, `getApiErrorMessage` for mutation errors, `useNotification` toasts, then invalidate the list and the audit log.
3. **Page routes**: create `page.tsx` in both trees. Each is one line:
   `export { default } from '@/app/(dashboard)/tenants/[tenantSlug]/page';`
   - `dashboard/src/app/(dashboard)/tenants/[tenantSlug]/<section>/page.tsx`
   - `dashboard/src/app/(dashboard)/organizations/[orgSlug]/tenants/[tenantSlug]/<section>/page.tsx`
4. **Register in `dashboard/src/app/(dashboard)/tenants/[tenantSlug]/page.tsx`**, all three places:
   - `tenantSections` (label to card component),
   - `tenantSectionIcons` (label to Material Symbol),
   - the `pathname.endsWith('/<section>')` chain that picks the initial section.
5. **Add the nav item** in `getTenantNavItemsByBasePath` in `dashboard/src/utils/dashboard-nav.ts` (`href`, `label`, `icon`, `activeMatch: 'nested'`, and a `group` such as `Infrastructure` or `Agents` if it belongs to one). The label must match the label used in step 4.
6. **Gate the section** in `dashboard/src/utils/tenant-section-permissions.ts`: add `'<section>': '<Resource>'` to `tenantSectionResource`, using an existing `TenantPermissionResource` from `dashboard/src/types/permission.ts`. Without this the sidebar item shows for users who cannot use it.
7. **Icon**: add any new Material Symbols name to `ICON_NAMES` in `dashboard/src/constants/icon-names.ts`. `dashboard/scripts/build-icons.mjs` only warns about an unregistered icon, and the icon then does not render. Run `npm run build-icons` (needs network) to regenerate the font subset.
8. **Detail pages** (a screen that opens a single item, like a domain or pipeline) are separate routes with their own `use-<x>-route-params` hook. Copy the Domains or Pipelines pattern instead of nesting inside the card.
9. **Docs**: add the component rows to the matching file in `docs/components/` (`tenant.md`, `tenant-infrastructure.md` or `tenant-agents.md`), update `docs/src/content/docs/dashboard/routing.mdx`, and update the Help Center in `dashboard/src/constants` for what users can now do.

## Check before finishing

- Both route trees open the screen, and links inside it use `getTenantScopedPath` so they stay in the current tree.
- A user without the resource permission does not see the sidebar item or the action buttons.
- `npm run lint`, `npm run type-check`, `npm run format:check`.
