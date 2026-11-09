## What this changes

<!-- In a few sentences: what it does and why. Link the issue if there is one: "Closes #123". -->

## How it was checked

<!-- The tests you added or ran, and anything you tried by hand. For the dashboard, say which session type you tested: organization, tenant, or both. -->

## Screenshots

<!-- For visible dashboard changes: before and after. Delete this section otherwise. -->

## AI use

<!-- Did you use an AI tool? For what? For example: "none", or "tests drafted with an assistant, then read and corrected by hand". See docs: Contributing > Using AI in your contributions. -->

## Checklist

- [ ] I understand every line of this change and can explain why it is safe.
- [ ] I said above whether and how I used AI.
- [ ] It adds tests, including cases where a request is refused if it touches signing in, permissions, tokens, tenant separation, the gateway's headers or the audit log.
- [ ] I did not delete, loosen or switch off a test, lint or convention check to make this pass.
- [ ] No secrets, keys or real user data are in this change, or were pasted into any tool while making it.
- [ ] The docs (`docs/`) are updated for anything a reader would notice.

**If it changes the dashboard (`dashboard/`):**

- [ ] `npm run lint`, `npm run type-check` and `npm run format:check` pass.
- [ ] Backend calls go through a service in `src/lib/api/services` and a proxy route in `src/app/api`.
- [ ] Tenant screens work under both route trees and respect `useTenantPermissions()`.
- [ ] `dashboard/docs/` is updated for new or changed components, routes, hooks or API calls.
- [ ] The Help Center (`src/constants/help-center.ts`) is updated if users can see or do something new.
- [ ] New icons are added to `ICON_NAMES`.

**If it changes deployment (`deploy/`, Helm, compose):**

- [ ] `helm lint` passes for each changed chart, and an upgrade from the previous version keeps existing secrets and data.
