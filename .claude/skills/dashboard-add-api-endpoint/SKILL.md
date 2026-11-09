---
name: dashboard-add-api-endpoint
description: Add a backend call to the ianua dashboard end to end - typed service function, barrel export, Next.js proxy route, types and Zod schema, then the React Query hook in the component. Use when a feature needs a new or changed backend endpoint.
---

# Add an API endpoint

The browser never calls the backend directly: component, then service, then `apiClient` (`/api`), then a route handler in `dashboard/src/app/api`, then `API_URL`. Do every step. A service without its proxy route returns 404 in the browser.

Reference implementation: groups. See `dashboard/src/lib/api/services/groups.ts` and `dashboard/src/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/authorization/groups/`.

## Steps

0. **Read the contract from the backend spec. Never guess field names.** The API reference at https://api.ianua.io/api/v1/reference embeds the full OpenAPI spec. Print what you need with the bundled script (run from the repo root):
   `python -I .claude/skills/dashboard-add-api-endpoint/spec.py "<path substring>"`
   Use a narrow substring such as `tenants/{tenant_slug}/webhooks` or `webhooks/{id}/pause`; a broad one prints thousands of lines. The script shows each method's parameters, request body and success responses with `$ref` schemas inlined. Take from it: exact path and methods, required vs optional fields, enums, snake_case names, pagination (`after`, `limit`, `next_cursor`) and sort fields.
   - The spec can be wrong or inconsistent (a description listing a value the enum lacks, a list returning a bare array where other lists are paginated). Note each mismatch in your answer and follow the response shape the spec declares, but say so.
   - If the endpoint is not in the spec, stop and tell the user. Do not invent it.
   - The script needs network. If the host answers 403 to it, fetch the page with `curl` and extract the JSON in the `<script id="api-reference">` tag.
   - It reads the hosted API (`api.ianua.io`) by default. To read the spec of the backend you actually run (a local or self-hosted one, which may be a different version), set `IANUA_API_SPEC_URL` to its reference page, for example `IANUA_API_SPEC_URL=http://localhost:8080/api/v1/reference`.
1. **Types** in `dashboard/src/types/<area>.ts`. Use camelCase here.
2. **Zod schema** for any form input in `dashboard/src/schemas/<area>-schemas.ts`. Export the inferred input type.
3. **Service function** in `dashboard/src/lib/api/services/<area>.ts`:
   - Declare `...Response` types in snake_case exactly as the backend sends them, then map to the camelCase type with a `to<Thing>` function (see `toGroup`).
   - Build the path with `encodeURIComponent` on every slug.
   - Use the helpers from `@/lib/api/crud` (`getList`, `createResource`, `updateResource`, `deleteResource`, `buildSortParam`) where they fit.
   - Default missing strings to a readable fallback and dates through `formatBackendDate`.
4. **Export** the function and its types from `dashboard/src/lib/api/index.ts`. Components import from `@/lib/api`.
5. **Proxy route** under `dashboard/src/app/api` that mirrors the backend path, for example `.../tenants/[tenantSlug]/<area>/route.ts`:
   - Reuse an existing route file if the path already exists. Add the missing method (`GET`, `POST`, `PATCH`, `DELETE`).
   - For tenant-scoped paths prefer `proxyTenantRequest({ method, actionPath, request, routeContext })` from `dashboard/src/app/api/organizations/[orgSlug]/tenants/[tenantSlug]/proxy.ts`.
   - Otherwise follow `groups/route.ts`: return `500 CONFIG_ERROR` when `API_URL` is empty, forward `Authorization`, forward `Content-Type` only when there is a body (`readOptionalRequestBody`), use `cache: 'no-store'`, and return `createProxyResponse(response)`.
   - Dynamic params arrive as a `Promise`, so `await params`.
6. **Use it in the component**:
   - Reads: `useQuery` with `enabled: Boolean(orgSlug && tenantSlug)` and an inline key such as `['tenant-groups', orgSlug, tenantSlug, ...]`.
   - Writes: `useMutation`. On error call `showNotification({ message: getApiErrorMessage(error, 'Failed to ... Please try again.'), type: 'error' })`. On success show a success toast, then invalidate the list key and call `invalidateAuditLogQueries(queryClient, orgSlug)`.
7. **Docs**: update `docs/src/content/docs/dashboard/api-layer.mdx` if the layer itself changed, and the matching `docs/components/*.md` for the component. Update the Help Center in `dashboard/src/constants` if users see a new capability.

## Check before finishing

- The route file exists for every method the service uses.
- Slugs are encoded in both the service path and the proxy URL.
- No `fetch` to the backend from a component.
- `npm run lint`, `npm run type-check`, `npm run format:check`.
