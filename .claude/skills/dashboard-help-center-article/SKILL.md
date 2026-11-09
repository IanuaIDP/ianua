---
name: dashboard-help-center-article
description: Add or update a Help Center article for the ianua dashboard (content in dashboard/src/constants/help-center.ts, shown at /help-center). Use when a change alters what users see or can do, when the user asks to document a feature for end users, or to mark an unbuilt feature as coming soon.
---

# Help Center article

The Help Center is the end-user manual. Content lives in one file, `dashboard/src/constants/help-center.ts`, as `HELP_CENTER_CATEGORIES`. Types are in `dashboard/src/types/help-center.ts`. Lookups (`getHelpArticleHref`, `getAdjacentHelpArticleRefs`) are in `dashboard/src/utils/help-center.ts`.

## The shape

```ts
article({
  slug: 'user-attributes', // URL segment, kebab-case, unique in its category
  title: 'User attributes',
  lastUpdated: 'YYYY-MM-DD', // today's date whenever the article changes
  intro: 'One or two sentences on what this is and why it matters.',
  sections: [
    {
      id: 'adding-a-field', // anchor for the table of contents, kebab-case
      heading: 'Adding a field',
      blocks: [
        { type: 'paragraph', text: '…' },
        { type: 'list', items: ['…', '…'] },
        { type: 'steps', items: ['…', '…'] }, // numbered how-to
        { type: 'callout', tone: 'info', text: '…' }, // tone: 'info' | 'warning'
      ],
    },
  ],
  subArticles: [/* optional, for a topic split into pages */],
});
```

## Rules

1. **Ground every sentence in the code.** Read the component before writing. Use the exact labels users see (button text, field labels, toast wording, sidebar names). Never describe a feature from memory or from the backend docs alone.
2. **It is a user manual.** Add `steps` for anything a user does (where to click, in order), and say what happens afterwards. Prefer “Open the tenant, go to Users, click Manage fields” over abstract descriptions.
3. **Say who can do it** when it depends on role or permission (Owners only, needs a tenant permission).
4. **Not built yet?** Keep the article but mark it: `intro: 'Coming soon.'` and one section `{ id: 'coming-soon', heading: 'Coming soon', blocks: [{ type: 'callout', tone: 'info', text: 'What it will do, and what to use today.' }] }`. Do not describe it as working.
5. **Both ways into a tenant.** Organization users reach tenant screens at `/tenants/{tenant}/…`, tenant users at `/organizations/{org}/tenants/{tenant}/…`. Write steps that work for both, or say which one applies.
6. **Bump `lastUpdated`** on every article you change, and on articles that link to it if their text changed.
7. **Cross-check related articles.** Search the file for the old label or behaviour (for example the old button name) and fix every mention, not only the main article.
8. Plain words, short sentences, no internal names (component, hook or endpoint names) in user-facing text.

## Check before finishing

- `npx prettier --write dashboard/src/constants/help-center.ts`
- `npm run type-check` (the content is typed; a wrong block type fails here).
- Open `/help-center/<category>/<article>` in the running app if you can, and confirm the table of contents and previous/next links.
