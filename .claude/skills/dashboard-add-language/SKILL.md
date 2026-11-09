---
name: dashboard-add-language
description: Add a new interface language to the whole ianua dashboard (landing, auth, legal pages, dashboard, Help Center, dates and numbers) the way Ukrainian was added - foundation, translations in batches, the per-language code, and a design check that every screen and dialog looks the same as English. Use when the user asks to add, support or translate the project into another language.
argument-hint: <language, e.g. German>
---

# Add a language

The language to add: $ARGUMENTS

If that is empty, ask which language and region (for example German, de-DE) before doing anything. Work out the code (`de`) and the backend tag (`de-DE`, check `GET /locales`) from it.

Ukrainian (`uk`) was added in six batches. This skill repeats that path for another language, with the mistakes from that work written down. Replace `<locale>` with the language code (`pl`, `de`, `ka`), `<LOCALE>` with its upper-case form.

Read first: `docs/src/content/docs/dashboard/overview.mdx` (section "Languages") and the Ukrainian overlay as the model: `dashboard/src/constants/help-center-uk/`.

## Ground rules

- English (`dashboard/messages/en.json`) is the source of truth. Every other file in `dashboard/messages/` must have exactly its keys (`npm run check-messages`).
- You write the first translation yourself. A native speaker reviews it later. Say so in your final report; do not claim review happened.
- The new language must look the same as English: same padding and spacing, no sideways overflow, no extra wrapping. Fix by shortening the translation, not by changing the layout, unless a font or width is really wrong.
- Backend text (audit events, notification bodies, permission names, API error messages), brand and provider names, and example data sent to the backend stay English.
- Commit in batches of about 40 files. lint-staged fails on Windows with "command line too long" above about 80 staged files. Never use `--no-verify`. Headers are lowercase conventional and at most 120 characters. Add `[skip ci]` only when the user asks. No `Co-Authored-By` trailer.
- Do not push unless asked. Do not run Prettier over whole folders, only on changed files. Some files are CRLF on Windows, so `npm run format:check` flags them locally; that is not a real failure and CI on Linux is fine. Discard line-ending-only diffs with `git checkout --`.
- Write files with the Write tool. Long bash heredocs with quotes break the Bash tool.

## Batch 0: foundation

1. `dashboard/src/i18n/config.ts`: add `<locale>` to `LOCALES`, `LOCALE_NATIVE_NAMES` (the language in its own name) and `BACKEND_LOCALES` (the BCP 47 tag the backend stores, from `GET /locales`).
2. Add the plural rules check: Ukrainian needed `one / few / many / other`. Look up the CLDR plural categories for the language and write every ICU `plural` message with all of them.
3. Create `dashboard/messages/<locale>.json` with every key of `en.json` (start by copying, then translate in batches below). Use `getTranslations` / `useTranslations`; never hard-code text.
4. Check fonts: headings use Space Grotesk, which has no Cyrillic. Other scripts (Georgian, Greek, Arabic, CJK) need a font fallback in every `font-['Space_Grotesk',…]` stack.
5. Check the language switcher (landing, legal, Help Center headers, auth pages, dashboard user menu) and the profile sync (`PATCH …/me { locale }`, `LocaleSync`) pick the new language up from `LOCALES`.

## Per-language code (not just JSON)

Search the codebase for the existing Ukrainian branches and give the new language its own entry. TypeScript catches most of them because the tables are `Record<AppLocale, …>`.

```
rg -n "'uk'|\buk\b" src --glob '!dashboard/src/constants/help-center-uk/**'
```

Known places:

- `dashboard/src/utils/date.ts`: date/time joiner ("at"), duration units (`s/m/h/d`), the word for "Expired".
- `dashboard/src/utils/not-available.ts`: the "N/A" text.
- `dashboard/src/lib/overview/metrics.ts`: latency units (`formatLatency` uses `isUk`; replace the boolean with a per-language table).
- `dashboard/src/hooks/i18n/use-day-picker-locale.ts`: the `react-day-picker` locale (import from `react-day-picker/locale`).
- `dashboard/src/utils/help-center.ts`: `locale === 'uk'` checks choose the Help Center overlay. Replace them with a map from locale to its overlay when the second non-English language is added.
- `dashboard/src/lib/api/services/reference-data.ts` and `dashboard/src/constants/countries.ts`: country and language names come from `Intl.DisplayNames`; use the `short` style for non-English so select values are not clipped.
- `dashboard/src/i18n/active-locale.ts`: `getActiveLocale()` reads `<html lang>`; services format text at fetch time, so `useChangeLanguage` refetches queries after the language flips.

## Translation batches

Do them in this order, one commit per batch (split further above 40 files). After each batch run `npm run check-messages`, `npm run lint`, `npm run type-check`.

1. Landing and shared header/footer.
2. Auth pages (login, signup, MFA, passkeys, password).
3. Legal pages (terms, privacy). Legal copy is the team's wording: keep meaning exact and mark it for review.
4. Dashboard, area by area: organization (overview, team, settings, notifications), tenant users/roles/groups/permissions/policy, infrastructure (domains, connections, API keys, OAuth clients, signals, services, routes, pipelines, crypto), agents (agents, flows, tools, model providers), tenant settings.
5. Help Center.
6. Dates, numbers, countries, calendars (the per-language code above).

### Rules for the dashboard batches

- Constants keep English ids; hooks in `dashboard/src/hooks/dashboard/` build the translated options and dialog text (`use-stream-options`, `use-pipeline-options`, …). Follow that pattern for new constants. Navigation items, statuses and action ids stay English identifiers; the visible text comes from `useNavLabels`, `dashboard.status.<Status>` and `dashboard.actions.labels.<id>`.
- Zod schemas name messages `validation.<key>` and the form components translate them with `useFieldError` (`useValidationText()` for raw error text).
- Keys built at run time use `useLooseTranslations(ns)`.
- Watch for key collisions: a key cannot be both a string and an object (`create` vs `create.title`), and an existing key may already exist under another name. Rename yours (`createAction`, `permissionActionRequired`).
- `eslint react-hooks/purity` rejects `Date.now()` during render; keep the time in state.
- Keep terms consistent across the file. Align status words with the UI text (Active, Blocked, Invited, Pending, Invitation expired).
- Translate one area at a time as small fragments (English and the new language side by side), then merge them into the two message files so both get the same keys in the same place. `npm run check-messages` catches any drift.

## Help Center

English articles stay in `dashboard/src/constants/help-center.ts` (slugs, section ids, dates). The translation is an overlay in `dashboard/src/constants/help-center-<locale>/`: one file per category (`getting-started.ts`, `organizations.ts`, …), plus `index.ts` exporting `HELP_CENTER_<LOCALE>_CATEGORY_TITLES` and `HELP_CENTER_<LOCALE>_ARTICLES`, and `types.ts`. Keys are article paths `category/topic[/sub]`. The structure of each translated article (section ids, block types, list and step counts) must match English.

Check coverage:

```
npx tsx ../.claude/skills/dashboard-add-language/scripts/help-center-coverage.ts <locale>
```

It prints `OK` or one line per problem, and exits non-zero on problems.

## Design check

Needs a signed-in browser. Ask the user to sign in in the browser window you control (Playwright MCP) and verify the session before measuring: `fetch('/api/organizations/<org>/me')` must return 200, not 401. If it returns 401 or the page has no auth cookies, the user is signed in somewhere else; do not loop on asking, say so and offer to skip the dialog part.

**Never click anything that changes data.** An earlier run clicked "Enable SCIM" and turned SCIM on for a real tenant. The dialog script only clicks an allowlist (create/add/new/register/invite/connect/classify, row menus, delete/revoke/archive/suspend/cancel/remove, schema) and never confirms a dialog. Do not widen it.

Language switching: use the sidebar globe on an organization-level page such as `/overview`: button "Change language", then the radio item for the language. The profile language wins over the cookie.

### Pages

1. In English, run `dashboard/scripts/measure-pages.pw` with `browser_run_code_unsafe` (filename = the file; edit the tenant slug and route list first). It stores `measure-en` in `localStorage`.
2. Switch to the new language and run it again (`measure-<locale>`).
3. Diff in the page:

```js
() => {
  const en = JSON.parse(localStorage.getItem('measure-en'));
  const other = JSON.parse(localStorage.getItem('measure-<locale>'));
  return Object.keys(en)
    .map((k) => {
      const a = en[k],
        b = other[k];
      if (!a || !b || a.err || b.err) return k + ' ERR';
      const same = a.count === b.count;
      let extra = 0,
        fewer = 0;
      if (same)
        for (let i = 0; i < a.lines.length; i++) {
          const d = +b.lines[i] - +a.lines[i];
          if (d > 0) extra++;
          else if (d < 0) fewer++;
        }
      return `${k} | n ${a.count}/${b.count} | extra ${same ? extra : '?'} fewer ${same ? fewer : '?'} | clips ${a.clips}/${b.clips} | wide ${b.docW > b.winW ? 'YES' : 'no'}`;
    })
    .filter((r) => !/extra 0 fewer 0/.test(r) || /wide YES/.test(r));
};
```

Any `wide YES` is a failure. `extra` lines mean a text wraps more than English; `clips` means a truncated text (`truncate` with an ellipsis). Different element counts usually mean the page was still loading; re-measure that page.

The tool aborts a script after 30 silent minutes and results are only saved at the end; the whole page list takes a few minutes. If it gets slow, run it per slice.

### Details of a page that differs

Re-run only the differing routes at 390 px, listing elements with 2+ lines or clipped text (`[index, lines, 'C' if clipped, text]`) for both languages and compare by index. Common fixes:

- Description under a title wraps more: shorten the translation (keep the meaning).
- Breadcrumb truncates with an ellipsis: the status badge ("Active") is wider in the language; shortening the badge text or accepting it is the only option short of changing layout. Tell the user.
- Table header or column wraps: pick a shorter word (Joined: "Приєднано").
- Select value clipped: language and country names use `Intl.DisplayNames` with `style: 'short'`.

### Dialogs

1. In English, run `dashboard/scripts/dialogs.pw` (edit `T` and `allRoutes`). It stores `modal-en`.
2. Switch language, run it again (stores `modal-<locale>`, visiting only the dialogs English found). The first thing it does is open `/overview` and wait, so it reads the right language; a read taken while the page is still on its first render returns the wrong language.
3. Compare each key: dialog width and height, `xo` (sideways overflow, must be false), and the per-element line counts. A dialog hint wrapping one line more is normal; text that is clipped (`C`) or a dialog wider than English is a bug.
4. Keys can point at different dialogs when the data differs (index shift). Check those by hand.

Playwright quirks that cost time: use `click({ force: true })` (the elements never count as stable); tag buttons with `data-pw` and exclude `aside,nav,header,[role="dialog"]` (the sidebar sits inside `main`; the breadcrumb click navigates away); wait for `networkidle` plus 2.5 s after loading; a formatter may append `;` after the final `}` of a script, which breaks `browser_run_code_unsafe`; strip it.

## Finish

1. `npm run check-messages`, `npm run lint`, `npm run type-check`, and Prettier on changed files only.
2. `npx tsx ../.claude/skills/dashboard-add-language/scripts/help-center-coverage.ts <locale>`.
3. Update the docs: `docs/src/content/docs/dashboard/overview.mdx` (Languages), `docs/src/content/docs/dashboard/state-and-hooks.mdx` (new hooks) and `docs/src/content/docs/dashboard/reference.mdx` (new utils and folders).
4. Report: what was translated, what was measured (and what was not, such as dialogs that could not be opened), the text left in English on purpose, and that a native speaker must review `dashboard/messages/<locale>.json`, `dashboard/src/constants/help-center-<locale>/` and the legal pages.
5. Ask before pushing.
