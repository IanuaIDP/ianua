---
name: dashboard-add-icon
description: Add a Material Symbols icon to the ianua dashboard so it actually renders - register the name in ICON_NAMES and regenerate the icon font subset. Use whenever code uses an icon name (material-symbols-rounded ligature) that may not be registered yet.
---

# Add an icon

The app ships a **subset** of the Material Symbols Rounded font containing only registered icons (`dashboard/src/assets/material-symbols-rounded.woff2`). An icon name that is not registered renders as plain text, for example the word `archive` instead of the archive icon.

## Steps

1. **Find the exact name** on https://fonts.google.com/icons (Material Symbols, Rounded). Use the ligature name in snake_case, for example `keyboard_arrow_down`.
2. **Check whether it is registered**: search `dashboard/src/constants/icon-names.ts`. If it is already in `ICON_NAMES`, you are done.
3. **Register it**: add the name to `ICON_NAMES`, keeping the list in alphabetical order. The array must stay `as const` (the build script parses it).
4. **Regenerate the font**: `npm run build-icons`. It needs network access (it downloads the subset from Google Fonts). `npm run build` also runs it.
   - If it cannot reach Google, it warns and keeps the old font. Tell the user to run it on a machine with network, and do not hand-edit the `.woff2`.
5. **Use it**: `<span className="material-symbols-rounded" aria-hidden="true">archive</span>`. Size with `text-*!` (for example `text-lg!`). Give icon-only buttons an `aria-label` and a `FloatingTooltip`.

## Check before finishing

- Every new icon name used in the change is in `ICON_NAMES`. A quick check:
  `npm run build-icons` prints a warning listing names it found in the code but not in the list.
- The regenerated `dashboard/src/assets/material-symbols-rounded.woff2` is part of the change.
