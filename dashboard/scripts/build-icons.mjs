#!/usr/bin/env node
/**
 * Regenerates src/assets/material-symbols-rounded.woff2 as a font subset
 * containing only the Material Symbols icons actually referenced in the
 * codebase, using Google's Material Symbols Fonts API (`icon_names=`).
 *
 * Why: the full Material Symbols Rounded variable font is ~5MB (every icon,
 * every weight/fill/grade axis). This app only ever renders icon names via
 * the `material-symbols-rounded` ligature class, so a subset built from just
 * the names actually used is a byte-for-byte drop-in replacement (same
 * class, same usage, just a much smaller file) that loads near-instantly.
 *
 * The list of icons to include comes from src/constants/icon-names.ts - that
 * file is the source of truth. (An earlier version of this script tried to
 * regex-scan the whole codebase for icon usages instead of using a checked-in
 * list, but that missed several real icons and matched a couple of fake ones
 * - too unreliable for something that silently swaps a font. The codebase
 * scan is still run below, but only as a warning for icons that look used
 * but aren't registered yet, never as the actual source of truth.)
 *
 * Usage:
 *   npm run build-icons        (manual, e.g. right after adding a new icon)
 *   npm run build              (runs automatically via the `prebuild` hook)
 *
 * If Google Fonts is unreachable (offline dev), this script warns and leaves
 * the existing font file untouched rather than failing the build.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import https from 'node:https';

const SRC_DIR = path.resolve(process.cwd(), 'src');
const OUTPUT_DIR = path.resolve(process.cwd(), 'src/assets');
const ICON_NAMES_FILE = path.resolve(process.cwd(), 'src/constants/icon-names.ts');
// opsz,wght,FILL,GRAD - must match the font-size/weight used by the
// `.material-symbols-rounded` class in src/app/globals.css.
const FONT_AXES = '20,400,0,0';
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

function listSourceFiles(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...listSourceFiles(fullPath));
    } else if (/\.(tsx?|jsx?)$/.test(entry.name)) {
      files.push(fullPath);
    }
  }

  return files;
}

function extractIconNames(source) {
  const found = new Set();

  // `icon: 'name'` / `icon: "name"` object fields (nav item configs, action
  // menus, DashboardPageHeader trail items, etc.)
  for (const match of source.matchAll(/\bicon:\s*['"]([a-z][a-z0-9_]*)['"]/g)) {
    found.add(match[1]);
  }

  // `icon="name"` / `icon={'name'}` JSX props
  for (const match of source.matchAll(/\bicon=\{?['"]([a-z][a-z0-9_]*)['"]\}?/g)) {
    found.add(match[1]);
  }

  // Lookup records whose variable name contains "icon", e.g.
  // `const tenantSectionIcons: Record<string, string> = { Users: 'groups' }`
  for (const match of source.matchAll(
    /\b\w*[Ii]con\w*\s*(?::\s*Record<[^>]*>)?\s*=\s*\{([\s\S]*?)\n\}/g,
  )) {
    for (const inner of match[1].matchAll(/['"]([a-z][a-z0-9_]*)['"]/g)) {
      found.add(inner[1]);
    }
  }

  // Direct or ternary JSX children of a material-symbols-rounded element,
  // e.g. `<span className="material-symbols-rounded">check_circle</span>`
  // or `{isLast ? 'check_circle' : 'arrow_forward'}`
  for (const spanMatch of source.matchAll(
    /material-symbols-rounded[\s\S]{0,400}?>([\s\S]{0,200}?)</g,
  )) {
    const chunk = spanMatch[1];
    const bare = chunk.trim();

    if (/^[a-z][a-z0-9_]*$/.test(bare)) {
      found.add(bare);
    }

    for (const literal of chunk.matchAll(/['"]([a-z][a-z0-9_]*)['"]/g)) {
      found.add(literal[1]);
    }
  }

  return found;
}

function collectScannedIconNames() {
  const files = listSourceFiles(SRC_DIR);
  const all = new Set();

  for (const file of files) {
    const source = readFileSync(file, 'utf8');

    if (!/icon/i.test(source)) {
      continue;
    }

    for (const name of extractIconNames(source)) {
      all.add(name);
    }
  }

  return all;
}

function readRegisteredIconNames() {
  const source = readFileSync(ICON_NAMES_FILE, 'utf8');
  const match = source.match(/ICON_NAMES\s*=\s*\[([\s\S]*?)\]\s*as const/);

  if (!match) {
    throw new Error(`Could not parse ICON_NAMES array out of ${ICON_NAMES_FILE}`);
  }

  const names = [...match[1].matchAll(/['"]([a-z][a-z0-9_]*)['"]/g)].map((m) => m[1]);

  return [...new Set(names)].sort();
}

function warnAboutUnregisteredIcons(registeredNames) {
  const registered = new Set(registeredNames);
  const scanned = collectScannedIconNames();
  const unregistered = [...scanned].filter((name) => !registered.has(name)).sort();

  // The codebase scan is a blunt regex heuristic (it can both miss real
  // icons and pick up false positives from unrelated string literals), so
  // this is only ever a hint to double check, never treated as ground truth.
  if (unregistered.length > 0) {
    console.warn(
      `[build-icons] Heads up: found ${unregistered.length} icon-like name(s) in src/ not listed in ` +
        `src/constants/icon-names.ts: ${unregistered.join(', ')}\n` +
        '  If any of these are real icons you added, add them to ICON_NAMES and re-run this script. ' +
        "(This scan can also produce false positives - ignore anything that isn't actually an icon name.)",
    );
  }
}

function request(url, { binary = false } = {}) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': USER_AGENT } }, (res) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          resolve(request(res.headers.location, { binary }));
          return;
        }

        if (res.statusCode !== 200) {
          reject(new Error(`Request to ${url} failed with status ${res.statusCode}`));
          return;
        }

        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          resolve(binary ? buffer : buffer.toString('utf8'));
        });
      })
      .on('error', reject);
  });
}

async function main() {
  const iconNames = readRegisteredIconNames();

  if (iconNames.length === 0) {
    console.warn(
      '[build-icons] ICON_NAMES in src/constants/icon-names.ts is empty - skipping font regeneration.',
    );
    return;
  }

  console.log(
    `[build-icons] Building a subset for ${iconNames.length} registered icons: ${iconNames.join(', ')}`,
  );
  warnAboutUnregisteredIcons(iconNames);

  const cssUrl =
    'https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@' +
    FONT_AXES +
    '&icon_names=' +
    iconNames.join(',') +
    '&display=block';

  let css;

  try {
    css = await request(cssUrl);
  } catch (error) {
    console.warn(
      `[build-icons] Could not reach Google Fonts (offline?) - keeping existing font file. (${error.message})`,
    );
    return;
  }

  const fontUrlMatch = css.match(
    /url\((https:\/\/fonts\.gstatic\.com\/[^)]+)\)\s*format\(['"]([a-z0-9]+)['"]\)/,
  );

  if (!fontUrlMatch) {
    console.warn(
      '[build-icons] Could not parse font URL from Google Fonts response - keeping existing font file.',
    );
    return;
  }

  const [, fontUrl, format] = fontUrlMatch;
  const extension = format === 'woff2' ? 'woff2' : 'ttf';

  let fontBuffer;

  try {
    fontBuffer = await request(fontUrl, { binary: true });
  } catch (error) {
    console.warn(
      `[build-icons] Failed to download font file - keeping existing font file. (${error.message})`,
    );
    return;
  }

  const outputPath = path.join(OUTPUT_DIR, `material-symbols-rounded.${extension}`);
  writeFileSync(outputPath, fontBuffer);

  console.log(
    `[build-icons] Wrote ${(fontBuffer.length / 1024).toFixed(1)} KB to src/assets/material-symbols-rounded.${extension}`,
  );

  if (extension !== 'woff2') {
    console.warn(
      "[build-icons] Google served a non-woff2 format - update src/lib/fonts.ts's `src` path to match the new extension.",
    );
  }
}

main();
