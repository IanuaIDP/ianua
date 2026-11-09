// Checks that every language file in messages/ has exactly the keys of en.json.
// English is the source of truth; run with `npm run check-messages`.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const MESSAGES_DIR = path.resolve(process.cwd(), 'messages');
const SOURCE_LOCALE = 'en';

function flatten(node, prefix = '') {
  return Object.entries(node).flatMap(([key, value]) => {
    const fullKey = prefix ? `${prefix}.${key}` : key;

    return value !== null && typeof value === 'object' ? flatten(value, fullKey) : [fullKey];
  });
}

function readKeys(file) {
  return new Set(flatten(JSON.parse(readFileSync(path.join(MESSAGES_DIR, file), 'utf8'))));
}

const files = readdirSync(MESSAGES_DIR).filter((file) => file.endsWith('.json'));
const sourceKeys = readKeys(`${SOURCE_LOCALE}.json`);
let hasProblems = false;

for (const file of files) {
  if (file === `${SOURCE_LOCALE}.json`) {
    continue;
  }

  const keys = readKeys(file);
  const missing = [...sourceKeys].filter((key) => !keys.has(key));
  const extra = [...keys].filter((key) => !sourceKeys.has(key));

  if (missing.length > 0 || extra.length > 0) {
    hasProblems = true;
    console.error(`${file} does not match ${SOURCE_LOCALE}.json`);
    missing.forEach((key) => console.error(`  missing: ${key}`));
    extra.forEach((key) => console.error(`  extra:   ${key}`));
  }
}

if (hasProblems) {
  process.exit(1);
}

console.log(`Messages OK: ${files.length} languages, ${sourceKeys.size} keys each.`);
