// Checks that a language overlay covers every Help Center article.
//
//   npx tsx ../.claude/skills/dashboard-add-language/scripts/help-center-coverage.ts <locale>
//
// For each English article it expects an overlay entry at the same path
// (`category/topic[/sub]`) with the same section ids and the same block types
// (and list / steps lengths). Prints "OK" or one line per problem.

import { HELP_CENTER_CATEGORIES } from '@/constants/help-center';
import type { HelpArticle } from '@/types/help-center';

const locale = process.argv[2];

if (!locale) {
  console.error('Usage: help-center-coverage.ts <locale>');
  process.exit(2);
}

async function main() {
  const overlay = (await import(`@/constants/help-center-${locale}/index`)) as Record<
    string,
    Record<string, unknown>
  >;
  const articlesExport = Object.keys(overlay).find((name) => name.endsWith('_ARTICLES'));
  const titlesExport = Object.keys(overlay).find((name) => name.endsWith('_CATEGORY_TITLES'));

  if (!articlesExport || !titlesExport) {
    console.error(
      `dashboard/src/constants/help-center-${locale}/index.ts must export *_ARTICLES and *_CATEGORY_TITLES`,
    );
    process.exit(2);
  }

  type Block = { type: string; items?: unknown[] };
  type Translation = {
    intro?: string;
    sections?: { id: string; blocks: Block[] }[];
  };

  const articles = overlay[articlesExport] as Record<string, Translation>;
  const titles = overlay[titlesExport] as Record<string, string>;
  const problems: string[] = [];

  function signature(blocks: Block[]) {
    return blocks
      .map(
        (block) =>
          block.type + (block.type === 'list' || block.type === 'steps' ? block.items?.length : ''),
      )
      .join(',');
  }

  function visit(article: HelpArticle, trail: string[]) {
    const key = trail.join('/');
    const translated = articles[key];

    if (!translated) {
      problems.push(`missing article ${key}`);
    } else {
      if (article.intro && !translated.intro) {
        problems.push(`no intro ${key}`);
      }

      const englishIds = article.sections.map((section) => section.id).join(',');
      const translatedIds = (translated.sections ?? []).map((section) => section.id).join(',');

      if (englishIds !== translatedIds) {
        problems.push(
          `section ids differ ${key}\n  en ${englishIds}\n  ${locale} ${translatedIds}`,
        );
      }

      article.sections.forEach((section, index) => {
        const other = translated.sections?.[index];

        if (other && signature(section.blocks) !== signature(other.blocks)) {
          problems.push(
            `blocks differ ${key}#${section.id}\n  en ${signature(section.blocks)}\n  ${locale} ${signature(other.blocks)}`,
          );
        }
      });
    }

    for (const sub of article.subArticles ?? []) {
      visit(sub, [...trail, sub.slug]);
    }
  }

  for (const category of HELP_CENTER_CATEGORIES) {
    if (!titles[category.slug]) {
      problems.push(`missing category title ${category.slug}`);
    }

    for (const topic of category.topics) {
      visit(topic, [category.slug, topic.slug]);
    }
  }

  console.log(problems.length ? problems.join('\n') : 'OK');
  process.exit(problems.length ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(2);
});
