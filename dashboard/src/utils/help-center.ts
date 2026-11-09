import { HELP_CENTER_CATEGORIES } from '@/constants/help-center';
import {
  HELP_CENTER_UK_ARTICLES,
  HELP_CENTER_UK_CATEGORY_TITLES,
} from '@/constants/help-center-uk';
import type { HelpArticle, HelpArticleRef, HelpCategory } from '@/types/help-center';

function collectRefs(
  category: HelpCategory,
  article: HelpArticle,
  slugPath: string[],
  parent: HelpArticle | undefined,
  refs: HelpArticleRef[],
) {
  refs.push({ article, category, parent, slugPath });

  for (const subArticle of article.subArticles ?? []) {
    collectRefs(category, subArticle, [...slugPath, subArticle.slug], article, refs);
  }
}

function buildAllRefs(): HelpArticleRef[] {
  const refs: HelpArticleRef[] = [];

  for (const category of HELP_CENTER_CATEGORIES) {
    for (const topic of category.topics) {
      collectRefs(category, topic, [category.slug, topic.slug], undefined, refs);
    }
  }

  return refs;
}

const ALL_HELP_ARTICLE_REFS = buildAllRefs();

const NAVIGABLE_HELP_ARTICLE_REFS = ALL_HELP_ARTICLE_REFS.filter(
  (ref) => !ref.article.subArticles?.length,
);

export function getHelpArticleBySlugPath(slugPath: string[]): HelpArticleRef | undefined {
  const key = slugPath.join('/');

  return ALL_HELP_ARTICLE_REFS.find((ref) => ref.slugPath.join('/') === key);
}

export function getHelpArticleHref(slugPath: string[]): string {
  return `/help-center/${slugPath.join('/')}`;
}

export function getDefaultHelpArticleRef(): HelpArticleRef {
  return ALL_HELP_ARTICLE_REFS[0];
}

export function getAdjacentHelpArticleRefs(slugPath: string[]): {
  next?: HelpArticleRef;
  previous?: HelpArticleRef;
} {
  const key = slugPath.join('/');
  const index = NAVIGABLE_HELP_ARTICLE_REFS.findIndex((ref) => ref.slugPath.join('/') === key);

  if (index === -1) {
    return {};
  }

  return {
    next: NAVIGABLE_HELP_ARTICLE_REFS[index + 1],
    previous: NAVIGABLE_HELP_ARTICLE_REFS[index - 1],
  };
}

export function isHelpArticleWritten(article: HelpArticle): boolean {
  return Boolean(article.intro) || article.sections.length > 0;
}

function localizeArticle(article: HelpArticle, slugPath: string[], locale: string): HelpArticle {
  const translation = locale === 'uk' ? HELP_CENTER_UK_ARTICLES[slugPath.join('/')] : undefined;
  const subArticles = article.subArticles?.map((subArticle) =>
    localizeArticle(subArticle, [...slugPath, subArticle.slug], locale),
  );

  return {
    ...article,
    ...(translation
      ? {
          intro: translation.intro ?? article.intro,
          sections: translation.sections ?? article.sections,
          title: translation.title,
        }
      : {}),
    ...(subArticles ? { subArticles } : {}),
  };
}

/** The categories with their titles and articles worded in `locale` (English when untranslated). */
export function localizeHelpCategories(categories: HelpCategory[], locale: string): HelpCategory[] {
  return categories.map((category) => ({
    ...category,
    title:
      (locale === 'uk' ? HELP_CENTER_UK_CATEGORY_TITLES[category.slug] : undefined) ??
      category.title,
    topics: category.topics.map((topic) =>
      localizeArticle(topic, [category.slug, topic.slug], locale),
    ),
  }));
}

/** An article reference whose texts are worded in `locale`; slugs and ids do not change. */
export function localizeHelpArticleRef(ref: HelpArticleRef, locale: string): HelpArticleRef {
  if (locale !== 'uk') {
    return ref;
  }

  const [category] = localizeHelpCategories([ref.category], locale);
  const parentPath = ref.slugPath.slice(0, -1);

  return {
    ...ref,
    article: localizeArticle(ref.article, ref.slugPath, locale),
    category: { ...ref.category, title: category.title },
    parent: ref.parent ? localizeArticle(ref.parent, parentPath, locale) : undefined,
  };
}
