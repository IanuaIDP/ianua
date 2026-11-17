import 'server-only';

import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import matter from 'gray-matter';
import { z } from 'zod';

import { BLOG_CONTENT_DIRECTORY, BLOG_SLUG_PATTERN, BLOG_WORDS_PER_MINUTE } from '@/constants/blog';
import { DEFAULT_LOCALE, type AppLocale } from '@/i18n/config';

const frontmatterSchema = z.object({
  author: z.string().min(1),
  date: z.union([z.date(), z.string()]).transform((value, context) => {
    const date = value instanceof Date ? value : new Date(value);

    if (Number.isNaN(date.getTime())) {
      context.addIssue({ code: 'custom', message: 'date is not a valid date' });
      return z.NEVER;
    }

    return date.toISOString().slice(0, 10);
  }),
  description: z.string().min(1),
  draft: z.boolean().default(false),
  tags: z.array(z.string().min(1)).default([]),
  title: z.string().min(1),
});

export type BlogPostSummary = z.output<typeof frontmatterSchema> & {
  minutesToRead: number;
  slug: string;
};

export type BlogPost = BlogPostSummary & {
  body: string;
  isTranslated: boolean;
};

function directoryFor(locale: AppLocale): string {
  return path.join(process.cwd(), BLOG_CONTENT_DIRECTORY, locale);
}

function minutesToRead(body: string): number {
  const words = body.split(/\s+/).filter(Boolean).length;

  return Math.max(1, Math.ceil(words / BLOG_WORDS_PER_MINUTE));
}

async function readFileIfPresent(file: string): Promise<string | null> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return null;
  }
}

function parsePost(slug: string, source: string, isTranslated: boolean): BlogPost {
  const { content, data } = matter(source);
  const frontmatter = frontmatterSchema.parse(data);

  return {
    ...frontmatter,
    body: content,
    isTranslated,
    minutesToRead: minutesToRead(content),
    slug,
  };
}

function isVisible(post: BlogPost): boolean {
  return !post.draft || process.env.NODE_ENV !== 'production';
}

async function slugsIn(locale: AppLocale): Promise<string[]> {
  try {
    const files = await readdir(directoryFor(locale));

    return files
      .filter((file) => file.endsWith('.mdx'))
      .map((file) => file.slice(0, -'.mdx'.length))
      .filter((slug) => BLOG_SLUG_PATTERN.test(slug));
  } catch {
    return [];
  }
}

/**
 * One article in the visitor's language, or in English when it has no
 * translation. Returns `null` for an unknown or hidden article, and for a
 * slug that is not a plain file name.
 */
export async function blogPost(slug: string, locale: AppLocale): Promise<BlogPost | null> {
  if (!BLOG_SLUG_PATTERN.test(slug)) {
    return null;
  }

  const own = await readFileIfPresent(path.join(directoryFor(locale), `${slug}.mdx`));
  const source =
    own ?? (await readFileIfPresent(path.join(directoryFor(DEFAULT_LOCALE), `${slug}.mdx`)));

  if (source === null) {
    return null;
  }

  const post = parsePost(slug, source, own !== null || locale === DEFAULT_LOCALE);

  return isVisible(post) ? post : null;
}

/** Every visible article in the visitor's language, newest first. */
export async function blogPosts(locale: AppLocale): Promise<BlogPostSummary[]> {
  const slugs = new Set([...(await slugsIn(DEFAULT_LOCALE)), ...(await slugsIn(locale))]);
  const posts = await Promise.all([...slugs].map((slug) => blogPost(slug, locale)));

  return posts
    .filter((post): post is BlogPost => post !== null)
    .sort((a, b) => b.date.localeCompare(a.date))
    .map(summaryOf);
}

function summaryOf(post: BlogPost): BlogPostSummary {
  return {
    author: post.author,
    date: post.date,
    description: post.description,
    draft: post.draft,
    minutesToRead: post.minutesToRead,
    slug: post.slug,
    tags: post.tags,
    title: post.title,
  };
}
