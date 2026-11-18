// Blog settings. Articles are MDX files in dashboard/content/blog/<language>/,
// one file per article, and the file name is the address. The text of the blog
// pages is in messages/<language>.json under `blog`.

export const BLOG_CONTENT_DIRECTORY = 'content/blog';

export const BLOG_SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export const BLOG_WORDS_PER_MINUTE = 200;
