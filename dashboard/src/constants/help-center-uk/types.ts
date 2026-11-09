import type { HelpSection } from '@/types/help-center';

/** The Ukrainian text of one article; slugs, ids and dates stay in `help-center.ts`. */
export type HelpArticleTranslation = {
  intro?: string;
  sections?: HelpSection[];
  title: string;
};
