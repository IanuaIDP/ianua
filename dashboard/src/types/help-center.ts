export type HelpContentBlock =
  | { type: 'paragraph'; text: string }
  | { type: 'list'; items: string[]; ordered?: boolean }
  | { type: 'callout'; text: string; tone?: 'info' | 'warning' }
  | { type: 'steps'; items: string[] };

export type HelpSection = {
  blocks: HelpContentBlock[];
  heading: string;
  id: string;
};

export type HelpArticle = {
  intro?: string;
  lastUpdated?: string;
  sections: HelpSection[];
  slug: string;
  subArticles?: HelpArticle[];
  title: string;
};

export type HelpCategory = {
  slug: string;
  title: string;
  topics: HelpArticle[];
};

export type HelpArticleRef = {
  article: HelpArticle;
  category: HelpCategory;
  parent?: HelpArticle;
  slugPath: string[];
};
