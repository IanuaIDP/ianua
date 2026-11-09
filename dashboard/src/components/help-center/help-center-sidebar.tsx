'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useLocale, useTranslations } from 'next-intl';
import { usePathname } from 'next/navigation';

import { Input } from '@/components/ui/Input';
import { HELP_CENTER_CATEGORIES } from '@/constants/help-center';
import type { HelpArticle, HelpCategory } from '@/types/help-center';
import { getHelpArticleHref, localizeHelpCategories } from '@/utils/help-center';
import { cn } from '@/utils/cn';

function matchesQuery(article: HelpArticle, query: string): boolean {
  if (article.title.toLowerCase().includes(query)) {
    return true;
  }

  return (article.subArticles ?? []).some((subArticle) => matchesQuery(subArticle, query));
}

function filterCategories(categories: HelpCategory[], query: string): HelpCategory[] {
  const trimmed = query.trim().toLowerCase();

  if (!trimmed) {
    return categories;
  }

  return categories
    .map((category) => ({
      ...category,
      topics: category.topics.filter((topic) => matchesQuery(topic, trimmed)),
    }))
    .filter((category) => category.topics.length > 0);
}

function TopicRow({
  article,
  depth,
  onNavigate,
  pathname,
  slugPath,
}: {
  article: HelpArticle;
  depth: number;
  onNavigate?: () => void;
  pathname: string;
  slugPath: string[];
}) {
  const href = getHelpArticleHref(slugPath);
  const isActive = pathname === href;
  const hasChildren = Boolean(article.subArticles?.length);
  const containsActiveChild = hasChildren && pathname.startsWith(`${href}/`);
  const [isOpen, setIsOpen] = useState(containsActiveChild);

  return (
    <div>
      <div className="relative flex min-w-0 items-center">
        {hasChildren ? (
          <button
            type="button"
            aria-expanded={isOpen}
            onClick={() => setIsOpen((value) => !value)}
            className={cn(
              "flex h-8 min-w-0 flex-1 items-center rounded-md border border-transparent pr-2 text-left font-['Manrope',sans-serif] text-[14px] font-medium transition",
              depth === 0 ? 'pl-3' : 'pl-6',
              containsActiveChild ? 'text-white' : 'text-textGray hover:text-white',
            )}
          >
            <span className="truncate">{article.title}</span>
            <span
              className="material-symbols-rounded text-base! ml-auto shrink-0 transition-transform duration-200 ease-in-out"
              style={{ transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)' }}
              aria-hidden="true"
            >
              chevron_right
            </span>
          </button>
        ) : (
          <Link
            href={href}
            onClick={onNavigate}
            className={cn(
              "flex h-8 min-w-0 flex-1 items-center rounded-md border border-transparent pr-2 font-['Manrope',sans-serif] text-[14px] font-medium transition",
              depth === 0 ? 'pl-3' : 'pl-6',
              isActive
                ? 'border-borderGray bg-cardBg text-white'
                : 'text-textGray hover:text-white',
            )}
          >
            {isActive ? (
              <span
                aria-hidden="true"
                className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary"
              />
            ) : null}
            <span className="truncate">{article.title}</span>
          </Link>
        )}
      </div>

      {hasChildren ? (
        <div
          className="grid transition-[grid-template-rows] duration-200 ease-in-out"
          style={{ gridTemplateRows: isOpen ? '1fr' : '0fr' }}
        >
          <div className="overflow-hidden">
            {article.subArticles?.map((subArticle) => (
              <TopicRow
                key={subArticle.slug}
                article={subArticle}
                depth={depth + 1}
                onNavigate={onNavigate}
                pathname={pathname}
                slugPath={[...slugPath, subArticle.slug]}
              />
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

type HelpCenterSidebarProps = {
  onNavigate?: () => void;
  variant?: 'desktop' | 'mobile';
};

export function HelpCenterSidebar({ onNavigate, variant = 'desktop' }: HelpCenterSidebarProps) {
  const t = useTranslations('helpCenter');
  const locale = useLocale();
  const pathname = usePathname();
  const [query, setQuery] = useState('');
  const categories = useMemo(
    () => filterCategories(localizeHelpCategories(HELP_CENTER_CATEGORIES, locale), query),
    [locale, query],
  );

  return (
    <aside
      className={cn(
        'flex h-full flex-col overflow-y-auto bg-appBg',
        variant === 'desktop'
          ? 'hidden w-64 shrink-0 border-r border-borderGray lg:flex'
          : 'w-full flex-1',
      )}
    >
      <div className="sticky top-0 z-10 bg-appBg px-3 pb-3 pt-4">
        <Input
          placeholder={t('search')}
          containerClassName="mb-0"
          className="bg-cardBg"
          leftIcon={
            <span className="material-symbols-rounded text-base!" aria-hidden="true">
              search
            </span>
          }
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      <nav aria-label={t('navigation')} className="flex-1 px-3 pb-6">
        {categories.length === 0 ? (
          <p className="px-3 py-4 text-xs text-textGray">{t('noMatch', { query })}</p>
        ) : (
          categories.map((category) => (
            <div key={category.slug} className="mb-5">
              <p className="px-3 pb-1.5 font-['Space_Grotesk','Manrope',sans-serif] text-[12px] font-medium text-white">
                {category.title}
              </p>
              <div className="flex flex-col gap-0.5">
                {category.topics.map((topic) => (
                  <TopicRow
                    key={topic.slug}
                    article={topic}
                    depth={0}
                    onNavigate={onNavigate}
                    pathname={pathname}
                    slugPath={[category.slug, topic.slug]}
                  />
                ))}
              </div>
            </div>
          ))
        )}
      </nav>
    </aside>
  );
}
