'use client';

import { useTranslations } from 'next-intl';

import { JsonView } from '@/components/dashboard/workflows/json-view';
import { Button } from '@/components/ui/Button';
import type { LoopApprovalPage } from '@/types/workflows';

type LoopItemsListProps = {
  isLoadingMore: boolean;
  loop: LoopApprovalPage;
  onLoadMore: () => void;
};

function hasSharedData(shared: unknown) {
  return typeof shared === 'object' && shared !== null && Object.keys(shared).length > 0;
}

/** Every item a whole-loop approval covers, opened page by page. */
export function LoopItemsList({ isLoadingMore, loop, onLoadMore }: LoopItemsListProps) {
  const t = useTranslations('auth.workflowApproval');
  const progress = loop.total > 0 ? Math.min(100, (loop.shown / loop.total) * 100) : 100;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <p className="mb-1.5 text-xs font-medium text-textGray">
          {t('itemsShown', { shown: loop.shown, total: loop.total })}
        </p>
        <div
          aria-label={t('progressLabel')}
          aria-valuemax={loop.total}
          aria-valuemin={0}
          aria-valuenow={loop.shown}
          className="h-1.5 overflow-hidden rounded-full bg-white/15"
          role="progressbar"
        >
          <span
            className="block h-full rounded-full bg-primary"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {hasSharedData(loop.shared) ? (
        <div>
          <p className="mb-1 text-xs font-medium text-textGray">{t('sharedData')}</p>
          <JsonView value={loop.shared} />
        </div>
      ) : null}

      <ol className="flex flex-col gap-2">
        {loop.items.map(({ item, position }) => (
          <li key={position}>
            <p className="mb-1 text-xs font-medium text-textGray">
              {t('itemNumber', { number: position + 1 })}
            </p>
            <JsonView value={item} className="max-h-48" />
          </li>
        ))}
      </ol>

      {loop.nextCursor ? (
        <Button type="button" variant="outline" isLoading={isLoadingMore} onClick={onLoadMore}>
          {t('loadMore')}
        </Button>
      ) : null}
    </div>
  );
}
