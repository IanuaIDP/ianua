import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { TableCellStack, TableCellText } from '@/components/ui/table-cell';
import { getSettingsTabHref } from '@/lib/settings/settings-routes';
import type { AuditLogEntry } from '@/types/audit-log';
import { getBadgeColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { getInitials } from '@/utils/initials';

type RecentActivityCardProps = {
  currentUserEmail?: string;
  entries: AuditLogEntry[];
  isLoading?: boolean;
};

export function RecentActivityCard({
  currentUserEmail,
  entries,
  isLoading = false,
}: RecentActivityCardProps) {
  const t = useTranslations('dashboard.overview.recent');

  return (
    <section className="flex flex-col rounded-lg border border-borderGray bg-cardBg pt-4 px-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-base font-bold text-white">{t('title')}</h2>
        <Link
          href={getSettingsTabHref('Audit Log')}
          className="flex items-center gap-1 text-xs font-medium text-primary transition hover:text-primary/80"
        >
          {t('viewAuditLog')}
          <span className="material-symbols-rounded text-base!" aria-hidden="true">
            arrow_forward
          </span>
        </Link>
      </div>

      {isLoading || entries.length === 0 ? (
        <div className="mt-4 flex h-32 items-center justify-center text-sm text-textGray">
          {isLoading ? t('loading') : t('empty')}
        </div>
      ) : (
        <div className="-mx-4 mt-4 flex flex-col divide-y divide-borderGray border-t border-borderGray">
          {entries.map((entry) => (
            <div key={entry.id} className="flex items-center gap-3 px-4 py-2.5">
              <div className="flex min-w-0 flex-1 items-center gap-3">
                <span
                  className={cn(
                    'flex size-6 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                    getBadgeColorClass(entry.actorEmail ?? entry.actor),
                  )}
                >
                  {getInitials(entry.actor)}
                </span>
                {entry.actorEmail ? (
                  <TableCellStack
                    primary={
                      currentUserEmail &&
                      entry.actorEmail.toLowerCase() === currentUserEmail.toLowerCase()
                        ? t('me', { name: entry.actor })
                        : entry.actor
                    }
                    primaryClassName="font-semibold text-white text-xs"
                    secondary={entry.actorEmail}
                    secondaryClassName="text-[10px] font-medium text-textGray"
                  />
                ) : (
                  <TableCellText className="font-semibold text-white">{entry.actor}</TableCellText>
                )}
              </div>
              <TableCellText className="w-44 shrink-0 text-left text-xs font-semibold text-white">
                {entry.event}
              </TableCellText>
              <TableCellText className="w-36 shrink-0 text-left text-xs font-semibold text-white">
                {entry.dateTime}
              </TableCellText>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
