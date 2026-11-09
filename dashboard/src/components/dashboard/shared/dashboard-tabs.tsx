import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { cn } from '@/utils/cn';
import { formatStatusLabel } from '@/utils/format-status-label';

type DashboardTabsProps<Tab extends string> = {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  tabs: Tab[];
};

export function DashboardTabs<Tab extends string>({
  activeTab,
  onTabChange,
  tabs,
}: DashboardTabsProps<Tab>) {
  const tTabs = useLooseTranslations('dashboard.tabs');
  const tStatus = useLooseTranslations('dashboard.status');

  return (
    <div className="scrollbar-hidden flex gap-4 overflow-x-auto border-b border-borderGray px-4">
      {tabs.map((tab) => {
        const isActive = activeTab === tab;

        return (
          <button
            key={tab}
            type="button"
            onClick={() => {
              if (!isActive) {
                onTabChange(tab);
              }
            }}
            className={cn(
              'relative h-5.5 shrink-0 text-xs font-medium transition',
              isActive ? 'cursor-default! text-primary' : 'text-textGray hover:text-white',
            )}
          >
            {tTabs.has(tab) ? tTabs(tab) : tStatus.has(tab) ? tStatus(tab) : formatStatusLabel(tab)}
            {isActive && (
              <span className="absolute inset-x-0 bottom-0 h-px rounded-full bg-primary" />
            )}
          </button>
        );
      })}
    </div>
  );
}
