import { ChangeBadge } from '@/components/dashboard/overview/change-badge';
import type { OverviewMetricItem } from '@/types/overview';

type MetricItemProps = OverviewMetricItem;

export function MetricItem({ label, value, change, tone }: MetricItemProps) {
  return (
    <div>
      <p className="min-h-8 text-xs font-medium text-textGray">{label}</p>
      <div className="mt-1.5 flex items-center gap-2">
        <p className="text-2xl font-semibold leading-none text-white">{value}</p>
        <ChangeBadge value={change} tone={tone} />
      </div>
    </div>
  );
}
