import { MetricItem } from '@/components/dashboard/overview/metric-item';
import type { OverviewMetricItem } from '@/types/overview';

type MetricCardProps = {
  title: string;
  items: OverviewMetricItem[];
};

export function MetricCard({ title, items }: MetricCardProps) {
  return (
    <section className="overflow-hidden rounded-lg border border-borderGray bg-cardBg">
      <div className="border-b border-borderGray px-4 pb-3 pt-4">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      <div className="grid grid-cols-1 gap-4 px-4 pb-3 pt-4 sm:grid-cols-3">
        {items.map((item) => (
          <MetricItem key={item.label} {...item} />
        ))}
      </div>
    </section>
  );
}
