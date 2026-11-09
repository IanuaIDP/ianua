import { cn } from '@/utils/cn';

type MiniLineChartProps = {
  points: [number, number, number, number, number];
  className?: string;
};

export function MiniLineChart({ points, className }: MiniLineChartProps) {
  const width = 220;
  const height = 64;
  const padding = 8;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const step = (width - padding * 2) / (points.length - 1);

  const coordinates = points.map((point, index) => {
    const x = padding + index * step;
    const normalized = (point - min) / range;
    const y = height - padding - normalized * (height - padding * 2);

    return { x, y };
  });

  const linePath = coordinates.reduce((path, point, index) => {
    if (index === 0) {
      return `M${point.x} ${point.y}`;
    }

    const previousPoint = coordinates[index - 1];
    const controlX = (previousPoint.x + point.x) / 2;

    return `${path} C${controlX} ${previousPoint.y}, ${controlX} ${point.y}, ${point.x} ${point.y}`;
  }, '');
  const firstPoint = coordinates[0];
  const lastPoint = coordinates[coordinates.length - 1];
  const areaPath = `${linePath} L${lastPoint.x} ${height} L${firstPoint.x} ${height} Z`;

  return (
    <div
      className={cn('h-8 w-full overflow-hidden rounded-lg text-primary', className)}
      aria-hidden="true"
    >
      <svg viewBox={`0 0 ${width} ${height}`} className="h-full w-full">
        <defs>
          <linearGradient id="mini-line-chart-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.45" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={areaPath} fill="url(#mini-line-chart-area)" />
        <path
          d={linePath}
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="3"
        />
        <circle cx={lastPoint.x} cy={lastPoint.y} r="5.5" fill="currentColor" />
      </svg>
    </div>
  );
}
