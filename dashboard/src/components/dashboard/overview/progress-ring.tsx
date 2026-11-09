type ProgressRingProps = {
  value: number;
  max: number;
};

export function ProgressRing({ value, max }: ProgressRingProps) {
  const size = 56;
  const strokeWidth = 7;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(Math.max(value / max, 0), 1);
  const dashOffset = circumference * (1 - progress);

  return (
    <div className="relative size-14" aria-hidden="true">
      <svg viewBox={`0 0 ${size} ${size}`} className="size-full -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          className="stroke-borderGray"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          className="stroke-primary"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          strokeWidth={strokeWidth}
        />
      </svg>
      <div className="absolute inset-3 rounded-full bg-cardBg" />
    </div>
  );
}
