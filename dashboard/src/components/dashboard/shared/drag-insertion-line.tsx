import { cn } from '@/utils/cn';

type DragInsertionLineProps = {
  className?: string;
  orientation?: 'horizontal' | 'vertical';
};

export function DragInsertionLine({
  className,
  orientation = 'horizontal',
}: DragInsertionLineProps) {
  if (orientation === 'vertical') {
    return (
      <div
        aria-hidden
        className={cn(
          'pointer-events-none absolute inset-y-0 w-px rounded-full bg-primary shadow-primary-line-glow',
          className,
        )}
      >
        <span className="absolute left-1/2 top-0 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary shadow-primary-dot-glow" />
        <span className="absolute bottom-0 left-1/2 size-1.5 -translate-x-1/2 translate-y-1/2 rounded-full bg-primary shadow-primary-dot-glow" />
      </div>
    );
  }

  return (
    <div
      aria-hidden
      className={cn(
        'pointer-events-none absolute inset-x-0 h-px rounded-full bg-primary shadow-primary-line-glow',
        className,
      )}
    >
      <span className="absolute left-0 top-1/2 size-1.5 -translate-y-1/2 rounded-full bg-primary shadow-primary-dot-glow" />
      <span className="absolute right-0 top-1/2 size-1.5 -translate-y-1/2 rounded-full bg-primary shadow-primary-dot-glow" />
    </div>
  );
}
