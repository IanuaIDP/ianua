import { cn } from '@/utils/cn';

type SectionBadgeProps = {
  children: string;
  className?: string;
  iconName?: string;
  labelClassName?: string;
};

export function SectionBadge({
  children,
  className = 'border-borderGray bg-white/3 px-3.5 py-2',
  iconName,
  labelClassName = 'text-sm font-normal text-textGray',
}: SectionBadgeProps) {
  return (
    <div
      className={cn(
        'inline-flex w-fit max-w-full items-center gap-2 self-start rounded-full border uppercase',
        className,
      )}
    >
      {iconName ? (
        <span
          className="material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-primary"
          aria-hidden="true"
        >
          {iconName}
        </span>
      ) : (
        <span className="size-2 rounded-full bg-primary" />
      )}
      <span className={labelClassName}>{children}</span>
    </div>
  );
}
