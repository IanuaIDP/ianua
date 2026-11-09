import { cn } from '@/utils/cn';

type SecurityCardProps = {
  description: string;
  icon: string;
  isLast?: boolean;
  title: string;
};

export function SecurityCard({ description, icon, isLast = false, title }: SecurityCardProps) {
  return (
    <article
      className={cn(
        'flex min-h-55 min-w-64 flex-col gap-6 px-6 py-8 lg:min-w-0 hover:bg-hoverBg',
        !isLast && 'border-r border-borderGray',
      )}
    >
      <div className="flex size-12 items-center justify-center rounded-md border border-focus/30 text-focus bg-focus/5">
        <span className="material-symbols-rounded" aria-hidden="true">
          {icon}
        </span>
      </div>
      <div>
        <h3 className="text-xl font-bold text-white font-['Space_Grotesk','Manrope',sans-serif]">
          {title}
        </h3>
        <p className="mt-2 text-sm text-textGray">{description}</p>
      </div>
    </article>
  );
}
