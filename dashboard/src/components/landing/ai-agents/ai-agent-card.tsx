import { cn } from '@/utils/cn';

type AiAgentCardProps = {
  description: string;
  icon: string;
  size?: 'normal' | 'wide';
  tall?: boolean;
  title: string;
};

export function AiAgentCard({
  description,
  icon,
  size = 'normal',
  tall = false,
  title,
}: AiAgentCardProps) {
  return (
    <article
      className={cn(
        'flex w-full flex-col gap-6 rounded-xl bg-appBg border border-borderGray p-6',
        size === 'wide' ? 'lg:flex-[1.35]' : 'lg:flex-1',
        tall && 'lg:pb-10',
      )}
    >
      <div className="flex size-10 items-center justify-center rounded-lg border border-focus/30 bg-focus/10 text-focus">
        <span className="material-symbols-rounded text-xl!" aria-hidden="true">
          {icon}
        </span>
      </div>
      <div>
        <h3 className="font-['Space_Grotesk','Manrope',sans-serif] text-lg font-bold leading-6 text-white">
          {title}
        </h3>
        <p className="mt-3 text-sm leading-6 text-textGray">{description}</p>
      </div>
    </article>
  );
}
