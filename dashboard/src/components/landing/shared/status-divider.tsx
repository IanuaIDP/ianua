import { cn } from '@/utils/cn';

type StatusDividerProps = {
  id: string;
  label: string;
  tone?: 'focus' | 'primary';
};

export function StatusDivider({ id, label, tone = 'primary' }: StatusDividerProps) {
  const accentClasses =
    tone === 'focus'
      ? {
          line: 'bg-focus shadow-focus-line-glow',
          dot: 'bg-focus shadow-focus-dot-glow',
        }
      : {
          line: 'bg-primary shadow-primary-line-glow',
          dot: 'bg-primary shadow-primary-dot-glow',
        };

  return (
    <div id={id} className="relative h-8 bg-appBg">
      <div
        className={cn('absolute left-0 top-1/2 h-px w-full -translate-y-1/2', accentClasses.line)}
      />
      <div className="relative mx-auto flex h-full max-w-7xl items-center">
        <div className="flex items-center gap-3 bg-app-fade-x px-4 font-['Space_Grotesk','Manrope',sans-serif]">
          <span className={cn('size-2 rounded-full', accentClasses.dot)} />
          <span className="text-[10px] uppercase tracking-[0.16em] text-white">{label}</span>
        </div>
      </div>
    </div>
  );
}
