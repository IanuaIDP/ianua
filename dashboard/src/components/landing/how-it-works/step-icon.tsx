import { cn } from '@/utils/cn';

type StepIconProps = {
  isLast: boolean;
};

export function StepIcon({ isLast }: StepIconProps) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'material-symbols-rounded flex size-5 items-center justify-center',
        isLast ? 'text-primary' : 'text-focus',
      )}
    >
      {isLast ? 'check_circle' : 'arrow_forward'}
    </span>
  );
}
