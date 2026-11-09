import { StepIcon } from './step-icon';

import { cn } from '@/utils/cn';

type StepCardProps = {
  description: string;
  isLast: boolean;
  number: string;
  title: string;
};

export function StepCard({ description, isLast, number, title }: StepCardProps) {
  return (
    <div
      className={cn(
        'flex min-w-48 flex-col border-borderGray py-8 px-4 text-left lg:min-w-0 hover:bg-hoverBg',
        !isLast && 'border-r',
      )}
    >
      <div className="flex items-center justify-between gap-4">
        <span className="text-lg font-normal font-['Space_Grotesk','Manrope',sans-serif] text-textGray">
          {number}
        </span>
        <StepIcon isLast={isLast} />
      </div>

      <h3 className="mt-6 text-xl font-['Space_Grotesk','Manrope',sans-serif] font-bold text-white">
        {title}
      </h3>
      <p className="mt-2 text-sm text-textGray">{description}</p>
    </div>
  );
}
