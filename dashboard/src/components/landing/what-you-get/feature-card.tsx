import type { ReactNode } from 'react';
import { cn } from '@/utils/cn';

type FeatureCardProps = {
  children?: ReactNode;
  className?: string;
  description?: string;
  title?: string;
};

export function FeatureCard({ children, className = '', description, title }: FeatureCardProps) {
  return (
    <div className={cn('inline-flex flex-col bg-transparent', className)}>
      {children ?? (
        <>
          <h3 className="font-['Space_Grotesk','Manrope',sans-serif] text-2xl font-bold leading-10 text-white">
            {title}
          </h3>
          <p className="mt-4 text-lg font-medium leading-8 text-textGray">{description}</p>
        </>
      )}
    </div>
  );
}
