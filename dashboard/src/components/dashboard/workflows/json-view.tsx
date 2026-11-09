import { WithheldNotice } from '@/components/dashboard/workflows/withheld-notice';
import { cn } from '@/utils/cn';

type JsonViewProps = {
  className?: string;
  value: unknown;
  /** Set when the API held this data back from the reader. */
  withheld?: boolean;
};

/** Read-only JSON, or the notice shown when the data is above the reader's clearance. */
export function JsonView({ className, value, withheld = false }: JsonViewProps) {
  if (withheld) {
    return <WithheldNotice />;
  }

  return (
    <pre
      className={cn(
        'max-h-96 overflow-auto rounded-lg bg-appBg p-3 font-mono text-xs break-all whitespace-pre-wrap text-white',
        className,
      )}
    >
      {JSON.stringify(value ?? null, null, 2)}
    </pre>
  );
}
