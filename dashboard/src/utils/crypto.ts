import type { CryptoMigrationAction } from '@/types/crypto';
import { cn } from '@/utils/cn';

export function getCryptoMigrationActionClassName(action: CryptoMigrationAction) {
  return cn(
    'inline-flex h-8 items-center gap-2 rounded-lg px-4 text-sm font-medium transition disabled:pointer-events-none disabled:opacity-50',
    action === 'Start' || action === 'Complete' || action === 'Promote'
      ? 'bg-focus text-white hover:bg-focus/90'
      : 'border border-borderGray bg-cardBg text-white hover:bg-hoverBg',
  );
}
